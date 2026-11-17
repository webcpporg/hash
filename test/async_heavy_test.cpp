// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The heavy functions on another thread (spec 11.5, 11.4), in a build with threads (natively, and
// on Emscripten with -pthread under node): async_argon2id, async_argon2, async_scrypt and
// async_pbkdf2 on a webcpp::asio::thread_pool of two threads, each completing on the caller's
// io_context, to which its callback is bound. The work runs on a thread of the pool, never the
// caller's: a backend of this test, `recording`, whose engines run libsodium's and Hash2's and
// record the thread they run on, shows it. Each result equals the synchronous function's; a guard's
// refusal completes through the executor, never inside the call; a handler with no executor of
// its own completes on the pool; and a 10 ms timer on the caller's io_context fires while an
// Argon2id of 64 MiB runs.

#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/async.hpp>
#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/backends/sodium.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/pbkdf2.hpp>
#include <webcpp/hash/scrypt.hpp>

#include <webcpp/asio/bind_executor.hpp>
#include <webcpp/asio/io_context.hpp>
#include <webcpp/asio/steady_timer.hpp>
#include <webcpp/asio/thread_pool.hpp>
#include <webcpp/asio/use_future.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/result.hpp>

#include <webcpp/test/exit_status.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#ifndef WEBCPP_HASH_HAS_THREADS
#error "async_heavy_test is built where the program has threads"
#endif

namespace asio = webcpp::asio;
namespace hash = webcpp::hash;

namespace {

// The caller's thread, set by main before any work, and whether every engine of `recording` ran on
// another one. Both global: the engines are static member functions with no state of their own.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): set once by main
std::thread::id caller_thread;
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): written by the pool's threads
std::atomic<int> runs_off_caller{0};
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): written by the pool's threads
std::atomic<int> runs_on_caller{0};

void record_thread() {
    if (std::this_thread::get_id() == caller_thread) {
        ++runs_on_caller;
    } else {
        ++runs_off_caller;
    }
}

std::span<std::uint8_t const> bytes_of(std::string_view text) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): the text's bytes
    return {reinterpret_cast<std::uint8_t const*>(text.data()), text.size()};
}

}  // namespace

namespace webcpp::test {

// A backend of this test: libsodium's Argon2id and scrypt, and Hash2's PBKDF2, recording the
// thread each runs on.
struct recording;

}  // namespace webcpp::test

namespace webcpp::hash::detail {

/** Argon2id on `recording`: libsodium's, on the thread recorded. */
template <>
struct argon2id_engine<test::recording> {
    static constexpr argon2id_limits limits = argon2id_engine<backends::sodium>::limits;

    [[nodiscard]] static boost::system::result<void> derive(std::span<std::uint8_t> output,
                                                            std::span<std::uint8_t const> password,
                                                            std::span<std::uint8_t const> salt,
                                                            std::uint64_t passes,
                                                            std::size_t memory) noexcept {
        record_thread();
        return argon2id_engine<backends::sodium>::derive(output, password, salt, passes, memory);
    }
};

/** scrypt on `recording`: libsodium's, on the thread recorded. */
template <>
struct scrypt_engine<test::recording> {
    static constexpr scrypt_limits limits = scrypt_engine<backends::sodium>::limits;

    [[nodiscard]] static boost::system::result<void> derive(std::span<std::uint8_t> output,
                                                            std::span<std::uint8_t const> password,
                                                            std::span<std::uint8_t const> salt,
                                                            std::uint64_t cost_n,
                                                            std::uint32_t block_size_r,
                                                            std::uint32_t parallelism_p) noexcept {
        record_thread();
        return scrypt_engine<backends::sodium>::derive(output, password, salt, cost_n, block_size_r,
                                                       parallelism_p);
    }
};

/** PBKDF2 on `recording`: Hash2's, on the thread recorded. */
template <class Hmac>
struct pbkdf2_engine<test::recording, Hmac> {
    [[nodiscard]] static boost::system::result<void> derive(std::span<std::uint8_t> output,
                                                            std::span<std::uint8_t const> password,
                                                            std::span<std::uint8_t const> salt,
                                                            std::uint64_t iterations) noexcept {
        record_thread();
        return pbkdf2_engine<backends::hash2, Hmac>::derive(output, password, salt, iterations);
    }
};

/**
 Argon2id in the family on `recording`: libsodium's Argon2id with one lane, no secret and no
 associated data, which its limits hold, on the thread recorded.
*/
template <>
struct argon2_engine<test::recording, kdfs::argon2id> {
    static constexpr argon2_limits limits{
        .max_lanes = 1,
        .secret = false,
        .associated_data = false,
    };

    [[nodiscard]] static boost::system::result<void> derive(
        std::span<std::uint8_t> output, std::span<std::uint8_t const> password,
        std::span<std::uint8_t const> salt, argon2_parameters const& parameters) noexcept {
        record_thread();
        constexpr std::size_t kib = 1024;
        return argon2id_engine<backends::sodium>::derive(output, password, salt, parameters.passes,
                                                         std::size_t{parameters.memory_kib} * kib);
    }
};

}  // namespace webcpp::hash::detail

namespace {

using webcpp::test::recording;

// What a callback saw: whether it ran, whether the initiating call had returned when it did, on
// which thread, and the error code.
struct completion {
    bool called = false;
    bool after_return = false;
    std::thread::id thread;
    boost::system::error_code code;
};

// Runs `start(handler)` with a callback bound to the caller's io_context, then the context until it
// completes, which the operation's work keeps running; checks that it completed once, after the
// call returned, on the caller's thread. Returns the error code.
template <class Start>
boost::system::error_code complete_on_caller(asio::io_context& context, Start start) {
    completion seen;
    bool returned = false;
    start(asio::bind_executor(context.get_executor(),
                              [&seen, &returned](boost::system::error_code code) {
                                  seen.called = true;
                                  seen.after_return = returned;
                                  seen.thread = std::this_thread::get_id();
                                  seen.code = code;
                              }));
    returned = true;
    context.restart();
    context.run();
    BOOST_TEST(seen.called);
    BOOST_TEST(seen.after_return);
    BOOST_TEST(seen.thread == caller_thread);
    return seen.code;
}

// The work of each function on `recording` runs on the pool, and its result is the synchronous
// function's.
void check_on_pool(asio::io_context& context, asio::thread_pool& pool) {
    auto work = pool.get_executor();
    auto const password = bytes_of("password");
    std::array<std::uint8_t, hash::argon2id_salt_size> const salt{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    };
    hash::argon2id_parameters const small{.passes = 2, .memory = 65536};

    std::array<std::uint8_t, 32> expected{};
    BOOST_TEST(hash::argon2id(expected, password, salt, small).has_value());
    std::array<std::uint8_t, 32> output{};
    auto code = complete_on_caller(context, [&](auto handler) {
        hash::async_argon2id<recording>(work, output, password, salt, small, std::move(handler));
    });
    BOOST_TEST(!code);
    BOOST_TEST(output == expected);

    hash::argon2_parameters const family{.passes = 2, .memory_kib = 64};
    std::array<std::uint8_t, 32> family_expected{};
    BOOST_TEST(
        (hash::argon2<hash::kdfs::argon2id, recording>(family_expected, password, salt, family)
             .has_value()));
    BOOST_TEST(family_expected == expected);
    std::array<std::uint8_t, 32> family_output{};
    code = complete_on_caller(context, [&](auto handler) {
        hash::async_argon2<hash::kdfs::argon2id, recording>(work, family_output, password, salt,
                                                            family, std::move(handler));
    });
    BOOST_TEST(!code);
    BOOST_TEST(family_output == expected);

    hash::scrypt_parameters const costs{.n = 1024, .r = 8, .p = 1};
    std::array<std::uint8_t, 64> scrypt_expected{};
    BOOST_TEST(hash::scrypt(scrypt_expected, password, salt, costs).has_value());
    std::array<std::uint8_t, 64> scrypt_output{};
    code = complete_on_caller(context, [&](auto handler) {
        hash::async_scrypt<recording>(work, scrypt_output, password, salt, costs,
                                      std::move(handler));
    });
    BOOST_TEST(!code);
    BOOST_TEST(scrypt_output == scrypt_expected);

    std::array<std::uint8_t, 64> pbkdf2_expected{};
    BOOST_TEST(
        hash::pbkdf2<hash::hmac_sha2_512>(pbkdf2_expected, password, salt, 1000).has_value());
    std::array<std::uint8_t, 64> pbkdf2_output{};
    code = complete_on_caller(context, [&](auto handler) {
        hash::async_pbkdf2<hash::hmac_sha2_512, recording>(work, pbkdf2_output, password, salt,
                                                           1000, std::move(handler));
    });
    BOOST_TEST(!code);
    BOOST_TEST(pbkdf2_output == pbkdf2_expected);

    // The four asynchronous calls ran off the caller's thread; the one synchronous call on
    // `recording`, argon2's, on it.
    BOOST_TEST_EQ(runs_off_caller.load(), 4);
    BOOST_TEST_EQ(runs_on_caller.load(), 1);
}

// Each function on its default backend (async_pbkdf2 on backends::hash2 named, as spec 11.4 says),
// its result the synchronous function's; and a completion on the pool's thread.
void check_defaults(asio::io_context& context, asio::thread_pool& pool) {
    auto work = pool.get_executor();
    auto const password = bytes_of("password");
    std::array<std::uint8_t, hash::argon2id_salt_size> const salt{
        0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09,
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
    };

    hash::argon2id_parameters const small{.passes = 1, .memory = 32768};
    std::array<std::uint8_t, 16> expected{};
    BOOST_TEST(hash::argon2id(expected, password, salt, small).has_value());
    std::array<std::uint8_t, 16> output{};
    auto code = complete_on_caller(context, [&](auto handler) {
        hash::async_argon2id(work, output, password, salt, small, std::move(handler));
    });
    BOOST_TEST(!code);
    BOOST_TEST(output == expected);

    hash::scrypt_parameters const costs{.n = 16, .r = 1, .p = 1};
    std::array<std::uint8_t, 64> scrypt_expected{};
    BOOST_TEST(hash::scrypt(scrypt_expected, bytes_of(""), bytes_of(""), costs).has_value());
    std::array<std::uint8_t, 64> scrypt_output{};
    code = complete_on_caller(context, [&](auto handler) {
        hash::async_scrypt(work, scrypt_output, bytes_of(""), bytes_of(""), costs,
                           std::move(handler));
    });
    BOOST_TEST(!code);
    BOOST_TEST(scrypt_output == scrypt_expected);

    std::array<std::uint8_t, 64> pbkdf2_expected{};
    BOOST_TEST(hash::pbkdf2<hash::hmac_sha2_512>(pbkdf2_expected, password, salt, 1).has_value());
    std::array<std::uint8_t, 64> pbkdf2_output{};
    code = complete_on_caller(context, [&](auto handler) {
        hash::async_pbkdf2<hash::hmac_sha2_512, hash::backends::hash2>(
            work, pbkdf2_output, password, salt, 1, std::move(handler));
    });
    BOOST_TEST(!code);
    BOOST_TEST(pbkdf2_output == pbkdf2_expected);

    // A handler with no executor of its own completes on the pool's thread (Asio's default, the
    // executor the call was given): here use_future's, which the caller waits on.
    std::array<std::uint8_t, 64> by_future{};
    auto done = hash::async_pbkdf2<hash::hmac_sha2_512, hash::backends::hash2>(
        work, by_future, password, salt, 1, asio::use_future);
    done.get();
    BOOST_TEST(by_future == pbkdf2_expected);
}

// A guard's refusal completes through the executor, never inside the call, with the guard's error
// and the output untouched.
void check_guards(asio::io_context& context, asio::thread_pool& pool) {
    auto work = pool.get_executor();
    std::array<std::uint8_t, hash::argon2id_salt_size> const salt{};
    std::span<std::uint8_t> nothing{};

    auto code = complete_on_caller(context, [&](auto handler) {
        hash::async_argon2id(work, nothing, {}, salt, hash::argon2id_interactive,
                             std::move(handler));
    });
    BOOST_TEST(code == hash::error::invalid_output_size);

    std::array<std::uint8_t, 32> untouched{0x5a};
    code = complete_on_caller(context, [&](auto handler) {
        hash::async_argon2<hash::kdfs::argon2id, recording>(
            work, untouched, {}, salt, hash::argon2_parameters{.passes = 0, .memory_kib = 64},
            std::move(handler));
    });
    BOOST_TEST(code == hash::error::invalid_parameters);
    BOOST_TEST_EQ(untouched[0], 0x5a);

    code = complete_on_caller(context, [&](auto handler) {
        hash::async_scrypt(work, untouched, {}, {}, hash::scrypt_parameters{.n = 3, .r = 1, .p = 1},
                           std::move(handler));
    });
    BOOST_TEST(code == hash::error::invalid_parameters);
    BOOST_TEST_EQ(untouched[0], 0x5a);

    code = complete_on_caller(context, [&](auto handler) {
        hash::async_pbkdf2<hash::hmac_sha2_256, hash::backends::hash2>(work, untouched, {}, {}, 0,
                                                                       std::move(handler));
    });
    BOOST_TEST(code == hash::error::invalid_iterations);
    BOOST_TEST_EQ(untouched[0], 0x5a);
}

// The caller's event loop stays responsive: a 10 ms timer on its io_context fires while an Argon2id
// of 64 MiB (libsodium's interactive costs) runs on the pool.
void check_responsive(asio::io_context& context, asio::thread_pool& pool) {
    auto const password = bytes_of("correct horse battery staple");
    std::array<std::uint8_t, hash::argon2id_salt_size> const salt{};
    std::array<std::uint8_t, 32> output{};
    bool derived = false;
    bool timer_fired = false;
    bool timer_fired_first = false;
    hash::async_argon2id(
        pool.get_executor(), output, password, salt, hash::argon2id_interactive,
        asio::bind_executor(context.get_executor(), [&](boost::system::error_code code) {
            BOOST_TEST(!code);
            derived = true;
        }));
    asio::steady_timer timer(context, std::chrono::milliseconds(10));
    timer.async_wait([&](boost::system::error_code code) {
        BOOST_TEST(!code);
        timer_fired = true;
        timer_fired_first = !derived;
    });
    context.restart();
    context.run();
    BOOST_TEST(derived);
    BOOST_TEST(timer_fired);
    BOOST_TEST(timer_fired_first);
    std::array<std::uint8_t, 32> expected{};
    BOOST_TEST(hash::argon2id(expected, password, salt, hash::argon2id_interactive).has_value());
    BOOST_TEST(output == expected);
}

}  // namespace

int main() {
    caller_thread = std::this_thread::get_id();
    asio::io_context context;
    asio::thread_pool pool(2);
    check_on_pool(context, pool);
    check_defaults(context, pool);
    check_guards(context, pool);
    check_responsive(context, pool);
    pool.join();
    return webcpp::test::exit_status(boost::report_errors());
}
