// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The heavy functions on backends::botan, on another thread (spec 11.5), in a build with threads
// (natively, and on Emscripten with -pthread under node): async_bcrypt, async_bcrypt_pbkdf,
// async_bcrypt_verify (whose completion carries a bool), async_argon2<kdfs::argon2id>,
// async_scrypt and async_pbkdf2<hmac_sha2_256> on a webcpp::asio::thread_pool of two threads. Each
// completes once, after the call returned, on the caller's io_context its callback is bound to,
// with the synchronous function's result; a handler with no executor of its own completes on the
// pool's thread that ran the work, never the caller's. A guard's refusal completes through a post,
// the output untouched; a cancellation before the work starts completes at once with
// operation_aborted, the output untouched and verify's bool false.

#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/async.hpp>
#include <webcpp/hash/bcrypt.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/pbkdf2.hpp>
#include <webcpp/hash/scrypt.hpp>

#include <webcpp/asio/bind_cancellation_slot.hpp>
#include <webcpp/asio/bind_executor.hpp>
#include <webcpp/asio/cancellation_signal.hpp>
#include <webcpp/asio/cancellation_type.hpp>
#include <webcpp/asio/error.hpp>
#include <webcpp/asio/io_context.hpp>
#include <webcpp/asio/post.hpp>
#include <webcpp/asio/thread_pool.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/system/error_code.hpp>

#include <webcpp/test/exit_status.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <future>
#include <span>
#include <string_view>
#include <thread>
#include <utility>

#ifndef WEBCPP_HASH_HAS_THREADS
#error "async_heavy_botan_test is built where the program has threads"
#endif

namespace asio = webcpp::asio;
namespace hash = webcpp::hash;

namespace {

using hash::backends::botan;

// The caller's thread, set by main before any work.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): set once by main
std::thread::id caller_thread;

std::span<std::uint8_t const> bytes_of(std::string_view text) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): the text's bytes
    return {reinterpret_cast<std::uint8_t const*>(text.data()), text.size()};
}

// What a completion saw: whether it ran, after the call returned, on which thread, with which code
// and, for verify, which bool.
struct completion {
    bool called = false;
    bool after_return = false;
    std::thread::id thread{};
    boost::system::error_code code{};
    bool same = false;
};

// Runs `start(handler)` with a callback bound to the caller's io_context, then the context until it
// completes; checks that it completed once, after the call returned, on the caller's thread.
template <class Start>
completion complete_on_caller(asio::io_context& context, Start start) {
    completion seen;
    bool returned = false;
    auto record = [&seen, &returned](boost::system::error_code code, auto... same) {
        seen.called = true;
        seen.after_return = returned;
        seen.thread = std::this_thread::get_id();
        seen.code = code;
        ((seen.same = same), ...);
    };
    start(asio::bind_executor(context.get_executor(), record));
    returned = true;
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST(seen.called);
    BOOST_TEST(seen.after_return);
    BOOST_TEST(seen.thread == caller_thread);
    return seen;
}

// Runs `start(handler)` with a callback of no executor of its own, which completes on the work
// executor's thread that ran the work: its thread is the work's, which is not the caller's.
template <class Start>
completion complete_on_pool(Start start) {
    std::promise<completion> done;
    auto seen = done.get_future();
    start([&done](boost::system::error_code code, auto... same) {
        // verify's bool, or false for a completion without one.
        bool const received = (false || ... || same);
        completion const c{
            .called = true,
            .thread = std::this_thread::get_id(),
            .code = code,
            .same = received,
        };
        done.set_value(c);
    });
    BOOST_TEST(seen.wait_for(std::chrono::seconds(60)) == std::future_status::ready);
    completion const c = seen.get();
    BOOST_TEST(c.called);
    BOOST_TEST(c.thread != caller_thread);
    return c;
}

// "password", as bytes, and a salt: named test_*, which no parameter of the library hides (MSVC
// C4459 at /WX).
constexpr std::array<std::uint8_t, 8> test_password{'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
constexpr std::array<std::uint8_t, 16> test_salt{1, 2,  3,  4,  5,  6,  7,  8,
                                                 9, 10, 11, 12, 13, 14, 15, 16};

void check_bcrypt(asio::io_context& context, asio::thread_pool& pool) {
    auto work = pool.get_executor();
    hash::bcrypt_parameters const parameters{.cost = 5};
    std::array<char, hash::bcrypt_hash_size> expected{};
    BOOST_TEST((hash::bcrypt<botan>(expected, test_password, test_salt, parameters).has_value()));
    std::string_view const stored(expected.data(), expected.size());

    std::array<char, hash::bcrypt_hash_size> output{};
    auto seen = complete_on_caller(context, [&](auto handler) {
        hash::async_bcrypt<botan>(work, output, test_password, test_salt, parameters,
                                  std::move(handler));
    });
    BOOST_TEST(!seen.code);
    BOOST_TEST(output == expected);
    output.fill('\0');
    seen = complete_on_pool([&](auto handler) {
        hash::async_bcrypt<botan>(work, output, test_password, test_salt, parameters,
                                  std::move(handler));
    });
    BOOST_TEST(!seen.code);
    BOOST_TEST(output == expected);

    seen = complete_on_caller(context, [&](auto handler) {
        hash::async_bcrypt_verify<botan>(work, test_password, stored, std::move(handler));
    });
    BOOST_TEST(!seen.code);
    BOOST_TEST(seen.same);
    seen = complete_on_pool([&](auto handler) {
        hash::async_bcrypt_verify<botan>(work, bytes_of("passwore"), stored, std::move(handler));
    });
    BOOST_TEST(!seen.code);
    BOOST_TEST(!seen.same);

    // A guard's refusal completes through a post: a salt of 15 bytes, the output untouched; a
    // string not of bcrypt's form, the bool false.
    output.fill('U');
    seen = complete_on_caller(context, [&](auto handler) {
        hash::async_bcrypt<botan>(work, output, test_password, std::span(test_salt).first(15),
                                  parameters, std::move(handler));
    });
    BOOST_TEST(seen.code == hash::error::invalid_salt_size);
    BOOST_TEST(std::ranges::all_of(output, [](char c) { return c == 'U'; }));
    seen = complete_on_caller(context, [&](auto handler) {
        hash::async_bcrypt_verify<botan>(work, test_password, stored.substr(1), std::move(handler));
    });
    BOOST_TEST(seen.code == hash::error::invalid_parameters);
    BOOST_TEST(!seen.same);
}

void check_bcrypt_pbkdf(asio::io_context& context, asio::thread_pool& pool) {
    auto work = pool.get_executor();
    std::array<std::uint8_t, 48> expected{};
    BOOST_TEST((hash::bcrypt_pbkdf<botan>(expected, test_password, test_salt, 4).has_value()));
    std::array<std::uint8_t, 48> output{};
    auto seen = complete_on_caller(context, [&](auto handler) {
        hash::async_bcrypt_pbkdf<botan>(work, output, test_password, test_salt, 4,
                                        std::move(handler));
    });
    BOOST_TEST(!seen.code);
    BOOST_TEST(output == expected);
    output.fill(0);
    seen = complete_on_pool([&](auto handler) {
        hash::async_bcrypt_pbkdf<botan>(work, output, test_password, test_salt, 4,
                                        std::move(handler));
    });
    BOOST_TEST(!seen.code);
    BOOST_TEST(output == expected);
    seen = complete_on_caller(context, [&](auto handler) {
        hash::async_bcrypt_pbkdf<botan>(work, output, test_password, test_salt, 0,
                                        std::move(handler));
    });
    BOOST_TEST(seen.code == hash::error::invalid_iterations);
}

void check_families(asio::io_context& context, asio::thread_pool& pool) {
    auto work = pool.get_executor();
    hash::argon2_parameters const family{.passes = 2, .memory_kibibytes = 64, .lanes = 2};
    std::array<std::uint8_t, 32> argon2_expected{};
    BOOST_TEST((
        hash::argon2<hash::kdfs::argon2id, botan>(argon2_expected, test_password, test_salt, family)
            .has_value()));
    std::array<std::uint8_t, 32> argon2_output{};
    auto seen = complete_on_caller(context, [&](auto handler) {
        hash::async_argon2<hash::kdfs::argon2id, botan>(work, argon2_output, test_password,
                                                        test_salt, family, std::move(handler));
    });
    BOOST_TEST(!seen.code);
    BOOST_TEST(argon2_output == argon2_expected);
    argon2_output.fill(0);
    seen = complete_on_pool([&](auto handler) {
        hash::async_argon2<hash::kdfs::argon2id, botan>(work, argon2_output, test_password,
                                                        test_salt, family, std::move(handler));
    });
    BOOST_TEST(argon2_output == argon2_expected);

    hash::scrypt_parameters const costs{.cost = 1024, .block_size = 8, .parallelism = 1};
    std::array<std::uint8_t, 64> scrypt_expected{};
    BOOST_TEST(hash::scrypt<botan>(scrypt_expected, test_password, test_salt, costs).has_value());
    std::array<std::uint8_t, 64> scrypt_output{};
    seen = complete_on_caller(context, [&](auto handler) {
        hash::async_scrypt<botan>(work, scrypt_output, test_password, test_salt, costs,
                                  std::move(handler));
    });
    BOOST_TEST(!seen.code);
    BOOST_TEST(scrypt_output == scrypt_expected);
    scrypt_output.fill(0);
    seen = complete_on_pool([&](auto handler) {
        hash::async_scrypt<botan>(work, scrypt_output, test_password, test_salt, costs,
                                  std::move(handler));
    });
    BOOST_TEST(scrypt_output == scrypt_expected);

    std::array<std::uint8_t, 32> pbkdf2_expected{};
    BOOST_TEST(
        (hash::pbkdf2<hash::hmac_sha2_256, botan>(pbkdf2_expected, test_password, test_salt, 1000)
             .has_value()));
    std::array<std::uint8_t, 32> pbkdf2_output{};
    seen = complete_on_caller(context, [&](auto handler) {
        hash::async_pbkdf2<hash::hmac_sha2_256, botan>(work, pbkdf2_output, test_password,
                                                       test_salt, 1000, std::move(handler));
    });
    BOOST_TEST(!seen.code);
    BOOST_TEST(pbkdf2_output == pbkdf2_expected);
    pbkdf2_output.fill(0);
    seen = complete_on_pool([&](auto handler) {
        hash::async_pbkdf2<hash::hmac_sha2_256, botan>(work, pbkdf2_output, test_password,
                                                       test_salt, 1000, std::move(handler));
    });
    BOOST_TEST(pbkdf2_output == pbkdf2_expected);
}

// A pool kept busy by a job of the test's: a cancellation before the work starts completes at once
// with operation_aborted, the output untouched and the bool false, the work never run.
void check_cancelled_before(asio::io_context& context) {
    asio::thread_pool busy(1);
    std::promise<void> release;
    auto const released = release.get_future().share();
    std::atomic<bool> blocking{false};
    asio::post(busy, [&blocking, released] {
        blocking = true;
        released.wait();
    });
    while (!blocking) {
        std::this_thread::yield();
    }
    auto const cancelled = [&](auto start) {
        asio::cancellation_signal signal;
        // `same` starts true, so that verify's false is seen to arrive.
        completion seen{.same = true};
        start(asio::bind_cancellation_slot(
            signal.slot(),
            asio::bind_executor(context.get_executor(),
                                [&seen](boost::system::error_code code, auto... same) {
                                    seen.called = true;
                                    seen.code = code;
                                    ((seen.same = same), ...);
                                })));
        signal.emit(asio::cancellation_type::terminal);
        context.restart();
        context.run_for(std::chrono::seconds(5));  // lint-run: the test's event loop
        BOOST_TEST(seen.called);
        BOOST_TEST(seen.code == asio::error::operation_aborted);
        return seen;
    };
    std::array<char, hash::bcrypt_hash_size> output{};
    output.fill('U');
    cancelled([&](auto handler) {
        hash::async_bcrypt<botan>(busy.get_executor(), output, test_password, test_salt,
                                  {.cost = 4}, std::move(handler));
    });
    BOOST_TEST(std::ranges::all_of(output, [](char c) { return c == 'U'; }));
    std::array<std::uint8_t, 32> derived{};
    derived.fill(0x5a);
    cancelled([&](auto handler) {
        hash::async_bcrypt_pbkdf<botan>(busy.get_executor(), derived, test_password, test_salt, 2,
                                        std::move(handler));
    });
    BOOST_TEST(std::ranges::all_of(derived, [](std::uint8_t b) { return b == 0x5a; }));
    std::array<char, hash::bcrypt_hash_size> stored{};
    BOOST_TEST((hash::bcrypt<botan>(stored, test_password, test_salt, {.cost = 4}).has_value()));
    auto const seen = cancelled([&](auto handler) {
        hash::async_bcrypt_verify<botan>(busy.get_executor(), test_password,
                                         std::string_view(stored.data(), stored.size()),
                                         std::move(handler));
    });
    BOOST_TEST(!seen.same);
    release.set_value();
    busy.join();
}

}  // namespace

int main() {
    caller_thread = std::this_thread::get_id();
    asio::io_context context;
    asio::thread_pool pool(2);
    check_bcrypt(context, pool);
    check_bcrypt_pbkdf(context, pool);
    check_families(context, pool);
    check_cancelled_before(context);
    pool.join();
    return webcpp::test::exit_status(boost::report_errors());
}
