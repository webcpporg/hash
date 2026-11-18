// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The heavy functions on another thread (spec 11.5, 11.4), in a build with threads (natively, and
// on Emscripten with -pthread under node): async_argon2id, async_argon2 (Argon2id and Argon2i,
// libsodium's by default), async_scrypt and async_pbkdf2 on a webcpp::asio::thread_pool of two
// threads, each completing on the caller's io_context, to which its callback is bound. The work
// runs on a thread of the pool, never the caller's: a backend of this test, `recording`, whose
// engines run libsodium's and Hash2's and record the thread they run on, shows it. Each result
// equals the synchronous function's; a guard's refusal completes through the executor, never inside
// the call; a handler with no executor of its own completes on the pool; and a 10 ms timer on the
// caller's io_context fires while an Argon2id of 64 MiB runs. Cancellation (spec 11.5): before the
// work starts it completes at once, the work never run; after it starts, the work runs to its end
// and only then the completion is operation_aborted, the output zeroed, while a `total` one is not
// honoured; a second test backend, `gated`, holds its work until the test lets it go, and shows
// that the work reads the caller's spans themselves, never a copy, so that they are the caller's
// until the completion. The handler's associated allocator gets back every block before the handler
// runs; and co_await in Asio (use_awaitable) completes on the caller's loop, an error read through
// as_tuple without exceptions (ruling R71).

#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/async.hpp>
#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/backends/sodium.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/pbkdf2.hpp>
#include <webcpp/hash/scrypt.hpp>

#include <webcpp/asio/as_tuple.hpp>
#include <webcpp/asio/awaitable.hpp>
#include <webcpp/asio/bind_allocator.hpp>
#include <webcpp/asio/bind_cancellation_slot.hpp>
#include <webcpp/asio/bind_executor.hpp>
#include <webcpp/asio/cancellation_signal.hpp>
#include <webcpp/asio/cancellation_type.hpp>
#include <webcpp/asio/co_spawn.hpp>
#include <webcpp/asio/error.hpp>
#include <webcpp/asio/io_context.hpp>
#include <webcpp/asio/post.hpp>
#include <webcpp/asio/steady_timer.hpp>
#include <webcpp/asio/thread_pool.hpp>
#include <webcpp/asio/use_awaitable.hpp>
#include <webcpp/asio/use_future.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/result.hpp>
#include <boost/system/system_error.hpp>

#include <webcpp/test/exit_status.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <future>
#include <memory>
#include <span>
#include <string_view>
#include <thread>
#include <type_traits>
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

// The gate of the `gated` backend: whether its work has started, whether the test has let it go,
// and the spans the work was given. Global, as the counters above.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): written by the pool's thread
std::atomic<bool> gate_entered{false};
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): set by the test
std::atomic<bool> gate_open{false};
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): written by the pool's thread
std::atomic<std::uint8_t const*> gated_password{nullptr};
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): written by the pool's thread
std::atomic<std::uint8_t*> gated_output{nullptr};

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

// A backend of this test whose Argon2id waits for the test's gate, then fills the output with 0x11:
// a work that has started and has not ended, for as long as the test needs.
struct gated;

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

/**
 Argon2id on `gated`: records the spans it was given, waits until the test opens the gate, then
 fills the output with 0x11.
*/
template <>
struct argon2id_engine<test::gated> {
    static constexpr argon2id_limits limits = argon2id_engine<backends::sodium>::limits;

    [[nodiscard]] static boost::system::result<void> derive(std::span<std::uint8_t> output,
                                                            std::span<std::uint8_t const> password,
                                                            std::span<std::uint8_t const> /*salt*/,
                                                            std::uint64_t /*passes*/,
                                                            std::size_t /*memory*/) noexcept {
        gated_output = output.data();
        gated_password = password.data();
        gate_entered = true;
        while (!gate_open) {
            std::this_thread::yield();
        }
        std::ranges::fill(output, std::uint8_t{0x11});
        return {};
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

using webcpp::test::gated;
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
    context.run();  // lint-run: the test's event loop
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

// async_argon2 of `Variant` on its default backend, backends::sodium, and on it named: each
// result the synchronous family's; then libsodium's own limit (Argon2i takes 3 passes at least,
// and Argon2id one lane), answered by the guards with unsupported_by_backend, the output untouched.
template <class Variant>
void check_family_defaults(asio::io_context& context, asio::thread_pool& pool,
                           hash::argon2_parameters const& parameters) {
    static_assert(std::is_same_v<hash::default_backend<Variant>, hash::backends::sodium>);
    auto work = pool.get_executor();
    auto const password = bytes_of("password");
    std::array<std::uint8_t, hash::argon2id_salt_size> const salt{
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    };
    std::array<std::uint8_t, 32> expected{};
    BOOST_TEST((hash::argon2<Variant>(expected, password, salt, parameters).has_value()));
    std::array<std::uint8_t, 32> by_default{};
    auto code = complete_on_caller(context, [&](auto handler) {
        hash::async_argon2<Variant>(work, by_default, password, salt, parameters,
                                    std::move(handler));
    });
    BOOST_TEST(!code);
    BOOST_TEST(by_default == expected);
    std::array<std::uint8_t, 32> named{};
    code = complete_on_caller(context, [&](auto handler) {
        hash::async_argon2<Variant, hash::backends::sodium>(work, named, password, salt, parameters,
                                                            std::move(handler));
    });
    BOOST_TEST(!code);
    BOOST_TEST(named == expected);

    hash::argon2_parameters beyond = parameters;
    if constexpr (std::is_same_v<Variant, hash::kdfs::argon2i>) {
        beyond.passes = 2;
    } else {
        beyond.lanes = 2;
        beyond.memory_kib = 64;
    }
    std::array<std::uint8_t, 32> untouched{0x5a};
    code = complete_on_caller(context, [&](auto handler) {
        hash::async_argon2<Variant>(work, untouched, password, salt, beyond, std::move(handler));
    });
    BOOST_TEST(code == hash::error::unsupported_by_backend);
    BOOST_TEST_EQ(untouched[0], 0x5a);
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

    check_family_defaults<hash::kdfs::argon2id>(context, pool, {.passes = 1, .memory_kib = 32});
    check_family_defaults<hash::kdfs::argon2i>(context, pool, {.passes = 3, .memory_kib = 32});

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

// A pool kept busy by a job of the test's: what waits in its queue must not wait for it. A
// cancellation before the work starts completes at once with operation_aborted, the output
// untouched, and the work never runs; a guard's refusal completes without the pool.
void check_queued(asio::io_context& context) {
    asio::thread_pool busy(1);
    std::promise<void> release;
    auto released = release.get_future();
    std::atomic<bool> blocking{false};
    asio::post(busy, [&] {
        blocking = true;
        released.wait();
    });
    while (!blocking) {
        std::this_thread::yield();
    }

    auto const password = bytes_of("password");
    std::array<std::uint8_t, hash::argon2id_salt_size> const salt{};
    hash::argon2id_parameters const small{.passes = 1, .memory = 32768};
    int const runs_before = runs_off_caller.load();

    std::array<std::uint8_t, 32> output{};
    output[0] = 0x5a;
    asio::cancellation_signal signal;
    bool cancelled = false;
    boost::system::error_code cancel_code;
    hash::async_argon2id<recording>(
        busy.get_executor(), output, password, salt, small,
        asio::bind_cancellation_slot(
            signal.slot(),
            asio::bind_executor(context.get_executor(), [&](boost::system::error_code code) {
                cancelled = true;
                cancel_code = code;
            })));
    signal.emit(asio::cancellation_type::terminal);
    context.restart();
    context.run_for(std::chrono::seconds(5));  // lint-run: the test's event loop
    BOOST_TEST(cancelled);
    BOOST_TEST(cancel_code == asio::error::operation_aborted);
    BOOST_TEST_EQ(output[0], 0x5a);

    bool refused = false;
    boost::system::error_code refusal_code;
    hash::async_argon2id<recording>(
        busy.get_executor(), output, password, std::span(salt).first(8), small,
        asio::bind_executor(context.get_executor(), [&](boost::system::error_code code) {
            refused = true;
            refusal_code = code;
        }));
    context.restart();
    context.run_for(std::chrono::seconds(5));  // lint-run: the test's event loop
    BOOST_TEST(refused);
    BOOST_TEST(refusal_code == hash::error::invalid_salt_size);

    release.set_value();
    busy.join();
    BOOST_TEST_EQ(runs_off_caller.load(), runs_before);
    BOOST_TEST_EQ(output[0], 0x5a);
}

// What a holding_allocator counts, shared by its rebound copies: the blocks it holds now, and
// every block it has given.
struct holding {
    std::atomic<int> held{0};
    std::atomic<int> taken{0};
};

// An allocator that counts the blocks it holds and gives; its deallocation may run on a pool's
// thread.
template <class T>
struct holding_allocator {
    using value_type = T;
    holding* counts;

    explicit holding_allocator(holding* counter) noexcept : counts(counter) {}

    // Allocator rebind conversions must be implicit (Allocator requirements).
    template <class U>
    // NOLINTNEXTLINE(misc-explicit-constructor)
    holding_allocator(holding_allocator<U> const& other) noexcept : counts(other.counts) {}

    T* allocate(std::size_t count) {
        counts->held.fetch_add(1);
        counts->taken.fetch_add(1);
        return std::allocator<T>().allocate(count);
    }

    void deallocate(T* pointer, std::size_t count) noexcept {
        std::allocator<T>().deallocate(pointer, count);
        counts->held.fetch_sub(1);
    }

    template <class U>
    bool operator==(holding_allocator<U> const& other) const noexcept {
        return counts == other.counts;
    }
};

// The operation's storage is the handler's (spec 11.4): the operation's state and its completion
// come from the handler's associated allocator, two blocks at least, and, by Asio's rule, the
// operation gives back every one before it calls the handler, so that the handler can reuse it.
// Checked on the four ways a heavy call completes: the work done (with a connected cancellation
// slot), a guard's refusal (its post alone), a cancellation before the work starts, in a busy
// pool, and one after the work has started.
void check_allocator_released(asio::io_context& context, asio::thread_pool& pool) {
    auto const password = bytes_of("password");
    std::array<std::uint8_t, hash::argon2id_salt_size> const salt{};
    hash::argon2id_parameters const small{.passes = 1, .memory = 32768};
    std::array<std::uint8_t, 32> output{};
    holding counts;

    struct seen {
        int held_at_call = -1;
        int taken = 0;
        boost::system::error_code code;
    };
    auto const start = [&]<class Backend>(Backend*, auto& work,
                                          std::span<std::uint8_t const> salt_bytes,
                                          asio::cancellation_signal& signal, seen& call) {
        int const taken_before = counts.taken.load();
        hash::async_argon2id<Backend>(
            work.get_executor(), output, password, salt_bytes, small,
            asio::bind_cancellation_slot(
                signal.slot(),
                asio::bind_executor(
                    context.get_executor(),
                    asio::bind_allocator(holding_allocator<char>(&counts),
                                         [&, taken_before](boost::system::error_code done) {
                                             call.held_at_call = counts.held.load();
                                             call.taken = counts.taken.load() - taken_before;
                                             call.code = done;
                                         }))));
    };
    auto* const on_recording = static_cast<recording*>(nullptr);

    asio::cancellation_signal done_signal;
    seen done;
    start(on_recording, pool, salt, done_signal, done);
    context.restart();
    context.run_for(std::chrono::seconds(30));  // lint-run: the test's event loop
    BOOST_TEST(!done.code);
    BOOST_TEST_EQ(done.held_at_call, 0);
    BOOST_TEST_GE(done.taken, 2);

    asio::cancellation_signal refused_signal;
    seen refused;
    start(on_recording, pool, std::span(salt).first(8), refused_signal, refused);
    context.restart();
    context.run_for(std::chrono::seconds(5));  // lint-run: the test's event loop
    BOOST_TEST(refused.code == hash::error::invalid_salt_size);
    BOOST_TEST_EQ(refused.held_at_call, 0);
    BOOST_TEST_GE(refused.taken, 1);

    asio::thread_pool busy(1);
    std::promise<void> release;
    auto released = release.get_future();
    std::atomic<bool> blocking{false};
    asio::post(busy, [&] {
        blocking = true;
        released.wait();
    });
    while (!blocking) {
        std::this_thread::yield();
    }
    asio::cancellation_signal cancel_signal;
    seen cancelled;
    start(on_recording, busy, salt, cancel_signal, cancelled);
    cancel_signal.emit(asio::cancellation_type::terminal);
    context.restart();
    context.run_for(std::chrono::seconds(5));  // lint-run: the test's event loop
    BOOST_TEST(cancelled.code == asio::error::operation_aborted);
    BOOST_TEST_EQ(cancelled.held_at_call, 0);
    BOOST_TEST_GE(cancelled.taken, 2);
    release.set_value();
    busy.join();

    asio::thread_pool one(1);
    gate_entered = false;
    gate_open = false;
    asio::cancellation_signal running_signal;
    seen running;
    start(static_cast<gated*>(nullptr), one, salt, running_signal, running);
    while (!gate_entered) {
        std::this_thread::yield();
    }
    running_signal.emit(asio::cancellation_type::terminal);
    gate_open = true;
    context.restart();
    context.run_for(std::chrono::seconds(5));  // lint-run: the test's event loop
    BOOST_TEST(running.code == asio::error::operation_aborted);
    BOOST_TEST_EQ(running.held_at_call, 0);
    BOOST_TEST_GE(running.taken, 2);
    one.join();
    BOOST_TEST_EQ(counts.held.load(), 0);
}

// A cancellation racing the pool: 300 quick PBKDF2s, each cancelled after a spin of 0 to 299
// yields, so that the emit lands while the job waits, while the pool takes it, while it runs and
// after it has completed. Each call completes exactly once, successfully or with
// operation_aborted, and the handler's allocator holds nothing when it runs.
void check_cancellation_races(asio::io_context& context) {
    asio::thread_pool pool(1);
    holding counts;
    std::array<std::uint8_t, 32> output{};
    int aborted = 0;
    for (int round = 0; round != 300; ++round) {
        asio::cancellation_signal signal;
        int calls = 0;
        int held_at_call = -1;
        boost::system::error_code code;
        hash::async_pbkdf2<hash::hmac_sha2_256, hash::backends::hash2>(
            pool.get_executor(), output, bytes_of("password"), bytes_of("salt"), 1,
            asio::bind_cancellation_slot(
                signal.slot(),
                asio::bind_executor(context.get_executor(),
                                    asio::bind_allocator(holding_allocator<char>(&counts),
                                                         [&](boost::system::error_code done) {
                                                             ++calls;
                                                             held_at_call = counts.held.load();
                                                             code = done;
                                                         }))));
        for (int spin = 0; spin != round; ++spin) {
            std::this_thread::yield();
        }
        signal.emit(asio::cancellation_type::terminal);
        context.restart();
        context.run_for(std::chrono::seconds(5));  // lint-run: the test's event loop
        BOOST_TEST_EQ(calls, 1);
        BOOST_TEST_EQ(held_at_call, 0);
        BOOST_TEST(!code || code == asio::error::operation_aborted);
        aborted += code ? 1 : 0;
    }
    pool.join();
    BOOST_TEST_EQ(counts.held.load(), 0);
    BOOST_TEST_GE(aborted, 1);
}

// The handler of a call that never completes: its executor, or the pool, destroyed with the
// operation's completion queued. Asio destroys a queued operation unrun, and with it the handler,
// whose storage goes back to its allocator: the handler is destroyed, never called, and the
// operation holds nothing of the handler's allocator. A sentinel the handler owns tells that it was
// destroyed.
struct unrun_handler {
    holding* counts;
    std::shared_ptr<int> sentinel;
    bool* called;

    void operator()(boost::system::error_code /*code*/) const { *called = true; }
};

// A pool of one thread blocked by the test, stopped and destroyed with the operation's job still
// queued; `bind` binds the handler (to an executor, or not). Returns once the pool is gone.
template <class Bind>
void destroy_pool_with_job_queued(holding& counts, std::weak_ptr<int>& alive, bool& called,
                                  Bind bind) {
    std::array<std::uint8_t, 32> output{};
    auto sentinel = std::make_shared<int>(1);
    alive = sentinel;
    asio::thread_pool pool(1);
    std::promise<void> release;
    auto const released = release.get_future();
    std::atomic<bool> blocking{false};
    asio::post(pool, [&] {
        blocking = true;
        released.wait();
    });
    while (!blocking) {
        std::this_thread::yield();
    }
    hash::async_pbkdf2<hash::hmac_sha2_256, hash::backends::hash2>(
        pool.get_executor(), output, bytes_of("password"), bytes_of("salt"), 1,
        bind(asio::bind_allocator(
            holding_allocator<char>(&counts),
            unrun_handler{.counts = &counts, .sentinel = std::move(sentinel), .called = &called})));
    pool.stop();
    release.set_value();
    pool.join();
}

// Operations that never complete (spec 11.5, Asio's rule): the handler destroyed, never called, and
// nothing of its allocator held, when
// - the pool is destroyed with the job queued and the handler has no executor of its own (its
//   executor is the pool's);
// - the pool is destroyed with the job queued and the handler's io_context runs on (the operation
//   is discarded there), or is destroyed without running again;
// - a cancellation before the work starts posts the completion to an io_context destroyed without
//   running again;
// and, with exceptions, a use_future's future then reports a broken promise.
void check_never_completed(asio::io_context& context) {
    holding counts;
    std::weak_ptr<int> alive;
    bool called = false;

    destroy_pool_with_job_queued(counts, alive, called, [](auto handler) { return handler; });
    BOOST_TEST(alive.expired());
    BOOST_TEST(!called);
    BOOST_TEST_EQ(counts.held.load(), 0);

    destroy_pool_with_job_queued(counts, alive, called, [&](auto handler) {
        return asio::bind_executor(context.get_executor(), std::move(handler));
    });
    context.restart();
    context.run_for(std::chrono::seconds(5));  // lint-run: the discarded operation's turn
    BOOST_TEST(alive.expired());
    BOOST_TEST(!called);
    BOOST_TEST_EQ(counts.held.load(), 0);

    {
        asio::io_context elsewhere;
        destroy_pool_with_job_queued(counts, alive, called, [&](auto handler) {
            return asio::bind_executor(elsewhere.get_executor(), std::move(handler));
        });
    }
    BOOST_TEST(alive.expired());
    BOOST_TEST(!called);
    BOOST_TEST_EQ(counts.held.load(), 0);

    {
        asio::thread_pool busy(1);
        std::promise<void> release;
        auto released = release.get_future();
        std::atomic<bool> blocking{false};
        asio::post(busy, [&] {
            blocking = true;
            released.wait();
        });
        while (!blocking) {
            std::this_thread::yield();
        }
        std::array<std::uint8_t, 32> output{};
        // The signal outlives the context, as a slot must outlive what it is connected to.
        asio::cancellation_signal signal;
        {
            asio::io_context elsewhere;
            auto sentinel = std::make_shared<int>(1);
            alive = sentinel;
            hash::async_pbkdf2<hash::hmac_sha2_256, hash::backends::hash2>(
                busy.get_executor(), output, bytes_of("password"), bytes_of("salt"), 1,
                asio::bind_cancellation_slot(
                    signal.slot(),
                    asio::bind_executor(elsewhere.get_executor(),
                                        asio::bind_allocator(holding_allocator<char>(&counts),
                                                             unrun_handler{
                                                                 .counts = &counts,
                                                                 .sentinel = std::move(sentinel),
                                                                 .called = &called,
                                                             }))));
            signal.emit(asio::cancellation_type::terminal);
        }
        BOOST_TEST(alive.expired());
        BOOST_TEST(!called);
        BOOST_TEST_EQ(counts.held.load(), 0);
        release.set_value();
        busy.join();
    }

#ifndef WEBCPP_HASH_NO_EXCEPTIONS
    std::array<std::uint8_t, 32> output{};
    std::future<void> done;
    {
        asio::thread_pool pool(1);
        std::promise<void> release;
        auto released = release.get_future();
        std::atomic<bool> blocking{false};
        asio::post(pool, [&] {
            blocking = true;
            released.wait();
        });
        while (!blocking) {
            std::this_thread::yield();
        }
        done = hash::async_pbkdf2<hash::hmac_sha2_256, hash::backends::hash2>(
            pool.get_executor(), output, bytes_of("password"), bytes_of("salt"), 1,
            asio::use_future);
        pool.stop();
        release.set_value();
        pool.join();
    }
    bool broken = false;
    try {
        done.get();
    } catch (std::future_error const& failure) {
        broken = failure.code() == std::future_errc::broken_promise;
    }
    BOOST_TEST(broken);
#endif
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
    context.run();  // lint-run: the test's event loop
    BOOST_TEST(derived);
    BOOST_TEST(timer_fired);
    BOOST_TEST(timer_fired_first);
    std::array<std::uint8_t, 32> expected{};
    BOOST_TEST(hash::argon2id(expected, password, salt, hash::argon2id_interactive).has_value());
    BOOST_TEST(output == expected);
}

// Starts an Argon2id on `gated` in a pool of one thread, its handler bound to the caller's
// io_context and to `signal`'s slot, and waits until its work has started.
struct gated_call {
    asio::thread_pool pool{1};
    std::array<std::uint8_t, 32> output{};
    std::string_view password = "password";
    std::array<std::uint8_t, hash::argon2id_salt_size> salt{};
    asio::cancellation_signal signal;
    int calls = 0;
    boost::system::error_code code;

    explicit gated_call(asio::io_context& context) {
        output.fill(0x5a);
        gate_entered = false;
        gate_open = false;
        hash::async_argon2id<gated>(
            pool.get_executor(), output, bytes_of(password), salt,
            hash::argon2id_parameters{.passes = 1, .memory = 32768},
            asio::bind_cancellation_slot(
                signal.slot(),
                asio::bind_executor(context.get_executor(), [this](boost::system::error_code done) {
                    ++calls;
                    code = done;
                })));
        while (!gate_entered) {
            std::this_thread::yield();
        }
    }

    gated_call(gated_call const&) = delete;
    gated_call& operator=(gated_call const&) = delete;
    gated_call(gated_call&&) = delete;
    gated_call& operator=(gated_call&&) = delete;

    ~gated_call() {
        gate_open = true;
        pool.join();
    }
};

// A cancellation after the work has started (spec 11.5): the work runs to its end, which no
// cancellation interrupts, so the handler waits for it; then the completion is operation_aborted
// and the output, which the work had written, is zeroed. Until then the output is the caller's
// own, untouched by the operation, and the work reads the caller's spans in place (spec 11.1:
// the spans are the caller's until the completion). A `partial` cancellation is honoured as a
// `terminal` one; a `total` one is not, and the work's result stands.
void check_cancelled_running(asio::io_context& context) {
    for (auto const type : {asio::cancellation_type::terminal, asio::cancellation_type::partial}) {
        gated_call call(context);
        BOOST_TEST(gated_output.load() == call.output.data());
        BOOST_TEST(gated_password.load() == bytes_of(call.password).data());
        call.signal.emit(type);
        context.restart();
        context.run_for(std::chrono::milliseconds(50));  // lint-run: the work still running
        BOOST_TEST_EQ(call.calls, 0);
        BOOST_TEST_EQ(call.output[0], 0x5a);
        gate_open = true;
        context.restart();
        context.run_for(std::chrono::seconds(5));  // lint-run: the test's event loop
        BOOST_TEST_EQ(call.calls, 1);
        BOOST_TEST(call.code == asio::error::operation_aborted);
        BOOST_TEST((call.output == std::array<std::uint8_t, 32>{}));
    }

    gated_call total(context);
    total.signal.emit(asio::cancellation_type::total);
    gate_open = true;
    context.restart();
    context.run_for(std::chrono::seconds(5));  // lint-run: the test's event loop
    BOOST_TEST_EQ(total.calls, 1);
    BOOST_TEST(!total.code);
    BOOST_TEST_EQ(total.output[0], 0x11);
    BOOST_TEST_EQ(total.output[31], 0x11);
}

// co_await in Asio: use_awaitable resumes the coroutine on the caller's io_context with the
// synchronous function's result; an error through as_tuple(use_awaitable), and with exceptions a
// plain use_awaitable throws boost::system::system_error with hash's code.
void check_awaitable(asio::io_context& context, asio::thread_pool& pool) {
    auto const password = bytes_of("password");
    std::array<std::uint8_t, hash::argon2id_salt_size> const salt{};
    hash::argon2id_parameters const small{.passes = 1, .memory = 32768};
    std::array<std::uint8_t, 32> expected{};
    BOOST_TEST(hash::argon2id(expected, password, salt, small).has_value());
    std::array<std::uint8_t, 32> output{};
    std::array<std::uint8_t, 64> scrypt_output{};
    std::array<std::uint8_t, 64> scrypt_expected{};
    hash::scrypt_parameters const costs{.n = 16, .r = 1, .p = 1};
    BOOST_TEST(hash::scrypt(scrypt_expected, password, salt, costs).has_value());
    bool done = false;
    asio::co_spawn(
        context,
        [&]() -> asio::awaitable<void> {
            auto [code] = co_await hash::async_argon2id(pool.get_executor(), output, password, salt,
                                                        small, asio::as_tuple(asio::use_awaitable));
            BOOST_TEST(!code);
            BOOST_TEST(std::this_thread::get_id() == caller_thread);
            auto [refused] = co_await hash::async_argon2id(pool.get_executor(), output, password,
                                                           std::span(salt).first(8), small,
                                                           asio::as_tuple(asio::use_awaitable));
            BOOST_TEST(refused == hash::error::invalid_salt_size);
#ifndef WEBCPP_HASH_NO_EXCEPTIONS
            co_await hash::async_scrypt(pool.get_executor(), scrypt_output, password, salt, costs,
                                        asio::use_awaitable);
            bool thrown = false;
            try {
                co_await hash::async_scrypt(pool.get_executor(), scrypt_output, password, salt,
                                            hash::scrypt_parameters{.n = 3, .r = 1, .p = 1},
                                            asio::use_awaitable);
            } catch (boost::system::system_error const& failure) {
                thrown = failure.code() == hash::error::invalid_parameters;
            }
            BOOST_TEST(thrown);
#else
            auto [scrypt_code] =
                co_await hash::async_scrypt(pool.get_executor(), scrypt_output, password, salt,
                                            costs, asio::as_tuple(asio::use_awaitable));
            BOOST_TEST(!scrypt_code);
#endif
            done = true;
        },
        [](std::exception_ptr const& failure) { BOOST_TEST(!failure); });
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST(done);
    BOOST_TEST(output == expected);
    BOOST_TEST(scrypt_output == scrypt_expected);
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
    check_queued(context);
    check_allocator_released(context, pool);
    check_cancelled_running(context);
    check_cancellation_races(context);
    check_never_completed(context);
    check_awaitable(context, pool);
    pool.join();
    return webcpp::test::exit_status(boost::report_errors());
}
