// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The asynchronous forms set DIT on the thread that computes (design D6, ruling H13): every form
// of async.hpp computes by calling its synchronous function, which holds the guard, and no
// initiating function holds one. Through the seam of support/timing_seam.hpp, each heavy form
// (async_pbkdf2, async_argon2id, async_argon2, async_scrypt, and with
// WEBCPP_TEST_TIMING_ASYNC_BOTAN the same on backends::botan with async_bcrypt, async_bcrypt_verify
// and async_bcrypt_pbkdf) on a webcpp::asio::thread_pool of one thread entered the guard of its
// synchronous function first on the pool's thread and none on the calling thread; the cheap ones
// (async_hmac, async_hkdf) entered mac's and hkdf's on the calling thread, during the initiation,
// and none on the pool's; async_digest, unkeyed, entered none on either; and a cancellation before
// the heavy work starts entered none anywhere. After each completion, the pool's thread and the
// calling thread are back to DIT off (where the CPU has it). The threads are synchronised by
// futures and by probes posted to the pool and completed through the io_context, never by sleeps;
// the cancellation holds the pool's only thread in a job of the test, as async_heavy_test does.

#include "support/timing_seam.hpp"

#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/async.hpp>
#include <webcpp/hash/detail/timing.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/hash/pbkdf2.hpp>
#include <webcpp/hash/scrypt.hpp>
#ifdef WEBCPP_TEST_TIMING_ASYNC_BOTAN
#include <webcpp/hash/backends/botan.hpp>
#include <webcpp/hash/bcrypt.hpp>
#else
#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/backends/sodium.hpp>
#endif

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

#include <array>
#include <cstddef>
#include <cstdint>
#include <future>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

#ifndef WEBCPP_HASH_HAS_THREADS
#error "timing_async_test is built where the program has threads"
#endif

namespace asio = webcpp::asio;
namespace hash = webcpp::hash;
namespace test = webcpp::test;
namespace kdfs = webcpp::hash::kdfs;

namespace {

#ifdef WEBCPP_TEST_TIMING_ASYNC_BOTAN
using pbkdf2_backend = hash::backends::botan;
using argon2id_backend = hash::backends::botan;
using argon2_backend = hash::backends::botan;
using scrypt_backend = hash::backends::botan;
using bcrypt_backend = hash::backends::botan;
constexpr std::uint32_t argon2_lanes = 2;
#else
using pbkdf2_backend = hash::default_async_backend<kdfs::pbkdf2, hash::hmac_sha2_256>;
using argon2id_backend = hash::default_backend<kdfs::argon2id>;
using argon2_backend = hash::default_backend<kdfs::argon2i>;
using scrypt_backend = hash::default_backend<kdfs::scrypt>;
constexpr std::uint32_t argon2_lanes = 1;
#endif

constexpr std::array<std::uint8_t, 8> password{'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
constexpr std::array<std::uint8_t, 16> salt{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

// What a thread recorded through the seam, and whether it was back to DIT off when it was read.
struct record {
    std::size_t entries = 0;
    std::string first;
    bool dit_off = false;
};

// Resets the seam's two per-thread values and reads DIT, on the calling thread.
void reset_this_thread() {
    test::timing_entries = 0;
    test::timing_first_entry = nullptr;
}

record read_this_thread() {
    return {.entries = test::timing_entries,
            .first = test::timing_first_entry != nullptr ? test::timing_first_entry : "",
            .dit_off = !hash::detail::dit_is_set()};
}

// Runs a probe on the pool's thread and waits for its answer through a future.
template <class Probe>
auto on_pool(asio::thread_pool& pool, Probe probe) {
    std::promise<decltype(probe())> answer;
    auto future = answer.get_future();
    asio::post(pool, [&answer, &probe] { answer.set_value(probe()); });
    return future.get();
}

void reset_pool_thread(asio::thread_pool& pool) {
    on_pool(pool, [] {
        reset_this_thread();
        return true;
    });
}

record read_pool_thread(asio::thread_pool& pool) {
    return on_pool(pool, [] { return read_this_thread(); });
}

// What a completion saw.
struct completion {
    bool called = false;
    boost::system::error_code code{};
    bool same = false;
};

// A handler bound to the context, that records the completion.
auto recording_handler(asio::io_context& context, completion& seen) {
    return asio::bind_executor(context.get_executor(),
                               [&seen](boost::system::error_code code, auto... same) {
                                   seen.called = true;
                                   seen.code = code;
                                   ((seen.same = same), ...);
                               });
}

void run_to_completion(asio::io_context& context) {
    context.restart();
    context.run();  // lint-run: the test's event loop
}

// Reports `message` as an error when `ok` is false.
void expect(bool ok, std::string const& message) {
    if (!ok) {
        BOOST_ERROR(message.c_str());
    }
}

// Whether a record's first guard is the synchronous function's.
bool entered_first(record const& seen, std::string_view function) {
    return !seen.first.empty() && test::names_function(seen.first, test::function_named(function));
}

// A heavy form: the pool's thread enters the guard of `function` first, the calling thread none,
// and both threads are back to DIT off after the completion.
template <class Start>
void heavy(std::string_view name, std::string_view function, asio::io_context& context,
           asio::thread_pool& pool, Start start) {
    reset_pool_thread(pool);
    reset_this_thread();
    completion seen;
    start(recording_handler(context, seen));
    run_to_completion(context);
    record const caller = read_this_thread();
    record const worker = read_pool_thread(pool);
    std::string const label(name);
    expect(seen.called, label);
    expect(!seen.code, label + ": " + seen.code.message());
    expect(worker.entries >= 1, label);
    expect(entered_first(worker, function), label + " entered " + worker.first);
    expect(caller.entries == 0,
           label + ": " + std::to_string(caller.entries) + " guards entered on the wrong thread");
    expect(worker.dit_off, label);
    expect(caller.dit_off, label);
}

// A cheap form on a synchronous backend: the calling thread enters the guard of `function` first
// during the initiation, the pool's thread none.
template <class Start>
void cheap(std::string_view name, std::string_view function, asio::io_context& context,
           asio::thread_pool& pool, Start start) {
    reset_pool_thread(pool);
    reset_this_thread();
    completion seen;
    start(recording_handler(context, seen));
    run_to_completion(context);
    record const caller = read_this_thread();
    record const worker = read_pool_thread(pool);
    std::string const label(name);
    expect(seen.called, label);
    expect(!seen.code, label + ": " + seen.code.message());
    expect(caller.entries >= 1, label);
    expect(entered_first(caller, function), label + " entered " + caller.first);
    expect(worker.entries == 0,
           label + ": " + std::to_string(worker.entries) + " guards entered on the wrong thread");
    expect(caller.dit_off, label);
    expect(worker.dit_off, label);
}

void check_heavy(asio::io_context& context, asio::thread_pool& pool) {
    auto work = pool.get_executor();
    std::array<std::uint8_t, 32> output{};

    heavy("async_pbkdf2", "hash::pbkdf2", context, pool, [&](auto handler) {
        hash::async_pbkdf2<hash::hmac_sha2_256, pbkdf2_backend>(work, output, password, salt, 100,
                                                                std::move(handler));
    });
    heavy("async_argon2id", "hash::argon2id", context, pool, [&](auto handler) {
        hash::async_argon2id<argon2id_backend>(work, output, password, salt,
                                               {.passes = 2, .memory = 65536}, std::move(handler));
    });
    heavy("async_argon2", "hash::argon2", context, pool, [&](auto handler) {
        hash::async_argon2<std::conditional_t<std::is_same_v<argon2_backend, hash::backends::botan>,
                                              kdfs::argon2id, kdfs::argon2i>,
                           argon2_backend>(work, output, password, salt,
                                           {.passes = 3, .memory_kib = 64, .lanes = argon2_lanes},
                                           std::move(handler));
    });
    heavy("async_scrypt", "hash::scrypt", context, pool, [&](auto handler) {
        hash::async_scrypt<scrypt_backend>(work, output, password, salt,
                                           {.n = 1024, .r = 8, .p = 1}, std::move(handler));
    });
#ifdef WEBCPP_TEST_TIMING_ASYNC_BOTAN
    std::array<char, hash::bcrypt_hash_size> stored{};
    heavy("async_bcrypt", "hash::bcrypt", context, pool, [&](auto handler) {
        hash::async_bcrypt<bcrypt_backend>(work, stored, password, salt, {.cost = 4},
                                           std::move(handler));
    });
    heavy("async_bcrypt_verify", "hash::bcrypt_verify", context, pool, [&](auto handler) {
        hash::async_bcrypt_verify<bcrypt_backend>(
            work, password, std::string_view(stored.data(), stored.size()), std::move(handler));
    });
    heavy("async_bcrypt_pbkdf", "hash::bcrypt_pbkdf", context, pool, [&](auto handler) {
        hash::async_bcrypt_pbkdf<bcrypt_backend>(work, output, password, salt, 4,
                                                 std::move(handler));
    });
#endif
}

#ifndef WEBCPP_TEST_TIMING_ASYNC_BOTAN
void check_cheap(asio::io_context& context, asio::thread_pool& pool) {
    auto loop = context.get_executor();
    std::array<std::uint8_t, 32> output{};
    std::array<std::uint8_t, 32> key{};
    key.fill(0x0b);

    cheap("async_hmac", "hash::mac", context, pool, [&](auto handler) {
        hash::async_hmac<hash::hmac_sha2_256>(loop, output, key, password, std::move(handler));
    });
    cheap("async_hkdf", "hash::hkdf", context, pool, [&](auto handler) {
        hash::async_hkdf<hash::hmac_sha2_256>(loop, output, salt, key, password,
                                              std::move(handler));
    });

    // async_digest is unkeyed: no thread enters a guard.
    reset_pool_thread(pool);
    reset_this_thread();
    completion seen;
    hash::async_digest<hash::digests::sha2_256>(loop, output, password,
                                                recording_handler(context, seen));
    run_to_completion(context);
    record const caller = read_this_thread();
    record const worker = read_pool_thread(pool);
    BOOST_TEST(seen.called);
    BOOST_TEST(!seen.code);
    BOOST_TEST_EQ(caller.entries, 0u);
    BOOST_TEST_EQ(worker.entries, 0u);
}
#endif

// A cancellation before the work starts: the pool's only thread is held by a job of the test, so
// that each work is queued and never started; the completion arrives at once on the context, the
// work is skipped when the thread is released, and no thread entered a guard.
void check_cancelled_before(asio::io_context& context) {
    asio::thread_pool busy(1);
    std::promise<void> release;
    auto const released = release.get_future().share();
    std::promise<void> blocking;
    auto const holding = blocking.get_future();
    asio::post(busy, [&blocking, released] {
        reset_this_thread();
        blocking.set_value();
        released.wait();
    });
    holding.wait();
    reset_this_thread();
    auto work = busy.get_executor();
    std::array<std::uint8_t, 32> output{};
    auto const cancelled = [&](auto start) {
        asio::cancellation_signal signal;
        completion seen;
        start(asio::bind_cancellation_slot(signal.slot(), recording_handler(context, seen)));
        signal.emit(asio::cancellation_type::terminal);
        run_to_completion(context);
        BOOST_TEST(seen.called);
        BOOST_TEST(seen.code == asio::error::operation_aborted);
    };
    cancelled([&](auto handler) {
        hash::async_pbkdf2<hash::hmac_sha2_256, pbkdf2_backend>(work, output, password, salt, 100,
                                                                std::move(handler));
    });
    cancelled([&](auto handler) {
        hash::async_argon2id<argon2id_backend>(work, output, password, salt,
                                               {.passes = 2, .memory = 65536}, std::move(handler));
    });
    cancelled([&](auto handler) {
        hash::async_scrypt<scrypt_backend>(work, output, password, salt,
                                           {.n = 1024, .r = 8, .p = 1}, std::move(handler));
    });
#ifdef WEBCPP_TEST_TIMING_ASYNC_BOTAN
    std::array<char, hash::bcrypt_hash_size> stored{};
    cancelled([&](auto handler) {
        hash::async_bcrypt<bcrypt_backend>(work, stored, password, salt, {.cost = 4},
                                           std::move(handler));
    });
    cancelled([&](auto handler) {
        hash::async_bcrypt_pbkdf<bcrypt_backend>(work, output, password, salt, 4,
                                                 std::move(handler));
    });
#endif
    release.set_value();
    // The probe queues behind every skipped work on the pool's only thread.
    record const worker = read_pool_thread(busy);
    BOOST_TEST_EQ(worker.entries, 0u);
    BOOST_TEST_EQ(read_this_thread().entries, 0u);
    busy.join();
}

}  // namespace

int main() {
    asio::io_context context;
    {
        asio::thread_pool pool(1);
        check_heavy(context, pool);
#ifndef WEBCPP_TEST_TIMING_ASYNC_BOTAN
        check_cheap(context, pool);
#endif
        pool.join();
    }
    check_cancelled_before(context);
    return webcpp::test::exit_status(boost::report_errors());
}
