// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A heavy function in the browser's model (spec 11.5), on Emscripten with pthreads under node: an
// async_argon2id of 64 MiB (libsodium's interactive costs) on a webcpp::asio::thread_pool, whose
// threads are Web Workers, its completion bound to the executor of
// webcpp::asio::browser::main_thread_context, the page's thread. While the workers derive, a
// timer of the main thread's io_context keeps firing, every 5 ms: the page never blocks. The pool's
// threads first wait for a latch which the timer opens at its third tick, so that the derivation,
// queued behind them, cannot complete before the timer has fired three times, whatever the
// scheduler does with the main thread. The handler runs on the main browser thread, after the call
// has returned, with the synchronous function's result; and a refusal of a guard reaches the main
// thread the same way.

#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/async.hpp>
#include <webcpp/hash/backends/sodium.hpp>
#include <webcpp/hash/error.hpp>

#include <webcpp/asio/bind_executor.hpp>
#include <webcpp/asio/browser/main_thread_context.hpp>
#include <webcpp/asio/executor_work_guard.hpp>
#include <webcpp/asio/io_context.hpp>
#include <webcpp/asio/post.hpp>
#include <webcpp/asio/steady_timer.hpp>
#include <webcpp/asio/thread_pool.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/system/error_code.hpp>

#include <webcpp/test/exit_status.hpp>

#include <emscripten/threading.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <latch>
#include <span>
#include <string_view>

#if !defined(WEBCPP_TARGET_EMSCRIPTEN) || !defined(WEBCPP_HASH_HAS_THREADS)
#error "async_main_thread_test is built on Emscripten with pthreads"
#endif

namespace asio = webcpp::asio;
namespace hash = webcpp::hash;

namespace {

std::span<std::uint8_t const> bytes_of(std::string_view text) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): the text's bytes
    return {reinterpret_cast<std::uint8_t const*>(text.data()), text.size()};
}

// What the handler saw, on the main thread.
struct completion {
    int calls = 0;
    bool on_main = false;
    bool after_return = false;
    int ticks_then = 0;
    boost::system::error_code code;
};

// The threads of the pool of main: check_derivation holds each of them until the timer has ticked
// `required_ticks` times.
constexpr int pool_threads = 2;
constexpr int required_ticks = 3;

// Runs `start(handler)` with a handler bound to `main`'s executor while `loop`, the main thread's
// io_context, fires a timer every 5 ms until the handler has run; returns what the handler saw.
// When `gate` is not null, the timer opens it at its `required_ticks`th tick.
template <class Start>
completion on_main_thread(asio::io_context& loop, asio::browser::main_thread_context& main,
                          int& ticks, std::latch* gate, Start start) {
    completion seen;
    bool returned = false;
    auto work = asio::make_work_guard(loop);
    start(asio::bind_executor(main.get_executor(), [&](boost::system::error_code code) {
        ++seen.calls;
        seen.on_main = emscripten_is_main_browser_thread() != 0;
        seen.after_return = returned;
        seen.ticks_then = ticks;
        seen.code = code;
        // The handler is a browser callback: it must not run the io_context, so it hands the end
        // of the wait to the loop.
        asio::post(loop, [&work] { work.reset(); });
    }));
    returned = true;

    asio::steady_timer timer(loop);
    std::function<void(boost::system::error_code)> tick = [&](boost::system::error_code code) {
        if (code || seen.calls != 0) {
            return;
        }
        if (++ticks == required_ticks && gate != nullptr) {
            gate->count_down();
        }
        timer.expires_after(std::chrono::milliseconds(5));
        timer.async_wait(tick);
    };
    timer.expires_after(std::chrono::milliseconds(5));
    timer.async_wait(tick);
    loop.restart();
    loop.run();  // lint-run: the main thread's event loop, until the handler has run
    return seen;
}

void check_derivation(asio::io_context& loop, asio::browser::main_thread_context& main,
                      asio::thread_pool& pool) {
    auto const password = bytes_of("correct horse battery staple");
    std::array<std::uint8_t, hash::argon2id_salt_size> const salt{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    };
    std::array<std::uint8_t, 32> output{};
    int ticks = 0;
    // Each thread of the pool waits for the timer's third tick, so that the derivation, queued
    // behind them, starts only after the timer has fired three times, however late the loop runs.
    std::latch gate(1);
    for (int thread = 0; thread < pool_threads; ++thread) {
        asio::post(pool.get_executor(), [&gate] { gate.wait(); });
    }
    auto const seen = on_main_thread(loop, main, ticks, &gate, [&](auto handler) {
        hash::async_argon2id(pool.get_executor(), output, password, salt,
                             hash::argon2id_interactive, std::move(handler));
    });
    BOOST_TEST_EQ(seen.calls, 1);
    BOOST_TEST(seen.on_main);
    BOOST_TEST(seen.after_return);
    BOOST_TEST(!seen.code);
    // The derivation started after the third tick, so the page's timer fired meanwhile.
    BOOST_TEST_GE(seen.ticks_then, required_ticks);

    std::array<std::uint8_t, 32> expected{};
    BOOST_TEST(hash::argon2id(expected, password, salt, hash::argon2id_interactive).has_value());
    BOOST_TEST(output == expected);
}

void check_refusal(asio::io_context& loop, asio::browser::main_thread_context& main,
                   asio::thread_pool& pool) {
    std::array<std::uint8_t, 8> const short_salt{};
    std::array<std::uint8_t, 32> output{};
    output.fill(0x5a);
    int ticks = 0;
    auto const seen = on_main_thread(loop, main, ticks, nullptr, [&](auto handler) {
        hash::async_argon2id(pool.get_executor(), output, bytes_of("password"), short_salt,
                             hash::argon2id_interactive, std::move(handler));
    });
    BOOST_TEST_EQ(seen.calls, 1);
    BOOST_TEST(seen.on_main);
    BOOST_TEST(seen.after_return);
    BOOST_TEST(seen.code == hash::error::invalid_salt_size);
    BOOST_TEST_EQ(output[0], 0x5a);
}

}  // namespace

int main() {
    asio::io_context loop;
    asio::browser::main_thread_context main;
    asio::thread_pool pool(pool_threads);
    check_derivation(loop, main, pool);
    check_refusal(loop, main, pool);
    pool.join();
    return webcpp::test::exit_status(boost::report_errors());
}
