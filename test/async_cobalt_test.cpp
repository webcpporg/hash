// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// co_await in Cobalt (spec 11.1): the asynchronous family with webcpp::cobalt's use_op, in
// promises on an io_context, on every target; a promise is never moved, since Boost.Cobalt aborts
// on moving a pending coroutine without exceptions (Boost.Cobalt issue 287, as
// <webcpp/cobalt/config.hpp> records). The cheap functions on their default backend give the
// synchronous function's result, async_hkdf over pieces too; a guard's refusal is read through
// cobalt::as_tuple, and with exceptions a plain co_await throws boost::system::system_error with
// hash's code (ruling R71).
// Natively a heavy function, async_pbkdf2 on a thread pool, resumes the task on its own thread; on
// Emscripten async_digest on backends::webcrypto completes through Cobalt's executor, an
// io_context's.
// Under MSVC each promise's frame is aligned to __STDCPP_DEFAULT_NEW_ALIGNMENT__: Boost 1.92.0's
// Cobalt placed it 8 bytes off a 16-byte boundary, and MSVC's optimized code stores into the frame
// with movaps, so this test died with 0xC0000005 on MSVC x64 release (the CI's Boost carries the
// upstream fix, tools/ci/actions/boost/patches/cobalt-coroutine-align-msvc.patch); without that fix
// the check fails in a debug build too, where nothing faults.

#include <webcpp/hash/async.hpp>
#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/hash/pbkdf2.hpp>

#include <webcpp/cobalt/op.hpp>
#include <webcpp/cobalt/promise.hpp>
#include <webcpp/cobalt/result.hpp>
#include <webcpp/cobalt/this_coro.hpp>
#include <webcpp/cobalt/this_thread.hpp>

#include <webcpp/asio/io_context.hpp>

#ifdef WEBCPP_HASH_HAS_THREADS
#include <webcpp/asio/thread_pool.hpp>
#endif

#include <boost/config.hpp>
#include <boost/core/lightweight_test.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>

#include <webcpp/test/exit_status.hpp>

#include <array>
#include <coroutine>
#include <cstdint>
#include <span>
#include <string_view>
#include <thread>

namespace cobalt = webcpp::cobalt;
namespace hash = webcpp::hash;

namespace {

std::span<std::uint8_t const> bytes_of(std::string_view text) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): the text's bytes
    return {reinterpret_cast<std::uint8_t const*>(text.data()), text.size()};
}

// The address of the awaiting coroutine's frame, read without suspending it: awaited once, it is
// not ready until await_suspend has read the address.
class frame_address {
public:
    [[nodiscard]] bool await_ready() const noexcept { return address_ != nullptr; }

    bool await_suspend(std::coroutine_handle<> const handle) noexcept {
        address_ = handle.address();
        return false;
    }

    [[nodiscard]] void* await_resume() const noexcept { return address_; }

private:
    void* address_ = nullptr;
};

// Whether a frame starts where an operator new without std::align_val_t must place storage. Only
// MSVC is checked: there Boost's Cobalt aligns the frame to 16 bytes (coroutine_align) since the
// fix the CI's Boost carries; elsewhere Cobalt aligns it to std::max_align_t, as before.
[[nodiscard]] bool frame_aligned([[maybe_unused]] void const* const frame) {
#ifdef BOOST_MSVC
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): the frame's address
    return reinterpret_cast<std::uintptr_t>(frame) % __STDCPP_DEFAULT_NEW_ALIGNMENT__ == 0;
#else
    return true;
#endif
}

// GCC 14 warns that each promise below, a coroutine, frees its frame with an operator delete that
// does not pair with the operator new that made it (-Wmismatched-new-delete); the pair is
// Boost.Cobalt's own, from its promise_memory_resource_base, and GCC 15 does not warn
// (boostorg/cobalt#7).
#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ == 14
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmismatched-new-delete"
#endif

// The cheap functions, each awaited, against the synchronous function; and a refusal (an output of
// 0 bytes) through as_tuple, and with exceptions through a throw.
cobalt::promise<void> cheap() {
    // NOLINTNEXTLINE(readability-static-accessed-through-instance)
    auto const executor = co_await cobalt::this_coro::executor;
    void const* const frame = co_await frame_address{};
    BOOST_TEST(frame_aligned(frame));
    auto const abc = bytes_of("abc");
    auto const key = bytes_of("key");

    std::array<std::uint8_t, 32> digest{};
    std::array<std::uint8_t, 32> digest_expected{};
    BOOST_TEST(hash::digest_of<hash::digests::sha2_256>(digest_expected, abc).has_value());
    co_await hash::async_digest<hash::digests::sha2_256>(executor, digest, abc, cobalt::use_op);
    BOOST_TEST(digest == digest_expected);

    std::array<std::uint8_t, 32> tag{};
    std::array<std::uint8_t, 32> tag_expected{};
    BOOST_TEST(
        (hash::mac<hash::macs::hmac<hash::digests::sha2_256>>(tag_expected, key, abc).has_value()));
    co_await hash::async_hmac<hash::hmac_sha2_256>(executor, tag, key, abc, cobalt::use_op);
    BOOST_TEST(tag == tag_expected);

    std::array<std::uint8_t, 42> okm{};
    std::array<std::uint8_t, 42> okm_expected{};
    BOOST_TEST(hash::hkdf<hash::hmac_sha2_256>(okm_expected, key, abc, abc).has_value());
    co_await hash::async_hkdf<hash::hmac_sha2_256>(executor, okm, key, abc, abc, cobalt::use_op);
    BOOST_TEST(okm == okm_expected);

    // async_hkdf over pieces: "abc" as {"a", "bc"} gives the single-buffer bytes.
    std::array<std::uint8_t, 42> okm_pieces{};
    co_await hash::async_hkdf<hash::hmac_sha2_256>(executor, okm_pieces, key,
                                                   {abc.first(1), abc.subspan(1)},
                                                   {abc.first(2), abc.subspan(2)}, cobalt::use_op);
    BOOST_TEST(okm_pieces == okm_expected);

    std::span<std::uint8_t> const none{};
    auto [refused] = co_await cobalt::as_tuple(
        hash::async_digest<hash::digests::sha2_256>(executor, none, abc, cobalt::use_op));
    BOOST_TEST(refused == hash::error::invalid_output_size);
#ifndef WEBCPP_HASH_NO_EXCEPTIONS
    bool thrown = false;
    try {
        co_await hash::async_hmac<hash::hmac_sha2_256>(executor, none, key, abc, cobalt::use_op);
    } catch (boost::system::system_error const& failure) {
        thrown = failure.code() == hash::error::invalid_output_size;
    }
    BOOST_TEST(thrown);
#endif
}

#ifdef WEBCPP_HASH_HAS_THREADS
// A heavy function: the work on the pool, the task resumed on the thread that runs it.
cobalt::promise<void> heavy(webcpp::asio::thread_pool& pool) {
    void const* const frame = co_await frame_address{};
    BOOST_TEST(frame_aligned(frame));
    auto const caller = std::this_thread::get_id();
    auto const password = bytes_of("password");
    auto const salt = bytes_of("salt");
    std::array<std::uint8_t, 64> output{};
    std::array<std::uint8_t, 64> expected{};
    BOOST_TEST(hash::pbkdf2<hash::hmac_sha2_512>(expected, password, salt, 1000).has_value());
    co_await hash::async_pbkdf2<hash::hmac_sha2_512, hash::backends::hash2>(
        pool.get_executor(), output, password, salt, 1000, cobalt::use_op);
    BOOST_TEST(output == expected);
    BOOST_TEST(std::this_thread::get_id() == caller);
    auto [refused] =
        co_await cobalt::as_tuple(hash::async_pbkdf2<hash::hmac_sha2_512, hash::backends::hash2>(
            pool.get_executor(), output, password, salt, 0, cobalt::use_op));
    BOOST_TEST(refused == hash::error::invalid_iterations);
}
#endif

#ifdef WEBCPP_TARGET_EMSCRIPTEN
// backends::webcrypto through Cobalt's executor: SHA-256 of "abc".
cobalt::promise<void> browser() {
    // NOLINTNEXTLINE(readability-static-accessed-through-instance)
    auto const executor = co_await cobalt::this_coro::executor;
    std::array<std::uint8_t, 32> digest{};
    std::array<std::uint8_t, 32> expected{};
    BOOST_TEST(hash::digest_of<hash::digests::sha2_256>(expected, bytes_of("abc")).has_value());
    auto [code] = co_await cobalt::as_tuple(
        hash::async_digest<hash::digests::sha2_256, hash::backends::webcrypto>(
            executor, digest, bytes_of("abc"), cobalt::use_op));
    BOOST_TEST(!code);
    BOOST_TEST(digest == expected);
}
#endif

#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ == 14
#pragma GCC diagnostic pop
#endif

// Runs the context until `done`, a promise started on it, is ready, and reads it.
void complete(webcpp::asio::io_context& context, cobalt::promise<void>& done) {
    context.restart();
    context.run();  // lint-run: the promise's event loop
    if (BOOST_TEST(done.ready())) {
        done.get();
    }
}

}  // namespace

int main() {
    webcpp::asio::io_context context;
    cobalt::this_thread::set_executor(context.get_executor());
    auto cheap_done = cheap();
    complete(context, cheap_done);
#ifdef WEBCPP_HASH_HAS_THREADS
    webcpp::asio::thread_pool pool(2);
    auto heavy_done = heavy(pool);
    complete(context, heavy_done);
    pool.join();
#endif
#ifdef WEBCPP_TARGET_EMSCRIPTEN
    auto browser_done = browser();
    complete(context, browser_done);
#endif
    return webcpp::test::exit_status(boost::report_errors());
}
