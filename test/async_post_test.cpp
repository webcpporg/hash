// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The cheap functions of the asynchronous family, async_digest, async_hmac, async_hkdf_extract,
// async_hkdf_expand and async_hkdf, each HKDF function also over byte pieces, on a synchronous
// backend (spec 11.2): on their default, default_backend's (ruling R76), and on backends::hash2
// named, as a program on Emscripten names it to keep WebCrypto out (ruling R77, C-m2); the HKDF
// steps and the pieces forms also on backends::sodium. Each completes through a post on the
// handler's associated executor, never inside the initiating call: a callback records whether the
// call has returned. The result equals the synchronous function's; a guard's refusal (an output of
// 0 bytes, a pseudorandom key output or input of another size than the digest's) completes with
// its error through the executor, the output untouched; use_future completes; co_await in Asio
// (use_awaitable) gives the result and, through as_tuple, a refusal; and a counting allocator
// associated with the handler holds the operation's storage. The pieces forms read their pieces in
// the initiating call (ruling R4): a braced list of pieces whose bytes are overwritten after the
// call gives the HKDF of the original bytes, with a callback, with asio::deferred launched after
// the list's full-expression has ended, and with a use_awaitable awaitable awaited after it.
// Without exceptions an error is read by a callback alone: use_future's error path makes an
// exception (ruling R71). The asynchronous default equals the synchronous one for every tag the
// family serves.

#include <webcpp/hash/async.hpp>
#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/backends/sodium.hpp>
#include <webcpp/hash/byte_pieces.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/hash/mac.hpp>

#include <webcpp/asio/as_tuple.hpp>
#include <webcpp/asio/awaitable.hpp>
#include <webcpp/asio/bind_allocator.hpp>
#include <webcpp/asio/co_spawn.hpp>
#include <webcpp/asio/deferred.hpp>
#include <webcpp/asio/io_context.hpp>
#include <webcpp/asio/this_coro.hpp>
#include <webcpp/asio/use_awaitable.hpp>
#include <webcpp/asio/use_future.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/system/error_code.hpp>
#ifndef WEBCPP_HASH_NO_EXCEPTIONS
#include <boost/system/system_error.hpp>
#endif

#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace asio = webcpp::asio;
namespace hash = webcpp::hash;
using webcpp::test::from_hex;
using webcpp::test::to_hex;

namespace {

// An allocator that counts its allocations into a counter it shares with its rebound copies.
template <class T>
struct counting_allocator {
    using value_type = T;
    std::size_t* allocations;

    explicit counting_allocator(std::size_t* counter) noexcept : allocations(counter) {}

    // Allocator rebind conversions must be implicit (Allocator requirements).
    template <class U>
    // NOLINTNEXTLINE(misc-explicit-constructor)
    counting_allocator(counting_allocator<U> const& other) noexcept
        : allocations(other.allocations) {}

    T* allocate(std::size_t count) {
        ++*allocations;
        return std::allocator<T>().allocate(count);
    }

    void deallocate(T* pointer, std::size_t count) noexcept {
        std::allocator<T>().deallocate(pointer, count);
    }

    template <class U>
    bool operator==(counting_allocator<U> const& other) const noexcept {
        return allocations == other.allocations;
    }
};

std::span<std::uint8_t const> bytes_of(std::string_view text) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): the text's bytes, as Hash2 reads
    return {reinterpret_cast<std::uint8_t const*>(text.data()), text.size()};
}

// What a callback saw: whether it ran, whether the initiating call had returned when it did, and
// the error code.
struct completion {
    bool called = false;
    bool after_return = false;
    boost::system::error_code code;
};

// Runs `start(token)` with a callback, checks that it completes once through the executor, after
// the call has returned, and returns its error code. `start` takes the token.
template <class Start>
boost::system::error_code complete_by_callback(asio::io_context& context, Start start) {
    completion seen;
    bool returned = false;
    start([&seen, &returned](boost::system::error_code code) {
        seen.called = true;
        seen.after_return = returned;
        seen.code = code;
    });
    returned = true;
    BOOST_TEST(!seen.called);
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST(seen.called);
    BOOST_TEST(seen.after_return);
    return seen.code;
}

// The same with a callback whose associated allocator counts: the operation's storage is the
// handler's.
template <class Start>
void check_allocator(asio::io_context& context, Start start) {
    std::size_t allocations = 0;
    bool called = false;
    start(asio::bind_allocator(counting_allocator<char>(&allocations),
                               [&called](boost::system::error_code code) {
                                   called = true;
                                   BOOST_TEST(!code);
                               }));
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST(called);
    BOOST_TEST_GE(allocations, 1U);
}

// use_future on a success: the future is ready once the context has run (a single-threaded
// program runs it before get()).
template <class Start>
void check_future(asio::io_context& context, Start start) {
    auto done = start(asio::use_future);
    context.restart();
    context.run();  // lint-run: the test's event loop
    done.get();
}

// async_digest on Backend (none: the default): SHA-256 of "abc" against digest_of.
template <class... Backend>
void check_digest(asio::io_context& context) {
    auto executor = context.get_executor();
    auto const input = bytes_of("abc");
    std::array<std::uint8_t, 32> expected{};
    BOOST_TEST(hash::digest_of<hash::digests::sha2_256>(expected, input).has_value());
    BOOST_TEST_EQ(to_hex(expected),
                  std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));

    std::array<std::uint8_t, 32> output{};
    auto code = complete_by_callback(context, [&](auto token) {
        hash::async_digest<hash::digests::sha2_256, Backend...>(executor, output, input,
                                                                std::move(token));
    });
    BOOST_TEST(!code);
    BOOST_TEST(output == expected);

    std::array<std::uint8_t, 32> by_future{};
    check_future(context, [&](auto token) {
        return hash::async_digest<hash::digests::sha2_256, Backend...>(executor, by_future, input,
                                                                       token);
    });
    BOOST_TEST(by_future == expected);

    std::array<std::uint8_t, 32> counted{};
    check_allocator(context, [&](auto token) {
        hash::async_digest<hash::digests::sha2_256, Backend...>(executor, counted, input,
                                                                std::move(token));
    });
    BOOST_TEST(counted == expected);

    // A guard's refusal completes through the executor too, the output untouched.
    std::span<std::uint8_t> nothing{};
    code = complete_by_callback(context, [&](auto token) {
        hash::async_digest<hash::digests::sha2_256, Backend...>(executor, nothing, input,
                                                                std::move(token));
    });
    BOOST_TEST(code == hash::error::invalid_output_size);
}

// async_hmac on Backend (none: the default): HMAC-SHA-256 against mac.
template <class... Backend>
void check_hmac(asio::io_context& context) {
    auto executor = context.get_executor();
    auto const key = bytes_of("key");
    auto const input = bytes_of("The quick brown fox jumps over the lazy dog");
    std::array<std::uint8_t, 32> expected{};
    BOOST_TEST(
        hash::mac<hash::macs::hmac<hash::digests::sha2_256>>(expected, key, input).has_value());
    BOOST_TEST_EQ(to_hex(expected),
                  std::string("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"));

    std::array<std::uint8_t, 32> output{};
    auto code = complete_by_callback(context, [&](auto token) {
        hash::async_hmac<hash::hmac_sha2_256, Backend...>(executor, output, key, input,
                                                          std::move(token));
    });
    BOOST_TEST(!code);
    BOOST_TEST(output == expected);

    std::array<std::uint8_t, 32> by_future{};
    check_future(context, [&](auto token) {
        return hash::async_hmac<hash::hmac_sha2_256, Backend...>(executor, by_future, key, input,
                                                                 token);
    });
    BOOST_TEST(by_future == expected);

    std::array<std::uint8_t, 32> counted{};
    check_allocator(context, [&](auto token) {
        hash::async_hmac<hash::hmac_sha2_256, Backend...>(executor, counted, key, input,
                                                          std::move(token));
    });
    BOOST_TEST(counted == expected);

    std::span<std::uint8_t> nothing{};
    code = complete_by_callback(context, [&](auto token) {
        hash::async_hmac<hash::hmac_sha2_256, Backend...>(executor, nothing, key, input,
                                                          std::move(token));
    });
    BOOST_TEST(code == hash::error::invalid_output_size);
}

// async_hkdf on Backend (none: the default): RFC 5869's A.1 against hkdf.
template <class... Backend>
void check_hkdf(asio::io_context& context) {
    auto executor = context.get_executor();
    auto const ikm = from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    auto const salt = from_hex("000102030405060708090a0b0c");
    auto const info = from_hex("f0f1f2f3f4f5f6f7f8f9");
    std::array<std::uint8_t, 42> expected{};
    BOOST_TEST(hash::hkdf<hash::hmac_sha2_256>(expected, salt, ikm, info).has_value());
    BOOST_TEST_EQ(to_hex(expected), std::string("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5"
                                                "db02d56ecc4c5bf34007208d5b887185865"));

    std::array<std::uint8_t, 42> output{};
    auto code = complete_by_callback(context, [&](auto token) {
        hash::async_hkdf<hash::hmac_sha2_256, Backend...>(executor, output, salt, ikm, info,
                                                          std::move(token));
    });
    BOOST_TEST(!code);
    BOOST_TEST(output == expected);

    std::array<std::uint8_t, 42> by_future{};
    check_future(context, [&](auto token) {
        return hash::async_hkdf<hash::hmac_sha2_256, Backend...>(executor, by_future, salt, ikm,
                                                                 info, token);
    });
    BOOST_TEST(by_future == expected);

    std::array<std::uint8_t, 42> counted{};
    check_allocator(context, [&](auto token) {
        hash::async_hkdf<hash::hmac_sha2_256, Backend...>(executor, counted, salt, ikm, info,
                                                          std::move(token));
    });
    BOOST_TEST(counted == expected);

    std::span<std::uint8_t> nothing{};
    code = complete_by_callback(context, [&](auto token) {
        hash::async_hkdf<hash::hmac_sha2_256, Backend...>(executor, nothing, salt, ikm, info,
                                                          std::move(token));
    });
    BOOST_TEST(code == hash::error::invalid_output_size);
}

// RFC 5869's A.1: its input keying material, salt and application info, and its pseudorandom key
// and output keying material.
struct rfc5869_a1 {
    std::vector<std::uint8_t> input_key_material =
        from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    std::vector<std::uint8_t> salt = from_hex("000102030405060708090a0b0c");
    std::vector<std::uint8_t> application_info = from_hex("f0f1f2f3f4f5f6f7f8f9");
    std::string pseudorandom_key =
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";
    std::string output_key_material =
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
};

// One form of an HKDF function: `start(output, token)` initiates it into `output` and returns what
// the token gives. With a callback it completes through the executor after the call, with
// use_future and with a counting allocator too, each output equal to `expected`.
template <std::size_t Size, class Start>
void check_form(asio::io_context& context, std::array<std::uint8_t, Size> const& expected,
                Start start) {
    std::array<std::uint8_t, Size> output{};
    auto const code = complete_by_callback(
        context, [&](auto token) { start(std::span<std::uint8_t>(output), std::move(token)); });
    BOOST_TEST(!code);
    BOOST_TEST(output == expected);

    std::array<std::uint8_t, Size> by_future{};
    check_future(context,
                 [&](auto token) { return start(std::span<std::uint8_t>(by_future), token); });
    BOOST_TEST(by_future == expected);

    std::array<std::uint8_t, Size> counted{};
    check_allocator(context,
                    [&](auto token) { start(std::span<std::uint8_t>(counted), std::move(token)); });
    BOOST_TEST(counted == expected);
}

// A guard's refusal of one form: `start(output, token)` on an output of `Size` bytes completes with
// `expected` through the executor, after the call, the output untouched.
template <std::size_t Size, class Start>
void check_refusal(asio::io_context& context, boost::system::error_code expected, Start start) {
    std::array<std::uint8_t, Size> output{};
    output.fill(0xa5);
    auto const before = output;
    auto const code = complete_by_callback(
        context, [&](auto token) { start(std::span<std::uint8_t>(output), std::move(token)); });
    BOOST_TEST(code == expected);
    BOOST_TEST(output == before);
}

// async_hkdf_extract and async_hkdf_expand, each single-buffer and over pieces, and async_hkdf over
// pieces, on Backend (none: the default): RFC 5869's A.1, the pieces a split of its inputs with an
// empty piece among them, against the synchronous functions; each with use_awaitable; and each
// refusal of RFC 5869's sizes.
template <class... Backend>
void check_hkdf_steps(asio::io_context& context) {
    auto executor = context.get_executor();
    rfc5869_a1 const a1;
    std::span<std::uint8_t const> const salt(a1.salt);
    std::span<std::uint8_t const> const ikm(a1.input_key_material);
    std::span<std::uint8_t const> const info(a1.application_info);
    std::array<std::span<std::uint8_t const>, 3> const ikm_pieces{
        ikm.first(5), std::span<std::uint8_t const>{}, ikm.subspan(5)};
    std::array<std::span<std::uint8_t const>, 2> const info_pieces{info.first(3), info.subspan(3)};

    std::array<std::uint8_t, 32> prk_expected{};
    auto const extracted = hash::hkdf_extract<hash::hmac_sha2_256, Backend...>(salt, ikm);
    BOOST_TEST(extracted.has_value());
    if (extracted) {
        std::ranges::copy(*extracted, prk_expected.begin());
    }
    BOOST_TEST_EQ(to_hex(prk_expected), a1.pseudorandom_key);
    std::array<std::uint8_t, 42> okm_expected{};
    BOOST_TEST(
        (hash::hkdf_expand<hash::hmac_sha2_256, Backend...>(okm_expected, prk_expected, info))
            .has_value());
    BOOST_TEST_EQ(to_hex(okm_expected), a1.output_key_material);
    std::span<std::uint8_t const> const prk(prk_expected);

    auto const extract = [&](std::span<std::uint8_t> output, auto token) {
        return hash::async_hkdf_extract<hash::hmac_sha2_256, Backend...>(executor, output, salt,
                                                                         ikm, std::move(token));
    };
    auto const extract_pieces = [&](std::span<std::uint8_t> output, auto token) {
        return hash::async_hkdf_extract<hash::hmac_sha2_256, Backend...>(
            executor, output, salt, ikm_pieces, std::move(token));
    };
    auto const expand = [&](std::span<std::uint8_t> output, auto token) {
        return hash::async_hkdf_expand<hash::hmac_sha2_256, Backend...>(executor, output, prk, info,
                                                                        std::move(token));
    };
    auto const expand_pieces = [&](std::span<std::uint8_t> output, auto token) {
        return hash::async_hkdf_expand<hash::hmac_sha2_256, Backend...>(
            executor, output, prk, info_pieces, std::move(token));
    };
    auto const derive_pieces = [&](std::span<std::uint8_t> output, auto token) {
        return hash::async_hkdf<hash::hmac_sha2_256, Backend...>(executor, output, salt, ikm_pieces,
                                                                 info_pieces, std::move(token));
    };
    check_form(context, prk_expected, extract);
    check_form(context, prk_expected, extract_pieces);
    check_form(context, okm_expected, expand);
    check_form(context, okm_expected, expand_pieces);
    check_form(context, okm_expected, derive_pieces);

    // use_awaitable: each form awaited in a coroutine of the context.
    std::array<std::uint8_t, 32> awaited_prk{};
    std::array<std::uint8_t, 32> awaited_prk_pieces{};
    std::array<std::uint8_t, 42> awaited_okm{};
    std::array<std::uint8_t, 42> awaited_okm_pieces{};
    std::array<std::uint8_t, 42> awaited_derived{};
    bool done = false;
    asio::co_spawn(
        context,
        [&]() -> asio::awaitable<void> {
            auto const token = asio::as_tuple(asio::use_awaitable);
            auto [extracted_code] = co_await extract(awaited_prk, token);
            BOOST_TEST(!extracted_code);
            auto [extracted_pieces_code] = co_await extract_pieces(awaited_prk_pieces, token);
            BOOST_TEST(!extracted_pieces_code);
            auto [expanded_code] = co_await expand(awaited_okm, token);
            BOOST_TEST(!expanded_code);
            auto [expanded_pieces_code] = co_await expand_pieces(awaited_okm_pieces, token);
            BOOST_TEST(!expanded_pieces_code);
            auto [derived_code] = co_await derive_pieces(awaited_derived, token);
            BOOST_TEST(!derived_code);
            done = true;
        },
        [](std::exception_ptr const& failure) { BOOST_TEST(!failure); });
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST(done);
    BOOST_TEST(awaited_prk == prk_expected);
    BOOST_TEST(awaited_prk_pieces == prk_expected);
    BOOST_TEST(awaited_okm == okm_expected);
    BOOST_TEST(awaited_okm_pieces == okm_expected);
    BOOST_TEST(awaited_derived == okm_expected);

    // The refusals: Extract's pseudorandom key output of no byte, of 31 and of 33 bytes; Expand's
    // output of no byte and pseudorandom key of 31 bytes; hkdf's output of no byte and of
    // 255 * 32 + 1 bytes.
    boost::system::error_code const output_size = hash::error::invalid_output_size;
    boost::system::error_code const key_size = hash::error::invalid_key_size;
    auto const refuse_extract = [&](auto const& start) {
        check_refusal<0>(context, output_size, start);
        check_refusal<31>(context, output_size, start);
        check_refusal<33>(context, output_size, start);
    };
    refuse_extract(extract);
    refuse_extract(extract_pieces);
    check_refusal<0>(context, output_size, expand);
    check_refusal<0>(context, output_size, expand_pieces);
    check_refusal<42>(context, key_size, [&](std::span<std::uint8_t> output, auto token) {
        hash::async_hkdf_expand<hash::hmac_sha2_256, Backend...>(executor, output, prk.first(31),
                                                                 info, std::move(token));
    });
    check_refusal<42>(context, key_size, [&](std::span<std::uint8_t> output, auto token) {
        hash::async_hkdf_expand<hash::hmac_sha2_256, Backend...>(executor, output, prk.first(31),
                                                                 info_pieces, std::move(token));
    });
    check_refusal<0>(context, output_size, derive_pieces);
    check_refusal<(255 * 32) + 1>(context, output_size, derive_pieces);
}

// The spec's temporary list: async_hkdf over the braced lists {a, b} and {c, d}, whose arrays die
// at the end of the call's full-expression, then a to d overwritten before the operation runs.
// The pieces are read in the call (ruling R4): with a callback, with asio::deferred launched after
// the overwrite, and with a use_awaitable awaitable awaited after it, the completion is a success
// and the output is the HKDF of the original bytes.
void check_temporary_lists(asio::io_context& context) {
    auto const executor = context.get_executor();
    auto const salt = from_hex("000102030405060708090a0b0c");
    std::array<std::uint8_t, 4> a{};
    std::array<std::uint8_t, 3> b{};
    std::array<std::uint8_t, 2> c{};
    std::array<std::uint8_t, 5> d{};
    auto const restore = [&] {
        a = {1, 2, 3, 4};
        b = {5, 6, 7};
        c = {8, 9};
        d = {10, 11, 12, 13, 14};
    };
    auto const overwrite = [&] {
        a.fill(0xff);
        b.fill(0xff);
        c.fill(0xff);
        d.fill(0xff);
    };
    restore();
    std::array<std::uint8_t, 42> expected{};
    BOOST_TEST(hash::hkdf<hash::hmac_sha2_256>(expected, salt, {a, b}, {c, d}).has_value());
    std::array<std::uint8_t, 42> joined{};
    auto const ikm = from_hex("01020304050607");
    auto const info = from_hex("08090a0b0c0d0e");
    BOOST_TEST(hash::hkdf<hash::hmac_sha2_256>(joined, salt, ikm, info).has_value());
    BOOST_TEST(expected == joined);

    std::array<std::uint8_t, 42> output{};
    auto code = complete_by_callback(context, [&](auto token) {
        hash::async_hkdf<hash::hmac_sha2_256>(executor, output, salt, {a, b}, {c, d},
                                              std::move(token));
        overwrite();
    });
    BOOST_TEST(!code);
    BOOST_TEST(output == expected);

    restore();
    std::array<std::uint8_t, 42> deferred_output{};
    auto launch = hash::async_hkdf<hash::hmac_sha2_256>(executor, deferred_output, salt, {a, b},
                                                        {c, d}, asio::deferred);
    overwrite();
    code = complete_by_callback(context, [&](auto token) { std::move(launch)(std::move(token)); });
    BOOST_TEST(!code);
    BOOST_TEST(deferred_output == expected);

    restore();
    std::array<std::uint8_t, 42> awaited{};
    bool done = false;
    asio::co_spawn(
        context,
        [&]() -> asio::awaitable<void> {
            auto derive = hash::async_hkdf<hash::hmac_sha2_256>(
                executor, awaited, salt, {a, b}, {c, d}, asio::as_tuple(asio::use_awaitable));
            overwrite();
            auto [derived] = co_await std::move(derive);
            BOOST_TEST(!derived);
            done = true;
        },
        [](std::exception_ptr const& failure) { BOOST_TEST(!failure); });
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST(done);
    BOOST_TEST(awaited == expected);
}

// co_await in Asio: each function with use_awaitable in a coroutine of the context, its result the
// synchronous function's; a refusal (an output of 0 bytes) through as_tuple(use_awaitable), and
// with exceptions a plain use_awaitable throws system_error with hash's code.
void check_awaitable(asio::io_context& context) {
    auto const input = bytes_of("abc");
    auto const key = bytes_of("key");
    std::array<std::uint8_t, 32> digest{};
    std::array<std::uint8_t, 32> digest_expected{};
    BOOST_TEST(hash::digest_of<hash::digests::sha2_256>(digest_expected, input).has_value());
    std::array<std::uint8_t, 32> tag{};
    std::array<std::uint8_t, 32> tag_expected{};
    BOOST_TEST((hash::mac<hash::macs::hmac<hash::digests::sha2_256>>(tag_expected, key, input)
                    .has_value()));
    std::array<std::uint8_t, 42> okm{};
    std::array<std::uint8_t, 42> okm_expected{};
    BOOST_TEST(hash::hkdf<hash::hmac_sha2_256>(okm_expected, key, input, input).has_value());
    bool done = false;
    asio::co_spawn(
        context,
        [&]() -> asio::awaitable<void> {
            auto const executor = co_await asio::this_coro::executor;
            auto [digested] = co_await hash::async_digest<hash::digests::sha2_256>(
                executor, digest, input, asio::as_tuple(asio::use_awaitable));
            BOOST_TEST(!digested);
            auto [tagged] = co_await hash::async_hmac<hash::hmac_sha2_256>(
                executor, tag, key, input, asio::as_tuple(asio::use_awaitable));
            BOOST_TEST(!tagged);
            std::span<std::uint8_t> const nothing{};
            auto [refused] = co_await hash::async_hkdf<hash::hmac_sha2_256>(
                executor, nothing, key, input, input, asio::as_tuple(asio::use_awaitable));
            BOOST_TEST(refused == hash::error::invalid_output_size);
#ifndef WEBCPP_HASH_NO_EXCEPTIONS
            co_await hash::async_hkdf<hash::hmac_sha2_256>(executor, okm, key, input, input,
                                                           asio::use_awaitable);
            bool thrown = false;
            try {
                co_await hash::async_digest<hash::digests::sha2_256>(executor, nothing, input,
                                                                     asio::use_awaitable);
            } catch (boost::system::system_error const& failure) {
                thrown = failure.code() == hash::error::invalid_output_size;
            }
            BOOST_TEST(thrown);
#else
            auto [derived] = co_await hash::async_hkdf<hash::hmac_sha2_256>(
                executor, okm, key, input, input, asio::as_tuple(asio::use_awaitable));
            BOOST_TEST(!derived);
#endif
            done = true;
        },
        [](std::exception_ptr const& failure) { BOOST_TEST(!failure); });
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST(done);
    BOOST_TEST(digest == digest_expected);
    BOOST_TEST(tag == tag_expected);
    BOOST_TEST(okm == okm_expected);
}

#ifndef WEBCPP_HASH_NO_EXCEPTIONS
// With exceptions, use_future reports a guard's refusal as a system_error of hash's code.
void check_future_error(asio::io_context& context) {
    auto const executor = context.get_executor();
    std::span<std::uint8_t> const nothing{};
    auto done = hash::async_digest<hash::digests::sha2_256>(executor, nothing, bytes_of("abc"),
                                                            asio::use_future);
    context.restart();
    context.run();  // lint-run: the test's event loop
    bool thrown = false;
    try {
        done.get();
    } catch (boost::system::system_error const& failure) {
        thrown = true;
        BOOST_TEST(failure.code() == hash::error::invalid_output_size);
    }
    BOOST_TEST(thrown);
}
#endif

// The asynchronous default is the synchronous one (ruling R76), for every tag the cheap functions
// serve; async_hmac's is that of the HMAC over its hmac's digest.
template <class Tag>
constexpr bool same_default =
    std::is_same_v<hash::default_async_backend<Tag>, hash::default_backend<Tag>>;
static_assert(same_default<hash::digests::sha1> && same_default<hash::digests::sha2_256> &&
              same_default<hash::digests::sha2_384> && same_default<hash::digests::sha2_512>);
static_assert(same_default<hash::macs::hmac<hash::digests::sha2_256>> &&
              same_default<hash::kdfs::hkdf> && same_default<hash::kdfs::pbkdf2>);
static_assert(std::is_same_v<hash::default_async_backend<hash::kdfs::hkdf, hash::hmac_sha2_512>,
                             hash::backends::hash2>);
static_assert(same_default<hash::kdfs::hkdf_extract> && same_default<hash::kdfs::hkdf_expand> &&
              same_default<hash::kdfs::hkdf_pieces> &&
              same_default<hash::kdfs::hkdf_extract_pieces> &&
              same_default<hash::kdfs::hkdf_expand_pieces>);
static_assert(
    std::is_same_v<hash::default_async_backend<hash::kdfs::hkdf_pieces, hash::hmac_sha2_512>,
                   hash::backends::hash2>);

}  // namespace

int main() {
    asio::io_context context;
    // Each function on its default (no backend named), then on backends::hash2 named.
    check_digest<>(context);
    check_digest<hash::backends::hash2>(context);
    check_hmac<>(context);
    check_hmac<hash::backends::hash2>(context);
    check_hkdf<>(context);
    check_hkdf<hash::backends::hash2>(context);
    check_hkdf_steps<>(context);
    check_hkdf_steps<hash::backends::hash2>(context);
    check_hkdf_steps<hash::backends::sodium>(context);
    check_temporary_lists(context);
    check_awaitable(context);
#ifndef WEBCPP_HASH_NO_EXCEPTIONS
    check_future_error(context);
#endif
    return webcpp::test::exit_status(boost::report_errors());
}
