// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The cheap functions of the asynchronous family, async_digest, async_hmac and async_hkdf, on a
// synchronous backend (spec 11.2): on their default, default_backend's (ruling R76), and on
// backends::hash2 named, as a program on Emscripten names it to keep WebCrypto out (ruling R77,
// C-m2). Each completes through a post on the handler's associated executor, never inside the
// initiating call: a callback records whether the call has returned. The result equals the
// synchronous function's; a guard's refusal (an output of 0 bytes) completes with
// invalid_output_size through the executor; use_future completes; and a counting allocator
// associated with the handler holds the operation's storage. Without exceptions an error is
// read by a callback alone: use_future's error path makes an exception (ruling R71). The
// asynchronous default equals the synchronous one for every tag the family serves.

#include <webcpp/hash/async.hpp>
#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/hash/mac.hpp>

#include <webcpp/asio/bind_allocator.hpp>
#include <webcpp/asio/io_context.hpp>
#include <webcpp/asio/use_future.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/system/error_code.hpp>
#ifndef WEBCPP_HASH_NO_EXCEPTIONS
#include <boost/system/system_error.hpp>
#endif

#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

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
#ifndef WEBCPP_HASH_NO_EXCEPTIONS
    check_future_error(context);
#endif
    return webcpp::test::exit_status(boost::report_errors());
}
