// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// OpenSSL running out of memory in the middle of a call of backends::openssl (spec sections 2.8
// and 7.5): the test sets OpenSSL's allocator with CRYPTO_set_mem_functions before anything, and
// makes each allocation of a call fail in turn, the first, then the second, and so on until the
// call allocates no more than the ones that succeed. Each failing call answers
// errc::not_enough_memory or backend_failure (OpenSSL's last error decides, openssl_outcome),
// zeroes its output, frees every block OpenSSL allocated for it (the live blocks are back to where
// they were), and leaves the thread's error queue empty. The calls: mac over HMAC, KMAC, keyed
// BLAKE2b and SipHash, digest_of, and a hasher's make. A hasher's update and finish allocate
// nothing on OpenSSL 3.5.9 (counted below), so no allocation can make them fail: the hasher's
// failures reachable through this seam are its make's.

#include <webcpp/hash/backends/openssl.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/test/exit_status.hpp>

#include "require.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/result.hpp>

#include <openssl/crypto.h>
#include <openssl/err.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <span>
#include <string_view>

namespace {

namespace hash = webcpp::hash;
namespace digests = webcpp::hash::digests;
namespace macs = webcpp::hash::macs;
namespace test = webcpp::test;
using hash::backends::openssl;

// OpenSSL's blocks alive: each allocation through OpenSSL's allocator adds one, each free of a
// block takes one away.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): OpenSSL's live blocks
std::size_t openssl_live = 0;
// The allocations since the test armed the failure.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the allocations counted
std::size_t allocations = 0;
// The allocation that fails, counted from 1; 0 for none.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the failure armed
std::size_t failing = 0;

void* failing_malloc(std::size_t size, char const* /*file*/, int /*line*/) {
    ++allocations;
    if (allocations == failing) {
        return nullptr;
    }
    void* const block = std::malloc(size);
    if (block != nullptr) {
        ++openssl_live;
    }
    return block;
}

void* failing_realloc(void* block, std::size_t size, char const* file, int line) {
    // OpenSSL's CRYPTO_realloc sends a null block to malloc and a zero size to free: here the
    // block exists and stays one, unless this allocation is the failing one, which leaves it as
    // it was (realloc's contract).
    if (block == nullptr) {
        return failing_malloc(size, file, line);
    }
    ++allocations;
    if (allocations == failing) {
        return nullptr;
    }
    return std::realloc(block, size);
}

void failing_free(void* block, char const* /*file*/, int /*line*/) {
    if (block != nullptr) {
        --openssl_live;
    }
    std::free(block);
}

bool all_zero(std::span<std::uint8_t const> bytes) {
    return std::ranges::all_of(bytes, [](std::uint8_t byte) { return byte == 0; });
}

// The answers of the failing calls, over the whole test.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): counted across the calls
std::size_t out_of_memory = 0;
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): counted across the calls
std::size_t backend_failures = 0;

// Whether a failing call answered not_enough_memory or backend_failure, counting which.
bool counted_failure(boost::system::result<void> const& outcome) {
    if (!outcome.has_error()) {
        return false;
    }
    if (outcome.error() ==
        boost::system::errc::make_error_code(boost::system::errc::not_enough_memory)) {
        ++out_of_memory;
        return true;
    }
    if (outcome.error() == hash::error::backend_failure) {
        ++backend_failures;
        return true;
    }
    return false;
}

// Makes each allocation of `call` (which writes `output`) fail in turn, from the first until the
// call needs no more than succeed; checks each failure's answer, output, blocks and error queue.
// The call runs once first, to pay OpenSSL's one-time fetches, whose allocations a later call
// does not repeat.
template <class Call>
void fail_each_allocation(std::string_view name, std::span<std::uint8_t> output, Call call) {
    test::require(BOOST_TEST(call().has_value()));
    for (std::size_t index = 1;; ++index) {
        std::ranges::fill(output, std::uint8_t{0x55});
        std::size_t const live_before = openssl_live;
        allocations = 0;
        failing = index;
        boost::system::result<void> const outcome = call();
        failing = 0;
        if (allocations < index) {
            // Every allocation of the call succeeded: the call did too, and the loop is over.
            if (!BOOST_TEST(outcome.has_value()) || !BOOST_TEST_EQ(openssl_live, live_before)) {
                std::cerr << "  " << name << " without a failing allocation\n";
            }
            BOOST_TEST(index > 1);
            return;
        }
        if (!BOOST_TEST(counted_failure(outcome)) || !BOOST_TEST(all_zero(output)) ||
            !BOOST_TEST_EQ(openssl_live, live_before) || !BOOST_TEST_EQ(ERR_peek_error(), 0UL)) {
            std::cerr << "  " << name << ", allocation " << index << " failing\n";
        }
        ERR_clear_error();
    }
}

void check_macs() {
    std::array<std::uint8_t, 32> const key{1, 2, 3};
    std::array<std::uint8_t, 100> const input{4, 5, 6};
    std::array<std::uint8_t, 32> tag{};
    std::array<std::uint8_t, 16> cut{};
    std::array<std::uint8_t, 8> siphash{};
    fail_each_allocation("hmac sha2_256", tag, [&] {
        return hash::mac<macs::hmac<digests::sha2_256>, openssl>(tag, key, input);
    });
    fail_each_allocation("hmac sha3_256, cut", cut, [&] {
        return hash::mac<macs::hmac<digests::sha3_256>, openssl>(cut, key, input);
    });
    fail_each_allocation("kmac_128", tag, [&] {
        return hash::mac<macs::kmac_128, openssl>(tag, key, input, {.customisation = input});
    });
    fail_each_allocation("blake2b_mac", tag,
                         [&] { return hash::mac<macs::blake2b_mac, openssl>(tag, key, input); });
    fail_each_allocation("siphash_2_4", siphash, [&] {
        return hash::mac<macs::siphash_2_4, openssl>(siphash, std::span(key).first(16), input);
    });
}

void check_digests() {
    std::array<std::uint8_t, 100> const input{4, 5, 6};
    std::array<std::uint8_t, 32> digest{};
    fail_each_allocation("digest_of sha2_256", digest, [&] {
        return hash::digest_of<digests::sha2_256, openssl>(digest, input);
    });
    fail_each_allocation("digest_of shake_256", digest, [&] {
        return hash::digest_of<digests::shake_256, openssl>(digest, input);
    });
    std::array<std::uint8_t, 0> none{};
    fail_each_allocation("hasher<sm3>::make", none, [&]() -> boost::system::result<void> {
        auto const made = hash::hasher<digests::sm3, openssl>::make();
        if (!made) {
            return made.error();
        }
        return {};
    });

    // A hasher made, its update and finish allocate nothing.
    auto hashing = hash::hasher<digests::sha2_256, openssl>::make();
    test::require(BOOST_TEST(hashing.has_value()));
    allocations = 0;
    BOOST_TEST(hashing->update(input).has_value());
    BOOST_TEST(hashing->finish(digest).has_value());
    BOOST_TEST_EQ(allocations, 0U);
}

}  // namespace

int main() {
    // Before anything: OpenSSL allocates through the test's functions from here on.
    test::require(BOOST_TEST(
        (CRYPTO_set_mem_functions(&failing_malloc, &failing_realloc, &failing_free) == 1)));
    check_macs();
    check_digests();
    // OpenSSL's allocation failure is the last error of some failing calls: the mapping to
    // not_enough_memory is reached. The counts are printed only when it is not.
    if (!BOOST_TEST(out_of_memory > 0)) {
        std::cerr << "  failing allocations answered: " << out_of_memory << " not_enough_memory, "
                  << backend_failures << " backend_failure\n";
    }
    return webcpp::test::exit_status(boost::report_errors());
}
