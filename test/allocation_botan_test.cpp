// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// backends::botan's allocations (spec section 6.2's departure, design D43): Botan makes its
// objects and their state through operator new, so each call of every entry point backends::botan
// has is counted, operator new and, where the target counts it, the C library's allocator, and
// printed as a record, never bounded. The calls are digest_of and a hasher's whole hash over each
// of its 25 digests, and mac over each of its 27 MACs, each twice (a first call and a steady one).
// A refusal by a guard, before Botan is reached, allocates nothing at all, which is asserted.

#include <webcpp/hash/backends/botan.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/counting.hpp"

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string_view>
#include <tuple>
#include <utility>

namespace {

namespace hash = webcpp::hash;
namespace digests = webcpp::hash::digests;
namespace macs = webcpp::hash::macs;
using hash::backends::botan;

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the calls counted
std::size_t calls_made = 0;

std::array<std::uint8_t, 100> const input{};

// One call's allocations, printed as a record; the call must succeed.
template <class F>
void counted(char const* operation, std::string_view name, int call, F&& call_it) {
    ++calls_made;
    std::size_t const new_before = webcpp::test::counted_new.load();
    std::size_t const c_before = webcpp::test::counted_c.load();
    bool const done = std::forward<F>(call_it)();
    std::size_t const by_new = webcpp::test::counted_new.load() - new_before;
    std::size_t const by_c = webcpp::test::counted_c.load() - c_before;
    BOOST_TEST(done);
    std::printf(
        "record operation=%s tag=%.*s backend=botan target=%s call=%d new=%zu c=%zu "
        "counted=%d\n",
        operation, static_cast<int>(name.size()), name.data(), webcpp::test::target_name, call,
        by_new, by_c, webcpp::test::c_allocations_counted ? 1 : 0);
}

// A refusal by a guard, before Botan is reached: no allocation of any kind.
template <class F>
void refused_without_allocating(std::string_view name, F&& call_it) {
    ++calls_made;
    std::size_t const before = webcpp::test::allocations();
    bool const refused = std::forward<F>(call_it)();
    if (!BOOST_TEST(refused) || !BOOST_TEST_EQ(webcpp::test::allocations(), before)) {
        std::printf("allocated or not refused: %.*s\n", static_cast<int>(name.size()), name.data());
    }
}

// A digest: digest_of and a hasher's whole hash, twice; then an empty output, refused.
template <class Tag>
void digest_calls(std::string_view name, std::size_t size) {
    std::array<std::uint8_t, 64> output{};
    auto const out = std::span(output).first(size);
    for (int round = 1; round != 3; ++round) {
        counted("digest_of", name, round,
                [&] { return hash::digest_of<Tag, botan>(out, input).has_value(); });
        counted("hasher", name, round, [&] {
            auto made = hash::hasher<Tag, botan>::make();
            return made && made->update(input) && made->finish(out).has_value();
        });
    }
    refused_without_allocating(name, [&] {
        auto const refused = hash::digest_of<Tag, botan>(out.first(0), input);
        return refused.has_error() && refused.error() == hash::error::invalid_output_size;
    });
}

// A MAC: mac twice with a key it takes; then a tag of 0 bytes, refused.
template <class Tag>
void mac_calls(std::string_view name, std::size_t size, std::size_t key_size) {
    std::array<std::uint8_t, 64> output{};
    std::array<std::uint8_t, 64> const key{};
    auto const out = std::span(output).first(size);
    for (int round = 1; round != 3; ++round) {
        counted("mac", name, round, [&] {
            return hash::mac<Tag, botan>(out, std::span(key).first(key_size), input).has_value();
        });
    }
    refused_without_allocating(name, [&] {
        auto const refused =
            hash::mac<Tag, botan>(out.first(0), std::span(key).first(key_size), input);
        return refused.has_error() && refused.error() == hash::error::invalid_output_size;
    });
}

}  // namespace

int main() {
    digest_calls<digests::md5>("digests::md5", 16);
    digest_calls<digests::sha1>("digests::sha1", 20);
    digest_calls<digests::sha2_224>("digests::sha2_224", 28);
    digest_calls<digests::sha2_256>("digests::sha2_256", 32);
    digest_calls<digests::sha2_384>("digests::sha2_384", 48);
    digest_calls<digests::sha2_512>("digests::sha2_512", 64);
    digest_calls<digests::sha2_512_256>("digests::sha2_512_256", 32);
    digest_calls<digests::sha3_224>("digests::sha3_224", 28);
    digest_calls<digests::sha3_256>("digests::sha3_256", 32);
    digest_calls<digests::sha3_384>("digests::sha3_384", 48);
    digest_calls<digests::sha3_512>("digests::sha3_512", 64);
    digest_calls<digests::shake_128>("digests::shake_128", 64);
    digest_calls<digests::shake_256>("digests::shake_256", 64);
    digest_calls<digests::keccak_224>("digests::keccak_224", 28);
    digest_calls<digests::keccak_256>("digests::keccak_256", 32);
    digest_calls<digests::keccak_384>("digests::keccak_384", 48);
    digest_calls<digests::keccak_512>("digests::keccak_512", 64);
    digest_calls<digests::blake2b>("digests::blake2b", 64);
    digest_calls<digests::blake2s_256>("digests::blake2s_256", 32);
    digest_calls<digests::ripemd_160>("digests::ripemd_160", 20);
    digest_calls<digests::sm3>("digests::sm3", 32);
    digest_calls<digests::streebog_256>("digests::streebog_256", 32);
    digest_calls<digests::streebog_512>("digests::streebog_512", 64);
    digest_calls<digests::whirlpool>("digests::whirlpool", 64);
    digest_calls<digests::skein_512>("digests::skein_512", 64);

    mac_calls<macs::hmac<digests::md5>>("macs::hmac<digests::md5>", 16, 32);
    mac_calls<macs::hmac<digests::sha1>>("macs::hmac<digests::sha1>", 20, 32);
    mac_calls<macs::hmac<digests::sha2_224>>("macs::hmac<digests::sha2_224>", 28, 32);
    mac_calls<macs::hmac<digests::sha2_256>>("macs::hmac<digests::sha2_256>", 32, 32);
    mac_calls<macs::hmac<digests::sha2_384>>("macs::hmac<digests::sha2_384>", 48, 32);
    mac_calls<macs::hmac<digests::sha2_512>>("macs::hmac<digests::sha2_512>", 64, 32);
    mac_calls<macs::hmac<digests::sha2_512_256>>("macs::hmac<digests::sha2_512_256>", 32, 32);
    mac_calls<macs::hmac<digests::sha3_224>>("macs::hmac<digests::sha3_224>", 28, 32);
    mac_calls<macs::hmac<digests::sha3_256>>("macs::hmac<digests::sha3_256>", 32, 32);
    mac_calls<macs::hmac<digests::sha3_384>>("macs::hmac<digests::sha3_384>", 48, 32);
    mac_calls<macs::hmac<digests::sha3_512>>("macs::hmac<digests::sha3_512>", 64, 32);
    mac_calls<macs::hmac<digests::keccak_224>>("macs::hmac<digests::keccak_224>", 28, 32);
    mac_calls<macs::hmac<digests::keccak_256>>("macs::hmac<digests::keccak_256>", 32, 32);
    mac_calls<macs::hmac<digests::keccak_384>>("macs::hmac<digests::keccak_384>", 48, 32);
    mac_calls<macs::hmac<digests::keccak_512>>("macs::hmac<digests::keccak_512>", 64, 32);
    mac_calls<macs::hmac<digests::ripemd_160>>("macs::hmac<digests::ripemd_160>", 20, 32);
    mac_calls<macs::hmac<digests::blake2b>>("macs::hmac<digests::blake2b>", 64, 32);
    mac_calls<macs::hmac<digests::blake2s_256>>("macs::hmac<digests::blake2s_256>", 32, 32);
    mac_calls<macs::hmac<digests::sm3>>("macs::hmac<digests::sm3>", 32, 32);
    mac_calls<macs::hmac<digests::streebog_256>>("macs::hmac<digests::streebog_256>", 32, 32);
    mac_calls<macs::hmac<digests::streebog_512>>("macs::hmac<digests::streebog_512>", 64, 32);
    mac_calls<macs::hmac<digests::whirlpool>>("macs::hmac<digests::whirlpool>", 64, 32);
    mac_calls<macs::hmac<digests::skein_512>>("macs::hmac<digests::skein_512>", 64, 32);
    mac_calls<macs::kmac_128>("macs::kmac_128", 32, 32);
    mac_calls<macs::kmac_256>("macs::kmac_256", 64, 32);
    mac_calls<macs::siphash_2_4>("macs::siphash_2_4", 8, 16);
    mac_calls<macs::blake2b_mac>("macs::blake2b_mac", 64, 32);

    // 25 digests (two calls each of digest_of and hasher, and a refusal) and 27 MACs (two calls
    // and a refusal).
    BOOST_TEST_EQ(calls_made, (25U * 5U) + (27U * 3U));
    return webcpp::test::exit_status(boost::report_errors());
}
