// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// libsodium's SHA-2, SHA-3 and HMACs on backends::sodium: digests::sha2_256, sha2_512, sha3_256
// and sha3_512 (crypto_hash_sha256, crypto_hash_sha512, crypto_hash_sha3256, crypto_hash_sha3512)
// through digest_of and hasher, and macs::hmac over sha2_256 and sha2_512 (crypto_auth_hmacsha256
// and crypto_auth_hmacsha512, keyed by _init with a key of any size) through mac, each against
// Boost.Hash2's type on random inputs (keys of 0 to 300 bytes, past the block, and tags cut to 10
// bytes and more); the HMACs against RFC 4231's seven test cases. libsodium's HMAC-SHA-512-256 is
// HMAC-SHA-512 cut to 32 bytes (ruling R23): crypto_auth_hmacsha512256 gives what mac over
// sha2_512 cut to 32 bytes gives, not HMAC over SHA-512/256, of which backends::sodium has no
// cell.

#include <webcpp/hash/backends/sodium.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/test/exit_status.hpp>

#include "require.hpp"
#include "support/hex.hpp"
#include "support/random_cases.hpp"
#include "support/rfc4231.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/hmac.hpp>
#include <boost/hash2/sha2.hpp>
#include <boost/hash2/sha3.hpp>
#include <boost/system/result.hpp>

#include <sodium/crypto_auth_hmacsha512256.h>  // third_party/libs/libsodium

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <string_view>
#include <vector>

namespace {

namespace hash = webcpp::hash;
namespace test = webcpp::test;
namespace digests = webcpp::hash::digests;
namespace macs = webcpp::hash::macs;
namespace backends = webcpp::hash::backends;
namespace h2 = boost::hash2;

static_assert(hash::backend_has_v<backends::sodium, digests::sha2_256, void>);
static_assert(hash::backend_has_v<backends::sodium, digests::sha2_512, void>);
static_assert(hash::backend_has_v<backends::sodium, digests::sha3_256, void>);
static_assert(hash::backend_has_v<backends::sodium, digests::sha3_512, void>);
static_assert(hash::backend_has_v<backends::sodium, macs::hmac<digests::sha2_256>, void>);
static_assert(hash::backend_has_v<backends::sodium, macs::hmac<digests::sha2_512>, void>);
// libsodium's "HMAC-SHA-512-256" is HMAC-SHA-512 cut, not HMAC over SHA-512/256 (ruling R23).
static_assert(!hash::backend_has_v<backends::sodium, macs::hmac<digests::sha2_512_256>, void>);
static_assert(!hash::backend_has_v<backends::sodium, digests::sha2_512_256, void>);

bool failed_with(boost::system::result<void> const& outcome, hash::error expected) {
    return outcome.has_error() && outcome.error() == expected;
}

// Whether every byte is `value`.
bool all_of(std::span<std::uint8_t const> bytes, std::uint8_t value) {
    return std::ranges::all_of(bytes, [value](std::uint8_t byte) { return byte == value; });
}

// Boost.Hash2's Hash over `input`.
template <class Hash>
std::vector<std::uint8_t> hash2_digest(std::span<std::uint8_t const> input) {
    Hash hashed;
    hashed.update(input.data(), input.size());
    auto const result = hashed.result();
    return {result.begin(), result.end()};
}

// Boost.Hash2's hmac over Hash, of `input` under `key`, cut to `size` bytes.
template <class Hash>
std::vector<std::uint8_t> hash2_hmac(std::span<std::uint8_t const> key,
                                     std::span<std::uint8_t const> input, std::size_t size) {
    h2::hmac<Hash> keyed(key.data(), key.size());
    keyed.update(input.data(), input.size());
    auto const result = keyed.result();
    return {result.begin(), result.begin() + static_cast<std::ptrdiff_t>(size)};
}

// Digest on backends::sodium against Boost.Hash2's Hash on random inputs (the empty one first),
// by digest_of and by a hasher in three pieces split at random.
template <class Digest, class Hash>
void check_digest(std::string_view name) {
    constexpr std::size_t size = typename Hash::result_type{}.size();
    test::random_source random(test::agreement_seed);
    for (std::size_t i = 0; i < test::agreement_cases; ++i) {
        auto const message = random.bytes(i == 0 ? 0 : random.between(0, 1000));
        auto const expected = hash2_digest<Hash>(message);

        std::vector<std::uint8_t> once(size);
        bool const computed = hash::digest_of<Digest, backends::sodium>(once, message).has_value();

        std::span<std::uint8_t const> const whole(message);
        std::size_t const first = random.between(0, whole.size());
        std::size_t const second = random.between(first, whole.size());
        auto hashing = hash::hasher<Digest, backends::sodium>::make();
        test::require(BOOST_TEST(hashing.has_value()));
        std::vector<std::uint8_t> pieces(size);
        bool const fed = hashing->update(whole.first(first)).has_value() &&
                         hashing->update(whole.subspan(first, second - first)).has_value() &&
                         hashing->update(whole.subspan(second)).has_value() &&
                         hashing->finish(pieces).has_value();
        if (!BOOST_TEST(computed && fed) || !BOOST_TEST(once == expected) ||
            !BOOST_TEST(pieces == expected)) {
            std::cerr << "  " << name << ", seed " << test::agreement_seed << ", case " << i << ": "
                      << message.size() << " bytes\n";
        }
    }
    // A fixed-size digest takes an output of its size alone, before any work.
    std::array<std::uint8_t, 3> const abc{0x61, 0x62, 0x63};
    std::vector<std::uint8_t> shorter(size - 1, 0x5A);
    BOOST_TEST(failed_with(hash::digest_of<Digest, backends::sodium>(shorter, abc),
                           hash::error::invalid_output_size));
    BOOST_TEST(all_of(shorter, 0x5A));
}

// FIPS 180-4's and FIPS 202's "abc" (FIPS 180-4 appendix B.1 and C.1; NIST's SHA-3 examples),
// on backends::sodium.
void check_abc() {
    std::array<std::uint8_t, 3> const abc{0x61, 0x62, 0x63};
    auto const of = [&abc]<class Digest>(std::size_t size) {
        std::vector<std::uint8_t> output(size);
        test::require(
            BOOST_TEST((hash::digest_of<Digest, backends::sodium>(output, abc).has_value())));
        return test::to_hex(output);
    };
    BOOST_TEST_EQ(of.template operator()<digests::sha2_256>(32),
                  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    BOOST_TEST_EQ(of.template operator()<digests::sha2_512>(64),
                  "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                  "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    BOOST_TEST_EQ(of.template operator()<digests::sha3_256>(32),
                  "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    BOOST_TEST_EQ(of.template operator()<digests::sha3_512>(64),
                  "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
                  "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");
}

// The tag sizes of the HMAC agreement: the shortest mac gives, cut ones, and the whole digest.
template <std::size_t DigestSize>
constexpr std::array<std::size_t, 5> hmac_sizes{10, 16, 20, DigestSize - 1, DigestSize};

// HMAC over Digest on backends::sodium against Boost.Hash2's hmac on random keys and messages.
template <class Digest, class Hash>
void check_hmac(std::string_view name) {
    constexpr std::size_t digest_size = typename Hash::result_type{}.size();
    test::random_source random(test::agreement_seed);
    for (std::size_t i = 0; i < test::agreement_cases; ++i) {
        auto const key = random.bytes(i == 0 ? 0 : random.between(0, 300));
        auto const message = random.bytes(i == 0 ? 0 : random.between(0, 600));
        std::size_t const size = hmac_sizes<digest_size>[i % hmac_sizes<digest_size>.size()];
        std::vector<std::uint8_t> tag(size);
        bool const computed =
            hash::mac<macs::hmac<Digest>, backends::sodium>(tag, key, message).has_value();
        if (!BOOST_TEST(computed) || !BOOST_TEST(tag == hash2_hmac<Hash>(key, message, size))) {
            std::cerr << "  hmac " << name << ", seed " << test::agreement_seed << ", case " << i
                      << ": key " << key.size() << ", message " << message.size() << ", tag "
                      << size << '\n';
        }
    }
    // The family's guards: a tag under 10 bytes or past the digest, the output untouched.
    std::array<std::uint8_t, 3> const abc{0x61, 0x62, 0x63};
    for (std::size_t const size : {std::size_t{0}, std::size_t{9}, digest_size + 1}) {
        std::vector<std::uint8_t> tag(size, 0x5A);
        if (!BOOST_TEST(failed_with(hash::mac<macs::hmac<Digest>, backends::sodium>(tag, abc, abc),
                                    hash::error::invalid_output_size)) ||
            !BOOST_TEST(all_of(tag, 0x5A))) {
            std::cerr << "  hmac " << name << ": a tag of " << size << " bytes\n";
        }
    }
}

// Keys at the block's boundary, where HMAC stops padding a key and starts hashing it: one byte
// under the block, the block, one byte over (64 bytes for SHA-256, 128 for SHA-512).
template <class Digest, class Hash>
void check_hmac_block_keys(std::string_view name) {
    constexpr std::size_t digest_size = typename Hash::result_type{}.size();
    constexpr std::size_t block = Hash::block_size;
    test::random_source random(test::agreement_seed);
    for (std::size_t const key_size : {block - 1, block, block + 1}) {
        auto const key = random.bytes(key_size);
        auto const message = random.bytes(100);
        std::vector<std::uint8_t> tag(digest_size);
        bool const computed =
            hash::mac<macs::hmac<Digest>, backends::sodium>(tag, key, message).has_value();
        if (!BOOST_TEST(computed) ||
            !BOOST_TEST(tag == hash2_hmac<Hash>(key, message, digest_size))) {
            std::cerr << "  hmac " << name << ": a key of " << key_size << " bytes\n";
        }
    }
}

// RFC 4231's seven test cases on backends::sodium, and on the default (backends::hash2).
void check_rfc4231() {
    for (auto const& vector : test::rfc4231) {
        auto const key = test::from_hex(vector.key);
        auto const data = test::from_hex(vector.data);
        std::vector<std::uint8_t> tag_256(vector.sha2_256.size() / 2);
        std::vector<std::uint8_t> tag_512(vector.sha2_512.size() / 2);
        std::vector<std::uint8_t> default_256(tag_256.size());
        std::vector<std::uint8_t> default_512(tag_512.size());
        bool const computed =
            hash::mac<macs::hmac<digests::sha2_256>, backends::sodium>(tag_256, key, data)
                .has_value() &&
            hash::mac<macs::hmac<digests::sha2_512>, backends::sodium>(tag_512, key, data)
                .has_value() &&
            hash::mac<macs::hmac<digests::sha2_256>>(default_256, key, data).has_value() &&
            hash::mac<macs::hmac<digests::sha2_512>>(default_512, key, data).has_value();
        if (!BOOST_TEST(computed) || !BOOST_TEST_EQ(test::to_hex(tag_256), vector.sha2_256) ||
            !BOOST_TEST_EQ(test::to_hex(tag_512), vector.sha2_512) ||
            !BOOST_TEST_EQ(test::to_hex(default_256), vector.sha2_256) ||
            !BOOST_TEST_EQ(test::to_hex(default_512), vector.sha2_512)) {
            std::cerr << "  RFC 4231 test case " << vector.number << '\n';
        }
    }
}

// libsodium's crypto_auth_hmacsha512256 (a 32-byte key, its one-shot form) is mac over sha2_512
// cut to 32 bytes, on backends::sodium and on backends::hash2; HMAC over SHA-512/256 is another
// function.
void check_hmac_sha512_256() {
    test::random_source random(test::agreement_seed);
    for (std::size_t i = 0; i < 100; ++i) {
        auto const key = random.bytes(crypto_auth_hmacsha512256_KEYBYTES);
        auto const message = random.bytes(i == 0 ? 0 : random.between(0, 600));
        std::array<std::uint8_t, crypto_auth_hmacsha512256_BYTES> by_libsodium{};
        test::require(BOOST_TEST_EQ(crypto_auth_hmacsha512256(by_libsodium.data(), message.data(),
                                                              message.size(), key.data()),
                                    0));
        std::array<std::uint8_t, 32> on_sodium{};
        std::array<std::uint8_t, 32> on_hash2{};
        std::array<std::uint8_t, 32> over_512_256{};
        bool const computed =
            hash::mac<macs::hmac<digests::sha2_512>, backends::sodium>(on_sodium, key, message)
                .has_value() &&
            hash::mac<macs::hmac<digests::sha2_512>, backends::hash2>(on_hash2, key, message)
                .has_value() &&
            hash::mac<macs::hmac<digests::sha2_512_256>>(over_512_256, key, message).has_value();
        if (!BOOST_TEST(computed) || !BOOST_TEST(on_sodium == by_libsodium) ||
            !BOOST_TEST(on_hash2 == by_libsodium) || !BOOST_TEST(over_512_256 != by_libsodium)) {
            std::cerr << "  HMAC-SHA-512-256, case " << i << ": message " << message.size() << '\n';
        }
    }
}

}  // namespace

int main() {
    check_digest<digests::sha2_256, h2::sha2_256>("sha2_256");
    check_digest<digests::sha2_512, h2::sha2_512>("sha2_512");
    check_digest<digests::sha3_256, h2::sha3_256>("sha3_256");
    check_digest<digests::sha3_512, h2::sha3_512>("sha3_512");
    check_abc();
    check_hmac<digests::sha2_256, h2::sha2_256>("sha2_256");
    check_hmac<digests::sha2_512, h2::sha2_512>("sha2_512");
    check_hmac_block_keys<digests::sha2_256, h2::sha2_256>("sha2_256");
    check_hmac_block_keys<digests::sha2_512, h2::sha2_512>("sha2_512");
    check_rfc4231();
    check_hmac_sha512_256();
    return webcpp::test::exit_status(boost::report_errors());
}
