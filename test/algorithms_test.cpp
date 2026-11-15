// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Every name of <webcpp/hash/algorithms.hpp> and <webcpp/hash/hmac.hpp> is Boost.Hash2's type
// itself, and hash_append and the HMAC through webcpp's names give Hash2's results.

#include <webcpp/hash/algorithms.hpp>
#include <webcpp/hash/hmac.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/hash_append.hpp>
#include <boost/hash2/hmac.hpp>

#include <webcpp/test/exit_status.hpp>

#include <array>
#include <cstddef>
#include <string>
#include <type_traits>

static_assert(std::is_same_v<webcpp::hash::md5_128, boost::hash2::md5_128>);
static_assert(std::is_same_v<webcpp::hash::sha1_160, boost::hash2::sha1_160>);
static_assert(std::is_same_v<webcpp::hash::sha2_224, boost::hash2::sha2_224>);
static_assert(std::is_same_v<webcpp::hash::sha2_256, boost::hash2::sha2_256>);
static_assert(std::is_same_v<webcpp::hash::sha2_384, boost::hash2::sha2_384>);
static_assert(std::is_same_v<webcpp::hash::sha2_512, boost::hash2::sha2_512>);
static_assert(std::is_same_v<webcpp::hash::sha2_512_224, boost::hash2::sha2_512_224>);
static_assert(std::is_same_v<webcpp::hash::sha2_512_256, boost::hash2::sha2_512_256>);
static_assert(std::is_same_v<webcpp::hash::sha3_224, boost::hash2::sha3_224>);
static_assert(std::is_same_v<webcpp::hash::sha3_256, boost::hash2::sha3_256>);
static_assert(std::is_same_v<webcpp::hash::sha3_384, boost::hash2::sha3_384>);
static_assert(std::is_same_v<webcpp::hash::sha3_512, boost::hash2::sha3_512>);
static_assert(std::is_same_v<webcpp::hash::shake_128, boost::hash2::shake_128>);
static_assert(std::is_same_v<webcpp::hash::shake_256, boost::hash2::shake_256>);
static_assert(std::is_same_v<webcpp::hash::ripemd_128, boost::hash2::ripemd_128>);
static_assert(std::is_same_v<webcpp::hash::ripemd_160, boost::hash2::ripemd_160>);
static_assert(std::is_same_v<webcpp::hash::blake2b_512, boost::hash2::blake2b_512>);
static_assert(std::is_same_v<webcpp::hash::blake2s_256, boost::hash2::blake2s_256>);
static_assert(std::is_same_v<webcpp::hash::fnv1a_32, boost::hash2::fnv1a_32>);
static_assert(std::is_same_v<webcpp::hash::fnv1a_64, boost::hash2::fnv1a_64>);
static_assert(std::is_same_v<webcpp::hash::siphash_32, boost::hash2::siphash_32>);
static_assert(std::is_same_v<webcpp::hash::siphash_64, boost::hash2::siphash_64>);
static_assert(std::is_same_v<webcpp::hash::xxhash_32, boost::hash2::xxhash_32>);
static_assert(std::is_same_v<webcpp::hash::xxhash_64, boost::hash2::xxhash_64>);
static_assert(std::is_same_v<webcpp::hash::xxh3_128, boost::hash2::xxh3_128>);
static_assert(std::is_same_v<webcpp::hash::murmur3_32, boost::hash2::murmur3_32>);
static_assert(std::is_same_v<webcpp::hash::murmur3_128, boost::hash2::murmur3_128>);
static_assert(std::is_same_v<webcpp::hash::spooky2_128, boost::hash2::spooky2_128>);
static_assert(std::is_same_v<webcpp::hash::hmac_md5_128, boost::hash2::hmac_md5_128>);
static_assert(std::is_same_v<webcpp::hash::hmac_sha1_160, boost::hash2::hmac_sha1_160>);
static_assert(std::is_same_v<webcpp::hash::hmac_sha2_224, boost::hash2::hmac_sha2_224>);
static_assert(std::is_same_v<webcpp::hash::hmac_sha2_256, boost::hash2::hmac_sha2_256>);
static_assert(std::is_same_v<webcpp::hash::hmac_sha2_384, boost::hash2::hmac_sha2_384>);
static_assert(std::is_same_v<webcpp::hash::hmac_sha2_512, boost::hash2::hmac_sha2_512>);
static_assert(std::is_same_v<webcpp::hash::hmac_sha2_512_224, boost::hash2::hmac_sha2_512_224>);
static_assert(std::is_same_v<webcpp::hash::hmac_sha2_512_256, boost::hash2::hmac_sha2_512_256>);
static_assert(std::is_same_v<webcpp::hash::hmac_sha3_224, boost::hash2::hmac_sha3_224>);
static_assert(std::is_same_v<webcpp::hash::hmac_sha3_256, boost::hash2::hmac_sha3_256>);
static_assert(std::is_same_v<webcpp::hash::hmac_sha3_384, boost::hash2::hmac_sha3_384>);
static_assert(std::is_same_v<webcpp::hash::hmac_sha3_512, boost::hash2::hmac_sha3_512>);
static_assert(std::is_same_v<webcpp::hash::hmac_ripemd_128, boost::hash2::hmac_ripemd_128>);
static_assert(std::is_same_v<webcpp::hash::hmac_ripemd_160, boost::hash2::hmac_ripemd_160>);
static_assert(std::is_same_v<webcpp::hash::hmac_blake2b_512, boost::hash2::hmac_blake2b_512>);
static_assert(std::is_same_v<webcpp::hash::hmac_blake2s_256, boost::hash2::hmac_blake2s_256>);
static_assert(std::is_same_v<webcpp::hash::hmac<webcpp::hash::sha2_256>,
                             boost::hash2::hmac<boost::hash2::sha2_256>>);
static_assert(
    std::is_same_v<webcpp::hash::hmac<boost::hash2::sha2_256>, webcpp::hash::hmac_sha2_256>);
static_assert(std::is_same_v<webcpp::hash::digest<32>, boost::hash2::digest<32>>);

namespace {

// An array of N bytes, each `value`.
template <std::size_t N>
std::array<unsigned char, N> make_filled(unsigned char value) {
    std::array<unsigned char, N> a{};
    a.fill(value);
    return a;
}

void check_hash_append() {
    // Hash2's own test value: SHA-256 of "abc" (FIPS 180-4's example).
    webcpp::hash::sha2_256 hasher;
    hasher.update("abc", 3);
    BOOST_TEST_EQ(boost::hash2::to_string(hasher.result()),
                  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // hash_append through webcpp's name is Hash2's: the same digest as Hash2's own call.
    webcpp::hash::sha2_256 ours;
    boost::hash2::sha2_256 theirs;
    const std::string text = "webcpp";
    webcpp::hash::hash_append(ours, {}, text);
    boost::hash2::hash_append(theirs, {}, text);
    BOOST_TEST(ours.result() == theirs.result());
}

void check_hmac() {
    // RFC 4231, test case 1.
    const std::array<unsigned char, 20> key = make_filled<20>(0x0b);
    webcpp::hash::hmac_sha2_256 mac(key.data(), key.size());
    mac.update("Hi There", 8);
    BOOST_TEST_EQ(boost::hash2::to_string(mac.result()),
                  "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
}

}  // namespace

int main() {
    check_hash_append();
    check_hmac();
    return webcpp::test::exit_status(boost::report_errors());
}
