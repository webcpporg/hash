// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Every keyed cell of backends::hash2 enters its own detail::timing_guard first and leaves the
// thread's DIT as it found it, on every target, also where DIT does not apply, each with valid
// input and with input refused before the backend; every digest cell, called without a key,
// enters none; and so does every Boost.Hash2-form type of hmac.hpp and algorithms.hpp, seeded or
// not (design D3) (support/timing_coverage.hpp).
//
// What it covers, by family; the list is doc/capabilities.json's, read at run time. A new cell of
// a family the support knows gets its call from backend_has_v, which capabilities_test keeps equal
// to the table; a cell of a family or function the support does not know fails here until its
// call is written:
// - mac over siphash_2_4, blake2s_mac and hmac<D> for each digest of the backend's cells.
// - hkdf_extract, hkdf_expand, hkdf and pbkdf2 over each hmac of hmac.hpp and over another Hash2
//   hmac (the column "other").
// - BLAKE2b with a key: digest_of and a hasher round (design D1).
// - Not guarded: each digest cell without a key, through digest_of and a hasher round; the Hash2
//   types (md5_128 to spooky2_128, siphash_32 and siphash_64, hmac and its aliases).

#include "support/timing_coverage.hpp"

#include <webcpp/hash/algorithms.hpp>
#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstddef>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

namespace {

namespace hash = webcpp::hash;
namespace test = webcpp::test;

// The type rows of the table on hash2: algorithms.hpp's, then hmac.hpp's, hmac over another Hash2
// hash for "hmac" itself.
using hash2_types = std::tuple<
    hash::md5_128, hash::sha1_160, hash::sha2_224, hash::sha2_256, hash::sha2_384, hash::sha2_512,
    hash::sha2_512_224, hash::sha2_512_256, hash::sha3_224, hash::sha3_256, hash::sha3_384,
    hash::sha3_512, hash::shake_128, hash::shake_256, hash::blake2b_512, hash::blake2s_256,
    hash::ripemd_128, hash::ripemd_160, hash::siphash_32, hash::siphash_64,
    hash::hmac<test::other_hash>, hash::hmac_md5_128, hash::hmac_sha1_160, hash::hmac_sha2_224,
    hash::hmac_sha2_256, hash::hmac_sha2_384, hash::hmac_sha2_512, hash::hmac_sha2_512_224,
    hash::hmac_sha2_512_256, hash::hmac_sha3_224, hash::hmac_sha3_256, hash::hmac_sha3_384,
    hash::hmac_sha3_512, hash::hmac_ripemd_128, hash::hmac_ripemd_160, hash::hmac_blake2b_512,
    hash::hmac_blake2s_256, hash::fnv1a_32, hash::fnv1a_64, hash::xxhash_32, hash::xxhash_64,
    hash::xxh3_128, hash::murmur3_32, hash::murmur3_128, hash::spooky2_128>;
constexpr std::array<std::string_view, 45> hash2_type_names{
    "md5_128",           "sha1_160",          "sha2_224",
    "sha2_256",          "sha2_384",          "sha2_512",
    "sha2_512_224",      "sha2_512_256",      "sha3_224",
    "sha3_256",          "sha3_384",          "sha3_512",
    "shake_128",         "shake_256",         "blake2b_512",
    "blake2s_256",       "ripemd_128",        "ripemd_160",
    "siphash_32",        "siphash_64",        "hmac",
    "hmac_md5_128",      "hmac_sha1_160",     "hmac_sha2_224",
    "hmac_sha2_256",     "hmac_sha2_384",     "hmac_sha2_512",
    "hmac_sha2_512_224", "hmac_sha2_512_256", "hmac_sha3_224",
    "hmac_sha3_256",     "hmac_sha3_384",     "hmac_sha3_512",
    "hmac_ripemd_128",   "hmac_ripemd_160",   "hmac_blake2b_512",
    "hmac_blake2s_256",  "fnv1a_32",          "fnv1a_64",
    "xxhash_32",         "xxhash_64",         "xxh3_128",
    "murmur3_32",        "murmur3_128",       "spooky2_128",
};

test::coverage_calls type_calls() {
    test::coverage_calls calls;
    test::for_each_coverage_tag<hash2_types>(
        hash2_type_names, [&calls]<class H>(std::string_view name) {
            calls.emplace(name,
                          [name] { test::uncover_type<H>(std::string(name) + " on hash2", true); });
        });
    return calls;
}

}  // namespace

int main() {
    using webcpp::hash::backends::hash2;
    test::check_and_run("hash2", test::keyed_calls<hash2>());
    test::uncover_digests<hash2>();
    test::uncover_types("hash2", type_calls());
    return webcpp::test::exit_status(boost::report_errors());
}
