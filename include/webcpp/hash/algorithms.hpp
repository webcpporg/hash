// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 Boost.Hash2's algorithms under webcpp::hash's names. Each name is an alias: a type of
 webcpp::hash is the Hash2 type itself, so that `hash_append`, `get_integral_result` and every
 other part of Hash2 take it unchanged.
*/
#ifndef WEBCPP_HASH_ALGORITHMS_HPP
#define WEBCPP_HASH_ALGORITHMS_HPP

#include <webcpp/hash/config.hpp>

#include <boost/hash2/blake2.hpp>
#include <boost/hash2/digest.hpp>
#include <boost/hash2/fnv1a.hpp>
#include <boost/hash2/hash_append.hpp>
#include <boost/hash2/legacy/murmur3.hpp>
#include <boost/hash2/legacy/spooky2.hpp>
#include <boost/hash2/md5.hpp>
#include <boost/hash2/ripemd.hpp>
#include <boost/hash2/sha1.hpp>
#include <boost/hash2/sha2.hpp>
#include <boost/hash2/sha3.hpp>
#include <boost/hash2/siphash.hpp>
#include <boost/hash2/xxh3.hpp>
#include <boost/hash2/xxhash.hpp>

#include <cstddef>

namespace webcpp::hash {

/**
 A digest of `N` bytes, Boost.Hash2's.

 @tparam N The size in bytes.
*/
template <std::size_t N>
using digest = boost::hash2::digest<N>;

/** MD5, RFC 1321, a 128-bit digest. Broken: not for security, kept for compatibility with existing
 * data and protocols. */
using boost::hash2::md5_128;

/** SHA-1, FIPS 180-4, a 160-bit digest. Broken: not for security, kept for compatibility with
 * existing data and protocols. */
using boost::hash2::sha1_160;

/** SHA-224, FIPS 180-4, a 224-bit digest. */
using boost::hash2::sha2_224;

/** SHA-256, FIPS 180-4, a 256-bit digest. */
using boost::hash2::sha2_256;

/** SHA-384, FIPS 180-4, a 384-bit digest. */
using boost::hash2::sha2_384;

/** SHA-512, FIPS 180-4, a 512-bit digest. */
using boost::hash2::sha2_512;

/** SHA-512/224, FIPS 180-4, a 224-bit digest. */
using boost::hash2::sha2_512_224;

/** SHA-512/256, FIPS 180-4, a 256-bit digest. */
using boost::hash2::sha2_512_256;

/** SHA3-224, FIPS 202, a 224-bit digest. */
using boost::hash2::sha3_224;

/** SHA3-256, FIPS 202, a 256-bit digest. */
using boost::hash2::sha3_256;

/** SHA3-384, FIPS 202, a 384-bit digest. */
using boost::hash2::sha3_384;

/** SHA3-512, FIPS 202, a 512-bit digest. */
using boost::hash2::sha3_512;

/** SHAKE128, FIPS 202, an extendable-output function with a 128-bit security strength. */
using boost::hash2::shake_128;

/** SHAKE256, FIPS 202, an extendable-output function with a 256-bit security strength. */
using boost::hash2::shake_256;

/** RIPEMD-128, ISO/IEC 10118-3, a 128-bit digest. Legacy: not for security. */
using boost::hash2::ripemd_128;

/** RIPEMD-160, ISO/IEC 10118-3, a 160-bit digest. Legacy: prefer SHA-2 or SHA-3 in new designs. */
using boost::hash2::ripemd_160;

/** BLAKE2b with a 512-bit digest, RFC 7693. */
using boost::hash2::blake2b_512;

/** BLAKE2s with a 256-bit digest, RFC 7693. */
using boost::hash2::blake2s_256;

// Not cryptographic: the algorithms below are for hash tables, checksums and identifiers.

/** FNV-1a with a 32-bit result, the Fowler-Noll-Vo hash (IETF draft-eastlake-fnv). Not
 * cryptographic: for hash tables, checksums and identifiers, never for security. */
using boost::hash2::fnv1a_32;

/** FNV-1a with a 64-bit result, the Fowler-Noll-Vo hash (IETF draft-eastlake-fnv). Not
 * cryptographic: for hash tables, checksums and identifiers, never for security. */
using boost::hash2::fnv1a_64;

/** SipHash-2-4 truncated to a 32-bit result, Aumasson and Bernstein's keyed hash. A keyed function
 * for hash tables against flooding, not a general-purpose MAC or a digest. */
using boost::hash2::siphash_32;

/** SipHash-2-4 with a 64-bit result, Aumasson and Bernstein's keyed hash. A keyed function for hash
 * tables against flooding, not a general-purpose MAC or a digest. */
using boost::hash2::siphash_64;

/** xxHash32, Yann Collet's 32-bit hash. Not cryptographic: for hash tables, checksums and
 * identifiers, never for security. */
using boost::hash2::xxhash_32;

/** XXH64, Yann Collet's 64-bit hash. Not cryptographic: for hash tables, checksums and identifiers,
 * never for security. */
using boost::hash2::xxhash_64;

/** XXH3 with a 128-bit result, Yann Collet's hash. Not cryptographic: for hash tables, checksums
 * and identifiers, never for security. */
using boost::hash2::xxh3_128;

/** MurmurHash3 x86_32, Austin Appleby's hash. Not cryptographic: for hash tables, checksums and
 * identifiers, never for security. */
using boost::hash2::murmur3_32;

/** MurmurHash3 x64_128, Austin Appleby's hash. Not cryptographic: for hash tables, checksums and
 * identifiers, never for security. */
using boost::hash2::murmur3_128;

/** SpookyHash V2 with a 128-bit result, Bob Jenkins' hash. Not cryptographic: for hash tables,
 * checksums and identifiers, never for security. */
using boost::hash2::spooky2_128;

/** Boost.Hash2's `hash_append`: feeds a value to a hash algorithm. */
using boost::hash2::hash_append;
/** Boost.Hash2's `hash_append_range`: feeds a range to a hash algorithm. */
using boost::hash2::hash_append_range;
/** Boost.Hash2's `hash_append_range_and_size`: feeds a range and then its size. */
using boost::hash2::hash_append_range_and_size;
/** Boost.Hash2's `hash_append_size`: feeds a size. */
using boost::hash2::hash_append_size;
/** Boost.Hash2's `hash_append_unordered_range`: feeds an unordered range, order-independently. */
using boost::hash2::hash_append_unordered_range;
/** Boost.Hash2's `get_integral_result`: converts a result to an integer type. */
using boost::hash2::get_integral_result;

}  // namespace webcpp::hash

#endif  // WEBCPP_HASH_ALGORITHMS_HPP
