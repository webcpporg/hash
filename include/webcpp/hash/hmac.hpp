// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 Boost.Hash2's HMAC under webcpp::hash's names: HMAC, RFC 2104, over each of Hash2's
 cryptographic algorithms.

 A program checks a MAC with `webcpp::crypto::constant_time_equal`, never with
 `digest<N>::operator==`, which does not run in constant time:

 @code
 // key, message: the shared key and the message received; tag: the tag received with it,
 // a webcpp::hash::hmac_sha2_256::result_type
 webcpp::hash::hmac_sha2_256 mac(key.data(), key.size());
 mac.update(message.data(), message.size());
 bool genuine = webcpp::crypto::constant_time_equal(mac.result(), tag);
 @endcode

 @see "HMAC", in the guide.
*/
#ifndef WEBCPP_HASH_HMAC_HPP
#define WEBCPP_HASH_HMAC_HPP

#include <webcpp/hash/config.hpp>

#include <boost/hash2/blake2.hpp>
#include <boost/hash2/hmac.hpp>
#include <boost/hash2/md5.hpp>
#include <boost/hash2/ripemd.hpp>
#include <boost/hash2/sha1.hpp>
#include <boost/hash2/sha2.hpp>
#include <boost/hash2/sha3.hpp>

namespace webcpp::hash {

/**
 HMAC over `H`, RFC 2104, Boost.Hash2's.

 @tparam H A Hash2 HashAlgorithm.
*/
template <class H>
using hmac = boost::hash2::hmac<H>;

/** HMAC, RFC 2104, over MD5 (legacy, not for new designs). */
using boost::hash2::hmac_md5_128;

/** HMAC, RFC 2104, over SHA-1 (legacy, not for new designs). */
using boost::hash2::hmac_sha1_160;

/** HMAC, RFC 2104, over SHA-224. */
using boost::hash2::hmac_sha2_224;

/** HMAC, RFC 2104, over SHA-256. */
using boost::hash2::hmac_sha2_256;

/** HMAC, RFC 2104, over SHA-384. */
using boost::hash2::hmac_sha2_384;

/** HMAC, RFC 2104, over SHA-512. */
using boost::hash2::hmac_sha2_512;

/** HMAC, RFC 2104, over SHA-512/224. */
using boost::hash2::hmac_sha2_512_224;

/** HMAC, RFC 2104, over SHA-512/256. */
using boost::hash2::hmac_sha2_512_256;

/** HMAC, RFC 2104, over SHA3-224. */
using boost::hash2::hmac_sha3_224;

/** HMAC, RFC 2104, over SHA3-256. */
using boost::hash2::hmac_sha3_256;

/** HMAC, RFC 2104, over SHA3-384. */
using boost::hash2::hmac_sha3_384;

/** HMAC, RFC 2104, over SHA3-512. */
using boost::hash2::hmac_sha3_512;

/** HMAC, RFC 2104, over RIPEMD-128. */
using boost::hash2::hmac_ripemd_128;

/** HMAC, RFC 2104, over RIPEMD-160. */
using boost::hash2::hmac_ripemd_160;

/** HMAC, RFC 2104, over BLAKE2b. */
using boost::hash2::hmac_blake2b_512;

/** HMAC, RFC 2104, over BLAKE2s. */
using boost::hash2::hmac_blake2s_256;

}  // namespace webcpp::hash

#endif  // WEBCPP_HASH_HMAC_HPP
