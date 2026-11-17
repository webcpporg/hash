// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 Every public header of webcpp::hash: those that need no C library always, and
 each part over a C library when the program links that library (its target
 defines `WEBCPP_HASH_HAS_<NAME>`).
*/
#ifndef WEBCPP_HASH_HPP
#define WEBCPP_HASH_HPP

#include <webcpp/hash/config.hpp>

#include <webcpp/hash/algorithms.hpp>
#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/blake2b_subkey.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/hash/pbkdf2.hpp>

// keccak_256 and backends::xkcp when the program links XKCP (/third_party//xkcp defines
// WEBCPP_HASH_HAS_XKCP).
#ifdef WEBCPP_HASH_HAS_XKCP
#include <webcpp/hash/backends/xkcp.hpp>
#include <webcpp/hash/keccak.hpp>
#endif

// blake3 and backends::blake3 need BLAKE3's C implementation, /third_party//blake3, which
// defines WEBCPP_HASH_HAS_BLAKE3: a program that does not link it leaves their headers out.
#ifdef WEBCPP_HASH_HAS_BLAKE3
#include <webcpp/hash/backends/blake3.hpp>
#include <webcpp/hash/blake3.hpp>
#endif

// backends::bearssl needs BearSSL, /third_party//bearssl, which defines
// WEBCPP_HASH_HAS_BEARSSL: a program that does not link it leaves its header out.
#ifdef WEBCPP_HASH_HAS_BEARSSL
#include <webcpp/hash/backends/bearssl.hpp>
#endif

// backends::sodium when the program links libsodium (/third_party//sodium defines
// WEBCPP_HASH_HAS_SODIUM).
#ifdef WEBCPP_HASH_HAS_SODIUM
#include <webcpp/hash/backends/sodium.hpp>
#endif

// backends::openssl needs OpenSSL, /webcpp/hash//openssl, which defines
// WEBCPP_HASH_HAS_OPENSSL (native, wasip2 and wasip3): a program that does not
// link it leaves backends/openssl.hpp out.
#ifdef WEBCPP_HASH_HAS_OPENSSL
#include <webcpp/hash/backends/openssl.hpp>
#endif

// scrypt, whose only backend is libsodium's: a program that does not link it leaves it out.
// argon2.hpp, above, needs no library: its functions refuse at compile time, with the Jamfile
// line to add, when they are called without one.
#ifdef WEBCPP_HASH_HAS_SODIUM
#include <webcpp/hash/scrypt.hpp>
#endif

#endif  // WEBCPP_HASH_HPP
