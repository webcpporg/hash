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
#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/hash/pbkdf2.hpp>

// keccak_256 when the program links XKCP (/third_party//xkcp defines WEBCPP_HASH_HAS_XKCP).
#ifdef WEBCPP_HASH_HAS_XKCP
#include <webcpp/hash/keccak.hpp>
#endif

// blake3 needs BLAKE3's C implementation, /third_party//blake3, which defines
// WEBCPP_HASH_HAS_BLAKE3: a program that does not link it leaves blake3.hpp out.
#ifdef WEBCPP_HASH_HAS_BLAKE3
#include <webcpp/hash/blake3.hpp>
#endif

// backends::bearssl needs BearSSL, /third_party//bearssl, which defines
// WEBCPP_HASH_HAS_BEARSSL: a program that does not link it leaves its header out.
#ifdef WEBCPP_HASH_HAS_BEARSSL
#include <webcpp/hash/backends/bearssl.hpp>
#endif

#endif  // WEBCPP_HASH_HPP
