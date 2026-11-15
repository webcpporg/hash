// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The per-algorithm overrides of the default backend (spec section 4.1), one block per algorithm
// of doc/capabilities.json and one define per backend of it:
// WEBCPP_HASH_DEFAULT_BACKEND_<ALGORITHM>_<NAME> names the backend of every function of the
// algorithm, whatever the profile. Two overrides of one algorithm, and OpenSSL's on Emscripten,
// are an #error. An override names its backend even where the backend lacks the function over
// the hmac used: the call then stops with that backend's refusal (spec 3.3); and when the
// program does not link it, hkdf.hpp and pbkdf2.hpp include its header, which stops with its
// "needs" message (spec 5.7). Written by hand in increment 1, checked against
// doc/capabilities.json by test/overrides_list_test.cpp; tools/hash/measure.py --overrides
// regenerates it from Task 21 on.

#ifndef WEBCPP_HASH_DETAIL_OVERRIDES_HPP
#define WEBCPP_HASH_DETAIL_OVERRIDES_HPP

#include <webcpp/hash/config.hpp>

#define WEBCPP_HASH_DETAIL_OVERRIDE_STRING_I(x) #x
#define WEBCPP_HASH_DETAIL_OVERRIDE_STRING(x) WEBCPP_HASH_DETAIL_OVERRIDE_STRING_I(x)

namespace webcpp::hash::detail {

/**
 The backend an override names for `Algorithm`, `void` without one.

 @tparam Algorithm A tag of `kdfs`, the algorithm (not one of its steps).
*/
template <class Algorithm>
struct override_choice {
    /** No override. */
    using type = void;
};

// HKDF: hkdf_extract, hkdf_expand, hkdf.
// clang-format off
#if defined(WEBCPP_HASH_DEFAULT_BACKEND_HKDF_HASH2) && defined(WEBCPP_HASH_DEFAULT_BACKEND_HKDF_SODIUM)
#error "webcpp::hash: WEBCPP_HASH_DEFAULT_BACKEND_HKDF_HASH2 and WEBCPP_HASH_DEFAULT_BACKEND_HKDF_SODIUM are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_DEFAULT_BACKEND_HKDF_HASH2) && defined(WEBCPP_HASH_DEFAULT_BACKEND_HKDF_BEARSSL)
#error "webcpp::hash: WEBCPP_HASH_DEFAULT_BACKEND_HKDF_HASH2 and WEBCPP_HASH_DEFAULT_BACKEND_HKDF_BEARSSL are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_DEFAULT_BACKEND_HKDF_HASH2) && defined(WEBCPP_HASH_DEFAULT_BACKEND_HKDF_OPENSSL)
#error "webcpp::hash: WEBCPP_HASH_DEFAULT_BACKEND_HKDF_HASH2 and WEBCPP_HASH_DEFAULT_BACKEND_HKDF_OPENSSL are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_DEFAULT_BACKEND_HKDF_SODIUM) && defined(WEBCPP_HASH_DEFAULT_BACKEND_HKDF_BEARSSL)
#error "webcpp::hash: WEBCPP_HASH_DEFAULT_BACKEND_HKDF_SODIUM and WEBCPP_HASH_DEFAULT_BACKEND_HKDF_BEARSSL are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_DEFAULT_BACKEND_HKDF_SODIUM) && defined(WEBCPP_HASH_DEFAULT_BACKEND_HKDF_OPENSSL)
#error "webcpp::hash: WEBCPP_HASH_DEFAULT_BACKEND_HKDF_SODIUM and WEBCPP_HASH_DEFAULT_BACKEND_HKDF_OPENSSL are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_DEFAULT_BACKEND_HKDF_BEARSSL) && defined(WEBCPP_HASH_DEFAULT_BACKEND_HKDF_OPENSSL)
#error "webcpp::hash: WEBCPP_HASH_DEFAULT_BACKEND_HKDF_BEARSSL and WEBCPP_HASH_DEFAULT_BACKEND_HKDF_OPENSSL are both defined. Keep one."
#endif
#if defined(WEBCPP_TARGET_EMSCRIPTEN) && defined(WEBCPP_HASH_DEFAULT_BACKEND_HKDF_OPENSSL)
#error "webcpp::hash: WEBCPP_HASH_DEFAULT_BACKEND_HKDF_OPENSSL selects OpenSSL, which is not built for Emscripten. Remove that define."
#endif
// clang-format on
#ifdef WEBCPP_HASH_DEFAULT_BACKEND_HKDF_HASH2
#define WEBCPP_HASH_DETAIL_OVERRIDE_HKDF hash2
#define WEBCPP_HASH_DETAIL_OVERRIDES_HASH2
#elif defined(WEBCPP_HASH_DEFAULT_BACKEND_HKDF_SODIUM)
#define WEBCPP_HASH_DETAIL_OVERRIDE_HKDF sodium
#define WEBCPP_HASH_DETAIL_OVERRIDES_SODIUM
#elif defined(WEBCPP_HASH_DEFAULT_BACKEND_HKDF_BEARSSL)
#define WEBCPP_HASH_DETAIL_OVERRIDE_HKDF bearssl
#define WEBCPP_HASH_DETAIL_OVERRIDES_BEARSSL
#elif defined(WEBCPP_HASH_DEFAULT_BACKEND_HKDF_OPENSSL)
#define WEBCPP_HASH_DETAIL_OVERRIDE_HKDF openssl
#define WEBCPP_HASH_DETAIL_OVERRIDES_OPENSSL
#endif
#ifdef WEBCPP_HASH_DETAIL_OVERRIDE_HKDF
/** The backend the override of HKDF names. */
template <>
struct override_choice<kdfs::hkdf> {
    /** The named backend. */
    using type = backends::WEBCPP_HASH_DETAIL_OVERRIDE_HKDF;
};
#ifdef _MSC_VER
#pragma detect_mismatch("webcpp_hash_default_backend_hkdf", \
                        WEBCPP_HASH_DETAIL_OVERRIDE_STRING(WEBCPP_HASH_DETAIL_OVERRIDE_HKDF))
#endif
#elif defined(_MSC_VER)
#pragma detect_mismatch("webcpp_hash_default_backend_hkdf", "none")
#endif

// PBKDF2: pbkdf2.
// clang-format off
#if defined(WEBCPP_HASH_DEFAULT_BACKEND_PBKDF2_HASH2) && defined(WEBCPP_HASH_DEFAULT_BACKEND_PBKDF2_SODIUM)
#error "webcpp::hash: WEBCPP_HASH_DEFAULT_BACKEND_PBKDF2_HASH2 and WEBCPP_HASH_DEFAULT_BACKEND_PBKDF2_SODIUM are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_DEFAULT_BACKEND_PBKDF2_HASH2) && defined(WEBCPP_HASH_DEFAULT_BACKEND_PBKDF2_BEARSSL)
#error "webcpp::hash: WEBCPP_HASH_DEFAULT_BACKEND_PBKDF2_HASH2 and WEBCPP_HASH_DEFAULT_BACKEND_PBKDF2_BEARSSL are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_DEFAULT_BACKEND_PBKDF2_HASH2) && defined(WEBCPP_HASH_DEFAULT_BACKEND_PBKDF2_OPENSSL)
#error "webcpp::hash: WEBCPP_HASH_DEFAULT_BACKEND_PBKDF2_HASH2 and WEBCPP_HASH_DEFAULT_BACKEND_PBKDF2_OPENSSL are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_DEFAULT_BACKEND_PBKDF2_SODIUM) && defined(WEBCPP_HASH_DEFAULT_BACKEND_PBKDF2_BEARSSL)
#error "webcpp::hash: WEBCPP_HASH_DEFAULT_BACKEND_PBKDF2_SODIUM and WEBCPP_HASH_DEFAULT_BACKEND_PBKDF2_BEARSSL are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_DEFAULT_BACKEND_PBKDF2_SODIUM) && defined(WEBCPP_HASH_DEFAULT_BACKEND_PBKDF2_OPENSSL)
#error "webcpp::hash: WEBCPP_HASH_DEFAULT_BACKEND_PBKDF2_SODIUM and WEBCPP_HASH_DEFAULT_BACKEND_PBKDF2_OPENSSL are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_DEFAULT_BACKEND_PBKDF2_BEARSSL) && defined(WEBCPP_HASH_DEFAULT_BACKEND_PBKDF2_OPENSSL)
#error "webcpp::hash: WEBCPP_HASH_DEFAULT_BACKEND_PBKDF2_BEARSSL and WEBCPP_HASH_DEFAULT_BACKEND_PBKDF2_OPENSSL are both defined. Keep one."
#endif
#if defined(WEBCPP_TARGET_EMSCRIPTEN) && defined(WEBCPP_HASH_DEFAULT_BACKEND_PBKDF2_OPENSSL)
#error "webcpp::hash: WEBCPP_HASH_DEFAULT_BACKEND_PBKDF2_OPENSSL selects OpenSSL, which is not built for Emscripten. Remove that define."
#endif
// clang-format on
#ifdef WEBCPP_HASH_DEFAULT_BACKEND_PBKDF2_HASH2
#define WEBCPP_HASH_DETAIL_OVERRIDE_PBKDF2 hash2
#define WEBCPP_HASH_DETAIL_OVERRIDES_HASH2
#elif defined(WEBCPP_HASH_DEFAULT_BACKEND_PBKDF2_SODIUM)
#define WEBCPP_HASH_DETAIL_OVERRIDE_PBKDF2 sodium
#define WEBCPP_HASH_DETAIL_OVERRIDES_SODIUM
#elif defined(WEBCPP_HASH_DEFAULT_BACKEND_PBKDF2_BEARSSL)
#define WEBCPP_HASH_DETAIL_OVERRIDE_PBKDF2 bearssl
#define WEBCPP_HASH_DETAIL_OVERRIDES_BEARSSL
#elif defined(WEBCPP_HASH_DEFAULT_BACKEND_PBKDF2_OPENSSL)
#define WEBCPP_HASH_DETAIL_OVERRIDE_PBKDF2 openssl
#define WEBCPP_HASH_DETAIL_OVERRIDES_OPENSSL
#endif
#ifdef WEBCPP_HASH_DETAIL_OVERRIDE_PBKDF2
/** The backend the override of PBKDF2 names. */
template <>
struct override_choice<kdfs::pbkdf2> {
    /** The named backend. */
    using type = backends::WEBCPP_HASH_DETAIL_OVERRIDE_PBKDF2;
};
#ifdef _MSC_VER
#pragma detect_mismatch("webcpp_hash_default_backend_pbkdf2", \
                        WEBCPP_HASH_DETAIL_OVERRIDE_STRING(WEBCPP_HASH_DETAIL_OVERRIDE_PBKDF2))
#endif
#elif defined(_MSC_VER)
#pragma detect_mismatch("webcpp_hash_default_backend_pbkdf2", "none")
#endif

// ARGON2ID: argon2id.
// clang-format off
#if defined(WEBCPP_HASH_DEFAULT_BACKEND_ARGON2ID_HASH2) && defined(WEBCPP_HASH_DEFAULT_BACKEND_ARGON2ID_SODIUM)
#error "webcpp::hash: WEBCPP_HASH_DEFAULT_BACKEND_ARGON2ID_HASH2 and WEBCPP_HASH_DEFAULT_BACKEND_ARGON2ID_SODIUM are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_DEFAULT_BACKEND_ARGON2ID_HASH2) && defined(WEBCPP_HASH_DEFAULT_BACKEND_ARGON2ID_BEARSSL)
#error "webcpp::hash: WEBCPP_HASH_DEFAULT_BACKEND_ARGON2ID_HASH2 and WEBCPP_HASH_DEFAULT_BACKEND_ARGON2ID_BEARSSL are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_DEFAULT_BACKEND_ARGON2ID_HASH2) && defined(WEBCPP_HASH_DEFAULT_BACKEND_ARGON2ID_OPENSSL)
#error "webcpp::hash: WEBCPP_HASH_DEFAULT_BACKEND_ARGON2ID_HASH2 and WEBCPP_HASH_DEFAULT_BACKEND_ARGON2ID_OPENSSL are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_DEFAULT_BACKEND_ARGON2ID_SODIUM) && defined(WEBCPP_HASH_DEFAULT_BACKEND_ARGON2ID_BEARSSL)
#error "webcpp::hash: WEBCPP_HASH_DEFAULT_BACKEND_ARGON2ID_SODIUM and WEBCPP_HASH_DEFAULT_BACKEND_ARGON2ID_BEARSSL are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_DEFAULT_BACKEND_ARGON2ID_SODIUM) && defined(WEBCPP_HASH_DEFAULT_BACKEND_ARGON2ID_OPENSSL)
#error "webcpp::hash: WEBCPP_HASH_DEFAULT_BACKEND_ARGON2ID_SODIUM and WEBCPP_HASH_DEFAULT_BACKEND_ARGON2ID_OPENSSL are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_DEFAULT_BACKEND_ARGON2ID_BEARSSL) && defined(WEBCPP_HASH_DEFAULT_BACKEND_ARGON2ID_OPENSSL)
#error "webcpp::hash: WEBCPP_HASH_DEFAULT_BACKEND_ARGON2ID_BEARSSL and WEBCPP_HASH_DEFAULT_BACKEND_ARGON2ID_OPENSSL are both defined. Keep one."
#endif
#if defined(WEBCPP_TARGET_EMSCRIPTEN) && defined(WEBCPP_HASH_DEFAULT_BACKEND_ARGON2ID_OPENSSL)
#error "webcpp::hash: WEBCPP_HASH_DEFAULT_BACKEND_ARGON2ID_OPENSSL selects OpenSSL, which is not built for Emscripten. Remove that define."
#endif
// clang-format on
#ifdef WEBCPP_HASH_DEFAULT_BACKEND_ARGON2ID_HASH2
#define WEBCPP_HASH_DETAIL_OVERRIDE_ARGON2ID hash2
#define WEBCPP_HASH_DETAIL_OVERRIDES_HASH2
#elif defined(WEBCPP_HASH_DEFAULT_BACKEND_ARGON2ID_SODIUM)
#define WEBCPP_HASH_DETAIL_OVERRIDE_ARGON2ID sodium
#define WEBCPP_HASH_DETAIL_OVERRIDES_SODIUM
#elif defined(WEBCPP_HASH_DEFAULT_BACKEND_ARGON2ID_BEARSSL)
#define WEBCPP_HASH_DETAIL_OVERRIDE_ARGON2ID bearssl
#define WEBCPP_HASH_DETAIL_OVERRIDES_BEARSSL
#elif defined(WEBCPP_HASH_DEFAULT_BACKEND_ARGON2ID_OPENSSL)
#define WEBCPP_HASH_DETAIL_OVERRIDE_ARGON2ID openssl
#define WEBCPP_HASH_DETAIL_OVERRIDES_OPENSSL
#endif
#ifdef WEBCPP_HASH_DETAIL_OVERRIDE_ARGON2ID
/** The backend the override of ARGON2ID names. */
template <>
struct override_choice<kdfs::argon2id> {
    /** The named backend. */
    using type = backends::WEBCPP_HASH_DETAIL_OVERRIDE_ARGON2ID;
};
#ifdef _MSC_VER
#pragma detect_mismatch("webcpp_hash_default_backend_argon2id", \
                        WEBCPP_HASH_DETAIL_OVERRIDE_STRING(WEBCPP_HASH_DETAIL_OVERRIDE_ARGON2ID))
#endif
#elif defined(_MSC_VER)
#pragma detect_mismatch("webcpp_hash_default_backend_argon2id", "none")
#endif

// SCRYPT: scrypt.
// clang-format off
#if defined(WEBCPP_HASH_DEFAULT_BACKEND_SCRYPT_HASH2) && defined(WEBCPP_HASH_DEFAULT_BACKEND_SCRYPT_SODIUM)
#error "webcpp::hash: WEBCPP_HASH_DEFAULT_BACKEND_SCRYPT_HASH2 and WEBCPP_HASH_DEFAULT_BACKEND_SCRYPT_SODIUM are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_DEFAULT_BACKEND_SCRYPT_HASH2) && defined(WEBCPP_HASH_DEFAULT_BACKEND_SCRYPT_BEARSSL)
#error "webcpp::hash: WEBCPP_HASH_DEFAULT_BACKEND_SCRYPT_HASH2 and WEBCPP_HASH_DEFAULT_BACKEND_SCRYPT_BEARSSL are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_DEFAULT_BACKEND_SCRYPT_HASH2) && defined(WEBCPP_HASH_DEFAULT_BACKEND_SCRYPT_OPENSSL)
#error "webcpp::hash: WEBCPP_HASH_DEFAULT_BACKEND_SCRYPT_HASH2 and WEBCPP_HASH_DEFAULT_BACKEND_SCRYPT_OPENSSL are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_DEFAULT_BACKEND_SCRYPT_SODIUM) && defined(WEBCPP_HASH_DEFAULT_BACKEND_SCRYPT_BEARSSL)
#error "webcpp::hash: WEBCPP_HASH_DEFAULT_BACKEND_SCRYPT_SODIUM and WEBCPP_HASH_DEFAULT_BACKEND_SCRYPT_BEARSSL are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_DEFAULT_BACKEND_SCRYPT_SODIUM) && defined(WEBCPP_HASH_DEFAULT_BACKEND_SCRYPT_OPENSSL)
#error "webcpp::hash: WEBCPP_HASH_DEFAULT_BACKEND_SCRYPT_SODIUM and WEBCPP_HASH_DEFAULT_BACKEND_SCRYPT_OPENSSL are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_DEFAULT_BACKEND_SCRYPT_BEARSSL) && defined(WEBCPP_HASH_DEFAULT_BACKEND_SCRYPT_OPENSSL)
#error "webcpp::hash: WEBCPP_HASH_DEFAULT_BACKEND_SCRYPT_BEARSSL and WEBCPP_HASH_DEFAULT_BACKEND_SCRYPT_OPENSSL are both defined. Keep one."
#endif
#if defined(WEBCPP_TARGET_EMSCRIPTEN) && defined(WEBCPP_HASH_DEFAULT_BACKEND_SCRYPT_OPENSSL)
#error "webcpp::hash: WEBCPP_HASH_DEFAULT_BACKEND_SCRYPT_OPENSSL selects OpenSSL, which is not built for Emscripten. Remove that define."
#endif
// clang-format on
#ifdef WEBCPP_HASH_DEFAULT_BACKEND_SCRYPT_HASH2
#define WEBCPP_HASH_DETAIL_OVERRIDE_SCRYPT hash2
#define WEBCPP_HASH_DETAIL_OVERRIDES_HASH2
#elif defined(WEBCPP_HASH_DEFAULT_BACKEND_SCRYPT_SODIUM)
#define WEBCPP_HASH_DETAIL_OVERRIDE_SCRYPT sodium
#define WEBCPP_HASH_DETAIL_OVERRIDES_SODIUM
#elif defined(WEBCPP_HASH_DEFAULT_BACKEND_SCRYPT_BEARSSL)
#define WEBCPP_HASH_DETAIL_OVERRIDE_SCRYPT bearssl
#define WEBCPP_HASH_DETAIL_OVERRIDES_BEARSSL
#elif defined(WEBCPP_HASH_DEFAULT_BACKEND_SCRYPT_OPENSSL)
#define WEBCPP_HASH_DETAIL_OVERRIDE_SCRYPT openssl
#define WEBCPP_HASH_DETAIL_OVERRIDES_OPENSSL
#endif
#ifdef WEBCPP_HASH_DETAIL_OVERRIDE_SCRYPT
/** The backend the override of SCRYPT names. */
template <>
struct override_choice<kdfs::scrypt> {
    /** The named backend. */
    using type = backends::WEBCPP_HASH_DETAIL_OVERRIDE_SCRYPT;
};
#ifdef _MSC_VER
#pragma detect_mismatch("webcpp_hash_default_backend_scrypt", \
                        WEBCPP_HASH_DETAIL_OVERRIDE_STRING(WEBCPP_HASH_DETAIL_OVERRIDE_SCRYPT))
#endif
#elif defined(_MSC_VER)
#pragma detect_mismatch("webcpp_hash_default_backend_scrypt", "none")
#endif

}  // namespace webcpp::hash::detail

#endif  // WEBCPP_HASH_DETAIL_OVERRIDES_HPP
