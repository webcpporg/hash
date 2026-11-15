// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The configuration of webcpp::hash, which each of its headers includes first:
 whether it is built without exceptions, whether the target is WebAssembly, the
 C libraries the build links and the backends of the key derivation functions.

 @see "Using webcpp::hash in your Jamfile", in the guide.
*/
#ifndef WEBCPP_HASH_CONFIG_HPP
#define WEBCPP_HASH_CONFIG_HPP

#include <webcpp/config.hpp>

// MrDocs parses hash natively, as a build with exceptions does, where none of these macros is
// defined: these definitions, each undone at once, are the ones the reference lists.
#ifdef __MRDOCS__
/**
 Defined when webcpp::hash is built without exceptions: when webcpp has none (the compiler has
 none, or the developer defined `WEBCPP_NO_EXCEPTIONS` for every webcpp library), or when the
 developer defines it alone.

 webcpp::hash raises no exception of its own: every operation that can fail reports it as a
 value, whether or not the macro is defined.

 @see "Exceptions", in the guide.
*/
#define WEBCPP_HASH_NO_EXCEPTIONS
#undef WEBCPP_HASH_NO_EXCEPTIONS
/** Defined on the WebAssembly targets, wasip2, wasip3 and Emscripten. */
#define WEBCPP_HASH_WEBASSEMBLY 1
#undef WEBCPP_HASH_WEBASSEMBLY
/**
 Defined by `/third_party//xkcp` when the program links XKCP; a program built without b2
 defines it to 1 itself.
*/
#define WEBCPP_HASH_HAS_XKCP 1
#undef WEBCPP_HASH_HAS_XKCP
/**
 Defined by `/third_party//blake3` when the program links the BLAKE3 C implementation; a
 program built without b2 defines it to 1 itself.
*/
#define WEBCPP_HASH_HAS_BLAKE3 1
#undef WEBCPP_HASH_HAS_BLAKE3
/**
 Defined by `/third_party//sodium` when the program links libsodium; a program built without
 b2 defines it to 1 itself.
*/
#define WEBCPP_HASH_HAS_SODIUM 1
#undef WEBCPP_HASH_HAS_SODIUM
/**
 Defined by `/third_party//bearssl` when the program links BearSSL; a program built without
 b2 defines it to 1 itself.
*/
#define WEBCPP_HASH_HAS_BEARSSL 1
#undef WEBCPP_HASH_HAS_BEARSSL
/**
 Defined by `/webcpp/hash//openssl` when the program links OpenSSL; a program built without
 b2 defines it to 1 itself. Refused on Emscripten, where OpenSSL is not built.
*/
#define WEBCPP_HASH_HAS_OPENSSL 1
#undef WEBCPP_HASH_HAS_OPENSSL
/** Defined by a program to choose the fastest linked backend for every algorithm. */
#define WEBCPP_HASH_PROFILE_FASTEST
#undef WEBCPP_HASH_PROFILE_FASTEST
/** Defined by a program to choose the backend that gives the smallest binary. */
#define WEBCPP_HASH_PROFILE_SMALLEST
#undef WEBCPP_HASH_PROFILE_SMALLEST
/** Defined by a program to choose the backend that exists on every target. */
#define WEBCPP_HASH_PROFILE_PORTABLE
#undef WEBCPP_HASH_PROFILE_PORTABLE
/** Defined by a program to choose backends::hash2 for every algorithm. */
#define WEBCPP_HASH_PROFILE_BACKEND_HASH2
#undef WEBCPP_HASH_PROFILE_BACKEND_HASH2
/**
 Defined by a program to choose backends::sodium for every algorithm it has, when the program
 links it; the others keep the default without a profile.
*/
#define WEBCPP_HASH_PROFILE_BACKEND_SODIUM
#undef WEBCPP_HASH_PROFILE_BACKEND_SODIUM
/**
 Defined by a program to choose backends::bearssl for every function it has, when the program
 links it (`hkdf`, not its two steps alone); the others keep the default without a profile.
*/
#define WEBCPP_HASH_PROFILE_BACKEND_BEARSSL
#undef WEBCPP_HASH_PROFILE_BACKEND_BEARSSL
/**
 Defined by a program to choose backends::openssl for every algorithm it has, when the program
 links it; the others keep the default without a profile. Refused on Emscripten.
*/
#define WEBCPP_HASH_PROFILE_BACKEND_OPENSSL
#undef WEBCPP_HASH_PROFILE_BACKEND_OPENSSL
/**
 webcpp's umbrella profile, for every webcpp library: the fastest, as
 `WEBCPP_HASH_PROFILE_FASTEST`, unless the program gives webcpp::hash a profile of its own.
*/
#define WEBCPP_PROFILE_FASTEST
#undef WEBCPP_PROFILE_FASTEST
/** webcpp's umbrella profile: the smallest, as `WEBCPP_HASH_PROFILE_SMALLEST`. */
#define WEBCPP_PROFILE_SMALLEST
#undef WEBCPP_PROFILE_SMALLEST
/** webcpp's umbrella profile: the portable, as `WEBCPP_HASH_PROFILE_PORTABLE`. */
#define WEBCPP_PROFILE_PORTABLE
#undef WEBCPP_PROFILE_PORTABLE
// ... and the overrides WEBCPP_HASH_DEFAULT_BACKEND_<ALGORITHM>_<NAME>, one per algorithm of
// doc/capabilities.json and backend, in detail/overrides.hpp (spec 4.1).
#endif

#if !defined(WEBCPP_HAS_EXCEPTIONS) && !defined(WEBCPP_HASH_NO_EXCEPTIONS)
#define WEBCPP_HASH_NO_EXCEPTIONS
#endif

#if defined(WEBCPP_TARGET_WASIP2) || defined(WEBCPP_TARGET_WASIP3) || \
    defined(WEBCPP_TARGET_EMSCRIPTEN)
#define WEBCPP_HASH_WEBASSEMBLY 1
#endif

// The refusals of impossible combinations (spec 5.7). Clang and gcc go on after an #error, so
// the first error is the instruction; MSVC stops at it.
// clang-format off
#if defined(WEBCPP_TARGET_EMSCRIPTEN) && defined(WEBCPP_HASH_HAS_OPENSSL)
#error "webcpp::hash: OpenSSL is not built for Emscripten. In the program's Jamfile, remove /webcpp/hash//openssl: hkdf and pbkdf2 then run on backends::hash2."
#endif
#if defined(WEBCPP_TARGET_EMSCRIPTEN) && defined(WEBCPP_HASH_PROFILE_BACKEND_OPENSSL)
#error "webcpp::hash: WEBCPP_HASH_PROFILE_BACKEND_OPENSSL selects OpenSSL, which is not built for Emscripten. Remove that define."
#endif
// The profile's refusals (spec 4.1): two library profiles, or two umbrella profiles, name both
// defines. A library profile beside an umbrella profile is not an error: the library's wins. The
// overrides' refusals are in detail/overrides.hpp.
#if defined(WEBCPP_HASH_PROFILE_FASTEST) && defined(WEBCPP_HASH_PROFILE_SMALLEST)
#error "webcpp::hash: WEBCPP_HASH_PROFILE_FASTEST and WEBCPP_HASH_PROFILE_SMALLEST are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_PROFILE_FASTEST) && defined(WEBCPP_HASH_PROFILE_PORTABLE)
#error "webcpp::hash: WEBCPP_HASH_PROFILE_FASTEST and WEBCPP_HASH_PROFILE_PORTABLE are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_PROFILE_FASTEST) && defined(WEBCPP_HASH_PROFILE_BACKEND_HASH2)
#error "webcpp::hash: WEBCPP_HASH_PROFILE_FASTEST and WEBCPP_HASH_PROFILE_BACKEND_HASH2 are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_PROFILE_FASTEST) && defined(WEBCPP_HASH_PROFILE_BACKEND_SODIUM)
#error "webcpp::hash: WEBCPP_HASH_PROFILE_FASTEST and WEBCPP_HASH_PROFILE_BACKEND_SODIUM are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_PROFILE_FASTEST) && defined(WEBCPP_HASH_PROFILE_BACKEND_BEARSSL)
#error "webcpp::hash: WEBCPP_HASH_PROFILE_FASTEST and WEBCPP_HASH_PROFILE_BACKEND_BEARSSL are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_PROFILE_FASTEST) && defined(WEBCPP_HASH_PROFILE_BACKEND_OPENSSL)
#error "webcpp::hash: WEBCPP_HASH_PROFILE_FASTEST and WEBCPP_HASH_PROFILE_BACKEND_OPENSSL are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_PROFILE_SMALLEST) && defined(WEBCPP_HASH_PROFILE_PORTABLE)
#error "webcpp::hash: WEBCPP_HASH_PROFILE_SMALLEST and WEBCPP_HASH_PROFILE_PORTABLE are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_PROFILE_SMALLEST) && defined(WEBCPP_HASH_PROFILE_BACKEND_HASH2)
#error "webcpp::hash: WEBCPP_HASH_PROFILE_SMALLEST and WEBCPP_HASH_PROFILE_BACKEND_HASH2 are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_PROFILE_SMALLEST) && defined(WEBCPP_HASH_PROFILE_BACKEND_SODIUM)
#error "webcpp::hash: WEBCPP_HASH_PROFILE_SMALLEST and WEBCPP_HASH_PROFILE_BACKEND_SODIUM are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_PROFILE_SMALLEST) && defined(WEBCPP_HASH_PROFILE_BACKEND_BEARSSL)
#error "webcpp::hash: WEBCPP_HASH_PROFILE_SMALLEST and WEBCPP_HASH_PROFILE_BACKEND_BEARSSL are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_PROFILE_SMALLEST) && defined(WEBCPP_HASH_PROFILE_BACKEND_OPENSSL)
#error "webcpp::hash: WEBCPP_HASH_PROFILE_SMALLEST and WEBCPP_HASH_PROFILE_BACKEND_OPENSSL are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_PROFILE_PORTABLE) && defined(WEBCPP_HASH_PROFILE_BACKEND_HASH2)
#error "webcpp::hash: WEBCPP_HASH_PROFILE_PORTABLE and WEBCPP_HASH_PROFILE_BACKEND_HASH2 are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_PROFILE_PORTABLE) && defined(WEBCPP_HASH_PROFILE_BACKEND_SODIUM)
#error "webcpp::hash: WEBCPP_HASH_PROFILE_PORTABLE and WEBCPP_HASH_PROFILE_BACKEND_SODIUM are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_PROFILE_PORTABLE) && defined(WEBCPP_HASH_PROFILE_BACKEND_BEARSSL)
#error "webcpp::hash: WEBCPP_HASH_PROFILE_PORTABLE and WEBCPP_HASH_PROFILE_BACKEND_BEARSSL are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_PROFILE_PORTABLE) && defined(WEBCPP_HASH_PROFILE_BACKEND_OPENSSL)
#error "webcpp::hash: WEBCPP_HASH_PROFILE_PORTABLE and WEBCPP_HASH_PROFILE_BACKEND_OPENSSL are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_PROFILE_BACKEND_HASH2) && defined(WEBCPP_HASH_PROFILE_BACKEND_SODIUM)
#error "webcpp::hash: WEBCPP_HASH_PROFILE_BACKEND_HASH2 and WEBCPP_HASH_PROFILE_BACKEND_SODIUM are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_PROFILE_BACKEND_HASH2) && defined(WEBCPP_HASH_PROFILE_BACKEND_BEARSSL)
#error "webcpp::hash: WEBCPP_HASH_PROFILE_BACKEND_HASH2 and WEBCPP_HASH_PROFILE_BACKEND_BEARSSL are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_PROFILE_BACKEND_HASH2) && defined(WEBCPP_HASH_PROFILE_BACKEND_OPENSSL)
#error "webcpp::hash: WEBCPP_HASH_PROFILE_BACKEND_HASH2 and WEBCPP_HASH_PROFILE_BACKEND_OPENSSL are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_PROFILE_BACKEND_SODIUM) && defined(WEBCPP_HASH_PROFILE_BACKEND_BEARSSL)
#error "webcpp::hash: WEBCPP_HASH_PROFILE_BACKEND_SODIUM and WEBCPP_HASH_PROFILE_BACKEND_BEARSSL are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_PROFILE_BACKEND_SODIUM) && defined(WEBCPP_HASH_PROFILE_BACKEND_OPENSSL)
#error "webcpp::hash: WEBCPP_HASH_PROFILE_BACKEND_SODIUM and WEBCPP_HASH_PROFILE_BACKEND_OPENSSL are both defined. Keep one."
#endif
#if defined(WEBCPP_HASH_PROFILE_BACKEND_BEARSSL) && defined(WEBCPP_HASH_PROFILE_BACKEND_OPENSSL)
#error "webcpp::hash: WEBCPP_HASH_PROFILE_BACKEND_BEARSSL and WEBCPP_HASH_PROFILE_BACKEND_OPENSSL are both defined. Keep one."
#endif
#if defined(WEBCPP_PROFILE_FASTEST) && defined(WEBCPP_PROFILE_SMALLEST)
#error "webcpp::hash: WEBCPP_PROFILE_FASTEST and WEBCPP_PROFILE_SMALLEST are both defined. Keep one."
#endif
#if defined(WEBCPP_PROFILE_FASTEST) && defined(WEBCPP_PROFILE_PORTABLE)
#error "webcpp::hash: WEBCPP_PROFILE_FASTEST and WEBCPP_PROFILE_PORTABLE are both defined. Keep one."
#endif
#if defined(WEBCPP_PROFILE_SMALLEST) && defined(WEBCPP_PROFILE_PORTABLE)
#error "webcpp::hash: WEBCPP_PROFILE_SMALLEST and WEBCPP_PROFILE_PORTABLE are both defined. Keep one."
#endif
// clang-format on

namespace webcpp::hash::backends {

/** webcpp's own HKDF and PBKDF2 over Boost.Hash2's `hmac<H>`, on every target. */
struct hash2;
/** libsodium, built from its sources by `/third_party//sodium`. */
struct sodium;
/** BearSSL, built from its sources by `/third_party//bearssl`. */
struct bearssl;
/** OpenSSL 3.5, built from its pinned sources, named by `/webcpp/hash//openssl`. */
struct openssl;

}  // namespace webcpp::hash::backends

namespace webcpp::hash::kdfs {

/** HKDF, RFC 5869: `hkdf_extract`, `hkdf_expand` and `hkdf`. */
struct hkdf;
/**
 HKDF-Extract alone, `hkdf_extract`: the tag by which @ref webcpp::hash::backend_has_v and
 @ref webcpp::hash::default_backend answer for the step, which a backend that has HKDF only whole
 (`backends::bearssl`) lacks.
*/
struct hkdf_extract;
/** HKDF-Expand alone, `hkdf_expand`: as @ref hkdf_extract, for the second step. */
struct hkdf_expand;
/** PBKDF2, RFC 8018: `pbkdf2`. */
struct pbkdf2;
/** Argon2id, RFC 9106, with one lane: `argon2id`, on `backends::sodium`. */
struct argon2id;
/** scrypt, RFC 7914: `scrypt`, on `backends::sodium`. */
struct scrypt;

}  // namespace webcpp::hash::kdfs

namespace webcpp::hash::detail::profiles {

/** No profile defined: natively `fastest`, on WebAssembly `smallest` (spec 4.1). */
struct automatic;
/** The linked backend with the best measured throughput on this target. */
struct fastest;
/** The linked backend with the smallest measured program on this target. */
struct smallest;
/** The first of `portable_order` that has the algorithm: the same code on every target. */
struct portable;
/**
 A named backend for every algorithm it has, linked; `automatic`'s choice for the others.

 @tparam Backend A backend of `backends`.
*/
template <class Backend>
struct named;

}  // namespace webcpp::hash::detail::profiles

namespace webcpp::hash::detail {

// The profile in force: the library's, else webcpp's umbrella, else auto (spec 4.1). On MSVC the
// linker refuses two translation units of one program that choose differently.
#ifdef WEBCPP_HASH_PROFILE_FASTEST
/** The profile in force: fastest. */
using profile = profiles::fastest;
#define WEBCPP_HASH_DETAIL_PROFILE_NAME "fastest"
#elif defined(WEBCPP_HASH_PROFILE_SMALLEST)
/** The profile in force: smallest. */
using profile = profiles::smallest;
#define WEBCPP_HASH_DETAIL_PROFILE_NAME "smallest"
#elif defined(WEBCPP_HASH_PROFILE_PORTABLE)
/** The profile in force: portable. */
using profile = profiles::portable;
#define WEBCPP_HASH_DETAIL_PROFILE_NAME "portable"
#elif defined(WEBCPP_HASH_PROFILE_BACKEND_HASH2)
/** The profile in force: backends::hash2 named. */
using profile = profiles::named<backends::hash2>;
#define WEBCPP_HASH_DETAIL_PROFILE_NAME "hash2"
#elif defined(WEBCPP_HASH_PROFILE_BACKEND_SODIUM)
/** The profile in force: backends::sodium named. */
using profile = profiles::named<backends::sodium>;
#define WEBCPP_HASH_DETAIL_PROFILE_NAME "sodium"
#elif defined(WEBCPP_HASH_PROFILE_BACKEND_BEARSSL)
/** The profile in force: backends::bearssl named. */
using profile = profiles::named<backends::bearssl>;
#define WEBCPP_HASH_DETAIL_PROFILE_NAME "bearssl"
#elif defined(WEBCPP_HASH_PROFILE_BACKEND_OPENSSL)
/** The profile in force: backends::openssl named. */
using profile = profiles::named<backends::openssl>;
#define WEBCPP_HASH_DETAIL_PROFILE_NAME "openssl"
#elif defined(WEBCPP_PROFILE_FASTEST)
/** The profile in force: fastest, by webcpp's umbrella. */
using profile = profiles::fastest;
#define WEBCPP_HASH_DETAIL_PROFILE_NAME "fastest"
#elif defined(WEBCPP_PROFILE_SMALLEST)
/** The profile in force: smallest, by webcpp's umbrella. */
using profile = profiles::smallest;
#define WEBCPP_HASH_DETAIL_PROFILE_NAME "smallest"
#elif defined(WEBCPP_PROFILE_PORTABLE)
/** The profile in force: portable, by webcpp's umbrella. */
using profile = profiles::portable;
#define WEBCPP_HASH_DETAIL_PROFILE_NAME "portable"
#else
/** The profile in force: none defined, auto. */
using profile = profiles::automatic;
#define WEBCPP_HASH_DETAIL_PROFILE_NAME "auto"
#endif

#ifdef _MSC_VER
#pragma detect_mismatch("webcpp_hash_profile", WEBCPP_HASH_DETAIL_PROFILE_NAME)
#endif

}  // namespace webcpp::hash::detail

#include <webcpp/hash/detail/overrides.hpp>

#endif  // WEBCPP_HASH_CONFIG_HPP
