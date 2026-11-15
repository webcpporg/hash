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
// ... and WEBCPP_HASH_PROFILE_BACKEND_<NAME>, WEBCPP_HASH_DEFAULT_BACKEND_<ALGORITHM>_<NAME> and
// webcpp's umbrella WEBCPP_PROFILE_FASTEST, _SMALLEST, _PORTABLE (spec 4.1)
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
// The profile's and the overrides' refusals (spec 4.1): more than one profile, two overrides of
// one algorithm, OpenSSL selected on Emscripten.
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
/** PBKDF2, RFC 8018: `pbkdf2`. */
struct pbkdf2;

}  // namespace webcpp::hash::kdfs

#endif  // WEBCPP_HASH_CONFIG_HPP
