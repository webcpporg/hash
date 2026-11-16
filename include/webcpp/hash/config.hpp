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
// defined: these definitions are the ones the reference lists. Each is undone at once, except the
// libraries' WEBCPP_HASH_HAS_<NAME>, which stay defined: doc/Jamfile links every library, so that
// the reference reads each backend's header, as a program that links them all does.
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
/**
 Defined by `/third_party//blake3` when the program links the BLAKE3 C implementation; a
 program built without b2 defines it to 1 itself.
*/
#define WEBCPP_HASH_HAS_BLAKE3 1
/**
 Defined by `/third_party//sodium` when the program links libsodium; a program built without
 b2 defines it to 1 itself.
*/
#define WEBCPP_HASH_HAS_SODIUM 1
/**
 Defined by `/third_party//bearssl` when the program links BearSSL; a program built without
 b2 defines it to 1 itself.
*/
#define WEBCPP_HASH_HAS_BEARSSL 1
/**
 Defined by `/webcpp/hash//openssl` when the program links OpenSSL; a program built without
 b2 defines it to 1 itself. Refused on Emscripten, where OpenSSL is not built.
*/
#define WEBCPP_HASH_HAS_OPENSSL 1
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

/**
 HKDF, RFC 5869.

 A tag, declared and never defined: it names the algorithm to
 @ref webcpp::hash::backend_has_v and @ref webcpp::hash::default_backend; as an operation it is
 `hkdf`, both steps at once.
*/
struct hkdf;
/**
 HKDF-Extract alone, the operation `hkdf_extract` (RFC 5869, section 2.2).

 A tag, declared and never defined: @ref webcpp::hash::backend_has_v and @ref
 webcpp::hash::default_backend answer for the step through it, so that a backend that has HKDF only
 whole (`backends::bearssl`) says it lacks the step.
*/
struct hkdf_extract;
/**
 HKDF-Expand alone, the operation `hkdf_expand` (RFC 5869, section 2.3).

 A tag, declared and never defined, as @ref hkdf_extract is for the first step.
*/
struct hkdf_expand;
/**
 PBKDF2, RFC 8018, the operation `pbkdf2`.

 A tag, declared and never defined, for @ref webcpp::hash::backend_has_v and
 @ref webcpp::hash::default_backend.
*/
struct pbkdf2;
/**
 Argon2id, RFC 9106, with one lane, the operation `argon2id` (on `backends::sodium` alone).

 A tag, declared and never defined, for @ref webcpp::hash::backend_has_v (over no hmac: `void`)
 and @ref webcpp::hash::default_backend.
*/
struct argon2id;
/**
 scrypt, RFC 7914, the operation `scrypt` (on `backends::sodium` alone).

 A tag, declared and never defined, for @ref webcpp::hash::backend_has_v (over no hmac: `void`)
 and @ref webcpp::hash::default_backend.
*/
struct scrypt;

}  // namespace webcpp::hash::kdfs

#endif  // WEBCPP_HASH_CONFIG_HPP
