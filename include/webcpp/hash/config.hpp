// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The configuration of webcpp::hash, which each of its headers includes first:
 whether it is built without exceptions, whether the target is WebAssembly, the
 C libraries the build links, the backends, and the tags that name each algorithm to the
 families (`digest_of`, `hasher`, `mac`, `argon2`) and to `default_backend`.

 @see "Using webcpp::hash in your Jamfile", in the guide.
*/
#ifndef WEBCPP_HASH_CONFIG_HPP
#define WEBCPP_HASH_CONFIG_HPP

#include <webcpp/config.hpp>

// MrDocs parses hash as a build with exceptions does, where none of these macros is defined: these
// definitions are the ones the reference lists. Each is undone at once but WEBCPP_HASH_HAS_THREADS,
// which stays defined, as a native build has it. The libraries' WEBCPP_HASH_HAS_<NAME> are left as
// the build set them (push_macro and pop_macro keep the definition or its absence): hash's
// doc/Jamfile links every library, so its reference reads each backend's header, while the
// reference of a library that includes hash reads only the backends that library links (trystero's,
// for Emscripten's target, reads BearSSL's alone).
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
#pragma push_macro("WEBCPP_HASH_HAS_XKCP")
#undef WEBCPP_HASH_HAS_XKCP
/**
 Defined by `/third_party//xkcp` when the program links XKCP; a program built without b2
 defines it to 1 itself.
*/
#define WEBCPP_HASH_HAS_XKCP 1
#pragma pop_macro("WEBCPP_HASH_HAS_XKCP")
#pragma push_macro("WEBCPP_HASH_HAS_BLAKE3")
#undef WEBCPP_HASH_HAS_BLAKE3
/**
 Defined by `/third_party//blake3` when the program links the BLAKE3 C implementation; a
 program built without b2 defines it to 1 itself.
*/
#define WEBCPP_HASH_HAS_BLAKE3 1
#pragma pop_macro("WEBCPP_HASH_HAS_BLAKE3")
#pragma push_macro("WEBCPP_HASH_HAS_SODIUM")
#undef WEBCPP_HASH_HAS_SODIUM
/**
 Defined by `/third_party//sodium` when the program links libsodium; a program built without
 b2 defines it to 1 itself.
*/
#define WEBCPP_HASH_HAS_SODIUM 1
#pragma pop_macro("WEBCPP_HASH_HAS_SODIUM")
#pragma push_macro("WEBCPP_HASH_HAS_BEARSSL")
#undef WEBCPP_HASH_HAS_BEARSSL
/**
 Defined by `/third_party//bearssl` when the program links BearSSL; a program built without
 b2 defines it to 1 itself.
*/
#define WEBCPP_HASH_HAS_BEARSSL 1
#pragma pop_macro("WEBCPP_HASH_HAS_BEARSSL")
#pragma push_macro("WEBCPP_HASH_HAS_OPENSSL")
#undef WEBCPP_HASH_HAS_OPENSSL
/**
 Defined by `/webcpp/hash//openssl` when the program links OpenSSL; a program built without
 b2 defines it to 1 itself. Refused on Emscripten, where OpenSSL is not built.
*/
#define WEBCPP_HASH_HAS_OPENSSL 1
#pragma pop_macro("WEBCPP_HASH_HAS_OPENSSL")
#pragma push_macro("WEBCPP_HASH_HAS_BOTAN")
#undef WEBCPP_HASH_HAS_BOTAN
/**
 Defined by `/third_party//botan` when the program links Botan; a program built without b2
 defines it to 1 itself. Botan reports its errors by throwing: in a build without exceptions
 (`WEBCPP_HASH_NO_EXCEPTIONS`) `backends/botan.hpp` declares nothing, and a call on
 `backends::botan` stops at compile time. `/third_party//botan` is built natively and for
 Emscripten.
*/
#define WEBCPP_HASH_HAS_BOTAN 1
#pragma pop_macro("WEBCPP_HASH_HAS_BOTAN")
/**
 Defined where the heavy functions of `<webcpp/hash/async.hpp>` (`async_argon2id`, `async_argon2`,
 `async_scrypt`, `async_pbkdf2` on a synchronous backend) run on another thread: natively, where
 Boost.Config's `BOOST_HAS_THREADS` is defined (every native build, b2's `threading=single`
 included), and on Emscripten built with `-pthread` (b2's `threading=multi`); never on wasip2 or
 wasip3, whose cooperative threads do not run in parallel. Without it each of those names refuses
 at compile time.

 @see "Asynchronous calls", in the guide.
*/
#define WEBCPP_HASH_HAS_THREADS 1
/**
 Defined by the developer to leave `WEBCPP_HASH_HAS_THREADS` undefined in a build that has
 threads: the heavy functions of `<webcpp/hash/async.hpp>` then refuse at compile time, so that no
 call of the program can start a thread's work.
*/
#define WEBCPP_HASH_NO_THREADS
#undef WEBCPP_HASH_NO_THREADS
#endif

#if !defined(WEBCPP_HAS_EXCEPTIONS) && !defined(WEBCPP_HASH_NO_EXCEPTIONS)
#define WEBCPP_HASH_NO_EXCEPTIONS
#endif

#if defined(WEBCPP_TARGET_WASIP2) || defined(WEBCPP_TARGET_WASIP3) || \
    defined(WEBCPP_TARGET_EMSCRIPTEN)
#define WEBCPP_HASH_WEBASSEMBLY 1
#endif

// Threads that run in parallel (spec 11.5, ruling R70): natively Boost.Config's BOOST_HAS_THREADS,
// which <webcpp/config.hpp> has read; on Emscripten -pthread; never WASI, whose wasip3 threads are
// cooperative (BOOST_HAS_THREADS is defined there too, so the target decides first). The
// reference's run defines it above, documented, as a native build has it.
#if !defined(__MRDOCS__) && !defined(WEBCPP_HASH_NO_THREADS) &&       \
    ((defined(WEBCPP_TARGET_NATIVE) && defined(BOOST_HAS_THREADS)) || \
     (defined(WEBCPP_TARGET_EMSCRIPTEN) && defined(__EMSCRIPTEN_PTHREADS__)))
#define WEBCPP_HASH_HAS_THREADS 1
#endif

// The refusals of impossible combinations (spec 5.7). Clang and gcc go on after an #error, so
// the first error is the instruction; MSVC stops at it.
// A reference (MrDocs) describes the headers and builds no program, so none of them refuses it.
// clang-format off
#if !defined(__MRDOCS__) && defined(WEBCPP_TARGET_EMSCRIPTEN) && defined(WEBCPP_HASH_HAS_OPENSSL)
#error "webcpp::hash: OpenSSL is not built for Emscripten. In the program's Jamfile, remove /webcpp/hash//openssl: hkdf and pbkdf2 then run on backends::hash2."
#endif
// clang-format on

// The backends' tags. webcpp::crypto has tags of the same names in webcpp::crypto::backends, and
// a program that uses both libraries (design D1 of crypto) sees both: clang-tidy's
// bugprone-forward-declaration-namespace then takes a tag this translation unit does not use,
// or one whose library is not linked here, for a declaration in the wrong namespace. Each library
// names its own backends on purpose, so the tags crypto shares are exempt: sodium, bearssl,
// openssl, and botan, which crypto's Botan increment declares.
namespace webcpp::hash::backends {

/**
 Boost.Hash2, on every target: webcpp's own HKDF and PBKDF2 over its `hmac<H>`, and the families'
 engines (`digest_of`, `hasher`, `mac`) over its algorithms.
*/
struct hash2;
/** libsodium, built from its sources by `/third_party//sodium`. */
struct sodium;  // NOLINT(bugprone-forward-declaration-namespace)
/** BearSSL, built from its sources by `/third_party//bearssl`. */
struct bearssl;  // NOLINT(bugprone-forward-declaration-namespace)
/** OpenSSL 3.5, built from its pinned sources, named by `/webcpp/hash//openssl`. */
struct openssl;  // NOLINT(bugprone-forward-declaration-namespace)
/**
 Botan 3.14.1, built from its pinned sources by `/third_party//botan`, natively and on Emscripten,
 with exceptions only.
*/
struct botan;  // NOLINT(bugprone-forward-declaration-namespace)
/**
 XKCP, the Keccak team's code, built from its sources by `/third_party//xkcp`: the backend of
 `digests::keccak_256` and of the other Keccak functions: SHA-3, SHAKE, SP 800-185, KangarooTwelve
 and TurboSHAKE.
*/
struct xkcp;
/**
 BLAKE3's official C implementation, built from its sources by `/third_party//blake3`: the backend
 of `digests::blake3`.
*/
// NOLINTNEXTLINE(bugprone-forward-declaration-namespace): digests::blake3 is its namesake tag
struct blake3;
/**
 WebCrypto, the browser's `SubtleCrypto` (Emscripten only), a backend of the asynchronous family.

 Only the functions of `<webcpp/hash/async.hpp>` take it, named in the type, never as a default. A
 synchronous function that names it refuses at compile time, on every target; an asynchronous one
 refuses off Emscripten.
*/
struct webcrypto;

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
 Argon2id, RFC 9106, with one lane, the operation `argon2id` (on `backends::sodium` and
 `backends::openssl`).

 A tag, declared and never defined, for @ref webcpp::hash::backend_has_v (over no hmac: `void`)
 and @ref webcpp::hash::default_backend.
*/
struct argon2id;
/**
 scrypt, RFC 7914, the operation `scrypt` (on `backends::sodium` and `backends::openssl`).

 A tag, declared and never defined, for @ref webcpp::hash::backend_has_v (over no hmac: `void`)
 and @ref webcpp::hash::default_backend.
*/
struct scrypt;
/**
 Argon2d, RFC 9106, for `argon2`: data-dependent memory access, never for passwords an attacker can
 time.

 A tag, declared and never defined.
*/
struct argon2d;
/**
 Argon2i, RFC 9106, for `argon2`: data-independent memory access.

 A tag, declared and never defined.
*/
struct argon2i;
/**
 bcrypt, the password hash of OpenBSD (Provos and Mazieres, 1999).

 A tag, declared and never defined.
*/
struct bcrypt;
/**
 bcrypt-pbkdf, OpenBSD's key derivation over bcrypt, as OpenSSH's keys use it.

 A tag, declared and never defined.
*/
struct bcrypt_pbkdf;
/**
 BLAKE2b subkeys from a master key, as libsodium's `crypto_kdf` derives them, the operation
 `blake2b_subkey` (on `backends::sodium` alone).

 A tag, declared and never defined, for @ref webcpp::hash::backend_has_v (over no hmac: `void`)
 and @ref webcpp::hash::default_backend.
*/
struct blake2b_subkey;
/**
 KBKDF over HMAC, NIST SP 800-108.

 A tag, declared and never defined.
*/
struct kbkdf_hmac;
/**
 The single-step KDF of NIST SP 800-56C.

 A tag, declared and never defined.
*/
struct sskdf;
/**
 The KDF of ANSI X9.63.

 A tag, declared and never defined.
*/
struct x963kdf;

}  // namespace webcpp::hash::kdfs

// The families' tags (spec 2.15): each names an algorithm to `digest_of`, `hasher`, `mac`, `argon2`
// and `default_backend`. Every tag is declared here, whichever backends serve it: a call on a
// backend that lacks it refuses at compile time, naming the backends that have it.
namespace webcpp::hash::digests {

// The tags are declared and never defined, and share their names with the Hash2-form types
// (webcpp::hash::keccak_256, boost::hash2::keccak_256, ...) and with backends::blake3 on purpose:
// clang-tidy's forward-declaration check would report each.
// NOLINTBEGIN(bugprone-forward-declaration-namespace)

/**
 MD5, RFC 1321, a 16-byte digest.

 Broken: for compatibility only. A tag, declared and never defined.
*/
struct md5;
/**
 SHA-1, FIPS 180-4, a 20-byte digest.

 Broken: for compatibility only. A tag, declared and never defined.
*/
struct sha1;
/**
 SHA-224, FIPS 180-4, a 28-byte digest.

 A tag, declared and never defined.
*/
struct sha2_224;
/**
 SHA-256, FIPS 180-4, a 32-byte digest.

 A tag, declared and never defined.
*/
struct sha2_256;
/**
 SHA-384, FIPS 180-4, a 48-byte digest.

 A tag, declared and never defined.
*/
struct sha2_384;
/**
 SHA-512, FIPS 180-4, a 64-byte digest.

 A tag, declared and never defined.
*/
struct sha2_512;
/**
 SHA-512/224, FIPS 180-4, a 28-byte digest.

 A tag, declared and never defined.
*/
struct sha2_512_224;
/**
 SHA-512/256, FIPS 180-4, a 32-byte digest.

 A tag, declared and never defined.
*/
struct sha2_512_256;
/**
 SHA3-224, FIPS 202, a 28-byte digest.

 A tag, declared and never defined.
*/
struct sha3_224;
/**
 SHA3-256, FIPS 202, a 32-byte digest.

 A tag, declared and never defined.
*/
struct sha3_256;
/**
 SHA3-384, FIPS 202, a 48-byte digest.

 A tag, declared and never defined.
*/
struct sha3_384;
/**
 SHA3-512, FIPS 202, a 64-byte digest.

 A tag, declared and never defined.
*/
struct sha3_512;
/**
 SHAKE128, FIPS 202, an extendable-output function: any output size from 1 byte.

 A tag, declared and never defined.
*/
struct shake_128;
/**
 SHAKE256, FIPS 202, an extendable-output function: any output size from 1 byte.

 A tag, declared and never defined.
*/
struct shake_256;
/**
 Keccak-224 with the original padding (the SHA-3 submission), a 28-byte digest.

 A tag, declared and never defined.
*/
struct keccak_224;
/**
 Keccak-256 with the original padding, Ethereum's hash, a 32-byte digest.

 A tag, declared and never defined.
*/
struct keccak_256;
/**
 Keccak-384 with the original padding, a 48-byte digest.

 A tag, declared and never defined.
*/
struct keccak_384;
/**
 Keccak-512 with the original padding, a 64-byte digest.

 A tag, declared and never defined.
*/
struct keccak_512;
/**
 cSHAKE128, NIST SP 800-185, SHAKE128 with a function name and a customisation: any output size from
 1 byte.

 A tag, declared and never defined.
*/
struct cshake_128;
/**
 cSHAKE256, NIST SP 800-185: any output size from 1 byte.

 A tag, declared and never defined.
*/
struct cshake_256;
/**
 KT128 (KangarooTwelve), RFC 9861, with a customisation: any output size from 1 byte.

 A tag, declared and never defined.
*/
struct kt128;
/**
 KT256, RFC 9861, with a customisation: any output size from 1 byte.

 A tag, declared and never defined.
*/
struct kt256;
/**
 TurboSHAKE128, RFC 9861, with a domain byte: any output size from 1 byte.

 A tag, declared and never defined.
*/
struct turboshake_128;
/**
 TurboSHAKE256, RFC 9861, with a domain byte: any output size from 1 byte.

 A tag, declared and never defined.
*/
struct turboshake_256;
/**
 TupleHash128, NIST SP 800-185: any output size from 1 byte.

 A tag, declared and never defined.
*/
struct tuplehash_128;
/**
 TupleHash256, NIST SP 800-185: any output size from 1 byte.

 A tag, declared and never defined.
*/
struct tuplehash_256;
/**
 ParallelHash128, NIST SP 800-185: any output size from 1 byte.

 A tag, declared and never defined.
*/
struct parallelhash_128;
/**
 ParallelHash256, NIST SP 800-185: any output size from 1 byte.

 A tag, declared and never defined.
*/
struct parallelhash_256;
/**
 BLAKE2b, RFC 7693, with its key, salt, personalisation and output size (1 to 64 bytes).

 A tag, declared and never defined.
*/
struct blake2b;
/**
 BLAKE2s with a 32-byte digest, RFC 7693.

 A tag, declared and never defined.
*/
struct blake2s_256;
/**
 BLAKE3, an extendable-output function: any output size from 1 byte (32 is its digest).

 A tag, declared and never defined.
*/
struct blake3;
/**
 RIPEMD-160, ISO/IEC 10118-3, a 20-byte digest.

 Legacy. A tag, declared and never defined.
*/
struct ripemd_160;
/**
 MD5 then SHA-1 of the same input, 36 bytes: TLS 1.0 and 1.1's hash.

 Broken: for compatibility only. A tag, declared and never defined.
*/
struct md5_sha1;
/**
 SM3, GB/T 32905-2016, a 32-byte digest.

 A tag, declared and never defined.
*/
struct sm3;
/**
 Streebog-256, GOST R 34.11-2012, a 32-byte digest.

 A tag, declared and never defined.
*/
struct streebog_256;
/**
 Streebog-512, GOST R 34.11-2012, a 64-byte digest.

 A tag, declared and never defined.
*/
struct streebog_512;
/**
 Whirlpool, ISO/IEC 10118-3, a 64-byte digest.

 A tag, declared and never defined.
*/
struct whirlpool;
/**
 Skein-512 with a 64-byte digest.

 A tag, declared and never defined.
*/
struct skein_512;

// NOLINTEND(bugprone-forward-declaration-namespace)

}  // namespace webcpp::hash::digests

namespace webcpp::hash::macs {

/**
 HMAC, RFC 2104, over the digest `Digest`: a tag, declared and never defined.

 @tparam Digest A tag of `digests` whose output has a fixed size, as `digests::sha2_256`.
*/
template <class Digest>
struct hmac;
/**
 KMAC128, NIST SP 800-185, with its customisation: a tag of 4 bytes or more (SP 800-185,
 section 8.4.2).

 A tag, declared and never defined.
*/
struct kmac_128;
/**
 KMAC256, NIST SP 800-185, with its customisation: a tag of 4 bytes or more (SP 800-185,
 section 8.4.2).

 A tag, declared and never defined.
*/
struct kmac_256;
/**
 SipHash-2-4, a 16-byte key and an 8-byte tag: for hash tables against flooding.

 A tag, declared and never defined.
*/
struct siphash_2_4;
/**
 SipHash-2-4 with a 16-byte tag (libsodium's `siphashx24`), a 16-byte key.

 A tag, declared and never defined.
*/
struct siphash_2_4x;
/**
 BLAKE2b keyed, RFC 7693: a key of 1 to 64 bytes, a tag of 1 to 64 bytes.

 A tag, declared and never defined.
*/
struct blake2b_mac;
/**
 BLAKE2s keyed, RFC 7693: a key of 1 to 32 bytes, a tag of 1 to 32 bytes.

 A tag, declared and never defined.
*/
struct blake2s_mac;

}  // namespace webcpp::hash::macs

#endif  // WEBCPP_HASH_CONFIG_HPP
