// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 What the key derivations and the families share: which backend has which key derivation over
 which hmac, and which digest, MAC and Argon2 variant (the capability table, spec 3.5), and the
 backend a call uses when it names none (spec 4.1).

 @see "Key derivation", in the guide.
*/
#ifndef WEBCPP_HASH_KDF_HPP
#define WEBCPP_HASH_KDF_HPP

#include <webcpp/hash/config.hpp>

#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/hmac.hpp>

#include <type_traits>

namespace webcpp::hash {

/**
 Whether `Backend` has the key derivation `Kdf` over `Hmac`, or the algorithm of a family's tag: a
 property of the library behind it (spec sections 3.2 and 3.5), whether or not the program links
 it. A backend that has a tag only in part (a partial cell of `doc/capabilities.json`, as
 `backends::hash2`'s SHAKE, at most one digest's size) has it.

 @tparam Backend A backend of `backends`. @tparam Kdf `kdfs::hkdf`, `kdfs::pbkdf2` or another
 tag of `kdfs`; or a tag of `digests` or `macs`; or, for `argon2`, `kdfs::argon2d`,
 `kdfs::argon2i` or `kdfs::argon2id`.
 @tparam Hmac A Boost.Hash2 hmac for a key derivation over one (`kdfs::kbkdf_hmac` included);
 `void` for a function over none, `sskdf` and `x963kdf` (over a digest) among them, and for a
 family's tag; `argon2_parameters` for the family `argon2`, whose tags `kdfs::argon2id` also names
 the function `argon2id`.
*/
template <class Backend, class Kdf, class Hmac>
inline constexpr bool backend_has_v = false;

namespace detail {

/** Whether `Hmac` is one of `Hmacs`. */
template <class Hmac, class... Hmacs>
inline constexpr bool one_of_v = (std::is_same_v<Hmac, Hmacs> || ...);

/** The hmacs over which BearSSL has `hkdf`: MD5, SHA-1 and SHA-2 but the truncated SHA-512s. */
template <class Hmac>
inline constexpr bool bearssl_hmac_v = one_of_v<Hmac, hmac_md5_128, hmac_sha1_160, hmac_sha2_224,
                                                hmac_sha2_256, hmac_sha2_384, hmac_sha2_512>;

/** The hmacs OpenSSL 3.5 names a digest for: every alias of `hmac.hpp` but RIPEMD-128. */
template <class Hmac>
inline constexpr bool openssl_hmac_v =
    one_of_v<Hmac, hmac_md5_128, hmac_sha1_160, hmac_sha2_224, hmac_sha2_256, hmac_sha2_384,
             hmac_sha2_512, hmac_sha2_512_224, hmac_sha2_512_256, hmac_sha3_224, hmac_sha3_256,
             hmac_sha3_384, hmac_sha3_512, hmac_ripemd_160, hmac_blake2b_512, hmac_blake2s_256>;

}  // namespace detail

/** backends::hash2 has HKDF over every Boost.Hash2 hmac whose result is a digest. */
template <class Hmac>
inline constexpr bool backend_has_v<backends::hash2, kdfs::hkdf, Hmac> =
    detail::is_digest_hmac<Hmac>::value;

/** backends::hash2 has PBKDF2 over every Boost.Hash2 hmac whose result is a digest. */
template <class Hmac>
inline constexpr bool backend_has_v<backends::hash2, kdfs::pbkdf2, Hmac> =
    detail::is_digest_hmac<Hmac>::value;

/** backends::sodium has HKDF over HMAC-SHA-256 (`crypto_kdf_hkdf_sha256_*`). */
template <>
inline constexpr bool backend_has_v<backends::sodium, kdfs::hkdf, hmac_sha2_256> = true;

/** backends::sodium has HKDF over HMAC-SHA-512 (`crypto_kdf_hkdf_sha512_*`). */
template <>
inline constexpr bool backend_has_v<backends::sodium, kdfs::hkdf, hmac_sha2_512> = true;

/** backends::bearssl has `hkdf` (not its two steps alone) over MD5, SHA-1 and four SHA-2s. */
template <class Hmac>
inline constexpr bool backend_has_v<backends::bearssl, kdfs::hkdf, Hmac> =
    detail::bearssl_hmac_v<Hmac>;

/** backends::openssl has HKDF over every alias of `hmac.hpp` but `hmac_ripemd_128`. */
template <class Hmac>
inline constexpr bool backend_has_v<backends::openssl, kdfs::hkdf, Hmac> =
    detail::openssl_hmac_v<Hmac>;

/** backends::openssl has PBKDF2 over every alias of `hmac.hpp` but `hmac_ripemd_128`. */
template <class Hmac>
inline constexpr bool backend_has_v<backends::openssl, kdfs::pbkdf2, Hmac> =
    detail::openssl_hmac_v<Hmac>;

/**
 HKDF-Extract alone: every backend that has HKDF over `Hmac` but backends::bearssl, whose
 `br_hkdf_*` keeps the pseudorandom key inside its context (spec 3.2).
*/
template <class Backend, class Hmac>
inline constexpr bool backend_has_v<Backend, kdfs::hkdf_extract, Hmac> =
    backend_has_v<Backend, kdfs::hkdf, Hmac> && !std::is_same_v<Backend, backends::bearssl>;

/** HKDF-Expand alone: as HKDF-Extract, every backend with HKDF but backends::bearssl. */
template <class Backend, class Hmac>
inline constexpr bool backend_has_v<Backend, kdfs::hkdf_expand, Hmac> =
    backend_has_v<Backend, kdfs::hkdf, Hmac> && !std::is_same_v<Backend, backends::bearssl>;

/** backends::sodium has Argon2id (`crypto_pwhash_argon2id`), which takes no hmac. */
template <>
inline constexpr bool backend_has_v<backends::sodium, kdfs::argon2id, void> = true;

/** backends::sodium has scrypt (`crypto_pwhash_scryptsalsa208sha256_ll`), which takes no hmac. */
template <>
inline constexpr bool backend_has_v<backends::sodium, kdfs::scrypt, void> = true;

/** backends::openssl has the function argon2id (OpenSSL 3.5.9's `EVP_KDF` "ARGON2ID"). */
template <>
inline constexpr bool backend_has_v<backends::openssl, kdfs::argon2id, void> = true;

/** backends::openssl has scrypt (OpenSSL 3.5.9's `EVP_KDF` "SCRYPT"). */
template <>
inline constexpr bool backend_has_v<backends::openssl, kdfs::scrypt, void> = true;

/**
 backends::openssl has SP 800-108's KBKDF in counter mode (OpenSSL 3.5.9's `EVP_KDF` "KBKDF") over
 every alias of `hmac.hpp` but `hmac_ripemd_128`.
*/
template <class Hmac>
inline constexpr bool backend_has_v<backends::openssl, kdfs::kbkdf_hmac, Hmac> =
    detail::openssl_hmac_v<Hmac>;

/**
 backends::openssl has SP 800-56C's one-step KDF over a digest (OpenSSL 3.5.9's `EVP_KDF` "SSKDF"),
 the function `sskdf`, which takes a digest, not an hmac.
*/
template <>
inline constexpr bool backend_has_v<backends::openssl, kdfs::sskdf, void> = true;

/**
 backends::openssl has ANSI X9.63's KDF (OpenSSL 3.5.9's `EVP_KDF` "X963KDF"), the function
 `x963kdf`, which takes a digest, not an hmac.
*/
template <>
inline constexpr bool backend_has_v<backends::openssl, kdfs::x963kdf, void> = true;

/** backends::openssl has Argon2d with every parameter (OpenSSL 3.5.9's `EVP_KDF` "ARGON2D"). */
template <>
inline constexpr bool backend_has_v<backends::openssl, kdfs::argon2d, argon2_parameters> = true;

/** backends::openssl has Argon2i with every parameter (OpenSSL 3.5.9's `EVP_KDF` "ARGON2I"). */
template <>
inline constexpr bool backend_has_v<backends::openssl, kdfs::argon2i, argon2_parameters> = true;

/** backends::openssl has Argon2id with every parameter (OpenSSL 3.5.9's `EVP_KDF` "ARGON2ID"). */
template <>
inline constexpr bool backend_has_v<backends::openssl, kdfs::argon2id, argon2_parameters> = true;

/**
 backends::sodium has BLAKE2b subkeys (`crypto_kdf_blake2b_derive_from_key`), the function
 `blake2b_subkey`, which takes no hmac.
*/
template <>
inline constexpr bool backend_has_v<backends::sodium, kdfs::blake2b_subkey, void> = true;

/** backends::hash2 has `digests::md5` (Boost.Hash2's type). */
template <>
inline constexpr bool backend_has_v<backends::hash2, digests::md5, void> = true;

/** backends::hash2 has `digests::sha1` (Boost.Hash2's type). */
template <>
inline constexpr bool backend_has_v<backends::hash2, digests::sha1, void> = true;

/** backends::hash2 has `digests::sha2_224` (Boost.Hash2's type). */
template <>
inline constexpr bool backend_has_v<backends::hash2, digests::sha2_224, void> = true;

/** backends::hash2 has `digests::sha2_256` (Boost.Hash2's type). */
template <>
inline constexpr bool backend_has_v<backends::hash2, digests::sha2_256, void> = true;

/** backends::hash2 has `digests::sha2_384` (Boost.Hash2's type). */
template <>
inline constexpr bool backend_has_v<backends::hash2, digests::sha2_384, void> = true;

/** backends::hash2 has `digests::sha2_512` (Boost.Hash2's type). */
template <>
inline constexpr bool backend_has_v<backends::hash2, digests::sha2_512, void> = true;

/** backends::hash2 has `digests::sha2_512_224` (Boost.Hash2's type). */
template <>
inline constexpr bool backend_has_v<backends::hash2, digests::sha2_512_224, void> = true;

/** backends::hash2 has `digests::sha2_512_256` (Boost.Hash2's type). */
template <>
inline constexpr bool backend_has_v<backends::hash2, digests::sha2_512_256, void> = true;

/** backends::hash2 has `digests::sha3_224` (Boost.Hash2's type). */
template <>
inline constexpr bool backend_has_v<backends::hash2, digests::sha3_224, void> = true;

/** backends::hash2 has `digests::sha3_256` (Boost.Hash2's type). */
template <>
inline constexpr bool backend_has_v<backends::hash2, digests::sha3_256, void> = true;

/** backends::hash2 has `digests::sha3_384` (Boost.Hash2's type). */
template <>
inline constexpr bool backend_has_v<backends::hash2, digests::sha3_384, void> = true;

/** backends::hash2 has `digests::sha3_512` (Boost.Hash2's type). */
template <>
inline constexpr bool backend_has_v<backends::hash2, digests::sha3_512, void> = true;

/** backends::hash2 has `digests::ripemd_160` (Boost.Hash2's type). */
template <>
inline constexpr bool backend_has_v<backends::hash2, digests::ripemd_160, void> = true;

/** backends::hash2 has `digests::blake2s_256` (Boost.Hash2's type). */
template <>
inline constexpr bool backend_has_v<backends::hash2, digests::blake2s_256, void> = true;

/**
 backends::hash2 has `digests::shake_128` in part: at most 32 bytes, one Hash2 result (ruling R14).
*/
template <>
inline constexpr bool backend_has_v<backends::hash2, digests::shake_128, void> = true;

/**
 backends::hash2 has `digests::shake_256` in part: at most 64 bytes, one Hash2 result (ruling R14).
*/
template <>
inline constexpr bool backend_has_v<backends::hash2, digests::shake_256, void> = true;

/**
 backends::hash2 has `digests::blake2b` in part: a 64-byte output with no options, Boost.Hash2's
 `blake2b_512` (ruling R82).
*/
template <>
inline constexpr bool backend_has_v<backends::hash2, digests::blake2b, void> = true;

/** backends::xkcp has `digests::keccak_256` (webcpp's `keccak_256` over XKCP). */
template <>
inline constexpr bool backend_has_v<backends::xkcp, digests::keccak_256, void> = true;

/** backends::blake3 has `digests::blake3` (BLAKE3's C implementation), with its extendable output.
 */
template <>
inline constexpr bool backend_has_v<backends::blake3, digests::blake3, void> = true;

/**
 backends::sodium has `digests::blake2b` (`crypto_generichash_blake2b_*`), with its key, salt,
 personalisation and every output size.
*/
template <>
inline constexpr bool backend_has_v<backends::sodium, digests::blake2b, void> = true;

/** backends::openssl has `digests::md5` (OpenSSL 3.5.9's `EVP_MD`). */
template <>
inline constexpr bool backend_has_v<backends::openssl, digests::md5, void> = true;

/** backends::openssl has `digests::sha1` (OpenSSL 3.5.9's `EVP_MD`). */
template <>
inline constexpr bool backend_has_v<backends::openssl, digests::sha1, void> = true;

/** backends::openssl has `digests::sha2_224` (OpenSSL 3.5.9's `EVP_MD`). */
template <>
inline constexpr bool backend_has_v<backends::openssl, digests::sha2_224, void> = true;

/** backends::openssl has `digests::sha2_256` (OpenSSL 3.5.9's `EVP_MD`). */
template <>
inline constexpr bool backend_has_v<backends::openssl, digests::sha2_256, void> = true;

/** backends::openssl has `digests::sha2_384` (OpenSSL 3.5.9's `EVP_MD`). */
template <>
inline constexpr bool backend_has_v<backends::openssl, digests::sha2_384, void> = true;

/** backends::openssl has `digests::sha2_512` (OpenSSL 3.5.9's `EVP_MD`). */
template <>
inline constexpr bool backend_has_v<backends::openssl, digests::sha2_512, void> = true;

/** backends::openssl has `digests::sha2_512_224` (OpenSSL 3.5.9's `EVP_MD`). */
template <>
inline constexpr bool backend_has_v<backends::openssl, digests::sha2_512_224, void> = true;

/** backends::openssl has `digests::sha2_512_256` (OpenSSL 3.5.9's `EVP_MD`). */
template <>
inline constexpr bool backend_has_v<backends::openssl, digests::sha2_512_256, void> = true;

/** backends::openssl has `digests::sha3_224` (OpenSSL 3.5.9's `EVP_MD`). */
template <>
inline constexpr bool backend_has_v<backends::openssl, digests::sha3_224, void> = true;

/** backends::openssl has `digests::sha3_256` (OpenSSL 3.5.9's `EVP_MD`). */
template <>
inline constexpr bool backend_has_v<backends::openssl, digests::sha3_256, void> = true;

/** backends::openssl has `digests::sha3_384` (OpenSSL 3.5.9's `EVP_MD`). */
template <>
inline constexpr bool backend_has_v<backends::openssl, digests::sha3_384, void> = true;

/** backends::openssl has `digests::sha3_512` (OpenSSL 3.5.9's `EVP_MD`). */
template <>
inline constexpr bool backend_has_v<backends::openssl, digests::sha3_512, void> = true;

/**
 backends::openssl has `digests::shake_128` (OpenSSL 3.5.9's `EVP_MD`, `EVP_DigestFinalXOF`), with
 any output size.
*/
template <>
inline constexpr bool backend_has_v<backends::openssl, digests::shake_128, void> = true;

/**
 backends::openssl has `digests::shake_256` (OpenSSL 3.5.9's `EVP_MD`, `EVP_DigestFinalXOF`), with
 any output size.
*/
template <>
inline constexpr bool backend_has_v<backends::openssl, digests::shake_256, void> = true;

/** backends::openssl has `digests::keccak_224` (OpenSSL 3.5.9's `EVP_MD`). */
template <>
inline constexpr bool backend_has_v<backends::openssl, digests::keccak_224, void> = true;

/** backends::openssl has `digests::keccak_256` (OpenSSL 3.5.9's `EVP_MD`). */
template <>
inline constexpr bool backend_has_v<backends::openssl, digests::keccak_256, void> = true;

/** backends::openssl has `digests::keccak_384` (OpenSSL 3.5.9's `EVP_MD`). */
template <>
inline constexpr bool backend_has_v<backends::openssl, digests::keccak_384, void> = true;

/** backends::openssl has `digests::keccak_512` (OpenSSL 3.5.9's `EVP_MD`). */
template <>
inline constexpr bool backend_has_v<backends::openssl, digests::keccak_512, void> = true;

/** backends::openssl has `digests::blake2s_256` (OpenSSL 3.5.9's `EVP_MD`). */
template <>
inline constexpr bool backend_has_v<backends::openssl, digests::blake2s_256, void> = true;

/** backends::openssl has `digests::ripemd_160` (OpenSSL 3.5.9's `EVP_MD`). */
template <>
inline constexpr bool backend_has_v<backends::openssl, digests::ripemd_160, void> = true;

/** backends::openssl has `digests::md5_sha1` (OpenSSL 3.5.9's `EVP_MD`). */
template <>
inline constexpr bool backend_has_v<backends::openssl, digests::md5_sha1, void> = true;

/** backends::openssl has `digests::sm3` (OpenSSL 3.5.9's `EVP_MD`). */
template <>
inline constexpr bool backend_has_v<backends::openssl, digests::sm3, void> = true;

/** backends::openssl has `macs::hmac<digests::md5>` (OpenSSL 3.5.9's `EVP_MAC` "HMAC"). */
template <>
inline constexpr bool backend_has_v<backends::openssl, macs::hmac<digests::md5>, void> = true;

/** backends::openssl has `macs::hmac<digests::sha1>` (OpenSSL 3.5.9's `EVP_MAC` "HMAC"). */
template <>
inline constexpr bool backend_has_v<backends::openssl, macs::hmac<digests::sha1>, void> = true;

/** backends::openssl has `macs::hmac<digests::sha2_224>` (OpenSSL 3.5.9's `EVP_MAC` "HMAC"). */
template <>
inline constexpr bool backend_has_v<backends::openssl, macs::hmac<digests::sha2_224>, void> = true;

/** backends::openssl has `macs::hmac<digests::sha2_256>` (OpenSSL 3.5.9's `EVP_MAC` "HMAC"). */
template <>
inline constexpr bool backend_has_v<backends::openssl, macs::hmac<digests::sha2_256>, void> = true;

/** backends::openssl has `macs::hmac<digests::sha2_384>` (OpenSSL 3.5.9's `EVP_MAC` "HMAC"). */
template <>
inline constexpr bool backend_has_v<backends::openssl, macs::hmac<digests::sha2_384>, void> = true;

/** backends::openssl has `macs::hmac<digests::sha2_512>` (OpenSSL 3.5.9's `EVP_MAC` "HMAC"). */
template <>
inline constexpr bool backend_has_v<backends::openssl, macs::hmac<digests::sha2_512>, void> = true;

/** backends::openssl has `macs::hmac<digests::sha2_512_224>` (OpenSSL 3.5.9's `EVP_MAC` "HMAC"). */
template <>
inline constexpr bool backend_has_v<backends::openssl, macs::hmac<digests::sha2_512_224>, void> =
    true;

/** backends::openssl has `macs::hmac<digests::sha2_512_256>` (OpenSSL 3.5.9's `EVP_MAC` "HMAC"). */
template <>
inline constexpr bool backend_has_v<backends::openssl, macs::hmac<digests::sha2_512_256>, void> =
    true;

/** backends::openssl has `macs::hmac<digests::sha3_224>` (OpenSSL 3.5.9's `EVP_MAC` "HMAC"). */
template <>
inline constexpr bool backend_has_v<backends::openssl, macs::hmac<digests::sha3_224>, void> = true;

/** backends::openssl has `macs::hmac<digests::sha3_256>` (OpenSSL 3.5.9's `EVP_MAC` "HMAC"). */
template <>
inline constexpr bool backend_has_v<backends::openssl, macs::hmac<digests::sha3_256>, void> = true;

/** backends::openssl has `macs::hmac<digests::sha3_384>` (OpenSSL 3.5.9's `EVP_MAC` "HMAC"). */
template <>
inline constexpr bool backend_has_v<backends::openssl, macs::hmac<digests::sha3_384>, void> = true;

/** backends::openssl has `macs::hmac<digests::sha3_512>` (OpenSSL 3.5.9's `EVP_MAC` "HMAC"). */
template <>
inline constexpr bool backend_has_v<backends::openssl, macs::hmac<digests::sha3_512>, void> = true;

/** backends::openssl has `macs::hmac<digests::keccak_224>` (OpenSSL 3.5.9's `EVP_MAC` "HMAC"). */
template <>
inline constexpr bool backend_has_v<backends::openssl, macs::hmac<digests::keccak_224>, void> =
    true;

/** backends::openssl has `macs::hmac<digests::keccak_256>` (OpenSSL 3.5.9's `EVP_MAC` "HMAC"). */
template <>
inline constexpr bool backend_has_v<backends::openssl, macs::hmac<digests::keccak_256>, void> =
    true;

/** backends::openssl has `macs::hmac<digests::keccak_384>` (OpenSSL 3.5.9's `EVP_MAC` "HMAC"). */
template <>
inline constexpr bool backend_has_v<backends::openssl, macs::hmac<digests::keccak_384>, void> =
    true;

/** backends::openssl has `macs::hmac<digests::keccak_512>` (OpenSSL 3.5.9's `EVP_MAC` "HMAC"). */
template <>
inline constexpr bool backend_has_v<backends::openssl, macs::hmac<digests::keccak_512>, void> =
    true;

/** backends::openssl has `macs::hmac<digests::ripemd_160>` (OpenSSL 3.5.9's `EVP_MAC` "HMAC"). */
template <>
inline constexpr bool backend_has_v<backends::openssl, macs::hmac<digests::ripemd_160>, void> =
    true;

/** backends::openssl has `macs::hmac<digests::blake2b>` (OpenSSL 3.5.9's `EVP_MAC` "HMAC"). */
template <>
inline constexpr bool backend_has_v<backends::openssl, macs::hmac<digests::blake2b>, void> = true;

/** backends::openssl has `macs::hmac<digests::blake2s_256>` (OpenSSL 3.5.9's `EVP_MAC` "HMAC"). */
template <>
inline constexpr bool backend_has_v<backends::openssl, macs::hmac<digests::blake2s_256>, void> =
    true;

/** backends::openssl has `macs::hmac<digests::sm3>` (OpenSSL 3.5.9's `EVP_MAC` "HMAC"). */
template <>
inline constexpr bool backend_has_v<backends::openssl, macs::hmac<digests::sm3>, void> = true;

/** backends::openssl has `macs::kmac_128` (OpenSSL 3.5.9's `EVP_MAC` "KMAC-128"). */
template <>
inline constexpr bool backend_has_v<backends::openssl, macs::kmac_128, void> = true;

/** backends::openssl has `macs::kmac_256` (OpenSSL 3.5.9's `EVP_MAC` "KMAC-256"). */
template <>
inline constexpr bool backend_has_v<backends::openssl, macs::kmac_256, void> = true;

/** backends::openssl has `macs::siphash_2_4` (OpenSSL 3.5.9's `EVP_MAC` "SIPHASH"). */
template <>
inline constexpr bool backend_has_v<backends::openssl, macs::siphash_2_4, void> = true;

/** backends::openssl has `macs::siphash_2_4x` (OpenSSL 3.5.9's `EVP_MAC` "SIPHASH"). */
template <>
inline constexpr bool backend_has_v<backends::openssl, macs::siphash_2_4x, void> = true;

/** backends::openssl has `macs::blake2b_mac` (OpenSSL 3.5.9's `EVP_MAC` "BLAKE2BMAC"). */
template <>
inline constexpr bool backend_has_v<backends::openssl, macs::blake2b_mac, void> = true;

/** backends::openssl has `macs::blake2s_mac` (OpenSSL 3.5.9's `EVP_MAC` "BLAKE2SMAC"). */
template <>
inline constexpr bool backend_has_v<backends::openssl, macs::blake2s_mac, void> = true;

/**
 backends::openssl has `digests::blake2b` in part: unkeyed, every output size from 1 to 64 bytes
 (OpenSSL's "BLAKE2B-512" with its "size"); no key, salt or personalisation.
*/
template <>
inline constexpr bool backend_has_v<backends::openssl, digests::blake2b, void> = true;

/** backends::hash2 has `macs::hmac<digests::md5>` (Boost.Hash2's `hmac<H>`). */
template <>
inline constexpr bool backend_has_v<backends::hash2, macs::hmac<digests::md5>, void> = true;

/** backends::hash2 has `macs::hmac<digests::sha1>` (Boost.Hash2's `hmac<H>`). */
template <>
inline constexpr bool backend_has_v<backends::hash2, macs::hmac<digests::sha1>, void> = true;

/** backends::hash2 has `macs::hmac<digests::sha2_224>` (Boost.Hash2's `hmac<H>`). */
template <>
inline constexpr bool backend_has_v<backends::hash2, macs::hmac<digests::sha2_224>, void> = true;

/** backends::hash2 has `macs::hmac<digests::sha2_256>` (Boost.Hash2's `hmac<H>`). */
template <>
inline constexpr bool backend_has_v<backends::hash2, macs::hmac<digests::sha2_256>, void> = true;

/** backends::hash2 has `macs::hmac<digests::sha2_384>` (Boost.Hash2's `hmac<H>`). */
template <>
inline constexpr bool backend_has_v<backends::hash2, macs::hmac<digests::sha2_384>, void> = true;

/** backends::hash2 has `macs::hmac<digests::sha2_512>` (Boost.Hash2's `hmac<H>`). */
template <>
inline constexpr bool backend_has_v<backends::hash2, macs::hmac<digests::sha2_512>, void> = true;

/** backends::hash2 has `macs::hmac<digests::sha2_512_224>` (Boost.Hash2's `hmac<H>`). */
template <>
inline constexpr bool backend_has_v<backends::hash2, macs::hmac<digests::sha2_512_224>, void> =
    true;

/** backends::hash2 has `macs::hmac<digests::sha2_512_256>` (Boost.Hash2's `hmac<H>`). */
template <>
inline constexpr bool backend_has_v<backends::hash2, macs::hmac<digests::sha2_512_256>, void> =
    true;

/** backends::hash2 has `macs::hmac<digests::sha3_224>` (Boost.Hash2's `hmac<H>`). */
template <>
inline constexpr bool backend_has_v<backends::hash2, macs::hmac<digests::sha3_224>, void> = true;

/** backends::hash2 has `macs::hmac<digests::sha3_256>` (Boost.Hash2's `hmac<H>`). */
template <>
inline constexpr bool backend_has_v<backends::hash2, macs::hmac<digests::sha3_256>, void> = true;

/** backends::hash2 has `macs::hmac<digests::sha3_384>` (Boost.Hash2's `hmac<H>`). */
template <>
inline constexpr bool backend_has_v<backends::hash2, macs::hmac<digests::sha3_384>, void> = true;

/** backends::hash2 has `macs::hmac<digests::sha3_512>` (Boost.Hash2's `hmac<H>`). */
template <>
inline constexpr bool backend_has_v<backends::hash2, macs::hmac<digests::sha3_512>, void> = true;

/** backends::hash2 has `macs::hmac<digests::ripemd_160>` (Boost.Hash2's `hmac<H>`). */
template <>
inline constexpr bool backend_has_v<backends::hash2, macs::hmac<digests::ripemd_160>, void> = true;

/** backends::hash2 has `macs::hmac<digests::blake2b>` (Boost.Hash2's `hmac<H>`). */
template <>
inline constexpr bool backend_has_v<backends::hash2, macs::hmac<digests::blake2b>, void> = true;

/** backends::hash2 has `macs::hmac<digests::blake2s_256>` (Boost.Hash2's `hmac<H>`). */
template <>
inline constexpr bool backend_has_v<backends::hash2, macs::hmac<digests::blake2s_256>, void> = true;

/** backends::hash2 has `macs::siphash_2_4` (Boost.Hash2's `siphash_64`). */
template <>
inline constexpr bool backend_has_v<backends::hash2, macs::siphash_2_4, void> = true;

/** backends::sodium has `macs::siphash_2_4` (`crypto_shorthash_siphash24`). */
template <>
inline constexpr bool backend_has_v<backends::sodium, macs::siphash_2_4, void> = true;

/** backends::sodium has `macs::siphash_2_4x` (`crypto_shorthash_siphashx24`). */
template <>
inline constexpr bool backend_has_v<backends::sodium, macs::siphash_2_4x, void> = true;

/**
 backends::hash2 has `macs::blake2s_mac` in part: a 32-byte tag, Boost.Hash2's keyed `blake2s_256`
 (ruling R82).
*/
template <>
inline constexpr bool backend_has_v<backends::hash2, macs::blake2s_mac, void> = true;

namespace detail {

/**
 Refuses, with spec 3.3's text, an `Hmac` that is not a Boost.Hash2 hmac over a digest; every
 public key derivation calls it first, as the condition of an `if constexpr` whose other branch
 holds the work, so that the refusal is the only error such an `Hmac` gives.

 @tparam Hmac The hmac a key derivation was called with.
 @return Whether `Hmac` is a digest hmac.
*/
template <class Hmac>
constexpr bool takes_hmac() noexcept {
    static_assert(is_digest_hmac<Hmac>::value,
                  "webcpp::hash: the key derivations take a Boost.Hash2 hmac whose result is a "
                  "digest, as hmac_sha2_256.");
    return is_digest_hmac<Hmac>::value;
}

/**
 The result of a type that has no `result_type`: `hkdf_extract`'s signature stays well-formed
 for it, so that @ref takes_hmac's refusal is the error such a type gets.
*/
struct no_result {};

/** `Hmac::result_type` when it exists, else `no_result`. */
template <class Hmac, class = void>
struct hmac_result {
    /** No result type. */
    using type = no_result;
};

/** A type with a `result_type`. */
template <class Hmac>
struct hmac_result<Hmac, std::void_t<typename Hmac::result_type>> {
    /** Its result type. */
    using type = Hmac::result_type;
};

/**
 The tag of `digests` of a Boost.Hash2 hmac's hash, so that `macs::hmac<digest_tag_of<Hmac>::type>`
 names the same function as the Hash2 alias `Hmac` (ruling R15): `void` for an hmac without one
 (`hmac_ripemd_128`, and `hmac<H>` over a hash of no alias). `hmac_blake2b_512` is HMAC over
 BLAKE2b with its default options, a 64-byte digest: `digests::blake2b`.

 @tparam Hmac A Boost.Hash2 hmac.
*/
template <class Hmac>
struct digest_tag_of {
    /** No tag. */
    using type = void;
};

/** `hmac_md5_128`: `digests::md5`. */
template <>
struct digest_tag_of<hmac_md5_128> {
    /** digests::md5. */
    using type = digests::md5;
};

/** `hmac_sha1_160`: `digests::sha1`. */
template <>
struct digest_tag_of<hmac_sha1_160> {
    /** digests::sha1. */
    using type = digests::sha1;
};

/** `hmac_sha2_224`: `digests::sha2_224`. */
template <>
struct digest_tag_of<hmac_sha2_224> {
    /** digests::sha2_224. */
    using type = digests::sha2_224;
};

/** `hmac_sha2_256`: `digests::sha2_256`. */
template <>
struct digest_tag_of<hmac_sha2_256> {
    /** digests::sha2_256. */
    using type = digests::sha2_256;
};

/** `hmac_sha2_384`: `digests::sha2_384`. */
template <>
struct digest_tag_of<hmac_sha2_384> {
    /** digests::sha2_384. */
    using type = digests::sha2_384;
};

/** `hmac_sha2_512`: `digests::sha2_512`. */
template <>
struct digest_tag_of<hmac_sha2_512> {
    /** digests::sha2_512. */
    using type = digests::sha2_512;
};

/** `hmac_sha2_512_224`: `digests::sha2_512_224`. */
template <>
struct digest_tag_of<hmac_sha2_512_224> {
    /** digests::sha2_512_224. */
    using type = digests::sha2_512_224;
};

/** `hmac_sha2_512_256`: `digests::sha2_512_256`. */
template <>
struct digest_tag_of<hmac_sha2_512_256> {
    /** digests::sha2_512_256. */
    using type = digests::sha2_512_256;
};

/** `hmac_sha3_224`: `digests::sha3_224`. */
template <>
struct digest_tag_of<hmac_sha3_224> {
    /** digests::sha3_224. */
    using type = digests::sha3_224;
};

/** `hmac_sha3_256`: `digests::sha3_256`. */
template <>
struct digest_tag_of<hmac_sha3_256> {
    /** digests::sha3_256. */
    using type = digests::sha3_256;
};

/** `hmac_sha3_384`: `digests::sha3_384`. */
template <>
struct digest_tag_of<hmac_sha3_384> {
    /** digests::sha3_384. */
    using type = digests::sha3_384;
};

/** `hmac_sha3_512`: `digests::sha3_512`. */
template <>
struct digest_tag_of<hmac_sha3_512> {
    /** digests::sha3_512. */
    using type = digests::sha3_512;
};

/** `hmac_ripemd_160`: `digests::ripemd_160`. */
template <>
struct digest_tag_of<hmac_ripemd_160> {
    /** digests::ripemd_160. */
    using type = digests::ripemd_160;
};

/** `hmac_blake2b_512`: `digests::blake2b`. */
template <>
struct digest_tag_of<hmac_blake2b_512> {
    /** digests::blake2b. */
    using type = digests::blake2b;
};

/** `hmac_blake2s_256`: `digests::blake2s_256`. */
template <>
struct digest_tag_of<hmac_blake2s_256> {
    /** digests::blake2s_256. */
    using type = digests::blake2s_256;
};

/**
 The backend of `Algorithm` when the call names none (spec 4.1): backends::hash2, the one backend
 that has every key derivation over every hmac on every target, header-only. Each tag of the
 families has its own below (design D34): the first of `backends::hash2`, `backends::xkcp`,
 `backends::blake3` and `backends::sodium` that has the tag fully in the capability table once
 increments 2 to 7 have landed, else the first of them with a partial cell, else @ref no_default.
 A default never changes; until its backend's engine lands, a call on it refuses at compile time.

 @tparam Algorithm A tag of `kdfs`, `digests` or `macs`.
*/
template <class Algorithm>
struct default_of {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** Argon2id: backends::sodium, the one backend that has it. */
template <>
struct default_of<kdfs::argon2id> {
    /** backends::sodium. */
    using type = backends::sodium;
};

/** scrypt: backends::sodium, the one backend that has it. */
template <>
struct default_of<kdfs::scrypt> {
    /** backends::sodium. */
    using type = backends::sodium;
};

/** HMAC over a digest that Boost.Hash2 lacks: no default. */
template <class Digest>
struct default_of<macs::hmac<Digest>> {
    /** detail::no_default. */
    using type = no_default;
};

/** `digests::md5`: Boost.Hash2 has it. */
template <>
struct default_of<digests::md5> {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** `digests::sha1`: Boost.Hash2 has it. */
template <>
struct default_of<digests::sha1> {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** `digests::sha2_224`: Boost.Hash2 has it. */
template <>
struct default_of<digests::sha2_224> {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** `digests::sha2_256`: Boost.Hash2 has it. */
template <>
struct default_of<digests::sha2_256> {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** `digests::sha2_384`: Boost.Hash2 has it. */
template <>
struct default_of<digests::sha2_384> {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** `digests::sha2_512`: Boost.Hash2 has it. */
template <>
struct default_of<digests::sha2_512> {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** `digests::sha2_512_224`: Boost.Hash2 has it. */
template <>
struct default_of<digests::sha2_512_224> {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** `digests::sha2_512_256`: Boost.Hash2 has it. */
template <>
struct default_of<digests::sha2_512_256> {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** `digests::sha3_224`: Boost.Hash2 has it. */
template <>
struct default_of<digests::sha3_224> {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** `digests::sha3_256`: Boost.Hash2 has it. */
template <>
struct default_of<digests::sha3_256> {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** `digests::sha3_384`: Boost.Hash2 has it. */
template <>
struct default_of<digests::sha3_384> {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** `digests::sha3_512`: Boost.Hash2 has it. */
template <>
struct default_of<digests::sha3_512> {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** `digests::ripemd_160`: Boost.Hash2 has it. */
template <>
struct default_of<digests::ripemd_160> {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** `digests::blake2s_256`: Boost.Hash2 has it. */
template <>
struct default_of<digests::blake2s_256> {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** `digests::shake_128`: backends::xkcp (increment 3) has it whole; Boost.Hash2 has 32 bytes alone.
 */
template <>
struct default_of<digests::shake_128> {
    /** backends::xkcp. */
    using type = backends::xkcp;
};

/** `digests::shake_256`: backends::xkcp (increment 3) has it whole; Boost.Hash2 has 64 bytes alone.
 */
template <>
struct default_of<digests::shake_256> {
    /** backends::xkcp. */
    using type = backends::xkcp;
};

/** `macs::hmac<digests::md5>`: Boost.Hash2 has it. */
template <>
struct default_of<macs::hmac<digests::md5>> {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** `macs::hmac<digests::sha1>`: Boost.Hash2 has it. */
template <>
struct default_of<macs::hmac<digests::sha1>> {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** `macs::hmac<digests::sha2_224>`: Boost.Hash2 has it. */
template <>
struct default_of<macs::hmac<digests::sha2_224>> {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** `macs::hmac<digests::sha2_256>`: Boost.Hash2 has it. */
template <>
struct default_of<macs::hmac<digests::sha2_256>> {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** `macs::hmac<digests::sha2_384>`: Boost.Hash2 has it. */
template <>
struct default_of<macs::hmac<digests::sha2_384>> {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** `macs::hmac<digests::sha2_512>`: Boost.Hash2 has it. */
template <>
struct default_of<macs::hmac<digests::sha2_512>> {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** `macs::hmac<digests::sha2_512_224>`: Boost.Hash2 has it. */
template <>
struct default_of<macs::hmac<digests::sha2_512_224>> {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** `macs::hmac<digests::sha2_512_256>`: Boost.Hash2 has it. */
template <>
struct default_of<macs::hmac<digests::sha2_512_256>> {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** `macs::hmac<digests::sha3_224>`: Boost.Hash2 has it. */
template <>
struct default_of<macs::hmac<digests::sha3_224>> {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** `macs::hmac<digests::sha3_256>`: Boost.Hash2 has it. */
template <>
struct default_of<macs::hmac<digests::sha3_256>> {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** `macs::hmac<digests::sha3_384>`: Boost.Hash2 has it. */
template <>
struct default_of<macs::hmac<digests::sha3_384>> {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** `macs::hmac<digests::sha3_512>`: Boost.Hash2 has it. */
template <>
struct default_of<macs::hmac<digests::sha3_512>> {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** `macs::hmac<digests::ripemd_160>`: Boost.Hash2 has it. */
template <>
struct default_of<macs::hmac<digests::ripemd_160>> {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** `macs::hmac<digests::blake2b>`: Boost.Hash2 has it. */
template <>
struct default_of<macs::hmac<digests::blake2b>> {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** `macs::hmac<digests::blake2s_256>`: Boost.Hash2 has it. */
template <>
struct default_of<macs::hmac<digests::blake2s_256>> {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** `macs::siphash_2_4`: Boost.Hash2 has it. */
template <>
struct default_of<macs::siphash_2_4> {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** `macs::blake2s_mac`: Boost.Hash2 has it in part: its keyed `blake2s_256`, a 32-byte tag alone.
 */
template <>
struct default_of<macs::blake2s_mac> {
    /** backends::hash2. */
    using type = backends::hash2;
};

/** `digests::keccak_224`: XKCP is the first backend of the order that has it. */
template <>
struct default_of<digests::keccak_224> {
    /** backends::xkcp. */
    using type = backends::xkcp;
};

/** `digests::keccak_256`: XKCP is the first backend of the order that has it. */
template <>
struct default_of<digests::keccak_256> {
    /** backends::xkcp. */
    using type = backends::xkcp;
};

/** `digests::keccak_384`: XKCP is the first backend of the order that has it. */
template <>
struct default_of<digests::keccak_384> {
    /** backends::xkcp. */
    using type = backends::xkcp;
};

/** `digests::keccak_512`: XKCP is the first backend of the order that has it. */
template <>
struct default_of<digests::keccak_512> {
    /** backends::xkcp. */
    using type = backends::xkcp;
};

/** `digests::cshake_128`: XKCP is the first backend of the order that has it. */
template <>
struct default_of<digests::cshake_128> {
    /** backends::xkcp. */
    using type = backends::xkcp;
};

/** `digests::cshake_256`: XKCP is the first backend of the order that has it. */
template <>
struct default_of<digests::cshake_256> {
    /** backends::xkcp. */
    using type = backends::xkcp;
};

/** `digests::kt128`: XKCP is the first backend of the order that has it. */
template <>
struct default_of<digests::kt128> {
    /** backends::xkcp. */
    using type = backends::xkcp;
};

/** `digests::kt256`: XKCP is the first backend of the order that has it. */
template <>
struct default_of<digests::kt256> {
    /** backends::xkcp. */
    using type = backends::xkcp;
};

/** `digests::turboshake_128`: XKCP is the first backend of the order that has it. */
template <>
struct default_of<digests::turboshake_128> {
    /** backends::xkcp. */
    using type = backends::xkcp;
};

/** `digests::turboshake_256`: XKCP is the first backend of the order that has it. */
template <>
struct default_of<digests::turboshake_256> {
    /** backends::xkcp. */
    using type = backends::xkcp;
};

/** `digests::tuplehash_128`: XKCP is the first backend of the order that has it. */
template <>
struct default_of<digests::tuplehash_128> {
    /** backends::xkcp. */
    using type = backends::xkcp;
};

/** `digests::tuplehash_256`: XKCP is the first backend of the order that has it. */
template <>
struct default_of<digests::tuplehash_256> {
    /** backends::xkcp. */
    using type = backends::xkcp;
};

/** `digests::parallelhash_128`: XKCP is the first backend of the order that has it. */
template <>
struct default_of<digests::parallelhash_128> {
    /** backends::xkcp. */
    using type = backends::xkcp;
};

/** `digests::parallelhash_256`: XKCP is the first backend of the order that has it. */
template <>
struct default_of<digests::parallelhash_256> {
    /** backends::xkcp. */
    using type = backends::xkcp;
};

/** `macs::kmac_128`: XKCP is the first backend of the order that has it. */
template <>
struct default_of<macs::kmac_128> {
    /** backends::xkcp. */
    using type = backends::xkcp;
};

/** `macs::kmac_256`: XKCP is the first backend of the order that has it. */
template <>
struct default_of<macs::kmac_256> {
    /** backends::xkcp. */
    using type = backends::xkcp;
};

/** `digests::blake3`: its official C implementation. */
template <>
struct default_of<digests::blake3> {
    /** backends::blake3. */
    using type = backends::blake3;
};

/**
 `digests::blake2b`: libsodium is the first backend of the order that has it whole (Boost.Hash2 has
 its 64-byte output with no option alone).
*/
template <>
struct default_of<digests::blake2b> {
    /** backends::sodium. */
    using type = backends::sodium;
};

/** `macs::siphash_2_4x`: libsodium is the first backend of the order that has it whole. */
template <>
struct default_of<macs::siphash_2_4x> {
    /** backends::sodium. */
    using type = backends::sodium;
};

/** `macs::blake2b_mac`: libsodium is the first backend of the order that has it whole. */
template <>
struct default_of<macs::blake2b_mac> {
    /** backends::sodium. */
    using type = backends::sodium;
};

/**
 `kdfs::argon2i`: libsodium has it in part (one lane, at least 3 passes, a tag of 16 bytes or more;
 ruling R24), and no backend of the order has it whole, so the first with a cell is the default
 (ruling R2).
*/
template <>
struct default_of<kdfs::argon2i> {
    /** backends::sodium. */
    using type = backends::sodium;
};

/** `kdfs::blake2b_subkey`: libsodium is the first backend of the order that has it whole. */
template <>
struct default_of<kdfs::blake2b_subkey> {
    /** backends::sodium. */
    using type = backends::sodium;
};

/** `digests::md5_sha1`: no backend of the order has it. */
template <>
struct default_of<digests::md5_sha1> {
    /** detail::no_default. */
    using type = no_default;
};

/** `digests::sm3`: no backend of the order has it. */
template <>
struct default_of<digests::sm3> {
    /** detail::no_default. */
    using type = no_default;
};

/** `digests::streebog_256`: no backend of the order has it. */
template <>
struct default_of<digests::streebog_256> {
    /** detail::no_default. */
    using type = no_default;
};

/** `digests::streebog_512`: no backend of the order has it. */
template <>
struct default_of<digests::streebog_512> {
    /** detail::no_default. */
    using type = no_default;
};

/** `digests::whirlpool`: no backend of the order has it. */
template <>
struct default_of<digests::whirlpool> {
    /** detail::no_default. */
    using type = no_default;
};

/** `digests::skein_512`: no backend of the order has it. */
template <>
struct default_of<digests::skein_512> {
    /** detail::no_default. */
    using type = no_default;
};

/** `kdfs::argon2d`: no backend of the order has it. */
template <>
struct default_of<kdfs::argon2d> {
    /** detail::no_default. */
    using type = no_default;
};

/** `kdfs::bcrypt`: no backend of the order has it. */
template <>
struct default_of<kdfs::bcrypt> {
    /** detail::no_default. */
    using type = no_default;
};

/** `kdfs::bcrypt_pbkdf`: no backend of the order has it. */
template <>
struct default_of<kdfs::bcrypt_pbkdf> {
    /** detail::no_default. */
    using type = no_default;
};

/** `kdfs::kbkdf_hmac`: no backend of the order has it. */
template <>
struct default_of<kdfs::kbkdf_hmac> {
    /** detail::no_default. */
    using type = no_default;
};

/** `kdfs::sskdf`: no backend of the order has it. */
template <>
struct default_of<kdfs::sskdf> {
    /** detail::no_default. */
    using type = no_default;
};

/** `kdfs::x963kdf`: no backend of the order has it. */
template <>
struct default_of<kdfs::x963kdf> {
    /** detail::no_default. */
    using type = no_default;
};

}  // namespace detail

/**
 The backend a function of `Algorithm` uses when the call names none (spec 4.1).

 `backends::hash2` for `hkdf_extract`, `hkdf_expand`, `hkdf` and `pbkdf2`, on every target and
 whatever the program links; `backends::sodium` for `argon2id`, `scrypt` and `blake2b_subkey`, the
 one backend that has them, which stops the build with the line to add to the Jamfile when the
 program does not link libsodium. A tag of the families defaults to the first of `backends::hash2`,
 `backends::xkcp`, `backends::blake3` and `backends::sodium` that has it (design D34), or to
 `detail::no_default`, which refuses: the call names its backend. `backends::bearssl` and
 `backends::openssl` are never a default. No define changes it: another backend is chosen by
 naming it in the call, as `hkdf<hmac_sha2_256, backends::openssl>`.

 @tparam Algorithm A tag of `kdfs` (`hkdf`, `hkdf_extract`, `hkdf_expand`, `pbkdf2`, `argon2id`,
 `scrypt`, `blake2b_subkey`, ...), `digests` or `macs`.
 @tparam Hmac The hmac of a key derivation that takes one, else `void`; it does not change the
 answer.
*/
template <class Algorithm, class Hmac = void>
using default_backend = detail::default_of<Algorithm>::type;

/**
 The backend `hkdf_extract`, `hkdf_expand`, `hkdf` and `pbkdf2` use when the program names none:
 @ref default_backend of `Kdf`, `backends::hash2` on every target.

 @tparam Hmac A Boost.Hash2 hmac; it does not change the answer. @tparam Kdf `kdfs::hkdf` (the
 default), `kdfs::hkdf_extract`, `kdfs::hkdf_expand` or `kdfs::pbkdf2`.
*/
template <class Hmac, class Kdf = kdfs::hkdf>
using default_kdf_backend = default_backend<Kdf, Hmac>;

}  // namespace webcpp::hash

#endif  // WEBCPP_HASH_KDF_HPP
