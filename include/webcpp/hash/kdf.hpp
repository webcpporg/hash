// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 What the key derivations share: which backend has which key derivation over which hmac, and
 the backend a call uses when it names none.

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
 Whether `Backend` has the key derivation `Kdf` over `Hmac`: a property of the library behind it
 (spec section 3.2), whether or not the program links it.

 @tparam Backend A backend of `backends`. @tparam Kdf `kdfs::hkdf` or `kdfs::pbkdf2`.
 @tparam Hmac A Boost.Hash2 hmac.
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

/** Whether the program links `Backend`: backends::hash2 always, another when its target says so. */
template <class Backend>
inline constexpr bool linked_v = false;

/** backends::hash2 needs no library. */
template <>
inline constexpr bool linked_v<backends::hash2> = true;

#ifdef WEBCPP_HASH_HAS_SODIUM
/** `/third_party//sodium` defines `WEBCPP_HASH_HAS_SODIUM`. */
template <>
inline constexpr bool linked_v<backends::sodium> = true;
#endif

#ifdef WEBCPP_HASH_HAS_BEARSSL
/** `/third_party//bearssl` defines `WEBCPP_HASH_HAS_BEARSSL`. */
template <>
inline constexpr bool linked_v<backends::bearssl> = true;
#endif

#ifdef WEBCPP_HASH_HAS_OPENSSL
/** `/webcpp/hash//openssl` defines `WEBCPP_HASH_HAS_OPENSSL`. */
template <>
inline constexpr bool linked_v<backends::openssl> = true;
#endif

/**
 The backend of `Algorithm` when the call names none (spec 4.1): backends::hash2, the one backend
 that has every key derivation over every hmac on every target, header-only.

 @tparam Algorithm A tag of `kdfs`.
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

}  // namespace detail

/**
 The backend a function of `Algorithm` uses when the call names none (spec 4.1).

 `backends::hash2` for `hkdf_extract`, `hkdf_expand`, `hkdf` and `pbkdf2`, on every target and
 whatever the program links; `backends::sodium` for `argon2id` and `scrypt`, the one backend that
 has them, which stops the build with the line to add to the Jamfile when the program does not
 link libsodium. No define changes it: another backend is chosen by naming it in the call, as
 `hkdf<hmac_sha2_256, backends::openssl>`.

 @tparam Algorithm A tag of `kdfs`: `hkdf`, `hkdf_extract`, `hkdf_expand`, `pbkdf2`, `argon2id`
 or `scrypt`.
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
