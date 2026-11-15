// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 What HKDF and PBKDF2 share: which backend has which key derivation over which hmac, and the
 backend a call uses when it names none.

 @see "Key derivation", in the guide.
*/
#ifndef WEBCPP_HASH_KDF_HPP
#define WEBCPP_HASH_KDF_HPP

#include <webcpp/hash/config.hpp>

#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/detail/overrides.hpp>
#include <webcpp/hash/detail/ranking.hpp>
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
 The algorithm whose override `Algorithm` follows (spec 4.1, ruling R29): HKDF for its two steps,
 else `Algorithm` itself. Its ranking is its own: `ranking<Algorithm, Hmac>` holds a row per
 operation.

 @tparam Algorithm A tag of `kdfs`.
*/
template <class Algorithm>
struct algorithm_of {
    /** The algorithm itself. */
    using type = Algorithm;
};

/** HKDF-Extract follows HKDF. */
template <>
struct algorithm_of<kdfs::hkdf_extract> {
    /** HKDF. */
    using type = kdfs::hkdf;
};

/** HKDF-Expand follows HKDF. */
template <>
struct algorithm_of<kdfs::hkdf_expand> {
    /** HKDF. */
    using type = kdfs::hkdf;
};

/**
 The first of `Backends` for which `Keep<Backend>::value` holds, else `Fallback`.

 @tparam Keep A predicate over a backend. @tparam Fallback The answer when none holds.
 @tparam Backends The backends, in order.
*/
template <template <class> class Keep, class Fallback, class... Backends>
struct first_where {
    /** No backend kept: the fallback. */
    using type = Fallback;
};

/** The head when it is kept, else the first of the rest. */
template <template <class> class Keep, class Fallback, class Head, class... Tail>
struct first_where<Keep, Fallback, Head, Tail...>
    : std::conditional_t<Keep<Head>::value, std::type_identity<Head>,
                         first_where<Keep, Fallback, Tail...>> {};

/**
 The predicates of @ref first_serving over `Algorithm` and `Hmac`.

 @tparam Algorithm A tag of `kdfs`. @tparam Hmac The hmac, or `void`.
*/
template <class Algorithm, class Hmac>
struct serves {
    /** Whether `Backend` is linked and has `Algorithm` over `Hmac`. */
    template <class Backend>
    struct linked
        : std::bool_constant<linked_v<Backend> && backend_has_v<Backend, Algorithm, Hmac>> {};

    /** Whether `Backend` has `Algorithm` over `Hmac`, linked or not. */
    template <class Backend>
    struct any : std::bool_constant<backend_has_v<Backend, Algorithm, Hmac>> {};
};

/**
 The first backend of `List` that the program links and that has `Algorithm` over `Hmac`, so that
 an order that puts backends::bearssl first never makes `hkdf_extract` or `hkdf_expand` refuse. When
 no linked backend has it, the first of `List` that has it, whose engine then refuses with the line
 to add to the Jamfile; when none has it at all (an `Hmac` that is not a digest hmac),
 backends::hash2, so that @ref takes_hmac's refusal is the only error.

 @tparam Algorithm A tag of `kdfs`. @tparam Hmac The hmac, or `void`.
 @tparam List A @ref backend_list.
*/
template <class Algorithm, class Hmac, class List>
struct first_serving;

/** The selection over a @ref backend_list. */
template <class Algorithm, class Hmac, class... Backends>
struct first_serving<Algorithm, Hmac, backend_list<Backends...>>
    : first_where<serves<Algorithm, Hmac>::template linked,
                  typename first_where<serves<Algorithm, Hmac>::template any, backends::hash2,
                                       Backends...>::type,
                  Backends...> {};

/**
 The backend a profile chooses for `Algorithm` over `Hmac` (spec 4.1). The primary template is
 `auto`'s: natively the fastest, on WebAssembly the smallest.

 @tparam Profile A tag of `detail::profiles`. @tparam Algorithm A tag of `kdfs`.
 @tparam Hmac The hmac, or `void`.
*/
template <class Profile, class Algorithm, class Hmac>
struct profile_choice
#ifdef WEBCPP_HASH_WEBASSEMBLY
    : first_serving<Algorithm, Hmac, typename ranking<Algorithm, Hmac>::by_size> {
};
#else
    : first_serving<Algorithm, Hmac, typename ranking<Algorithm, Hmac>::by_throughput> {
};
#endif

/** The fastest on this target, by the measured order. */
template <class Algorithm, class Hmac>
struct profile_choice<profiles::fastest, Algorithm, Hmac>
    : first_serving<Algorithm, Hmac, typename ranking<Algorithm, Hmac>::by_throughput> {};

/** The smallest on this target, by the measured order. */
template <class Algorithm, class Hmac>
struct profile_choice<profiles::smallest, Algorithm, Hmac>
    : first_serving<Algorithm, Hmac, typename ranking<Algorithm, Hmac>::by_size> {};

/** The first of `portable_order` that serves. */
template <class Algorithm, class Hmac>
struct profile_choice<profiles::portable, Algorithm, Hmac>
    : first_serving<Algorithm, Hmac, portable_order> {};

/** The named backend when it is linked and has `Algorithm` over `Hmac`, else `auto`'s choice. */
template <class Backend, class Algorithm, class Hmac>
struct profile_choice<profiles::named<Backend>, Algorithm, Hmac>
    : std::conditional_t<linked_v<Backend> && backend_has_v<Backend, Algorithm, Hmac>,
                         std::type_identity<Backend>,
                         profile_choice<profiles::automatic, Algorithm, Hmac>> {};

/**
 The default of `Algorithm` over `Hmac`: the override's backend, else the profile's choice
 (spec 4.1's precedence: override, library profile, umbrella profile, auto).

 @tparam Algorithm A tag of `kdfs`. @tparam Hmac The hmac, or `void`.
*/
template <class Algorithm, class Hmac>
struct default_choice {
    /** The override's backend, or `void`. */
    using overridden = override_choice<typename algorithm_of<Algorithm>::type>::type;
    /** The chosen backend. */
    using type =
        std::conditional_t<std::is_void_v<overridden>,
                           typename profile_choice<profile, Algorithm, Hmac>::type, overridden>;
};

}  // namespace detail

/**
 The backend a function of `Algorithm` uses when the call names none: the override's
 (`WEBCPP_HASH_DEFAULT_BACKEND_<ALGORITHM>_<NAME>`), else the profile's choice among the backends
 the program links that have `Algorithm` over `Hmac`, from the measured orders of
 `detail/ranking.hpp` (spec sections 4.1 and 4.2).

 Chosen per function: `kdfs::hkdf_extract` and `kdfs::hkdf_expand` are never a backend that has
 HKDF only whole.

 @tparam Algorithm A tag of `kdfs`: `hkdf`, `hkdf_extract`, `hkdf_expand`, `pbkdf2`, `argon2id`
 or `scrypt`.
 @tparam Hmac The hmac of a key derivation that takes one, else `void`.
*/
template <class Algorithm, class Hmac = void>
using default_backend = detail::default_choice<Algorithm, Hmac>::type;

/**
 The backend `hkdf_extract`, `hkdf_expand`, `hkdf` and `pbkdf2` use when the program names none:
 @ref default_backend of `Kdf` over `Hmac`.

 Without a profile, natively the fastest linked backend, on WebAssembly the smallest, by the
 measured orders of `detail/ranking.hpp`, which the guide's measured table shows.

 @tparam Hmac A Boost.Hash2 hmac. @tparam Kdf `kdfs::hkdf` (the default), `kdfs::hkdf_extract`,
 `kdfs::hkdf_expand` or `kdfs::pbkdf2`.
*/
template <class Hmac, class Kdf = kdfs::hkdf>
using default_kdf_backend = default_backend<Kdf, Hmac>;

}  // namespace webcpp::hash

#endif  // WEBCPP_HASH_KDF_HPP
