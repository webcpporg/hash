// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

#ifndef WEBCPP_HASH_DETAIL_ENGINES_HPP
#define WEBCPP_HASH_DETAIL_ENGINES_HPP

#include <webcpp/hash/config.hpp>

#include <boost/hash2/has_constant_size.hpp>
#include <boost/hash2/hmac.hpp>

#include <cstdint>
#include <limits>
#include <type_traits>

namespace webcpp::hash::detail {

/** False for every `T`: a `static_assert` that fires only when its template is instantiated. */
template <class T>
inline constexpr bool always_false = false;

/** No limit beyond the spec's own: the largest 64-bit size. */
inline constexpr std::uint64_t no_limit = std::numeric_limits<std::uint64_t>::max();

/**
 The longest input and output a backend's C library takes, in bytes, where its interface holds a
 length in a narrower type than `std::size_t` (ruling R24). The public functions' guards read it
 after the spec's own guards and before any call of the backend, and refuse a longer output with
 `invalid_output_size` and a longer input with `input_too_long`, the output untouched. The
 primary template, every backend's unless its header specialises it, has no limit; a
 specialisation gives every member.

 @tparam Backend A backend of `backends`.
*/
template <class Backend>
struct backend_limits {
    /** HKDF's salt (`hkdf_extract`, `hkdf`). */
    static constexpr std::uint64_t hkdf_salt = no_limit;
    /** HKDF's input keying material (`hkdf_extract`, `hkdf`). */
    static constexpr std::uint64_t hkdf_ikm = no_limit;
    /** HKDF's pseudorandom key (`hkdf_expand`). */
    static constexpr std::uint64_t hkdf_prk = no_limit;
    /** HKDF's info (`hkdf_expand`, `hkdf`), within `hkdf_max_info_size`. */
    static constexpr std::uint64_t hkdf_info = no_limit;
    /** HKDF's output (`hkdf_expand`, `hkdf`), within 255 digests. */
    static constexpr std::uint64_t hkdf_output = no_limit;
    /** PBKDF2's password. */
    static constexpr std::uint64_t pbkdf2_password = no_limit;
    /** PBKDF2's salt. */
    static constexpr std::uint64_t pbkdf2_salt = no_limit;
    /** PBKDF2's output, within (2^32 - 1) digests. */
    static constexpr std::uint64_t pbkdf2_output = no_limit;
};

/**
 The HKDF of a backend over an hmac (spec section 2.12), which the backend's header specialises
 for each hmac it has. The primary template is reached only by a backend without HKDF, and
 refuses with spec 3.3's text.

 A specialisation has three static member functions, each `noexcept`, called by the public
 functions of `hkdf.hpp` only after every guard of spec 2.8 has passed; an engine does the work
 and no check, and wipes every intermediate it makes, on success and on failure:

 @code
 using digest_type = typename Hmac::result_type;
 // RFC 5869 2.2: the PRK of `ikm` under `salt` (empty: HashLen zeros).
 static boost::system::result<digest_type> extract(std::span<std::uint8_t const> salt,
                                                   std::span<std::uint8_t const> ikm) noexcept;
 // RFC 5869 2.3: `output` (1 to 255 digests) from `prk` (one digest) and `info` (at most
 // hkdf_max_info_size bytes).
 static boost::system::result<void> expand(std::span<std::uint8_t> output,
                                           std::span<std::uint8_t const> prk,
                                           std::span<std::uint8_t const> info) noexcept;
 // Both steps.
 static boost::system::result<void> extract_and_expand(std::span<std::uint8_t> output,
                                                       std::span<std::uint8_t const> salt,
                                                       std::span<std::uint8_t const> ikm,
                                                       std::span<std::uint8_t const> info) noexcept;
 @endcode

 A failure is `error::backend_failure`, or `errc::not_enough_memory` when the library could not
 allocate; the public function then zeroes the output. A backend that has `hkdf` alone
 (BearSSL) gives `extract` and `expand` a `static_assert` of their own (spec 3.3).

 @tparam Backend A backend of `backends`. @tparam Hmac A Boost.Hash2 hmac over a digest.
*/
template <class Backend, class Hmac>
struct hkdf_engine {
    static_assert(
        always_false<Backend>,
        "webcpp::hash: this backend has no HKDF. The backends that have HKDF: "
        "backends::hash2 (every hmac), backends::openssl (every hmac but "
        "hmac_ripemd_128), backends::sodium (hmac_sha2_256, hmac_sha2_512) and "
        "backends::bearssl (MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512; hkdf alone).");
};

/**
 The PBKDF2 of a backend over an hmac (spec section 2.12), specialised as @ref hkdf_engine is.
 A specialisation has one static member function, called after the guards of spec 2.9:

 @code
 // RFC 8018 5.2: `output` (1 to (2^32 - 1) digests) from `password` and `salt`, by
 // `iterations` (at least 1) rounds of Hmac.
 static boost::system::result<void> derive(std::span<std::uint8_t> output,
                                           std::span<std::uint8_t const> password,
                                           std::span<std::uint8_t const> salt,
                                           std::uint64_t iterations) noexcept;
 @endcode

 @tparam Backend A backend of `backends`. @tparam Hmac A Boost.Hash2 hmac over a digest.
*/
template <class Backend, class Hmac>
struct pbkdf2_engine {
    static_assert(always_false<Backend>,
                  "webcpp::hash: this backend has no PBKDF2. The backends that have pbkdf2: "
                  "backends::hash2 (every hmac) and backends::openssl (every hmac but "
                  "hmac_ripemd_128).");
};

/**
 The Argon2id of a backend (spec sections 2.10 and 2.12): `derive` and `limits`, which
 `backends::sodium` alone specialises. The primary template refuses every other backend.

 @tparam Backend A backend of `backends`.
*/
template <class Backend>
struct argon2id_engine {
    static_assert(always_false<Backend>,
                  "webcpp::hash: argon2id is in backends::sodium alone. Name backends::sodium "
                  "and add /third_party//sodium to the program's Jamfile.");
};

/**
 The scrypt of a backend (spec sections 2.11 and 2.12): `derive`, which `backends::sodium` alone
 specialises. The primary template refuses every other backend.

 @tparam Backend A backend of `backends`.
*/
template <class Backend>
struct scrypt_engine {
    static_assert(always_false<Backend>,
                  "webcpp::hash: scrypt is in backends::sodium alone. Name backends::sodium and "
                  "add /third_party//sodium to the program's Jamfile.");
};

/**
 Whether `Hmac` is a Boost.Hash2 hmac over a hash whose result is a digest: what every key
 derivation takes (spec section 3.3).

 @tparam Hmac Any type.
*/
template <class Hmac>
struct is_digest_hmac : std::false_type {};

/** A Boost.Hash2 hmac is a digest hmac when its hash's result has a constant size. */
template <class H>
struct is_digest_hmac<boost::hash2::hmac<H>>
    : std::bool_constant<boost::hash2::has_constant_size<typename H::result_type>::value &&
                         !std::is_integral_v<typename H::result_type>> {};

}  // namespace webcpp::hash::detail

#endif  // WEBCPP_HASH_DETAIL_ENGINES_HPP
