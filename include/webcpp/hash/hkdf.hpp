// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 HKDF, RFC 5869: `hkdf_extract`, `hkdf_expand` and `hkdf`, over any Boost.Hash2 hmac whose result
 is a digest, on the backend the call names or on @ref webcpp::hash::default_kdf_backend.

 Every guard runs before any work, and a guard's refusal leaves the output as it was; a backend's
 failure zeroes it.

 @code
 // salt, secret and info: std::span<std::uint8_t const>
 std::array<std::uint8_t, 32> key{};
 auto done = webcpp::hash::hkdf<webcpp::hash::hmac_sha2_256>(key, salt, secret, info);
 if (!done) {
     return done.error();  // key is as it was, or zeroed when the backend failed
 }
 @endcode

 @see "Key derivation", in the guide.
*/
#ifndef WEBCPP_HASH_HKDF_HPP
#define WEBCPP_HASH_HKDF_HPP

#include <webcpp/hash/config.hpp>

#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/detail/wipe.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/kdf.hpp>

// The backends the program links, each under its WEBCPP_HASH_HAS_<NAME>: default_kdf_backend
// names only a backend whose engines are visible here.
#ifdef WEBCPP_HASH_HAS_BEARSSL
#include <webcpp/hash/backends/bearssl.hpp>
#endif
#ifdef WEBCPP_HASH_HAS_SODIUM
#include <webcpp/hash/backends/sodium.hpp>
#endif

#include <boost/system/result.hpp>

#include <cstddef>
#include <cstdint>
#include <span>

namespace webcpp::hash {

/** The longest info every backend accepts, 32,768 bytes (OpenSSL 3.5's limit). */
inline constexpr std::size_t hkdf_max_info_size = 32768;

/**
 HKDF-Extract (RFC 5869, section 2.2): the pseudorandom key of `ikm` under `salt`.

 @tparam Hmac The hmac, as `hmac_sha2_256`. @tparam Backend The backend.
 @param salt The salt, any length; empty means `Hmac`'s digest size of zeros.
 @param ikm The input keying material, any length.
 @return The pseudorandom key, an `Hmac::result_type` of the hmac's digest size, or the backend's
 failure.
*/
template <class Hmac, class Backend = default_kdf_backend<Hmac>>
boost::system::result<typename detail::hmac_result<Hmac>::type> hkdf_extract(
    std::span<std::uint8_t const> salt, std::span<std::uint8_t const> ikm) {
    if constexpr (!detail::takes_hmac<Hmac>()) {
        return error::backend_failure;  // unreachable: takes_hmac has stopped the build
    } else {
        return detail::hkdf_engine<Backend, Hmac>::extract(salt, ikm);
    }
}

/**
 HKDF-Expand (RFC 5869, section 2.3): fills `output` from `prk` and `info`.

 @tparam Hmac The hmac. @tparam Backend The backend.
 @param output The output keying material, 1 to 255 times the digest size.
 @param prk The pseudorandom key, of exactly the digest size.
 @param info The context, at most `hkdf_max_info_size` bytes.
 @return Success, or the error of the first guard that fails (`invalid_output_size`,
 `invalid_key_size`, `input_too_long`), `output` untouched; or the backend's failure, `output`
 zeroed.
*/
template <class Hmac, class Backend = default_kdf_backend<Hmac>>
boost::system::result<void> hkdf_expand(std::span<std::uint8_t> output,
                                        std::span<std::uint8_t const> prk,
                                        std::span<std::uint8_t const> info) {
    if constexpr (!detail::takes_hmac<Hmac>()) {
        return error::backend_failure;  // unreachable: takes_hmac has stopped the build
    } else {
        // Hash2 1.92 declares no std::tuple_size for digest<N>; its size() is constexpr.
        constexpr std::size_t digest_size = typename Hmac::result_type().size();
        if (output.empty() || output.size() > 255 * digest_size) {
            return error::invalid_output_size;
        }
        if (prk.size() != digest_size) {
            return error::invalid_key_size;
        }
        if (info.size() > hkdf_max_info_size) {
            return error::input_too_long;
        }
        auto done = detail::hkdf_engine<Backend, Hmac>::expand(output, prk, info);
        if (!done) {
            detail::wipe(output);
        }
        return done;
    }
}

/**
 HKDF (RFC 5869, section 2): extract, then expand.

 @tparam Hmac The hmac. @tparam Backend The backend.
 @param output The output keying material, 1 to 255 times the digest size.
 @param salt The salt, any length; empty means `Hmac`'s digest size of zeros.
 @param ikm The input keying material, any length.
 @param info The context, at most `hkdf_max_info_size` bytes.
 @return Success, or the error of the first guard that fails (`invalid_output_size`,
 `input_too_long`), `output` untouched; or the backend's failure, `output` zeroed.
*/
template <class Hmac, class Backend = default_kdf_backend<Hmac>>
boost::system::result<void> hkdf(std::span<std::uint8_t> output, std::span<std::uint8_t const> salt,
                                 std::span<std::uint8_t const> ikm,
                                 std::span<std::uint8_t const> info) {
    if constexpr (!detail::takes_hmac<Hmac>()) {
        return error::backend_failure;  // unreachable: takes_hmac has stopped the build
    } else {
        constexpr std::size_t digest_size = typename Hmac::result_type().size();
        if (output.empty() || output.size() > 255 * digest_size) {
            return error::invalid_output_size;
        }
        if (info.size() > hkdf_max_info_size) {
            return error::input_too_long;
        }
        auto done = detail::hkdf_engine<Backend, Hmac>::extract_and_expand(output, salt, ikm, info);
        if (!done) {
            detail::wipe(output);
        }
        return done;
    }
}

}  // namespace webcpp::hash

#endif  // WEBCPP_HASH_HKDF_HPP
