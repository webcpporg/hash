// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 HKDF, RFC 5869: `hkdf_extract`, `hkdf_expand` and `hkdf`, over any Boost.Hash2 hmac whose result
 is a digest, on the backend the call names or on @ref webcpp::hash::default_kdf_backend.

 Every call holds the data-independent-timing guard (`detail::timing_guard`): where the CPU has
 DIT, the call sets it and leaves the thread's state as it found it.

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
#include <webcpp/hash/detail/limits.hpp>
#include <webcpp/hash/detail/timing.hpp>
#include <webcpp/hash/detail/wipe.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/kdf.hpp>

// The backends the program links, each under its WEBCPP_HASH_HAS_<NAME>, so that a call that names
// one finds its engines here; the default, backends::hash2, needs none of them.
#ifdef WEBCPP_HASH_HAS_BEARSSL
#include <webcpp/hash/backends/bearssl.hpp>
#endif
#ifdef WEBCPP_HASH_HAS_SODIUM
#include <webcpp/hash/backends/sodium.hpp>
#endif
#ifdef WEBCPP_HASH_HAS_OPENSSL
#include <webcpp/hash/backends/openssl.hpp>
#endif
#ifdef WEBCPP_HASH_HAS_BOTAN
#include <webcpp/hash/backends/botan.hpp>
#endif

#include <boost/system/result.hpp>

#include <cstddef>
#include <cstdint>
#include <span>

namespace webcpp::hash {

/** The longest info every backend accepts, 32,768 bytes (OpenSSL 3.5's limit). */
inline constexpr std::size_t hkdf_max_info_size = 32768;

namespace detail {

/**
 The guards of `hkdf` (spec 2.8), then `Backend`'s own limits, without the work: what `async_hkdf`
 checks on a backend that completes by itself before it starts the work.

 @tparam Hmac A Boost.Hash2 hmac over a digest. @tparam Backend The backend.
 @param output_size The output's size. @param salt_size The salt's size.
 @param ikm_size The input keying material's size. @param info_size The info's size.
 @return Success, or the error of the first guard that fails, as `hkdf` returns it.
*/
template <class Hmac, class Backend>
[[nodiscard]] boost::system::result<void> hkdf_guards(std::size_t output_size,
                                                      std::size_t salt_size, std::size_t ikm_size,
                                                      std::size_t info_size) noexcept {
    // Hash2 1.92 declares no std::tuple_size for digest<N>; its size() is constexpr.
    constexpr std::size_t digest_length = typename Hmac::result_type().size();
    if (output_size == 0 || output_size > 255 * digest_length) {
        return error::invalid_output_size;
    }
    if (info_size > hkdf_max_info_size) {
        return error::input_too_long;
    }
    using limits = backend_limits<Backend>;
    if (exceeds(output_size, limits::hkdf_output)) {
        return error::invalid_output_size;
    }
    if (exceeds(salt_size, limits::hkdf_salt) || exceeds(ikm_size, limits::hkdf_ikm) ||
        exceeds(info_size, limits::hkdf_info)) {
        return error::input_too_long;
    }
    return {};
}

}  // namespace detail

/**
 HKDF-Extract (RFC 5869, section 2.2): the pseudorandom key of `ikm_bytes` under `salt_bytes`.

 @tparam Hmac The hmac, as `hmac_sha2_256`. @tparam Backend The backend; by default the one
 `default_kdf_backend<Hmac, kdfs::hkdf_extract>` names, `backends::hash2`.
 @param salt_bytes The salt, any length the backend takes; empty means `Hmac`'s digest size of
 zeros.
 @param ikm_bytes The input keying material, any length the backend takes.
 @return The pseudorandom key, an `Hmac::result_type` of the hmac's digest size; or
 `input_too_long` for a salt or an IKM longer than the backend takes (`backends::openssl`: a salt
 of more than `INT_MAX` bytes); or the backend's failure.
*/
template <class Hmac, class Backend = default_kdf_backend<Hmac, kdfs::hkdf_extract>>
[[nodiscard]] boost::system::result<typename detail::hmac_result<Hmac>::type> hkdf_extract(
    std::span<std::uint8_t const> salt_bytes, std::span<std::uint8_t const> ikm_bytes) {
    detail::timing_guard const timing;
    if constexpr (!detail::takes_hmac<Hmac>()) {
        return error::backend_failure;  // unreachable: takes_hmac has stopped the build
    } else {
        using limits = detail::backend_limits<Backend>;
        if (detail::exceeds(salt_bytes.size(), limits::hkdf_salt) ||
            detail::exceeds(ikm_bytes.size(), limits::hkdf_ikm)) {
            return error::input_too_long;
        }
        return detail::hkdf_engine<Backend, Hmac>::extract(salt_bytes, ikm_bytes);
    }
}

/**
 HKDF-Expand (RFC 5869, section 2.3): fills `output_bytes` from `prk_bytes` and `info_bytes`.

 @tparam Hmac The hmac. @tparam Backend The backend; by default the one
 `default_kdf_backend<Hmac, kdfs::hkdf_expand>` names, `backends::hash2`.
 @param output_bytes The output keying material, 1 to 255 times the digest size.
 @param prk_bytes The pseudorandom key, of exactly the digest size.
 @param info_bytes The context, at most `hkdf_max_info_size` bytes.
 @return Success, or the error of the first guard that fails (`invalid_output_size`,
 `invalid_key_size`, `input_too_long`, then the backend's own limits: `invalid_output_size`,
 `input_too_long`), `output_bytes` untouched; or the backend's failure, `output_bytes` zeroed.
*/
template <class Hmac, class Backend = default_kdf_backend<Hmac, kdfs::hkdf_expand>>
[[nodiscard]] boost::system::result<void> hkdf_expand(std::span<std::uint8_t> output_bytes,
                                                      std::span<std::uint8_t const> prk_bytes,
                                                      std::span<std::uint8_t const> info_bytes) {
    detail::timing_guard const timing;
    if constexpr (!detail::takes_hmac<Hmac>()) {
        return error::backend_failure;  // unreachable: takes_hmac has stopped the build
    } else {
        // Hash2 1.92 declares no std::tuple_size for digest<N>; its size() is constexpr.
        constexpr std::size_t digest_length = typename Hmac::result_type().size();
        if (output_bytes.empty() || output_bytes.size() > 255 * digest_length) {
            return error::invalid_output_size;
        }
        if (prk_bytes.size() != digest_length) {
            return error::invalid_key_size;
        }
        if (info_bytes.size() > hkdf_max_info_size) {
            return error::input_too_long;
        }
        using limits = detail::backend_limits<Backend>;
        if (detail::exceeds(output_bytes.size(), limits::hkdf_output)) {
            return error::invalid_output_size;
        }
        if (detail::exceeds(prk_bytes.size(), limits::hkdf_prk) ||
            detail::exceeds(info_bytes.size(), limits::hkdf_info)) {
            return error::input_too_long;
        }
        auto derive_result =
            detail::hkdf_engine<Backend, Hmac>::expand(output_bytes, prk_bytes, info_bytes);
        if (!derive_result) {
            detail::wipe(output_bytes);
        }
        return derive_result;
    }
}

/**
 HKDF (RFC 5869, section 2): extract, then expand.

 @tparam Hmac The hmac. @tparam Backend The backend.
 @param output_bytes The output keying material, 1 to 255 times the digest size.
 @param salt_bytes The salt, any length the backend takes; empty means `Hmac`'s digest size of
 zeros.
 @param ikm_bytes The input keying material, any length the backend takes.
 @param info_bytes The context, at most `hkdf_max_info_size` bytes.
 @return Success, or the error of the first guard that fails (`invalid_output_size`,
 `input_too_long`, then the backend's own limits: `invalid_output_size`, `input_too_long`; for
 `backends::openssl` a salt of more than `INT_MAX` bytes), `output_bytes` untouched; or the
 backend's failure, `output_bytes` zeroed.
*/
template <class Hmac, class Backend = default_kdf_backend<Hmac>>
[[nodiscard]] boost::system::result<void> hkdf(std::span<std::uint8_t> output_bytes,
                                               std::span<std::uint8_t const> salt_bytes,
                                               std::span<std::uint8_t const> ikm_bytes,
                                               std::span<std::uint8_t const> info_bytes) {
    detail::timing_guard const timing;
    if constexpr (!detail::takes_hmac<Hmac>()) {
        return error::backend_failure;  // unreachable: takes_hmac has stopped the build
    } else {
        auto guarded = detail::hkdf_guards<Hmac, Backend>(output_bytes.size(), salt_bytes.size(),
                                                          ikm_bytes.size(), info_bytes.size());
        if (!guarded) {
            return guarded;
        }
        auto derive_result = detail::hkdf_engine<Backend, Hmac>::extract_and_expand(
            output_bytes, salt_bytes, ikm_bytes, info_bytes);
        if (!derive_result) {
            detail::wipe(output_bytes);
        }
        return derive_result;
    }
}

}  // namespace webcpp::hash

#endif  // WEBCPP_HASH_HKDF_HPP
