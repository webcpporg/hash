// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 HKDF, RFC 5869: `hkdf_extract`, `hkdf_expand` and `hkdf`, over any Boost.Hash2 hmac whose result
 is a digest, on the backend the call names or on @ref webcpp::hash::default_kdf_backend.

 Each has a form over pieces: its input keying material and its application info as
 @ref webcpp::hash::byte_pieces, read one after another as if concatenated, `{a, b, c}` at the
 call, with no cap on either and no buffer of webcpp's (RFC 9180's labeled inputs need no join).
 The single-buffer forms keep `hkdf_max_application_info_size`; the pieces forms refuse only RFC
 5869's sizes. A braced list of one `std::span<std::uint8_t const>`, `{x}`, is that span (the
 language's rule): the single-buffer form. `{}`, or a braced list of one element of another type
 (`{vec}`, `{array}`), in every pieces position is ambiguous between the two forms: pass `x`
 itself, which converts to the span, or write `byte_pieces{...}`, or an empty span.

 Every call holds the data-independent-timing guard (`detail::timing_guard`): where the CPU has
 DIT, the call sets it and leaves the thread's state as it found it.

 Every guard runs before any work, and a guard's refusal leaves the output as it was; a backend's
 failure zeroes it.

 @code
 // salt, input_key_material and application_info: std::span<std::uint8_t const>
 std::array<std::uint8_t, 32> key{};
 auto done = webcpp::hash::hkdf<webcpp::hash::hmac_sha2_256>(key, salt, input_key_material,
                                                             application_info);
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
#include <webcpp/hash/byte_pieces.hpp>
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

/** The longest application info every backend accepts, 32,768 bytes (OpenSSL 3.5's limit). */
inline constexpr std::size_t hkdf_max_application_info_size = 32768;

namespace detail {

/**
 The guards of the single-buffer `hkdf_extract`, without the work: `Backend`'s limits on the salt
 and on the input keying material. `async_hkdf_extract` checks them before its output is written,
 and @ref hkdf_guards after the output's size.

 @tparam Backend The backend. @param salt_size The salt's size.
 @param input_key_material_size The input keying material's size.
 @return Success, or `input_too_long`.
*/
template <class Backend>
[[nodiscard]] boost::system::result<void> hkdf_extract_guards(
    std::size_t salt_size, std::size_t input_key_material_size) noexcept {
    using limits = backend_limits<Backend>;
    if (exceeds(salt_size, limits::hkdf_salt) ||
        exceeds(input_key_material_size, limits::hkdf_input_key_material)) {
        return error::input_too_long;
    }
    return {};
}

/**
 The guards of `hkdf` (spec 2.8), then `Backend`'s own limits, without the work: what `async_hkdf`
 checks on a backend that completes by itself before it starts the work.

 @tparam Hmac A Boost.Hash2 hmac over a digest. @tparam Backend The backend.
 @param output_size The output's size. @param salt_size The salt's size.
 @param input_key_material_size The input keying material's size.
 @param application_info_size The application info's size.
 @return Success, or the error of the first guard that fails, as `hkdf` returns it.
*/
template <class Hmac, class Backend>
[[nodiscard]] boost::system::result<void> hkdf_guards(std::size_t output_size,
                                                      std::size_t salt_size,
                                                      std::size_t input_key_material_size,
                                                      std::size_t application_info_size) noexcept {
    // Hash2 1.92 declares no std::tuple_size for digest<N>; its size() is constexpr.
    constexpr std::size_t digest_length = typename Hmac::result_type().size();
    if (output_size == 0 || output_size > 255 * digest_length) {
        return error::invalid_output_size;
    }
    if (application_info_size > hkdf_max_application_info_size) {
        return error::input_too_long;
    }
    using limits = backend_limits<Backend>;
    if (exceeds(output_size, limits::hkdf_output)) {
        return error::invalid_output_size;
    }
    auto const extract_guarded = hkdf_extract_guards<Backend>(salt_size, input_key_material_size);
    if (!extract_guarded) {
        return extract_guarded;
    }
    if (exceeds(application_info_size, limits::hkdf_application_info)) {
        return error::input_too_long;
    }
    return {};
}

/**
 The guard of HKDF's salt over pieces, the Extract HMAC's key: `Backend`'s HMAC key limit
 (`backend_limits`' `hkdf_salt`, as `backends::openssl`'s `INT_MAX`). `hkdf_extract` over pieces
 calls it alone, `hkdf_pieces_guards` after the output's size.

 @tparam Backend The backend. @param salt_size The salt's size.
 @return Success, or `input_too_long`.
*/
template <class Backend>
[[nodiscard]] boost::system::result<void> hkdf_pieces_salt_guard(std::size_t salt_size) noexcept {
    if (exceeds(salt_size, backend_limits<Backend>::hkdf_salt)) {
        return error::input_too_long;
    }
    return {};
}

/**
 The guards of `hkdf` over pieces and of `hkdf_expand`'s output, without the work: RFC 5869's
 output size, then @ref hkdf_pieces_salt_guard; nothing on the input keying material or the
 application info.

 @tparam Hmac A Boost.Hash2 hmac over a digest. @tparam Backend The backend.
 @param output_size The output's size. @param salt_size The salt's size (0 for `hkdf_expand`).
 @return Success, or the error of the first guard that fails: `invalid_output_size`, then
 `input_too_long`.
*/
template <class Hmac, class Backend>
[[nodiscard]] boost::system::result<void> hkdf_pieces_guards(std::size_t output_size,
                                                             std::size_t salt_size) noexcept {
    // Hash2 1.92 declares no std::tuple_size for digest<N>; its size() is constexpr.
    constexpr std::size_t digest_length = typename Hmac::result_type().size();
    if (output_size == 0 || output_size > 255 * digest_length) {
        return error::invalid_output_size;
    }
    return hkdf_pieces_salt_guard<Backend>(salt_size);
}

}  // namespace detail

/**
 HKDF-Extract (RFC 5869, section 2.2): the pseudorandom key of `input_key_material` under `salt`.

 @tparam Hmac The hmac, as `hmac_sha2_256`. @tparam Backend The backend; by default the one
 `default_kdf_backend<Hmac, kdfs::hkdf_extract>` names, `backends::hash2`.
 @param salt The salt, any length the backend takes; empty means `Hmac`'s digest size of
 zeros.
 @param input_key_material The input keying material, any length the backend takes.
 @return The pseudorandom key, an `Hmac::result_type` of the hmac's digest size; or
 `input_too_long` for a salt or an IKM longer than the backend takes (`backends::openssl`: a salt
 of more than `INT_MAX` bytes); or the backend's failure.
*/
template <class Hmac, class Backend = default_kdf_backend<Hmac, kdfs::hkdf_extract>>
[[nodiscard]] boost::system::result<typename detail::hmac_result<Hmac>::type> hkdf_extract(
    std::span<std::uint8_t const> salt, std::span<std::uint8_t const> input_key_material) {
    detail::timing_guard const timing;
    if constexpr (!detail::takes_hmac<Hmac>()) {
        return error::backend_failure;  // unreachable: takes_hmac has stopped the build
    } else {
        auto const guarded =
            detail::hkdf_extract_guards<Backend>(salt.size(), input_key_material.size());
        if (!guarded) {
            return guarded.error();
        }
        return detail::hkdf_engine<Backend, Hmac>::extract(salt, input_key_material);
    }
}

/**
 HKDF-Expand (RFC 5869, section 2.3): fills `output_key_material` from `pseudorandom_key` and
 `application_info`.

 @tparam Hmac The hmac. @tparam Backend The backend; by default the one
 `default_kdf_backend<Hmac, kdfs::hkdf_expand>` names, `backends::hash2`.
 @param output_key_material The output keying material, 1 to 255 times the digest size.
 @param pseudorandom_key The pseudorandom key, of exactly the digest size.
 @param application_info The context, at most `hkdf_max_application_info_size` bytes.
 @return Success, or the error of the first guard that fails (`invalid_output_size`,
 `invalid_key_size`, `input_too_long`, then the backend's own limits: `invalid_output_size`,
 `input_too_long`), `output_key_material` untouched; or the backend's failure, `output_key_material`
 zeroed.
*/
template <class Hmac, class Backend = default_kdf_backend<Hmac, kdfs::hkdf_expand>>
[[nodiscard]] boost::system::result<void> hkdf_expand(
    std::span<std::uint8_t> output_key_material, std::span<std::uint8_t const> pseudorandom_key,
    std::span<std::uint8_t const> application_info) {
    detail::timing_guard const timing;
    if constexpr (!detail::takes_hmac<Hmac>()) {
        return error::backend_failure;  // unreachable: takes_hmac has stopped the build
    } else {
        // Hash2 1.92 declares no std::tuple_size for digest<N>; its size() is constexpr.
        constexpr std::size_t digest_length = typename Hmac::result_type().size();
        if (output_key_material.empty() || output_key_material.size() > 255 * digest_length) {
            return error::invalid_output_size;
        }
        if (pseudorandom_key.size() != digest_length) {
            return error::invalid_key_size;
        }
        if (application_info.size() > hkdf_max_application_info_size) {
            return error::input_too_long;
        }
        using limits = detail::backend_limits<Backend>;
        if (detail::exceeds(output_key_material.size(), limits::hkdf_output)) {
            return error::invalid_output_size;
        }
        if (detail::exceeds(pseudorandom_key.size(), limits::hkdf_pseudorandom_key) ||
            detail::exceeds(application_info.size(), limits::hkdf_application_info)) {
            return error::input_too_long;
        }
        auto derive_result = detail::hkdf_engine<Backend, Hmac>::expand(
            output_key_material, pseudorandom_key, application_info);
        if (!derive_result) {
            detail::wipe(output_key_material);
        }
        return derive_result;
    }
}

/**
 HKDF (RFC 5869, section 2): extract, then expand.

 @tparam Hmac The hmac. @tparam Backend The backend.
 @param output_key_material The output keying material, 1 to 255 times the digest size.
 @param salt The salt, any length the backend takes; empty means `Hmac`'s digest size of
 zeros.
 @param input_key_material The input keying material, any length the backend takes.
 @param application_info The context, at most `hkdf_max_application_info_size` bytes.
 @return Success, or the error of the first guard that fails (`invalid_output_size`,
 `input_too_long`, then the backend's own limits: `invalid_output_size`, `input_too_long`; for
 `backends::openssl` a salt of more than `INT_MAX` bytes), `output_key_material` untouched; or the
 backend's failure, `output_key_material` zeroed.
*/
template <class Hmac, class Backend = default_kdf_backend<Hmac>>
[[nodiscard]] boost::system::result<void> hkdf(std::span<std::uint8_t> output_key_material,
                                               std::span<std::uint8_t const> salt,
                                               std::span<std::uint8_t const> input_key_material,
                                               std::span<std::uint8_t const> application_info) {
    detail::timing_guard const timing;
    if constexpr (!detail::takes_hmac<Hmac>()) {
        return error::backend_failure;  // unreachable: takes_hmac has stopped the build
    } else {
        auto guarded =
            detail::hkdf_guards<Hmac, Backend>(output_key_material.size(), salt.size(),
                                               input_key_material.size(), application_info.size());
        if (!guarded) {
            return guarded;
        }
        auto derive_result = detail::hkdf_engine<Backend, Hmac>::extract_and_expand(
            output_key_material, salt, input_key_material, application_info);
        if (!derive_result) {
            detail::wipe(output_key_material);
        }
        return derive_result;
    }
}

/**
 HKDF-Extract (RFC 5869, section 2.2) over pieces: the pseudorandom key of the concatenation of
 `input_key_material`'s pieces under `salt`, each piece fed to the backend's HMAC.

 @code
 auto prk = webcpp::hash::hkdf_extract<webcpp::hash::hmac_sha2_256>(salt, {prefix, label, ikm});
 @endcode

 @tparam Hmac The hmac, as `hmac_sha2_256`. @tparam Backend The backend; by default the one
 `default_kdf_backend<Hmac, kdfs::hkdf_extract_pieces>` names, `backends::hash2`.
 @param salt The salt, any length the backend's HMAC takes as a key; empty means `Hmac`'s digest
 size of zeros.
 @param input_key_material The input keying material's pieces, of any number and length.
 @return The pseudorandom key, an `Hmac::result_type` of the hmac's digest size; or
 `input_too_long` for a salt longer than the backend's HMAC takes (`backends::openssl`: more than
 `INT_MAX` bytes); or the backend's failure.
*/
template <class Hmac, class Backend = default_kdf_backend<Hmac, kdfs::hkdf_extract_pieces>>
[[nodiscard]] boost::system::result<typename detail::hmac_result<Hmac>::type> hkdf_extract(
    std::span<std::uint8_t const> salt, byte_pieces input_key_material) {
    detail::timing_guard const timing;
    if constexpr (!detail::takes_hmac<Hmac>()) {
        return error::backend_failure;  // unreachable: takes_hmac has stopped the build
    } else {
        auto const guarded = detail::hkdf_pieces_salt_guard<Backend>(salt.size());
        if (!guarded) {
            return guarded.error();
        }
        return detail::hkdf_pieces_engine<Backend, Hmac>::extract(salt, input_key_material);
    }
}

/**
 HKDF-Expand (RFC 5869, section 2.3) over pieces: fills `output_key_material` from
 `pseudorandom_key` and the concatenation of `application_info`'s pieces, each piece fed to the
 backend's HMAC for each block.

 @tparam Hmac The hmac. @tparam Backend The backend; by default the one
 `default_kdf_backend<Hmac, kdfs::hkdf_expand_pieces>` names, `backends::hash2`.
 @param output_key_material The output keying material, 1 to 255 times the digest size.
 @param pseudorandom_key The pseudorandom key, of exactly the digest size.
 @param application_info The context's pieces, of any number and length: no cap.
 @return Success, or the error of the first guard that fails (`invalid_output_size`,
 `invalid_key_size`), `output_key_material` untouched; or the backend's failure,
 `output_key_material` zeroed.
*/
template <class Hmac, class Backend = default_kdf_backend<Hmac, kdfs::hkdf_expand_pieces>>
[[nodiscard]] boost::system::result<void> hkdf_expand(
    std::span<std::uint8_t> output_key_material, std::span<std::uint8_t const> pseudorandom_key,
    byte_pieces application_info) {
    detail::timing_guard const timing;
    if constexpr (!detail::takes_hmac<Hmac>()) {
        return error::backend_failure;  // unreachable: takes_hmac has stopped the build
    } else {
        auto guarded = detail::hkdf_pieces_guards<Hmac, Backend>(output_key_material.size(), 0);
        if (!guarded) {
            return guarded;
        }
        // Hash2 1.92 declares no std::tuple_size for digest<N>; its size() is constexpr.
        constexpr std::size_t digest_length = typename Hmac::result_type().size();
        if (pseudorandom_key.size() != digest_length) {
            return error::invalid_key_size;
        }
        auto derive_result = detail::hkdf_pieces_engine<Backend, Hmac>::expand(
            output_key_material, pseudorandom_key, application_info);
        if (!derive_result) {
            detail::wipe(output_key_material);
        }
        return derive_result;
    }
}

/**
 HKDF (RFC 5869, section 2) over pieces: extract, then expand, the pseudorandom key wiped between
 them.

 @code
 // RFC 9180's LabeledExtract and LabeledExpand in one call, no buffer joined.
 auto done = webcpp::hash::hkdf<webcpp::hash::hmac_sha2_256>(
     key, salt, {version, suite_id, label, ikm}, {length, version, suite_id, label, info});
 @endcode

 @tparam Hmac The hmac. @tparam Backend The backend; by default the one
 `default_kdf_backend<Hmac, kdfs::hkdf_pieces>` names, `backends::hash2`.
 @param output_key_material The output keying material, 1 to 255 times the digest size.
 @param salt The salt, any length the backend's HMAC takes as a key; empty means `Hmac`'s digest
 size of zeros.
 @param input_key_material The input keying material's pieces, of any number and length.
 @param application_info The context's pieces, of any number and length: no cap.
 @return Success, or the error of the first guard that fails (`invalid_output_size`, then
 `input_too_long` for a salt longer than the backend's HMAC takes), `output_key_material`
 untouched; or the backend's failure, `output_key_material` zeroed.
*/
template <class Hmac, class Backend = default_kdf_backend<Hmac, kdfs::hkdf_pieces>>
[[nodiscard]] boost::system::result<void> hkdf(std::span<std::uint8_t> output_key_material,
                                               std::span<std::uint8_t const> salt,
                                               byte_pieces input_key_material,
                                               byte_pieces application_info) {
    detail::timing_guard const timing;
    if constexpr (!detail::takes_hmac<Hmac>()) {
        return error::backend_failure;  // unreachable: takes_hmac has stopped the build
    } else {
        auto guarded =
            detail::hkdf_pieces_guards<Hmac, Backend>(output_key_material.size(), salt.size());
        if (!guarded) {
            return guarded;
        }
        auto derive_result = detail::hkdf_pieces_engine<Backend, Hmac>::extract_and_expand(
            output_key_material, salt, input_key_material, application_info);
        if (!derive_result) {
            detail::wipe(output_key_material);
        }
        return derive_result;
    }
}

}  // namespace webcpp::hash

#endif  // WEBCPP_HASH_HKDF_HPP
