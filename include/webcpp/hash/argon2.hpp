// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 Argon2id, RFC 9106: `argon2id`, version 0x13 with one lane, no secret and no associated data, on
 `backends::sodium` (libsodium's `crypto_pwhash_argon2id`), with libsodium's three presets; and the
 family `argon2` (spec 2.15): Argon2d, Argon2i and Argon2id with every parameter of RFC 9106, on the
 backends that have each (from increment 2, Argon2i on libsodium with one lane; from increment 4,
 every parameter on OpenSSL).

 Every guard runs before any work, and a guard's refusal leaves the output as it was; a backend's
 failure zeroes it. libsodium allocates the memory the costs name.

 @code
 // password: std::span<std::uint8_t const>; salt: 16 random bytes, stored with the tag
 std::array<std::uint8_t, 32> tag{};
 auto done = webcpp::hash::argon2id(tag, password, salt, webcpp::hash::argon2id_moderate);
 if (!done) {
     return done.error();  // tag is as it was, or zeroed when the backend failed
 }
 @endcode

 Tip: on Emscripten the memory grows to what the costs name; `/third_party//sodium` links its
 programs with `-sALLOW_MEMORY_GROWTH=1` for that reason.

 @see "Password hashing", in the guide.
*/
#ifndef WEBCPP_HASH_ARGON2_HPP
#define WEBCPP_HASH_ARGON2_HPP

#include <webcpp/hash/config.hpp>

#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/detail/limits.hpp>
#include <webcpp/hash/detail/wipe.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/kdf.hpp>

#include <boost/system/result.hpp>

#include <cstddef>
#include <cstdint>
#include <span>

namespace webcpp::hash {

/**
 The costs of Argon2id with one lane, as libsodium's crypto_pwhash takes them, for `argon2id`. Its
 memory is in bytes; @ref argon2_parameters, the family's, counts KiB as RFC 9106 does.
*/
struct argon2id_parameters {
    /** The number of passes over the memory, t: 1 to 4,294,967,295. */
    std::uint64_t passes;
    /**
     The memory in bytes, m times 1,024: at least 8,192, a multiple of 1,024, at most 4 TiB less
     1 KiB (2 GiB on wasm32).
    */
    std::size_t memory;
};

/** libsodium's interactive costs: 2 passes over 64 MiB. */
inline constexpr argon2id_parameters argon2id_interactive{.passes = 2, .memory = 67108864};
/** libsodium's moderate costs: 3 passes over 256 MiB. */
inline constexpr argon2id_parameters argon2id_moderate{.passes = 3, .memory = 268435456};
/** libsodium's sensitive costs: 4 passes over 1 GiB. */
inline constexpr argon2id_parameters argon2id_sensitive{.passes = 4, .memory = 1073741824};

/** The salt's size, 16 bytes. */
inline constexpr std::size_t argon2id_salt_size = 16;

namespace detail {

/** The shortest tag, 16 bytes (RFC 9106 allows 4; libsodium's `BYTES_MIN`). */
inline constexpr std::size_t argon2id_min_output_size = 16;
/** The longest tag and the longest password, 2^32 - 1 bytes (RFC 9106, section 3.1). */
inline constexpr std::uint64_t argon2id_max_size = 0xffffffffULL;
/** The fewest passes. */
inline constexpr std::uint64_t argon2id_min_passes = 1;
/** The most passes, 2^32 - 1 (RFC 9106, section 3.1). */
inline constexpr std::uint64_t argon2id_max_passes = 0xffffffffULL;
/** The least memory, 8 KiB: 8 blocks of 1 KiB for one lane (RFC 9106, section 3.1). */
inline constexpr std::size_t argon2id_min_memory = 8192;
/** The memory's unit, a block of 1 KiB. */
inline constexpr std::size_t argon2id_memory_unit = 1024;

/**
 The guards of `argon2id` (spec 2.10), then `Backend`'s own limits, without the work: what
 `async_argon2id` checks before it posts the work to another thread.

 @tparam Backend The backend.
 @param output_size The tag's size. @param password_size The password's size.
 @param salt_size The salt's size. @param cost_parameters The costs.
 @return Success, or the error of the first guard that fails, as `argon2id` returns it.
*/
template <class Backend>
[[nodiscard]] boost::system::result<void> argon2id_guards(
    std::size_t output_size, std::size_t password_size, std::size_t salt_size,
    argon2id_parameters const& cost_parameters) noexcept {
    using engine = argon2id_engine<Backend>;
    using limits = backend_limits<Backend>;
    if (output_size < argon2id_min_output_size || exceeds(output_size, argon2id_max_size)) {
        return error::invalid_output_size;
    }
    if (salt_size != argon2id_salt_size) {
        return error::invalid_salt_size;
    }
    if (exceeds(password_size, argon2id_max_size)) {
        return error::input_too_long;
    }
    if (cost_parameters.passes < argon2id_min_passes ||
        cost_parameters.passes > argon2id_max_passes) {
        return error::invalid_parameters;
    }
    // A memory that is not a whole number of blocks is refused: libsodium would round it down.
    if (cost_parameters.memory < argon2id_min_memory ||
        cost_parameters.memory % argon2id_memory_unit != 0 ||
        exceeds(cost_parameters.memory, engine::limits.memory)) {
        return error::invalid_parameters;
    }
    // The backend's own limits, where its C interface holds a length in a narrower type, after
    // the spec's.
    if (exceeds(output_size, limits::argon2id_output)) {
        return error::invalid_output_size;
    }
    if (exceeds(password_size, limits::argon2id_password) ||
        exceeds(salt_size, limits::argon2id_salt)) {
        return error::input_too_long;
    }
    return {};
}

}  // namespace detail

/**
 Argon2id version 0x13 (RFC 9106) with one lane, no secret and no associated data: fills
 `output_bytes` from `password_bytes` and `salt_bytes`.

 @tparam Backend The backend; by default @ref default_backend of `kdfs::argon2id` (spec 4.1),
 `backends::sodium`, the only one that has it.
 @param output_bytes The tag, 16 to 4,294,967,295 bytes; it must not overlap `password_bytes` or
 `salt_bytes` (libsodium zeroes it before it reads them).
 @param password_bytes The password, at most 4,294,967,295 bytes.
 @param salt_bytes The salt, of `argon2id_salt_size` bytes.
 @param cost_parameters The costs.
 @return Success, or the error of the first guard that fails (`invalid_output_size`,
 `invalid_salt_size`, `input_too_long`, `invalid_parameters`), `output_bytes` untouched; or
 `errc::not_enough_memory` when the memory cannot be allocated, or `backend_failure`, `output_bytes`
 zeroed.
*/
template <class Backend = default_backend<kdfs::argon2id>>
[[nodiscard]] boost::system::result<void> argon2id(std::span<std::uint8_t> output_bytes,
                                                   std::span<std::uint8_t const> password_bytes,
                                                   std::span<std::uint8_t const> salt_bytes,
                                                   argon2id_parameters const& cost_parameters) {
    auto guarded = detail::argon2id_guards<Backend>(output_bytes.size(), password_bytes.size(),
                                                    salt_bytes.size(), cost_parameters);
    if (!guarded) {
        return guarded;
    }
    auto derive_result = detail::argon2id_engine<Backend>::derive(
        output_bytes, password_bytes, salt_bytes, cost_parameters.passes, cost_parameters.memory);
    if (!derive_result) {
        detail::wipe(output_bytes);
    }
    return derive_result;
}

/**
 Every parameter of Argon2, RFC 9106, for the family `argon2`. The memory is in KiB, RFC 9106's m
 (@ref argon2id_parameters, `argon2id`'s, counts bytes: `argon2id_moderate`'s 268,435,456 bytes are
 262,144 KiB).

 A backend that lacks a parameter's value answers `unsupported_by_backend` (libsodium: one lane, no
 secret, no associated data, at least 3 passes for Argon2i).
*/
struct argon2_parameters {
    /** The number of passes over the memory, t: at least 1. */
    std::uint32_t passes;
    /** The memory in KiB, m: at least 8 times the lanes. */
    std::uint32_t memory_kib;
    /** The degree of parallelism, p: 1 to 16,777,215. */
    std::uint32_t lanes = 1;
    /** The secret, K (a pepper): at most 4,294,967,295 bytes, empty for none. */
    std::span<std::uint8_t const> secret = {};
    /** The associated data, X: at most 4,294,967,295 bytes, empty for none. */
    std::span<std::uint8_t const> associated_data = {};
};

namespace detail {

/** The most lanes, 2^24 - 1 (RFC 9106, section 3.1). */
inline constexpr std::uint32_t argon2_max_lanes = 0xffffffU;
/** The memory per lane at least, 8 KiB: m is at least 8p (RFC 9106, section 3.1). */
inline constexpr std::uint64_t argon2_min_memory_kib_per_lane = 8;
/** The shortest tag, 4 bytes (RFC 9106, section 3.1). */
inline constexpr std::uint64_t argon2_min_output = 4;
/** The shortest salt, 8 bytes (RFC 9106, section 3.1). */
inline constexpr std::uint64_t argon2_min_salt = 8;

/**
 The backend's limits within RFC 9106's: whether `Engine` takes these values.

 @param output_size The tag's size. @param salt_size The salt's size.
 @param parameters The parameters.
 @return Whether the engine's `limits` hold them all.
*/
template <class Engine>
bool argon2_engine_takes(std::size_t output_size, std::size_t salt_size,
                         argon2_parameters const& parameters) noexcept {
    // Each bound through exceeds: a limit at the type's own bound would be a tautology.
    constexpr argon2_limits limits = Engine::limits;
    return !exceeds(limits.min_passes, parameters.passes) &&
           !exceeds(parameters.memory_kib, limits.max_memory_kib) &&
           !exceeds(parameters.lanes, limits.max_lanes) &&
           !exceeds(limits.min_output, output_size) && !exceeds(limits.min_salt, salt_size) &&
           !exceeds(salt_size, limits.max_salt) && (limits.secret || parameters.secret.empty()) &&
           (limits.associated_data || parameters.associated_data.empty());
}

/**
 The guards of `argon2` (RFC 9106), then `Backend`'s own limits (`unsupported_by_backend`),
 without the work: what `async_argon2` checks before it posts the work to another thread.

 @tparam Variant The variant. @tparam Backend The backend.
 @param output_size The tag's size. @param password_size The password's size.
 @param salt_size The salt's size. @param parameters The parameters.
 @return Success, or the error of the first guard that fails, as `argon2` returns it.
*/
template <class Variant, class Backend>
[[nodiscard]] boost::system::result<void> argon2_guards(
    std::size_t output_size, std::size_t password_size, std::size_t salt_size,
    argon2_parameters const& parameters) noexcept {
    using engine = argon2_engine<Backend, Variant>;
    if (exceeds(argon2_min_output, output_size) || exceeds(output_size, argon2id_max_size)) {
        return error::invalid_output_size;
    }
    if (exceeds(argon2_min_salt, salt_size) || exceeds(salt_size, argon2id_max_size)) {
        return error::invalid_salt_size;
    }
    if (exceeds(password_size, argon2id_max_size) ||
        exceeds(parameters.secret.size(), argon2id_max_size) ||
        exceeds(parameters.associated_data.size(), argon2id_max_size)) {
        return error::input_too_long;
    }
    if (parameters.passes < 1 || parameters.lanes < 1 || parameters.lanes > argon2_max_lanes ||
        parameters.memory_kib < argon2_min_memory_kib_per_lane * std::uint64_t{parameters.lanes}) {
        return error::invalid_parameters;
    }
    if (!argon2_engine_takes<engine>(output_size, salt_size, parameters)) {
        return error::unsupported_by_backend;
    }
    return {};
}

}  // namespace detail

/**
 Argon2 version 0x13 (RFC 9106) of the variant `Variant` with every parameter: fills `output` from
 `password` and `salt`.

 Every guard of RFC 9106 runs first, then the backend's own limits (`unsupported_by_backend`), and
 a refusal leaves `output` as it was; a backend's failure zeroes it.

 @tparam Variant `kdfs::argon2id` (recommended for passwords), `kdfs::argon2i` or `kdfs::argon2d`.
 @tparam Backend The backend; by default @ref default_backend of `Variant` (spec 4.1):
 `backends::sodium` for Argon2id and Argon2i, none for Argon2d, which names its backend.
 @param output The tag, 4 to 4,294,967,295 bytes; it must not overlap the inputs.
 @param password The password, at most 4,294,967,295 bytes.
 @param salt The salt, 8 to 4,294,967,295 bytes (16 random bytes are the usual choice).
 @param parameters The costs, the lanes, the secret and the associated data.
 @return Success; or the first guard's error (`invalid_output_size`, `invalid_salt_size`,
 `input_too_long`, `invalid_parameters`, `unsupported_by_backend`), `output` untouched; or
 `errc::not_enough_memory` or `backend_failure`, `output` zeroed.
*/
template <class Variant, class Backend = default_backend<Variant>>
[[nodiscard]] boost::system::result<void> argon2(std::span<std::uint8_t> output,
                                                 std::span<std::uint8_t const> password,
                                                 std::span<std::uint8_t const> salt,
                                                 argon2_parameters const& parameters) {
    auto guarded = detail::argon2_guards<Variant, Backend>(output.size(), password.size(),
                                                           salt.size(), parameters);
    if (!guarded) {
        return guarded;
    }
    auto derived =
        detail::argon2_engine<Backend, Variant>::derive(output, password, salt, parameters);
    if (!derived) {
        detail::wipe(output);
    }
    return derived;
}

}  // namespace webcpp::hash

// backends::sodium when the program links libsodium, after the presets, which its header checks
// against libsodium's macros: a program that includes only this header gets argon2id's default
// backend complete here.
#ifdef WEBCPP_HASH_HAS_SODIUM
#include <webcpp/hash/backends/sodium.hpp>
#endif

#endif  // WEBCPP_HASH_ARGON2_HPP
