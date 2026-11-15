// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 Argon2id, RFC 9106: `argon2id`, version 0x13 with one lane, no secret and no associated data, on
 `backends::sodium` (libsodium's `crypto_pwhash_argon2id`), with libsodium's three presets.

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

/** The costs of Argon2id with one lane, as libsodium's crypto_pwhash takes them. */
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

}  // namespace detail

/**
 Argon2id version 0x13 (RFC 9106) with one lane, no secret and no associated data: fills
 `output_bytes` from `password_bytes` and `salt_bytes`.

 @tparam Backend The backend; by default @ref default_backend of `kdfs::argon2id` (spec 4.1):
 the one an override `WEBCPP_HASH_DEFAULT_BACKEND_ARGON2ID_<NAME>` names, else
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
    using engine = detail::argon2id_engine<Backend>;
    using limits = detail::backend_limits<Backend>;
    if (output_bytes.size() < detail::argon2id_min_output_size ||
        detail::exceeds(output_bytes.size(), detail::argon2id_max_size)) {
        return error::invalid_output_size;
    }
    if (salt_bytes.size() != argon2id_salt_size) {
        return error::invalid_salt_size;
    }
    if (detail::exceeds(password_bytes.size(), detail::argon2id_max_size)) {
        return error::input_too_long;
    }
    if (cost_parameters.passes < detail::argon2id_min_passes ||
        cost_parameters.passes > detail::argon2id_max_passes) {
        return error::invalid_parameters;
    }
    // A memory that is not a whole number of blocks is refused: libsodium would round it down.
    if (cost_parameters.memory < detail::argon2id_min_memory ||
        cost_parameters.memory % detail::argon2id_memory_unit != 0 ||
        detail::exceeds(cost_parameters.memory, engine::limits.memory)) {
        return error::invalid_parameters;
    }
    // The backend's own limits, where its C interface holds a length in a narrower type, after
    // the spec's.
    if (detail::exceeds(output_bytes.size(), limits::argon2id_output)) {
        return error::invalid_output_size;
    }
    if (detail::exceeds(password_bytes.size(), limits::argon2id_password) ||
        detail::exceeds(salt_bytes.size(), limits::argon2id_salt)) {
        return error::input_too_long;
    }
    auto derive_result = engine::derive(output_bytes, password_bytes, salt_bytes,
                                        cost_parameters.passes, cost_parameters.memory);
    if (!derive_result) {
        detail::wipe(output_bytes);
    }
    return derive_result;
}

}  // namespace webcpp::hash

// backends::sodium when the program links libsodium, after the presets, which its header checks
// against libsodium's macros: a program that includes only this header gets argon2id's default
// backend complete here. Also when an override names libsodium, whose header then stops with its
// "needs" message if the program does not link it (spec 5.7).
#if defined(WEBCPP_HASH_HAS_SODIUM) || defined(WEBCPP_HASH_DETAIL_OVERRIDES_SODIUM)
#include <webcpp/hash/backends/sodium.hpp>
#endif

#endif  // WEBCPP_HASH_ARGON2_HPP
