// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 scrypt, RFC 7914: `scrypt`, on `backends::sodium` (libsodium's
 `crypto_pwhash_scryptsalsa208sha256_ll`).

 Every guard runs before any work, and a guard's refusal leaves the output as it was; a backend's
 failure zeroes it. libsodium allocates the 128 r (N + p) bytes the costs name.

 @code
 // password and salt: std::span<std::uint8_t const>
 std::array<std::uint8_t, 64> key{};
 auto done = webcpp::hash::scrypt(key, password, salt, {.n = 32768, .r = 8, .p = 1});
 if (!done) {
     return done.error();  // key is as it was, or zeroed when the backend failed
 }
 @endcode

 Tip: on Emscripten the memory grows to what the costs name; `/third_party//sodium` links its
 programs with `-sALLOW_MEMORY_GROWTH=1` for that reason.

 @see "Key derivation", in the guide.
*/
#ifndef WEBCPP_HASH_SCRYPT_HPP
#define WEBCPP_HASH_SCRYPT_HPP

#include <webcpp/hash/config.hpp>

#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/detail/limits.hpp>
#include <webcpp/hash/detail/wipe.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/kdf.hpp>

#include <boost/system/result.hpp>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>

namespace webcpp::hash {

/** The costs of scrypt, RFC 7914's N, r and p. */
struct scrypt_parameters {
    /** The CPU and memory cost N: a power of two, greater than 1, less than 2^(16 r). */
    std::uint64_t n;
    /** The block size r, at least 1. */
    std::uint32_t r;
    /** The parallelisation p, at least 1, with r times p below 2^30. */
    std::uint32_t p;
};

namespace detail {

/** The longest output, (2^32 - 1) blocks of 32 bytes (RFC 7914, section 5, through PBKDF2). */
inline constexpr std::uint64_t scrypt_max_output_size = 0xffffffffULL * 32;
/** The bound r p stays below (RFC 7914, section 2: p <= ((2^32 - 1) 32) / (128 r)). */
inline constexpr std::uint64_t scrypt_max_rp = std::uint64_t{1} << 30U;

/**
 Whether N is a power of two above 1 and below 2^(16 r) (RFC 7914, section 2: N < 2^(128 r / 8)).

 @param n N. @param r r, at least 1.
 @return Whether RFC 7914 allows N.
*/
constexpr bool scrypt_valid_n(std::uint64_t n, std::uint32_t r) noexcept {
    if (n < 2 || (n & (n - 1)) != 0) {
        return false;
    }
    // From r = 4 on, 2^(16 r) is past every 64-bit N.
    constexpr std::uint32_t wide_r = 4;
    return r >= wide_r || n < (std::uint64_t{1} << (16U * r));
}

}  // namespace detail

/**
 scrypt (RFC 7914): fills `output` from `password` and `salt`.

 @tparam Backend The backend; by default @ref default_backend of `kdfs::scrypt` (spec 4.1):
 the one an override `WEBCPP_HASH_DEFAULT_BACKEND_SCRYPT_<NAME>` names, else
 `backends::sodium`, the only one that has it.
 @param output The derived key, 1 to (2^32 - 1) times 32 bytes; it must not overlap `password`
 or `salt`.
 @param password The password. @param salt The salt.
 @param parameters The costs.
 @return Success, or the error of the first guard that fails (`invalid_output_size`,
 `invalid_parameters`, `input_too_long`), `output` untouched; or `errc::not_enough_memory` when the
 128 r N bytes cannot be allocated, or `backend_failure`, `output` zeroed.
*/
template <class Backend = default_backend<kdfs::scrypt>>
boost::system::result<void> scrypt(std::span<std::uint8_t> output,
                                   std::span<std::uint8_t const> password,
                                   std::span<std::uint8_t const> salt,
                                   scrypt_parameters const& parameters) {
    using engine = detail::scrypt_engine<Backend>;
    using limits = detail::backend_limits<Backend>;
    auto const [n, r, p] = parameters;
    if (output.empty() || detail::exceeds(output.size(), detail::scrypt_max_output_size)) {
        return error::invalid_output_size;
    }
    if (r == 0 || p == 0 || !detail::scrypt_valid_n(n, r) ||
        std::uint64_t{r} * p >= detail::scrypt_max_rp) {
        return error::invalid_parameters;
    }
    // 128 r (N + p) bytes must fit size_t: N + p cannot wrap, N being at most 2^63.
    constexpr std::uint64_t block = 128;
    constexpr std::uint64_t most = std::numeric_limits<std::size_t>::max();
    if (detail::exceeds(n + p, most / block / r)) {
        return error::invalid_parameters;
    }
    // The backend's own limits, where its C interface holds a length in a narrower type, after
    // the spec's.
    if (detail::exceeds(n, engine::limits.n)) {
        return error::invalid_parameters;
    }
    if (detail::exceeds(output.size(), limits::scrypt_output)) {
        return error::invalid_output_size;
    }
    if (detail::exceeds(password.size(), limits::scrypt_password) ||
        detail::exceeds(salt.size(), limits::scrypt_salt)) {
        return error::input_too_long;
    }
    auto done = engine::derive(output, password, salt, n, r, p);
    if (!done) {
        detail::wipe(output);
    }
    return done;
}

}  // namespace webcpp::hash

// backends::sodium when the program links libsodium: a program that includes only this header
// gets scrypt's default backend complete here. Also when an override names libsodium, whose
// header then stops with its "needs" message if the program does not link it (spec 5.7).
#if defined(WEBCPP_HASH_HAS_SODIUM) || defined(WEBCPP_HASH_DETAIL_OVERRIDES_SODIUM)
#include <webcpp/hash/backends/sodium.hpp>
#endif

#endif  // WEBCPP_HASH_SCRYPT_HPP
