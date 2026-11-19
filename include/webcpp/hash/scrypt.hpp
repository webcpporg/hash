// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 scrypt, RFC 7914: `scrypt`, on `backends::sodium` (libsodium's
 `crypto_pwhash_scryptsalsa208sha256_ll`, the default) and `backends::openssl` (OpenSSL's
 "SCRYPT", its own memory limit lifted).

 Every guard runs before any work, and a guard's refusal leaves the output as it was; a backend's
 failure zeroes it. The backend allocates the 128 r (N + p) bytes the costs name.

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

 @see "Password hashing", in the guide.
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

 @param cost_n N. @param block_size_r r, at least 1.
 @return Whether RFC 7914 allows N.
*/
constexpr bool scrypt_valid_n(std::uint64_t cost_n, std::uint32_t block_size_r) noexcept {
    if (cost_n < 2 || (cost_n & (cost_n - 1)) != 0) {
        return false;
    }
    // From r = 4 on, 2^(16 r) is past every 64-bit N.
    constexpr std::uint32_t wide_block_size_r = 4;
    return block_size_r >= wide_block_size_r || cost_n < (std::uint64_t{1} << (16U * block_size_r));
}

/**
 The guards of `scrypt` (spec 2.11), then `Backend`'s own limits, without the work: what
 `async_scrypt` checks before it posts the work to another thread.

 @tparam Backend The backend.
 @param output_size The derived key's size. @param password_size The password's size.
 @param salt_size The salt's size. @param cost_parameters The costs.
 @return Success, or the error of the first guard that fails, as `scrypt` returns it.
*/
template <class Backend>
[[nodiscard]] boost::system::result<void> scrypt_guards(
    std::size_t output_size, std::size_t password_size, std::size_t salt_size,
    scrypt_parameters const& cost_parameters) noexcept {
    using engine = scrypt_engine<Backend>;
    using limits = backend_limits<Backend>;
    auto const [cost_n, block_size_r, parallelism_p] = cost_parameters;
    if (output_size == 0 || exceeds(output_size, scrypt_max_output_size)) {
        return error::invalid_output_size;
    }
    if (block_size_r == 0 || parallelism_p == 0 || !scrypt_valid_n(cost_n, block_size_r) ||
        std::uint64_t{block_size_r} * parallelism_p >= scrypt_max_rp) {
        return error::invalid_parameters;
    }
    // 128 r (N + p) bytes must fit size_t: N + p cannot wrap, N being at most 2^63.
    constexpr std::uint64_t block_bytes_count = 128;
    constexpr std::uint64_t size_max = std::numeric_limits<std::size_t>::max();
    if (exceeds(cost_n + parallelism_p, size_max / block_bytes_count / block_size_r)) {
        return error::invalid_parameters;
    }
    // The backend's own limits, where its C interface holds a length in a narrower type, after
    // the spec's.
    if (exceeds(cost_n, engine::limits.n) ||
        exceeds(std::uint64_t{block_size_r} * parallelism_p, engine::limits.rp)) {
        return error::invalid_parameters;
    }
    if (exceeds(output_size, limits::scrypt_output)) {
        return error::invalid_output_size;
    }
    if (exceeds(password_size, limits::scrypt_password) ||
        exceeds(salt_size, limits::scrypt_salt)) {
        return error::input_too_long;
    }
    return {};
}

}  // namespace detail

/**
 scrypt (RFC 7914): fills `output_bytes` from `password_bytes` and `salt_bytes`.

 @tparam Backend The backend; by default @ref default_backend of `kdfs::scrypt` (spec 4.1),
 `backends::sodium`; or `backends::openssl`, named.
 @param output_bytes The derived key, 1 to (2^32 - 1) times 32 bytes; it must not overlap
 `password_bytes` or `salt_bytes`.
 @param password_bytes The password. @param salt_bytes The salt.
 @param cost_parameters The costs.
 @return Success, or the error of the first guard that fails (`invalid_output_size`,
 `invalid_parameters`, `input_too_long`), `output_bytes` untouched; or `errc::not_enough_memory`
 when the 128 r N bytes cannot be allocated, or `backend_failure`, `output_bytes` zeroed.
 @note Each backend's narrower limits are refused as the spec's are: on `backends::sodium` an N
 above 2^32 - 1 (`invalid_parameters`); on `backends::openssl` an r p of 2^24 or more
 (`invalid_parameters`) and a password, salt or output of more than `INT_MAX` bytes.
*/
template <class Backend = default_backend<kdfs::scrypt>>
[[nodiscard]] boost::system::result<void> scrypt(std::span<std::uint8_t> output_bytes,
                                                 std::span<std::uint8_t const> password_bytes,
                                                 std::span<std::uint8_t const> salt_bytes,
                                                 scrypt_parameters const& cost_parameters) {
    auto guarded = detail::scrypt_guards<Backend>(output_bytes.size(), password_bytes.size(),
                                                  salt_bytes.size(), cost_parameters);
    if (!guarded) {
        return guarded;
    }
    auto derive_result = detail::scrypt_engine<Backend>::derive(
        output_bytes, password_bytes, salt_bytes, cost_parameters.n, cost_parameters.r,
        cost_parameters.p);
    if (!derive_result) {
        detail::wipe(output_bytes);
    }
    return derive_result;
}

}  // namespace webcpp::hash

// backends::sodium when the program links libsodium: a program that includes only this header
// gets scrypt's default backend complete here; and backends::openssl when it links OpenSSL.
#ifdef WEBCPP_HASH_HAS_SODIUM
#include <webcpp/hash/backends/sodium.hpp>
#endif
#ifdef WEBCPP_HASH_HAS_OPENSSL
#include <webcpp/hash/backends/openssl.hpp>
#endif

#endif  // WEBCPP_HASH_SCRYPT_HPP
