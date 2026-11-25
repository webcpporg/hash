// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 PBKDF2, RFC 8018: `pbkdf2`, over any Boost.Hash2 hmac whose result is a digest, on the backend
 the call names or on @ref webcpp::hash::default_kdf_backend.

 Every call holds the data-independent-timing guard (`webcpp::secure::timing_guard`, secure's
 guard): where the CPU has DIT, the call sets it and leaves the thread's state as it found it.

 Every guard runs before any work, and a guard's refusal leaves the output as it was; a backend's
 failure zeroes it.

 @code
 // password and salt: std::span<std::uint8_t const>
 std::array<std::uint8_t, 64> key{};
 auto done = webcpp::hash::pbkdf2<webcpp::hash::hmac_sha2_512>(key, password, salt, 600000);
 if (!done) {
     return done.error();  // key is as it was, or zeroed when the backend failed
 }
 @endcode

 @see "Key derivation", in the guide.
*/
#ifndef WEBCPP_HASH_PBKDF2_HPP
#define WEBCPP_HASH_PBKDF2_HPP

#include <webcpp/hash/config.hpp>

#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/detail/limits.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/secure/erase_secret.hpp>
#include <webcpp/secure/timing_guard.hpp>

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

namespace detail {

/**
 The guards of `pbkdf2` (spec 2.9), then `Backend`'s own limits, without the work: what
 `async_pbkdf2` checks before it posts the work to another thread.

 @tparam Hmac A Boost.Hash2 hmac over a digest. @tparam Backend The backend.
 @param output_size The derived key's size. @param password_size The password's size.
 @param salt_size The salt's size. @param iteration_count The iteration count.
 @return Success, or the error of the first guard that fails, as `pbkdf2` returns it.
*/
template <class Hmac, class Backend>
[[nodiscard]] boost::system::result<void> pbkdf2_guards(std::size_t output_size,
                                                        std::size_t password_size,
                                                        std::size_t salt_size,
                                                        std::uint64_t iteration_count) noexcept {
    constexpr std::uint64_t digest_length = typename Hmac::result_type().size();
    // RFC 8018 5.2, step 1: dkLen at most (2^32 - 1) * hLen, wider than size_t on wasm32.
    if (output_size == 0 || exceeds(output_size, 0xffffffffULL * digest_length)) {
        return error::invalid_output_size;
    }
    if (iteration_count == 0) {
        return error::invalid_iterations;
    }
    using limits = backend_limits<Backend>;
    if (exceeds(output_size, limits::pbkdf2_output)) {
        return error::invalid_output_size;
    }
    // A backend that derives fewer blocks than RFC 8018's 2^32 - 1 (backends::botan's 2^32 - 2).
    if (exceeds(output_size, pbkdf2_max_blocks<Backend> * digest_length)) {
        return error::invalid_output_size;
    }
    // A specialisation written before pbkdf2_iterations existed has no limit of iterations.
    if constexpr (requires { limits::pbkdf2_iterations; }) {
        if (exceeds(iteration_count, limits::pbkdf2_iterations)) {
            return error::invalid_iterations;
        }
    }
    if (exceeds(password_size, limits::pbkdf2_password) ||
        exceeds(salt_size, limits::pbkdf2_salt)) {
        return error::input_too_long;
    }
    return {};
}

}  // namespace detail

/**
 PBKDF2 (RFC 8018, section 5.2): fills `output_bytes` from `password_bytes` and `salt_bytes` by
 `iteration_count` rounds of `Hmac`.

 @tparam Hmac The pseudorandom function, as `hmac_sha2_512`. @tparam Backend The backend.
 @param output_bytes The derived key, 1 to (2^32 - 1) times the digest size.
 @param password_bytes The password, any bytes the backend takes. @param salt_bytes The salt,
 likewise.
 @param iteration_count The iteration count, at least 1.
 @return Success, or the error of the first guard that fails (`invalid_output_size`,
 `invalid_iterations`, then the backend's own limits: `invalid_output_size`, `invalid_iterations`,
 `input_too_long`;
 for `backends::openssl` an output, a password or a salt of more than `INT_MAX` bytes),
 `output_bytes` untouched; or the backend's failure, `output_bytes` zeroed.
*/
template <class Hmac, class Backend = default_kdf_backend<Hmac, kdfs::pbkdf2>>
[[nodiscard]] boost::system::result<void> pbkdf2(std::span<std::uint8_t> output_bytes,
                                                 std::span<std::uint8_t const> password_bytes,
                                                 std::span<std::uint8_t const> salt_bytes,
                                                 std::uint64_t iteration_count) {
    secure::timing_guard const timing;
    if constexpr (!detail::takes_hmac<Hmac>()) {
        return error::backend_failure;  // unreachable: takes_hmac has stopped the build
    } else {
        auto guarded = detail::pbkdf2_guards<Hmac, Backend>(
            output_bytes.size(), password_bytes.size(), salt_bytes.size(), iteration_count);
        if (!guarded) {
            return guarded;
        }
        auto derive_result = detail::pbkdf2_engine<Backend, Hmac>::derive(
            output_bytes, password_bytes, salt_bytes, iteration_count);
        if (!derive_result) {
            secure::erase_secret(output_bytes);
        }
        return derive_result;
    }
}

}  // namespace webcpp::hash

#endif  // WEBCPP_HASH_PBKDF2_HPP
