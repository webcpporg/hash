// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 PBKDF2, RFC 8018: `pbkdf2`, over any Boost.Hash2 hmac whose result is a digest, on the backend
 the call names or on @ref webcpp::hash::default_kdf_backend.

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
#include <webcpp/hash/detail/wipe.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/kdf.hpp>

// The backends the program links, each under its WEBCPP_HASH_HAS_<NAME>: default_kdf_backend
// names only a backend whose engines are visible here. A backend an override names comes in too,
// so that an override of a backend the program does not link stops with its header's message.
#if defined(WEBCPP_HASH_HAS_BEARSSL) || defined(WEBCPP_HASH_DETAIL_OVERRIDES_BEARSSL)
#include <webcpp/hash/backends/bearssl.hpp>
#endif
#if defined(WEBCPP_HASH_HAS_SODIUM) || defined(WEBCPP_HASH_DETAIL_OVERRIDES_SODIUM)
#include <webcpp/hash/backends/sodium.hpp>
#endif
#if defined(WEBCPP_HASH_HAS_OPENSSL) || defined(WEBCPP_HASH_DETAIL_OVERRIDES_OPENSSL)
#include <webcpp/hash/backends/openssl.hpp>
#endif

#include <boost/system/result.hpp>

#include <cstddef>
#include <cstdint>
#include <span>

namespace webcpp::hash {

/**
 PBKDF2 (RFC 8018, section 5.2): fills `output` from `password` and `salt` by `iterations`
 rounds of `Hmac`.

 @tparam Hmac The pseudorandom function, as `hmac_sha2_512`. @tparam Backend The backend.
 @param output The derived key, 1 to (2^32 - 1) times the digest size.
 @param password The password, any bytes the backend takes. @param salt The salt, likewise.
 @param iterations The iteration count, at least 1.
 @return Success, or the error of the first guard that fails (`invalid_output_size`,
 `invalid_iterations`, then the backend's own limits: `invalid_output_size`, `input_too_long`;
 for `backends::openssl` an output, a password or a salt of more than `INT_MAX` bytes), `output`
 untouched; or the backend's failure, `output` zeroed.
*/
template <class Hmac, class Backend = default_kdf_backend<Hmac, kdfs::pbkdf2>>
[[nodiscard]] boost::system::result<void> pbkdf2(std::span<std::uint8_t> output,
                                                 std::span<std::uint8_t const> password,
                                                 std::span<std::uint8_t const> salt,
                                                 std::uint64_t iterations) {
    if constexpr (!detail::takes_hmac<Hmac>()) {
        return error::backend_failure;  // unreachable: takes_hmac has stopped the build
    } else {
        constexpr std::uint64_t digest_size = typename Hmac::result_type().size();
        // RFC 8018 5.2, step 1: dkLen at most (2^32 - 1) * hLen, wider than size_t on wasm32.
        if (output.empty() || detail::exceeds(output.size(), 0xffffffffULL * digest_size)) {
            return error::invalid_output_size;
        }
        if (iterations == 0) {
            return error::invalid_iterations;
        }
        using limits = detail::backend_limits<Backend>;
        if (detail::exceeds(output.size(), limits::pbkdf2_output)) {
            return error::invalid_output_size;
        }
        if (detail::exceeds(password.size(), limits::pbkdf2_password) ||
            detail::exceeds(salt.size(), limits::pbkdf2_salt)) {
            return error::input_too_long;
        }
        auto done =
            detail::pbkdf2_engine<Backend, Hmac>::derive(output, password, salt, iterations);
        if (!done) {
            detail::wipe(output);
        }
        return done;
    }
}

}  // namespace webcpp::hash

#endif  // WEBCPP_HASH_PBKDF2_HPP
