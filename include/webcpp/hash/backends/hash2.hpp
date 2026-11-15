// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `backends::hash2`: HKDF (RFC 5869) and PBKDF2 (RFC 8018) written by webcpp over Boost.Hash2's
 `hmac<H>`, on every target and over every Hash2 hmac whose result is a digest. It needs no C
 library.

 The code follows each RFC's steps, named in its comments, and wipes every intermediate (each
 copy of the keyed hmac, each block) before it returns (spec sections 1.3 and 6.1).
*/
#ifndef WEBCPP_HASH_BACKENDS_HASH2_HPP
#define WEBCPP_HASH_BACKENDS_HASH2_HPP

#include <webcpp/hash/config.hpp>

#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/detail/wipe.hpp>

#include <boost/system/result.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

namespace webcpp::hash::backends {

/** webcpp's own HKDF and PBKDF2 over Boost.Hash2's `hmac<H>`, on every target. */
struct hash2 {};

}  // namespace webcpp::hash::backends

namespace webcpp::hash::detail {

/**
 HKDF on backends::hash2 (the engine's interface: @ref hkdf_engine).

 @tparam Hmac A Boost.Hash2 hmac over a digest.
*/
template <class Hmac>
struct hkdf_engine<backends::hash2, Hmac> {
    /** The hmac's result, a `digest<N>`: the PRK and each block T(i). */
    using digest_type = typename Hmac::result_type;

    /**
     RFC 5869, 2.2: PRK = HMAC-Hash(salt, IKM). An empty salt is HashLen zeros, which Hash2's
     hmac keys as zeros of the block, the same key.

     @param salt The salt. @param ikm The input keying material.
     @return The PRK.
    */
    static boost::system::result<digest_type> extract(std::span<std::uint8_t const> salt,
                                                      std::span<std::uint8_t const> ikm) noexcept {
        Hmac mac(salt.data(), salt.size());
        mac.update(ikm.data(), ikm.size());
        // Built in the result returned, so that no copy of the PRK is left behind.
        boost::system::result<digest_type> prk(boost::system::in_place_value, mac.result());
        wipe_object(mac);
        return prk;
    }

    /**
     RFC 5869, 2.3: T(0) = empty; T(i) = HMAC-Hash(PRK, T(i-1) | info | i); OKM = the first L
     octets of T(1) | T(2) | ... | T(N), N = ceil(L/HashLen).

     @param output The OKM, its size L. @param prk The PRK. @param info The info.
     @return Success.
    */
    static boost::system::result<void> expand(std::span<std::uint8_t> output,
                                              std::span<std::uint8_t const> prk,
                                              std::span<std::uint8_t const> info) noexcept {
        Hmac keyed(prk.data(), prk.size());  // not const: it is wiped at the end
        digest_type t{};
        std::size_t written = 0;
        for (unsigned counter = 1; written < output.size(); ++counter) {
            Hmac mac = keyed;
            if (counter > 1) {
                mac.update(t.data(), t.size());
            }
            mac.update(info.data(), info.size());
            const auto octet = static_cast<unsigned char>(counter);
            mac.update(&octet, 1);
            t = mac.result();
            wipe_object(mac);
            const std::size_t n = std::min(t.size(), output.size() - written);
            std::memcpy(output.data() + written, t.data(), n);
            written += n;
        }
        wipe_object(t);
        wipe_object(keyed);
        return {};
    }

    /**
     RFC 5869, 2: HKDF-Extract, then HKDF-Expand; the PRK is wiped.

     @param output The OKM. @param salt The salt. @param ikm The input keying material.
     @param info The info.
     @return Success.
    */
    static boost::system::result<void> extract_and_expand(
        std::span<std::uint8_t> output, std::span<std::uint8_t const> salt,
        std::span<std::uint8_t const> ikm, std::span<std::uint8_t const> info) noexcept {
        auto prk = extract(salt, ikm);
        auto done = expand(output, std::span<std::uint8_t const>(prk->data(), prk->size()), info);
        wipe_object(*prk);
        return done;
    }
};

}  // namespace webcpp::hash::detail

#endif  // WEBCPP_HASH_BACKENDS_HASH2_HPP
