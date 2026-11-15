// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `backends::hash2`: HKDF (RFC 5869) and PBKDF2 (RFC 8018) written by webcpp over Boost.Hash2's
 `hmac<H>`, on every target and over every Hash2 hmac whose result is a digest. It needs no C
 library.

 The code follows each RFC's steps, named in its comments, and wipes every intermediate it holds
 (each copy of the keyed hmac, each block) before it returns (spec sections 1.3 and 6.1). What it
 cannot reach is not wiped: Boost.Hash2's own temporaries (the padded key of `hmac`'s constructor,
 the inner digest of its `result()`) and the temporary a digest returned by `result()` may pass
 through before it is stored.
*/
#ifndef WEBCPP_HASH_BACKENDS_HASH2_HPP
#define WEBCPP_HASH_BACKENDS_HASH2_HPP

#include <webcpp/hash/config.hpp>

#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/detail/wipe.hpp>

#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
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
    using digest_type = Hmac::result_type;

    /**
     RFC 5869, 2.2: PRK = HMAC-Hash(salt, IKM). An empty salt is HashLen zeros, which Hash2's
     hmac keys as zeros of the block, the same key.

     @param salt_bytes The salt. @param ikm_bytes The input keying material.
     @return The PRK.
    */
    [[nodiscard]] static boost::system::result<digest_type> extract(
        std::span<std::uint8_t const> salt_bytes,
        std::span<std::uint8_t const> ikm_bytes) noexcept {
        Hmac mac_state(salt_bytes.data(), salt_bytes.size());
        mac_state.update(ikm_bytes.data(), ikm_bytes.size());
        // The PRK is stored in the result returned, whose wiping is the caller's.
        boost::system::result<digest_type> prk_bytes{
            boost::system::in_place_value,
            mac_state.result(),
        };
        wipe_object(mac_state);
        return prk_bytes;
    }

    /**
     RFC 5869, 2.3: T(0) = empty; T(i) = HMAC-Hash(PRK, T(i-1) | info | i); OKM = the first L
     octets of T(1) | T(2) | ... | T(N), N = ceil(L/HashLen).

     @param output_bytes The OKM, its size L. @param prk_bytes The PRK. @param info_bytes The info.
     @return Success.
    */
    [[nodiscard]] static boost::system::result<void> expand(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> prk_bytes,
        std::span<std::uint8_t const> info_bytes) noexcept {
        Hmac keyed_mac(prk_bytes.data(), prk_bytes.size());  // not const: it is wiped at the end
        digest_type t_block{};
        std::size_t written_count = 0;
        for (unsigned block_counter = 1; written_count < output_bytes.size(); ++block_counter) {
            Hmac mac_state = keyed_mac;
            if (block_counter > 1) {
                mac_state.update(t_block.data(), t_block.size());
            }
            mac_state.update(info_bytes.data(), info_bytes.size());
            const auto octet_value = static_cast<unsigned char>(block_counter);
            mac_state.update(&octet_value, 1);
            t_block = mac_state.result();
            wipe_object(mac_state);
            const std::size_t copied_count =
                std::min(t_block.size(), output_bytes.size() - written_count);
            std::memcpy(output_bytes.data() + written_count, t_block.data(), copied_count);
            written_count += copied_count;
        }
        wipe_object(t_block);
        wipe_object(keyed_mac);
        return {};
    }

    /**
     RFC 5869, 2: HKDF-Extract, then HKDF-Expand; the PRK is wiped.

     @param output_bytes The OKM. @param salt_bytes The salt. @param ikm_bytes The input keying
     material.
     @param info_bytes The info.
     @return Success.
    */
    [[nodiscard]] static boost::system::result<void> extract_and_expand(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> salt_bytes,
        std::span<std::uint8_t const> ikm_bytes,
        std::span<std::uint8_t const> info_bytes) noexcept {
        auto prk_bytes = extract(salt_bytes, ikm_bytes);
        if (!prk_bytes) {
            return prk_bytes.error();
        }
        digest_type& prk_digest = prk_bytes.unsafe_value();
        auto derive_result =
            expand(output_bytes,
                   std::span<std::uint8_t const>(prk_digest.data(), prk_digest.size()), info_bytes);
        wipe_object(prk_digest);
        return derive_result;
    }
};

/**
 PBKDF2 on backends::hash2 (the engine's interface: @ref pbkdf2_engine).

 @tparam Hmac A Boost.Hash2 hmac over a digest.
*/
template <class Hmac>
struct pbkdf2_engine<backends::hash2, Hmac> {
    /**
     RFC 8018, 5.2: T_i = F(P, S, c, i) = U_1 ^ U_2 ^ ... ^ U_c, with U_1 = PRF(P, S || INT(i))
     and U_j = PRF(P, U_{j-1}); DK = the first dkLen octets of T_1 || T_2 || ... || T_l.

     @param output_bytes DK, its size dkLen. @param password_bytes P. @param salt_bytes S.
     @param iteration_count c.
     @return Success.
    */
    [[nodiscard]] static boost::system::result<void> derive(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> password_bytes,
        std::span<std::uint8_t const> salt_bytes, std::uint64_t iteration_count) noexcept {
        using digest_type = Hmac::result_type;
        Hmac keyed_mac(password_bytes.data(),
                       password_bytes.size());  // not const: it is wiped at the end
        digest_type u_block{};
        digest_type t_block{};
        std::size_t written_count = 0;
        for (std::uint32_t block_number = 1; written_count < output_bytes.size(); ++block_number) {
            // INT(i): the block's index, four octets, most significant first.
            const std::array<unsigned char, 4> block_index_bytes{
                static_cast<unsigned char>(block_number >> 24U),
                static_cast<unsigned char>(block_number >> 16U),
                static_cast<unsigned char>(block_number >> 8U),
                static_cast<unsigned char>(block_number),
            };
            Hmac mac_state = keyed_mac;
            mac_state.update(salt_bytes.data(), salt_bytes.size());
            mac_state.update(block_index_bytes.data(), block_index_bytes.size());
            u_block = mac_state.result();
            t_block = u_block;
            for (std::uint64_t iteration_index = 1; iteration_index < iteration_count;
                 ++iteration_index) {
                mac_state = keyed_mac;
                mac_state.update(u_block.data(), u_block.size());
                u_block = mac_state.result();
                for (std::size_t byte_index = 0; byte_index < t_block.size(); ++byte_index) {
                    t_block[byte_index] ^= u_block[byte_index];
                }
            }
            wipe_object(mac_state);
            const std::size_t copied_count =
                std::min(t_block.size(), output_bytes.size() - written_count);
            std::memcpy(output_bytes.data() + written_count, t_block.data(), copied_count);
            written_count += copied_count;
        }
        wipe_object(u_block);
        wipe_object(t_block);
        wipe_object(keyed_mac);
        return {};
    }
};

}  // namespace webcpp::hash::detail

#endif  // WEBCPP_HASH_BACKENDS_HASH2_HPP
