// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `backends::hash2`: HKDF (RFC 5869) and PBKDF2 (RFC 8018) written by webcpp over Boost.Hash2's
 `hmac<H>`, on every target and over every Hash2 hmac whose result is a digest; and the families'
 engines over Boost.Hash2's own algorithms (spec 2.15): the digests MD5, SHA-1, SHA-2, SHA-3,
 RIPEMD-160 and BLAKE2s-256, BLAKE2b with its 64-byte output alone, SHAKE128 and SHAKE256 with
 any output size (each Hash2 `result()` permutes and gives the next block of the stream); HMAC
 over each fixed-size digest and over BLAKE2b-512; SipHash-2-4; and keyed BLAKE2s with its 32-byte
 tag alone. It needs no C library.

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

#include <boost/hash2/blake2.hpp>
#include <boost/hash2/hmac.hpp>
#include <boost/hash2/md5.hpp>
#include <boost/hash2/ripemd.hpp>
#include <boost/hash2/sha1.hpp>
#include <boost/hash2/sha2.hpp>
#include <boost/hash2/sha3.hpp>
#include <boost/hash2/siphash.hpp>
#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

namespace webcpp::hash::backends {

/**
 Boost.Hash2, on every target: webcpp's own HKDF and PBKDF2 over its `hmac<H>`, and the families'
 engines (`digest_of`, `hasher`, `mac`) over its algorithms.
*/
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

     @param salt The salt. @param input_key_material The input keying material.
     @return The PRK.
    */
    [[nodiscard]] static boost::system::result<digest_type> extract(
        std::span<std::uint8_t const> salt,
        std::span<std::uint8_t const> input_key_material) noexcept {
        Hmac mac_state(salt.data(), salt.size());
        mac_state.update(input_key_material.data(), input_key_material.size());
        // The PRK is stored in the result returned, whose wiping is the caller's.
        boost::system::result<digest_type> pseudorandom_key{
            boost::system::in_place_value,
            mac_state.result(),
        };
        wipe_object(mac_state);
        return pseudorandom_key;
    }

    /**
     RFC 5869, 2.3: T(0) = empty; T(i) = HMAC-Hash(PRK, T(i-1) | info | i); OKM = the first L
     octets of T(1) | T(2) | ... | T(N), N = ceil(L/HashLen).

     @param output_key_material The OKM, its size L. @param pseudorandom_key The PRK. @param
     application_info The info.
     @return Success.
    */
    [[nodiscard]] static boost::system::result<void> expand(
        std::span<std::uint8_t> output_key_material, std::span<std::uint8_t const> pseudorandom_key,
        std::span<std::uint8_t const> application_info) noexcept {
        Hmac keyed_mac(pseudorandom_key.data(),
                       pseudorandom_key.size());  // not const: it is wiped at the end
        digest_type t_block{};
        std::size_t written_count = 0;
        for (unsigned block_counter = 1; written_count < output_key_material.size();
             ++block_counter) {
            Hmac mac_state = keyed_mac;
            if (block_counter > 1) {
                mac_state.update(t_block.data(), t_block.size());
            }
            mac_state.update(application_info.data(), application_info.size());
            const auto octet_value = static_cast<unsigned char>(block_counter);
            mac_state.update(&octet_value, 1);
            t_block = mac_state.result();
            wipe_object(mac_state);
            const std::size_t copied_count =
                std::min(t_block.size(), output_key_material.size() - written_count);
            std::memcpy(output_key_material.data() + written_count, t_block.data(), copied_count);
            written_count += copied_count;
        }
        wipe_object(t_block);
        wipe_object(keyed_mac);
        return {};
    }

    /**
     RFC 5869, 2: HKDF-Extract, then HKDF-Expand; the PRK is wiped.

     @param output_key_material The OKM. @param salt The salt. @param input_key_material The input
     keying material.
     @param application_info The info.
     @return Success.
    */
    [[nodiscard]] static boost::system::result<void> extract_and_expand(
        std::span<std::uint8_t> output_key_material, std::span<std::uint8_t const> salt,
        std::span<std::uint8_t const> input_key_material,
        std::span<std::uint8_t const> application_info) noexcept {
        auto pseudorandom_key = extract(salt, input_key_material);
        if (!pseudorandom_key) {
            return pseudorandom_key.error();
        }
        digest_type& pseudorandom_key_digest = pseudorandom_key.unsafe_value();
        auto derive_result = expand(output_key_material,
                                    std::span<std::uint8_t const>(pseudorandom_key_digest.data(),
                                                                  pseudorandom_key_digest.size()),
                                    application_info);
        wipe_object(pseudorandom_key_digest);
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

/**
 A digest of `digests` on backends::hash2, over the Boost.Hash2 algorithm `Hash` (its interface is
 @ref digest_engine); the state is a `Hash`, wiped by `destroy`. The output is the first
 `output.size()` bytes of the results of `result()`, called one after the other: one result, the
 whole of it, for a fixed-size digest, which the family's guards hold to its size; for SHAKE, whose
 every `result()` permutes and gives the next block of the stream, as many blocks as the output
 needs.

 @tparam Digest The tag. @tparam Hash Its Boost.Hash2 algorithm.
*/
template <class Digest, class Hash>
struct hash2_digest_engine : full_engine {
    /** The Hash2 algorithm, which is all of the state. */
    using state = Hash;

    /** Starts a hash. @param hashed The state. @return Success. */
    [[nodiscard]] static boost::system::result<void> init(
        state& hashed, digest_options<Digest> const& /*options*/) noexcept {
        hashed = Hash();
        return {};
    }

    /** Absorbs `input`. @param hashed The state. @param input The bytes. @return Success. */
    [[nodiscard]] static boost::system::result<void> update(
        state& hashed, std::span<std::uint8_t const> input) noexcept {
        hashed.update(input.data(), input.size());
        return {};
    }

    /**
     Writes the first `output.size()` bytes of the successive results, each result wiped.

     @param hashed The state. @param output The digest. @return Success.
    */
    [[nodiscard]] static boost::system::result<void> finish(
        state& hashed, std::span<std::uint8_t> output) noexcept {
        while (!output.empty()) {
            auto result_bytes = hashed.result();
            auto const taken = std::min(output.size(), result_bytes.size());
            std::memcpy(output.data(), result_bytes.data(), taken);
            wipe_object(result_bytes);
            output = output.subspan(taken);
        }
        return {};
    }

    /** Wipes the state. @param hashed The state. */
    static void destroy(state& hashed) noexcept { wipe_object(hashed); }

    /**
     The hash of `input` at once, the state wiped.

     @param output The digest. @param input The bytes. @param options None.
     @return Success.
    */
    [[nodiscard]] static boost::system::result<void> one_shot(
        std::span<std::uint8_t> output, std::span<std::uint8_t const> input,
        digest_options<Digest> const& options) noexcept {
        state hashed;
        static_cast<void>(init(hashed, options));
        static_cast<void>(update(hashed, input));
        static_cast<void>(finish(hashed, output));
        destroy(hashed);
        return {};
    }
};

/** `digests::md5` on backends::hash2: Boost.Hash2's `md5_128`. */
template <>
struct digest_engine<backends::hash2, digests::md5>
    : hash2_digest_engine<digests::md5, boost::hash2::md5_128> {};

/** `digests::sha1` on backends::hash2: Boost.Hash2's `sha1_160`. */
template <>
struct digest_engine<backends::hash2, digests::sha1>
    : hash2_digest_engine<digests::sha1, boost::hash2::sha1_160> {};

/** `digests::sha2_224` on backends::hash2: Boost.Hash2's `sha2_224`. */
template <>
struct digest_engine<backends::hash2, digests::sha2_224>
    : hash2_digest_engine<digests::sha2_224, boost::hash2::sha2_224> {};

/** `digests::sha2_256` on backends::hash2: Boost.Hash2's `sha2_256`. */
template <>
struct digest_engine<backends::hash2, digests::sha2_256>
    : hash2_digest_engine<digests::sha2_256, boost::hash2::sha2_256> {};

/** `digests::sha2_384` on backends::hash2: Boost.Hash2's `sha2_384`. */
template <>
struct digest_engine<backends::hash2, digests::sha2_384>
    : hash2_digest_engine<digests::sha2_384, boost::hash2::sha2_384> {};

/** `digests::sha2_512` on backends::hash2: Boost.Hash2's `sha2_512`. */
template <>
struct digest_engine<backends::hash2, digests::sha2_512>
    : hash2_digest_engine<digests::sha2_512, boost::hash2::sha2_512> {};

/** `digests::sha2_512_224` on backends::hash2: Boost.Hash2's `sha2_512_224`. */
template <>
struct digest_engine<backends::hash2, digests::sha2_512_224>
    : hash2_digest_engine<digests::sha2_512_224, boost::hash2::sha2_512_224> {};

/** `digests::sha2_512_256` on backends::hash2: Boost.Hash2's `sha2_512_256`. */
template <>
struct digest_engine<backends::hash2, digests::sha2_512_256>
    : hash2_digest_engine<digests::sha2_512_256, boost::hash2::sha2_512_256> {};

/** `digests::sha3_224` on backends::hash2: Boost.Hash2's `sha3_224`. */
template <>
struct digest_engine<backends::hash2, digests::sha3_224>
    : hash2_digest_engine<digests::sha3_224, boost::hash2::sha3_224> {};

/** `digests::sha3_256` on backends::hash2: Boost.Hash2's `sha3_256`. */
template <>
struct digest_engine<backends::hash2, digests::sha3_256>
    : hash2_digest_engine<digests::sha3_256, boost::hash2::sha3_256> {};

/** `digests::sha3_384` on backends::hash2: Boost.Hash2's `sha3_384`. */
template <>
struct digest_engine<backends::hash2, digests::sha3_384>
    : hash2_digest_engine<digests::sha3_384, boost::hash2::sha3_384> {};

/** `digests::sha3_512` on backends::hash2: Boost.Hash2's `sha3_512`. */
template <>
struct digest_engine<backends::hash2, digests::sha3_512>
    : hash2_digest_engine<digests::sha3_512, boost::hash2::sha3_512> {};

/** `digests::ripemd_160` on backends::hash2: Boost.Hash2's `ripemd_160`. */
template <>
struct digest_engine<backends::hash2, digests::ripemd_160>
    : hash2_digest_engine<digests::ripemd_160, boost::hash2::ripemd_160> {};

/** `digests::blake2s_256` on backends::hash2: Boost.Hash2's `blake2s_256`. */
template <>
struct digest_engine<backends::hash2, digests::blake2s_256>
    : hash2_digest_engine<digests::blake2s_256, boost::hash2::blake2s_256> {};

/**
 `digests::blake2b` on backends::hash2, Boost.Hash2's `blake2b_512`, in part: a 64-byte output with
 no key, salt or personalisation (rulings R82 and R86); a shorter output size, or any option, is
 `unsupported_by_backend`, since BLAKE2b's output size is a parameter of the hash, not a cut of its
 64 bytes, and no option is ignored.
*/
template <>
struct digest_engine<backends::hash2, digests::blake2b>
    : hash2_digest_engine<digests::blake2b, boost::hash2::blake2b_512> {
    /** Boost.Hash2's one size: 64 bytes. */
    static constexpr std::uint64_t min_output = 64;

    /**
     Whether the options are BLAKE2b-512's own: a 64-byte output, no key, no salt, no
     personalisation. A template, so that it reads `digest_options<digests::blake2b>`, which
     digest.hpp defines after this header.

     @param options The options. @return Whether Boost.Hash2's `blake2b_512` computes them.
    */
    template <class Options>
    static constexpr bool accepts(Options const& options) noexcept {
        return options.output_size == min_output && options.key.empty() && options.salt.empty() &&
               options.personalisation.empty();
    }
};

/**
 `digests::shake_128` on backends::hash2, Boost.Hash2's `shake_128`, whole: each `result()`
 permutes and gives the next 168 bytes of the stream, so any output size is the stream's first
 bytes.
*/
template <>
struct digest_engine<backends::hash2, digests::shake_128>
    : hash2_digest_engine<digests::shake_128, boost::hash2::shake_128> {};

/**
 `digests::shake_256` on backends::hash2, Boost.Hash2's `shake_256`, whole: each `result()`
 permutes and gives the next 136 bytes of the stream, so any output size is the stream's first
 bytes.
*/
template <>
struct digest_engine<backends::hash2, digests::shake_256>
    : hash2_digest_engine<digests::shake_256, boost::hash2::shake_256> {};

/**
 HMAC over a digest of `digests` on backends::hash2 (its interface is @ref mac_engine);
 Boost.Hash2's `hmac<Hash>` keyed with the key, its result cut to the tag's size (RFC 2104,
 section 5), the keyed hmac and the result wiped.

 @tparam Digest The digest's tag. @tparam Hash Its Boost.Hash2 algorithm.
*/
template <class Digest, class Hash>
struct hash2_hmac_engine : full_engine {
    /**
     The tag of `input` under `key`.

     @param output The tag, at most the digest's size. @param key The key, of any size.
     @param input The message. @return Success.
    */
    [[nodiscard]] static boost::system::result<void> compute(
        std::span<std::uint8_t> output, std::span<std::uint8_t const> key,
        std::span<std::uint8_t const> input,
        mac_options<macs::hmac<Digest>> const& /*options*/) noexcept {
        boost::hash2::hmac<Hash> keyed_mac(key.data(), key.size());
        keyed_mac.update(input.data(), input.size());
        auto tag_bytes = keyed_mac.result();
        std::memcpy(output.data(), tag_bytes.data(), output.size());
        wipe_object(tag_bytes);
        wipe_object(keyed_mac);
        return {};
    }
};

/** `macs::hmac<digests::md5>` on backends::hash2: Boost.Hash2's `hmac<md5_128>`. */
template <>
struct mac_engine<backends::hash2, macs::hmac<digests::md5>>
    : hash2_hmac_engine<digests::md5, boost::hash2::md5_128> {};

/** `macs::hmac<digests::sha1>` on backends::hash2: Boost.Hash2's `hmac<sha1_160>`. */
template <>
struct mac_engine<backends::hash2, macs::hmac<digests::sha1>>
    : hash2_hmac_engine<digests::sha1, boost::hash2::sha1_160> {};

/** `macs::hmac<digests::sha2_224>` on backends::hash2: Boost.Hash2's `hmac<sha2_224>`. */
template <>
struct mac_engine<backends::hash2, macs::hmac<digests::sha2_224>>
    : hash2_hmac_engine<digests::sha2_224, boost::hash2::sha2_224> {};

/** `macs::hmac<digests::sha2_256>` on backends::hash2: Boost.Hash2's `hmac<sha2_256>`. */
template <>
struct mac_engine<backends::hash2, macs::hmac<digests::sha2_256>>
    : hash2_hmac_engine<digests::sha2_256, boost::hash2::sha2_256> {};

/** `macs::hmac<digests::sha2_384>` on backends::hash2: Boost.Hash2's `hmac<sha2_384>`. */
template <>
struct mac_engine<backends::hash2, macs::hmac<digests::sha2_384>>
    : hash2_hmac_engine<digests::sha2_384, boost::hash2::sha2_384> {};

/** `macs::hmac<digests::sha2_512>` on backends::hash2: Boost.Hash2's `hmac<sha2_512>`. */
template <>
struct mac_engine<backends::hash2, macs::hmac<digests::sha2_512>>
    : hash2_hmac_engine<digests::sha2_512, boost::hash2::sha2_512> {};

/** `macs::hmac<digests::sha2_512_224>` on backends::hash2: Boost.Hash2's `hmac<sha2_512_224>`. */
template <>
struct mac_engine<backends::hash2, macs::hmac<digests::sha2_512_224>>
    : hash2_hmac_engine<digests::sha2_512_224, boost::hash2::sha2_512_224> {};

/** `macs::hmac<digests::sha2_512_256>` on backends::hash2: Boost.Hash2's `hmac<sha2_512_256>`. */
template <>
struct mac_engine<backends::hash2, macs::hmac<digests::sha2_512_256>>
    : hash2_hmac_engine<digests::sha2_512_256, boost::hash2::sha2_512_256> {};

/** `macs::hmac<digests::sha3_224>` on backends::hash2: Boost.Hash2's `hmac<sha3_224>`. */
template <>
struct mac_engine<backends::hash2, macs::hmac<digests::sha3_224>>
    : hash2_hmac_engine<digests::sha3_224, boost::hash2::sha3_224> {};

/** `macs::hmac<digests::sha3_256>` on backends::hash2: Boost.Hash2's `hmac<sha3_256>`. */
template <>
struct mac_engine<backends::hash2, macs::hmac<digests::sha3_256>>
    : hash2_hmac_engine<digests::sha3_256, boost::hash2::sha3_256> {};

/** `macs::hmac<digests::sha3_384>` on backends::hash2: Boost.Hash2's `hmac<sha3_384>`. */
template <>
struct mac_engine<backends::hash2, macs::hmac<digests::sha3_384>>
    : hash2_hmac_engine<digests::sha3_384, boost::hash2::sha3_384> {};

/** `macs::hmac<digests::sha3_512>` on backends::hash2: Boost.Hash2's `hmac<sha3_512>`. */
template <>
struct mac_engine<backends::hash2, macs::hmac<digests::sha3_512>>
    : hash2_hmac_engine<digests::sha3_512, boost::hash2::sha3_512> {};

/** `macs::hmac<digests::ripemd_160>` on backends::hash2: Boost.Hash2's `hmac<ripemd_160>`. */
template <>
struct mac_engine<backends::hash2, macs::hmac<digests::ripemd_160>>
    : hash2_hmac_engine<digests::ripemd_160, boost::hash2::ripemd_160> {};

/** `macs::hmac<digests::blake2b>` on backends::hash2: Boost.Hash2's `hmac<blake2b_512>`. */
template <>
struct mac_engine<backends::hash2, macs::hmac<digests::blake2b>>
    : hash2_hmac_engine<digests::blake2b, boost::hash2::blake2b_512> {};

/** `macs::hmac<digests::blake2s_256>` on backends::hash2: Boost.Hash2's `hmac<blake2s_256>`. */
template <>
struct mac_engine<backends::hash2, macs::hmac<digests::blake2s_256>>
    : hash2_hmac_engine<digests::blake2s_256, boost::hash2::blake2s_256> {};

/**
 `macs::siphash_2_4` on backends::hash2: Boost.Hash2's `siphash_64` keyed with the 16-byte key
 (k0 and k1 read little-endian), its 64-bit result written little-endian, as the SipHash paper's
 reference does; the state and the result wiped.
*/
template <>
struct mac_engine<backends::hash2, macs::siphash_2_4> : full_engine {
    /**
     The tag of `input` under `key`.

     @param output The tag, 8 bytes. @param key The key, 16 bytes. @param input The message.
     @return Success.
    */
    [[nodiscard]] static boost::system::result<void> compute(
        std::span<std::uint8_t> output, std::span<std::uint8_t const> key,
        std::span<std::uint8_t const> input,
        mac_options<macs::siphash_2_4> const& /*options*/) noexcept {
        boost::hash2::siphash_64 keyed_mac(key.data(), key.size());
        keyed_mac.update(input.data(), input.size());
        std::uint64_t tag_value = keyed_mac.result();
        for (std::uint8_t& byte : output) {
            byte = static_cast<std::uint8_t>(tag_value & 0xffU);
            tag_value >>= 8U;
        }
        wipe_object(keyed_mac);
        return {};
    }
};

/**
 `macs::blake2s_mac` on backends::hash2, Boost.Hash2's keyed `blake2s_256` (RFC 7693's keyed
 BLAKE2s, a key of 1 to 32 bytes), in part: a 32-byte tag alone (ruling R82); a shorter one is
 `unsupported_by_backend`, since BLAKE2s's output size is a parameter of the hash, not a cut.
*/
template <>
struct mac_engine<backends::hash2, macs::blake2s_mac> : full_engine {
    /**
     Whether the engine takes these sizes: a 32-byte tag.

     @param output_size The tag's size. @return Whether it is 32.
    */
    static constexpr bool accepts(mac_options<macs::blake2s_mac> const& /*options*/,
                                  std::size_t /*key_size*/, std::size_t output_size) noexcept {
        return output_size == boost::hash2::blake2s_256::result_type().size();
    }

    /**
     The tag of `input` under `key`.

     @param output The tag, 32 bytes. @param key The key, 1 to 32 bytes. @param input The message.
     @return Success.
    */
    [[nodiscard]] static boost::system::result<void> compute(
        std::span<std::uint8_t> output, std::span<std::uint8_t const> key,
        std::span<std::uint8_t const> input,
        mac_options<macs::blake2s_mac> const& /*options*/) noexcept {
        boost::hash2::blake2s_256 keyed_mac(key.data(), key.size());
        keyed_mac.update(input.data(), input.size());
        auto tag_bytes = keyed_mac.result();
        std::memcpy(output.data(), tag_bytes.data(), output.size());
        wipe_object(tag_bytes);
        wipe_object(keyed_mac);
        return {};
    }
};

}  // namespace webcpp::hash::detail

#endif  // WEBCPP_HASH_BACKENDS_HASH2_HPP
