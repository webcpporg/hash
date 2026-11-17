// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `backends::xkcp`: the families' engines over XKCP, built from source by `/third_party//xkcp`, on
 every target: `digests::keccak_256` over webcpp's `keccak_256` (XKCP's Keccak-p[1600]);
 `digests::keccak_224`, `keccak_384` and `keccak_512`, `digests::sha3_224` to `sha3_512`, and
 `digests::shake_128` and `shake_256` (any output size) over FIPS 202's `Keccak_Hash`, through
 webcpp's adapter (`detail/xkcp.hpp`). Increment 3 brings the rest of XKCP's functions here.

 @see "Using webcpp::hash in your Jamfile", in the guide.
*/
#ifndef WEBCPP_HASH_BACKENDS_XKCP_HPP
#define WEBCPP_HASH_BACKENDS_XKCP_HPP

#include <webcpp/hash/config.hpp>

#ifndef WEBCPP_HASH_HAS_XKCP
// clang-format off
#error "webcpp::hash: backends::xkcp needs XKCP. Add /third_party//xkcp to the program's Jamfile: exe app : app.cpp /webcpp/hash//hash /third_party//xkcp ;"
// clang-format on
#else

#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/detail/wipe.hpp>
#include <webcpp/hash/detail/xkcp.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/keccak.hpp>

#include <boost/system/result.hpp>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

namespace webcpp::hash::backends {

/** XKCP, the Keccak team's code, built from its sources by `/third_party//xkcp`. */
struct xkcp {};

}  // namespace webcpp::hash::backends

namespace webcpp::hash::detail {

/**
 `digests::keccak_256` on backends::xkcp (its interface is @ref digest_engine); the state is
 a `keccak_256`, wiped by `destroy`.
*/
template <>
struct digest_engine<backends::xkcp, digests::keccak_256> : full_engine {
    /** webcpp's Keccak-256 over XKCP's permutation, which is all of the state. */
    using state = keccak_256;

    /** Starts a hash. @param hashed The state. @return Success. */
    [[nodiscard]] static boost::system::result<void> init(
        state& hashed, digest_options<digests::keccak_256> const& /*options*/) noexcept {
        hashed = keccak_256();
        return {};
    }

    /** Absorbs `input`. @param hashed The state. @param input The bytes. @return Success. */
    [[nodiscard]] static boost::system::result<void> update(
        state& hashed, std::span<std::uint8_t const> input) noexcept {
        hashed.update(input.data(), input.size());
        return {};
    }

    /**
     Writes the 32-byte digest.

     @param hashed The state. @param output The digest. @return Success.
    */
    [[nodiscard]] static boost::system::result<void> finish(
        state& hashed, std::span<std::uint8_t> output) noexcept {
        auto result_bytes = hashed.result();
        std::memcpy(output.data(), result_bytes.data(), output.size());
        wipe_object(result_bytes);
        return {};
    }

    /** Wipes the state. @param hashed The state. */
    static void destroy(state& hashed) noexcept { wipe_object(hashed); }

    /**
     The digest of `input` at once, the state wiped.

     @param output The digest. @param input The bytes. @param options None.
     @return Success.
    */
    [[nodiscard]] static boost::system::result<void> one_shot(
        std::span<std::uint8_t> output, std::span<std::uint8_t const> input,
        digest_options<digests::keccak_256> const& options) noexcept {
        state hashed;
        static_cast<void>(init(hashed, options));
        static_cast<void>(update(hashed, input));
        static_cast<void>(finish(hashed, output));
        destroy(hashed);
        return {};
    }
};

/**
 A digest of `digests` on backends::xkcp over FIPS 202's `Keccak_Hash` (its interface is
 @ref digest_engine): Keccak-n, SHA3-n or SHAKE, by the sponge's capacity and padding. The state
 is the instance's storage, `xkcp_keccak_hash_storage`, wiped by `destroy`. A fixed-size digest
 is written by `final`; an extendable output is squeezed, `output.size()` bytes from the first.
 A refusal of XKCP's, which the family's guards leave no way to reach, is `backend_failure`.

 @tparam Digest The tag.
 @tparam Capacity The sponge's capacity in bits (twice the digest's size; 256 for SHAKE128, 512
 for SHAKE256); the rate is `1600 - Capacity`.
 @tparam Fixed The digest's size in bytes, 0 for an extendable output.
 @tparam Suffix The padding's delimited suffix: 0x01 for Keccak, 0x06 for SHA-3, 0x1F for SHAKE.
*/
template <class Digest, unsigned int Capacity, std::size_t Fixed, unsigned char Suffix>
struct xkcp_keccak_hash_engine : full_engine {
    /** XKCP's `Keccak_HashInstance`, in storage the adapter checks is large enough. */
    using state = xkcp_keccak_hash_storage;

    /** Starts a hash. @param hashed The state. @return Success, or backend_failure. */
    [[nodiscard]] static boost::system::result<void> init(
        state& hashed, digest_options<Digest> const& /*options*/) noexcept {
        if (webcpp_hash_xkcp_keccak_hash_initialize(hashed.data(), 1600 - Capacity, Capacity, Fixed,
                                                    Suffix) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /**
     Absorbs `input`. @param hashed The state. @param input The bytes.
     @return Success, or backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> update(
        state& hashed, std::span<std::uint8_t const> input) noexcept {
        if (webcpp_hash_xkcp_keccak_hash_update(hashed.data(), input.data(), input.size()) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /**
     Writes the digest, or the first `output.size()` bytes of the extendable output.

     @param hashed The state. @param output The output. @return Success, or backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> finish(
        state& hashed, std::span<std::uint8_t> output) noexcept {
        if constexpr (Fixed != 0) {
            if (webcpp_hash_xkcp_keccak_hash_final(hashed.data(), output.data()) != 0) {
                return error::backend_failure;
            }
        } else {
            if (webcpp_hash_xkcp_keccak_hash_final(hashed.data(), nullptr) != 0 ||
                webcpp_hash_xkcp_keccak_hash_squeeze(hashed.data(), output.data(), output.size()) !=
                    0) {
                return error::backend_failure;
            }
        }
        return {};
    }

    /** Wipes the state. @param hashed The state. */
    static void destroy(state& hashed) noexcept { wipe_object(hashed); }

    /**
     The output of `input` at once, the state wiped.

     @param output The output. @param input The bytes. @param options None.
     @return Success, or backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> one_shot(
        std::span<std::uint8_t> output, std::span<std::uint8_t const> input,
        digest_options<Digest> const& options) noexcept {
        state hashed;
        auto done = init(hashed, options);
        if (done) {
            done = update(hashed, input);
        }
        if (done) {
            done = finish(hashed, output);
        }
        destroy(hashed);
        return done;
    }
};

/** `digests::keccak_224` on backends::xkcp: capacity 448, 28 bytes, Keccak's padding. */
template <>
struct digest_engine<backends::xkcp, digests::keccak_224>
    : xkcp_keccak_hash_engine<digests::keccak_224, 448, 28, 0x01> {};

/** `digests::keccak_384` on backends::xkcp: capacity 768, 48 bytes, Keccak's padding. */
template <>
struct digest_engine<backends::xkcp, digests::keccak_384>
    : xkcp_keccak_hash_engine<digests::keccak_384, 768, 48, 0x01> {};

/** `digests::keccak_512` on backends::xkcp: capacity 1024, 64 bytes, Keccak's padding. */
template <>
struct digest_engine<backends::xkcp, digests::keccak_512>
    : xkcp_keccak_hash_engine<digests::keccak_512, 1024, 64, 0x01> {};

/** `digests::sha3_224` on backends::xkcp: capacity 448, 28 bytes, FIPS 202's SHA-3 padding. */
template <>
struct digest_engine<backends::xkcp, digests::sha3_224>
    : xkcp_keccak_hash_engine<digests::sha3_224, 448, 28, 0x06> {};

/** `digests::sha3_256` on backends::xkcp: capacity 512, 32 bytes, FIPS 202's SHA-3 padding. */
template <>
struct digest_engine<backends::xkcp, digests::sha3_256>
    : xkcp_keccak_hash_engine<digests::sha3_256, 512, 32, 0x06> {};

/** `digests::sha3_384` on backends::xkcp: capacity 768, 48 bytes, FIPS 202's SHA-3 padding. */
template <>
struct digest_engine<backends::xkcp, digests::sha3_384>
    : xkcp_keccak_hash_engine<digests::sha3_384, 768, 48, 0x06> {};

/** `digests::sha3_512` on backends::xkcp: capacity 1024, 64 bytes, FIPS 202's SHA-3 padding. */
template <>
struct digest_engine<backends::xkcp, digests::sha3_512>
    : xkcp_keccak_hash_engine<digests::sha3_512, 1024, 64, 0x06> {};

/** `digests::shake_128` on backends::xkcp: capacity 256, any output size, SHAKE's padding. */
template <>
struct digest_engine<backends::xkcp, digests::shake_128>
    : xkcp_keccak_hash_engine<digests::shake_128, 256, 0, 0x1F> {};

/** `digests::shake_256` on backends::xkcp: capacity 512, any output size, SHAKE's padding. */
template <>
struct digest_engine<backends::xkcp, digests::shake_256>
    : xkcp_keccak_hash_engine<digests::shake_256, 512, 0, 0x1F> {};

}  // namespace webcpp::hash::detail

#endif  // WEBCPP_HASH_HAS_XKCP

#endif  // WEBCPP_HASH_BACKENDS_XKCP_HPP
