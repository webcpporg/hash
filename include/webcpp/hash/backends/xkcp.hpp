// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `backends::xkcp`: the families' engines over XKCP, built from source by `/third_party//xkcp`, on
 every target: `digests::keccak_256` over webcpp's `keccak_256` (XKCP's Keccak-p[1600]);
 `digests::keccak_224`, `keccak_384` and `keccak_512`, `digests::sha3_224` to `sha3_512`, and
 `digests::shake_128` and `shake_256` (any output size) over FIPS 202's `Keccak_Hash`; NIST SP
 800-185's `digests::cshake_128` and `cshake_256`, `digests::tuplehash_128` and `tuplehash_256`,
 `digests::parallelhash_128` and `parallelhash_256` (a block size that is a power of two of at
 least 8 bytes), and `macs::kmac_128` and `kmac_256`, each in both forms, over XKCP's
 `SP800-185`; RFC 9861's `digests::kt128` and `kt256` (with a customisation string) over XKCP's
 `KangarooTwelve`, and `digests::turboshake_128` and `turboshake_256` (with a domain byte) over its
 `TurboSHAKE`; all through webcpp's adapter (`detail/xkcp.hpp`).

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
#include <webcpp/hash/detail/limits.hpp>
#include <webcpp/hash/detail/xkcp.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/keccak.hpp>
#include <webcpp/secure/erase_secret.hpp>

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

    /** Starts a hash. @param digest_state The state. @return Success. */
    [[nodiscard]] static boost::system::result<void> init(
        state& digest_state,
        digest_options<digests::keccak_256> const& /*algorithm_options*/) noexcept {
        digest_state = keccak_256();
        return {};
    }

    /** Absorbs `input_bytes`. @param digest_state The state. @param input_bytes The bytes. @return
     * Success. */
    [[nodiscard]] static boost::system::result<void> update(
        state& digest_state, std::span<std::uint8_t const> input_bytes) noexcept {
        digest_state.update(input_bytes.data(), input_bytes.size());
        return {};
    }

    /**
     Writes the 32-byte digest.

     @param digest_state The state. @param output_bytes The digest. @return Success.
    */
    [[nodiscard]] static boost::system::result<void> finish(
        state& digest_state, std::span<std::uint8_t> output_bytes) noexcept {
        auto result_bytes = digest_state.result();
        std::memcpy(output_bytes.data(), result_bytes.data(), output_bytes.size());
        secure::erase_secret(std::span(&result_bytes, 1));
        return {};
    }

    /** Wipes the state. @param digest_state The state. */
    static void destroy(state& digest_state) noexcept {
        secure::erase_secret(std::span(&digest_state, 1));
    }

    /**
     The digest of `input_bytes` at once, the state wiped.

     @param output_bytes The digest. @param input_bytes The bytes. @param algorithm_options None.
     @return Success.
    */
    [[nodiscard]] static boost::system::result<void> one_shot(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> input_bytes,
        digest_options<digests::keccak_256> const& algorithm_options) noexcept {
        state digest_state;
        static_cast<void>(init(digest_state, algorithm_options));
        static_cast<void>(update(digest_state, input_bytes));
        static_cast<void>(finish(digest_state, output_bytes));
        destroy(digest_state);
        return {};
    }
};

/**
 A digest of `digests` on backends::xkcp over FIPS 202's `Keccak_Hash` (its interface is
 @ref digest_engine); Keccak-n, SHA3-n or SHAKE, by the sponge's capacity and padding. The state
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

    /** Starts a hash. @param digest_state The state. @return Success, or backend_failure. */
    [[nodiscard]] static boost::system::result<void> init(
        state& digest_state, digest_options<Digest> const& /*algorithm_options*/) noexcept {
        if (webcpp_hash_xkcp_keccak_hash_initialize(digest_state.data(), 1600 - Capacity, Capacity,
                                                    Fixed, Suffix) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /**
     Absorbs `input_bytes`. @param digest_state The state. @param input_bytes The bytes.
     @return Success, or backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> update(
        state& digest_state, std::span<std::uint8_t const> input_bytes) noexcept {
        if (webcpp_hash_xkcp_keccak_hash_update(digest_state.data(), input_bytes.data(),
                                                input_bytes.size()) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /**
     Writes the digest, or the first `output_bytes.size()` bytes of the extendable output.

     @param digest_state The state. @param output_bytes The output. @return Success, or
     backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> finish(
        state& digest_state, std::span<std::uint8_t> output_bytes) noexcept {
        if constexpr (Fixed != 0) {
            if (webcpp_hash_xkcp_keccak_hash_final(digest_state.data(), output_bytes.data()) != 0) {
                return error::backend_failure;
            }
        } else {
            if (webcpp_hash_xkcp_keccak_hash_final(digest_state.data(), nullptr) != 0 ||
                webcpp_hash_xkcp_keccak_hash_squeeze(digest_state.data(), output_bytes.data(),
                                                     output_bytes.size()) != 0) {
                return error::backend_failure;
            }
        }
        return {};
    }

    /** Wipes the state. @param digest_state The state. */
    static void destroy(state& digest_state) noexcept {
        secure::erase_secret(std::span(&digest_state, 1));
    }

    /**
     The output of `input_bytes` at once, the state wiped.

     @param output_bytes The output. @param input_bytes The bytes. @param algorithm_options None.
     @return Success, or backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> one_shot(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> input_bytes,
        digest_options<Digest> const& algorithm_options) noexcept {
        state digest_state;
        auto init_result = init(digest_state, algorithm_options);
        if (init_result) {
            init_result = update(digest_state, input_bytes);
        }
        if (init_result) {
            init_result = finish(digest_state, output_bytes);
        }
        destroy(digest_state);
        return init_result;
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

// NIST SP 800-185. Each engine is a template over its tag and the adapter's functions of the
// tag's security strength, so that the options it reads (digest.hpp's and mac.hpp's) are needed
// only where a call uses it, whichever of those headers a program includes first.

/** The adapter's functions of cSHAKE128. */
struct xkcp_cshake128_functions {
    /** `webcpp_hash_xkcp_cshake128_initialize`. */
    static constexpr auto initialize = &webcpp_hash_xkcp_cshake128_initialize;
    /** `webcpp_hash_xkcp_cshake128_update`. */
    static constexpr auto update = &webcpp_hash_xkcp_cshake128_update;
    /** `webcpp_hash_xkcp_cshake128_final`. */
    static constexpr auto final = &webcpp_hash_xkcp_cshake128_final;
    /** `webcpp_hash_xkcp_cshake128_squeeze`. */
    static constexpr auto squeeze = &webcpp_hash_xkcp_cshake128_squeeze;
};

/** The adapter's functions of cSHAKE256. */
struct xkcp_cshake256_functions {
    /** `webcpp_hash_xkcp_cshake256_initialize`. */
    static constexpr auto initialize = &webcpp_hash_xkcp_cshake256_initialize;
    /** `webcpp_hash_xkcp_cshake256_update`. */
    static constexpr auto update = &webcpp_hash_xkcp_cshake256_update;
    /** `webcpp_hash_xkcp_cshake256_final`. */
    static constexpr auto final = &webcpp_hash_xkcp_cshake256_final;
    /** `webcpp_hash_xkcp_cshake256_squeeze`. */
    static constexpr auto squeeze = &webcpp_hash_xkcp_cshake256_squeeze;
};

/** The adapter's functions of TupleHash128. */
struct xkcp_tuplehash128_functions {
    /** `webcpp_hash_xkcp_tuplehash128_initialize`. */
    static constexpr auto initialize = &webcpp_hash_xkcp_tuplehash128_initialize;
    /** `webcpp_hash_xkcp_tuplehash128_update`: one element of the tuple. */
    static constexpr auto update = &webcpp_hash_xkcp_tuplehash128_update;
    /** `webcpp_hash_xkcp_tuplehash128_final_length`. */
    static constexpr auto final_length = &webcpp_hash_xkcp_tuplehash128_final_length;
    /** `webcpp_hash_xkcp_tuplehash128_squeeze`. */
    static constexpr auto squeeze = &webcpp_hash_xkcp_tuplehash128_squeeze;
};

/** The adapter's functions of TupleHash256. */
struct xkcp_tuplehash256_functions {
    /** `webcpp_hash_xkcp_tuplehash256_initialize`. */
    static constexpr auto initialize = &webcpp_hash_xkcp_tuplehash256_initialize;
    /** `webcpp_hash_xkcp_tuplehash256_update`: one element of the tuple. */
    static constexpr auto update = &webcpp_hash_xkcp_tuplehash256_update;
    /** `webcpp_hash_xkcp_tuplehash256_final_length`. */
    static constexpr auto final_length = &webcpp_hash_xkcp_tuplehash256_final_length;
    /** `webcpp_hash_xkcp_tuplehash256_squeeze`. */
    static constexpr auto squeeze = &webcpp_hash_xkcp_tuplehash256_squeeze;
};

/** The adapter's functions of ParallelHash128. */
struct xkcp_parallelhash128_functions {
    /** `webcpp_hash_xkcp_parallelhash128_initialize`. */
    static constexpr auto initialize = &webcpp_hash_xkcp_parallelhash128_initialize;
    /** `webcpp_hash_xkcp_parallelhash128_update`. */
    static constexpr auto update = &webcpp_hash_xkcp_parallelhash128_update;
    /** `webcpp_hash_xkcp_parallelhash128_final_length`. */
    static constexpr auto final_length = &webcpp_hash_xkcp_parallelhash128_final_length;
    /** `webcpp_hash_xkcp_parallelhash128_squeeze`. */
    static constexpr auto squeeze = &webcpp_hash_xkcp_parallelhash128_squeeze;
};

/** The adapter's functions of ParallelHash256. */
struct xkcp_parallelhash256_functions {
    /** `webcpp_hash_xkcp_parallelhash256_initialize`. */
    static constexpr auto initialize = &webcpp_hash_xkcp_parallelhash256_initialize;
    /** `webcpp_hash_xkcp_parallelhash256_update`. */
    static constexpr auto update = &webcpp_hash_xkcp_parallelhash256_update;
    /** `webcpp_hash_xkcp_parallelhash256_final_length`. */
    static constexpr auto final_length = &webcpp_hash_xkcp_parallelhash256_final_length;
    /** `webcpp_hash_xkcp_parallelhash256_squeeze`. */
    static constexpr auto squeeze = &webcpp_hash_xkcp_parallelhash256_squeeze;
};

/** The adapter's functions of KMAC128. */
struct xkcp_kmac128_functions {
    /** `webcpp_hash_xkcp_kmac128_initialize`. */
    static constexpr auto initialize = &webcpp_hash_xkcp_kmac128_initialize;
    /** `webcpp_hash_xkcp_kmac128_update`. */
    static constexpr auto update = &webcpp_hash_xkcp_kmac128_update;
    /** `webcpp_hash_xkcp_kmac128_final`. */
    static constexpr auto final = &webcpp_hash_xkcp_kmac128_final;
    /** `webcpp_hash_xkcp_kmac128_squeeze`. */
    static constexpr auto squeeze = &webcpp_hash_xkcp_kmac128_squeeze;
};

/** The adapter's functions of KMAC256. */
struct xkcp_kmac256_functions {
    /** `webcpp_hash_xkcp_kmac256_initialize`. */
    static constexpr auto initialize = &webcpp_hash_xkcp_kmac256_initialize;
    /** `webcpp_hash_xkcp_kmac256_update`. */
    static constexpr auto update = &webcpp_hash_xkcp_kmac256_update;
    /** `webcpp_hash_xkcp_kmac256_final`. */
    static constexpr auto final = &webcpp_hash_xkcp_kmac256_final;
    /** `webcpp_hash_xkcp_kmac256_squeeze`. */
    static constexpr auto squeeze = &webcpp_hash_xkcp_kmac256_squeeze;
};

/**
 cSHAKE on backends::xkcp (its interface is @ref digest_engine); XKCP's `cSHAKE_Instance` in
 `xkcp_cshake_storage`, wiped by `destroy`. It starts in the XOF form, since cSHAKE does not
 encode the output's length, and squeezes `output.size()` bytes. The family's guards hold the
 strings within `sp800_185_max_bytes`, the adapter's only refusal at `initialize`; any other
 nonzero answer of XKCP's is `backend_failure`.

 @tparam Digest The tag. @tparam Functions The adapter's functions of its security strength.
*/
template <class Digest, class Functions>
struct xkcp_cshake_engine : full_engine {
    /** XKCP's `cSHAKE_Instance`, in storage the adapter checks is large enough. */
    using state = xkcp_cshake_storage;

    /**
     Starts a hash with the function name and the customisation.

     @param digest_state The state. @param algorithm_options N and S. @return Success, or
     backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> init(
        state& digest_state, digest_options<Digest> const& algorithm_options) noexcept {
        if (Functions::initialize(digest_state.data(), 0, algorithm_options.function_name.data(),
                                  algorithm_options.function_name.size(),
                                  algorithm_options.customisation.data(),
                                  algorithm_options.customisation.size()) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /**
     Absorbs `input_bytes`, which the adapter passes to XKCP in pieces of at most `SIZE_MAX / 8`
     bytes.

     @param digest_state The state. @param input_bytes The bytes. @return Success, or
     backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> update(
        state& digest_state, std::span<std::uint8_t const> input_bytes) noexcept {
        if (Functions::update(digest_state.data(), input_bytes.data(), input_bytes.size()) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /**
     Writes the first `output_bytes.size()` bytes of the stream.

     @param digest_state The state. @param output_bytes The output. @return Success, or
     backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> finish(
        state& digest_state, std::span<std::uint8_t> output_bytes) noexcept {
        if (Functions::final(digest_state.data(), nullptr) != 0 ||
            Functions::squeeze(digest_state.data(), output_bytes.data(), output_bytes.size()) !=
                0) {
            return error::backend_failure;
        }
        return {};
    }

    /** Wipes the state. @param digest_state The state. */
    static void destroy(state& digest_state) noexcept {
        secure::erase_secret(std::span(&digest_state, 1));
    }

    /**
     The output of `input_bytes` at once, the state wiped.

     @param output_bytes The output. @param input_bytes The bytes. @param algorithm_options N and S.
     @return Success, or backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> one_shot(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> input_bytes,
        digest_options<Digest> const& algorithm_options) noexcept {
        state digest_state{};
        auto init_result = init(digest_state, algorithm_options);
        if (init_result) {
            init_result = update(digest_state, input_bytes);
        }
        if (init_result) {
            init_result = finish(digest_state, output_bytes);
        }
        destroy(digest_state);
        return init_result;
    }
};

/**
 The state of TupleHash and ParallelHash on backends::xkcp: XKCP's instance, started with an
 output length of 0 since the fixed-length form's length is known only at `finish`, the form, and
 the bytes absorbed so far (ParallelHash's guard; TupleHash leaves it at 0).

 @tparam Storage The instance's storage.
*/
template <class Storage>
struct xkcp_sp800_185_state {
    /** XKCP's instance. */
    Storage storage{};
    /** The extendable-output form. */
    bool xof = false;
    /** The bytes absorbed so far, in 64 bits on every target. */
    std::uint64_t absorbed = 0;
};

/**
 Ends a TupleHash or a ParallelHash: in the fixed-length form, `final_length` with L the output's
 size, which writes it; in the XOF form, `final_length` with 0, then `output_bytes.size()` bytes
 squeezed. The output's size is L itself, so the length the digest encodes is always the one it
 writes.

 @tparam Functions The adapter's functions.
 @tparam State `xkcp_sp800_185_state` of the instance's storage.
 @param digest_state The state. @param output_bytes The output. @return Success, or backend_failure.
*/
template <class Functions, class State>
[[nodiscard]] boost::system::result<void> xkcp_finish_with_length(
    State& digest_state, std::span<std::uint8_t> output_bytes) noexcept {
    bool const finish_succeeded =
        digest_state.xof ? Functions::final_length(digest_state.storage.data(), nullptr, 0) == 0 &&
                               Functions::squeeze(digest_state.storage.data(), output_bytes.data(),
                                                  output_bytes.size()) == 0
                         : Functions::final_length(digest_state.storage.data(), output_bytes.data(),
                                                   output_bytes.size()) == 0;
    if (!finish_succeeded) {
        return error::backend_failure;
    }
    return {};
}

/**
 TupleHash on backends::xkcp (its interface is @ref digest_engine); `update` adds one element
 to the tuple, `one_shot` hashes the tuple of one element, its input. XKCP takes an element's
 length in bits in a `size_t`: an element longer than `sp800_185_max_bytes` is
 `input_too_long`, before XKCP sees it, after which a hasher is spent and `digest_of`'s output
 zeroed. Both forms; the state is wiped by `destroy`.

 @tparam Digest The tag. @tparam Functions The adapter's functions of its security strength.
*/
template <class Digest, class Functions>
struct xkcp_tuplehash_engine : full_engine {
    /** XKCP's `TupleHash_Instance` and the form. */
    using state = xkcp_sp800_185_state<xkcp_tuplehash_storage>;

    /**
     Starts a hash with the customisation, in the form the options name.

     @param digest_state The state. @param algorithm_options S and the form. @return Success, or
     backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> init(
        state& digest_state, digest_options<Digest> const& algorithm_options) noexcept {
        digest_state.xof = algorithm_options.xof;
        if (Functions::initialize(digest_state.storage.data(), 0,
                                  algorithm_options.customisation.data(),
                                  algorithm_options.customisation.size()) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /**
     Adds `input_bytes` to the tuple as its next element.

     @param digest_state The state. @param input_bytes The element.
     @return Success, `input_too_long`, or backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> update(
        state& digest_state, std::span<std::uint8_t const> input_bytes) noexcept {
        if (exceeds(input_bytes.size(), sp800_185_max_bytes)) {
            return error::input_too_long;
        }
        if (Functions::update(digest_state.storage.data(), input_bytes.data(),
                              input_bytes.size()) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /**
     Writes the digest of `output_bytes.size()` bytes, the form's.

     @param digest_state The state. @param output_bytes The output. @return Success, or
     backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> finish(
        state& digest_state, std::span<std::uint8_t> output_bytes) noexcept {
        return xkcp_finish_with_length<Functions>(digest_state, output_bytes);
    }

    /** Wipes the state. @param digest_state The state. */
    static void destroy(state& digest_state) noexcept {
        secure::erase_secret(std::span(&digest_state, 1));
    }

    /**
     The digest of the tuple of one element, `input_bytes`, the state wiped.

     @param output_bytes The output. @param input_bytes The element. @param algorithm_options S and
     the form.
     @return Success, `input_too_long`, or backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> one_shot(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> input_bytes,
        digest_options<Digest> const& algorithm_options) noexcept {
        state digest_state{};
        auto init_result = init(digest_state, algorithm_options);
        if (init_result) {
            init_result = update(digest_state, input_bytes);
        }
        if (init_result) {
            init_result = finish(digest_state, output_bytes);
        }
        destroy(digest_state);
        return init_result;
    }
};

/**
 ParallelHash on backends::xkcp (its interface is @ref digest_engine), in part: XKCP takes a
 block size that is a power of two of at least 8 bytes, its lane's size, and `accepts` refuses
 any other (`unsupported_by_backend`), which the family's guard of 0 leaves to it. XKCP counts
 the whole input in bits in a `size_t` (`totalInputSize`), which on wasm32 would wrap past 512 MiB
 into a wrong block count: the engine counts the bytes itself and refuses the call that would take
 the input past `sp800_185_max_bytes` with `input_too_long`, before XKCP sees it, after which a
 hasher is spent and `digest_of`'s output zeroed. XKCP computes the blocks one after another (no
 parallel permutation is compiled). Both forms; the state is wiped by `destroy`.

 @tparam Digest The tag. @tparam Functions The adapter's functions of its security strength.
*/
template <class Digest, class Functions>
struct xkcp_parallelhash_engine : full_engine {
    /** XKCP's `ParallelHash_Instance` and the form. */
    using state = xkcp_sp800_185_state<xkcp_parallelhash_storage>;

    /** XKCP's smallest block size, a lane of Keccak-p[1600], in bytes. */
    static constexpr std::size_t min_block_size = 8;

    /**
     Whether XKCP takes the options' block size: a power of two of at least 8.

     @param algorithm_options The options. @return Whether it does.
    */
    static constexpr bool accepts(digest_options<Digest> const& algorithm_options) noexcept {
        auto const block_size = algorithm_options.block_size;
        return block_size >= min_block_size && (block_size & (block_size - 1)) == 0;
    }

    /**
     Starts a hash with the block size and the customisation, in the form the options name.

     @param digest_state The state. @param algorithm_options B, S and the form.
     @return Success, or backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> init(
        state& digest_state, digest_options<Digest> const& algorithm_options) noexcept {
        digest_state.xof = algorithm_options.xof;
        if (Functions::initialize(digest_state.storage.data(), algorithm_options.block_size, 0,
                                  algorithm_options.customisation.data(),
                                  algorithm_options.customisation.size()) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /**
     Absorbs `input_bytes`, which the adapter passes to XKCP in pieces of at most `SIZE_MAX / 8`
     bytes, unless the whole input would pass `sp800_185_max_bytes`.

     @param digest_state The state. @param input_bytes The bytes.
     @return Success, `input_too_long`, or backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> update(
        state& digest_state, std::span<std::uint8_t const> input_bytes) noexcept {
        // hashed.absorbed never exceeds the limit, so the subtraction does not wrap.
        if (exceeds(input_bytes.size(), sp800_185_max_bytes - digest_state.absorbed)) {
            return error::input_too_long;
        }
        if (Functions::update(digest_state.storage.data(), input_bytes.data(),
                              input_bytes.size()) != 0) {
            return error::backend_failure;
        }
        digest_state.absorbed += input_bytes.size();
        return {};
    }

    /**
     Writes the digest of `output_bytes.size()` bytes, the form's.

     @param digest_state The state. @param output_bytes The output. @return Success, or
     backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> finish(
        state& digest_state, std::span<std::uint8_t> output_bytes) noexcept {
        return xkcp_finish_with_length<Functions>(digest_state, output_bytes);
    }

    /** Wipes the state. @param digest_state The state. */
    static void destroy(state& digest_state) noexcept {
        secure::erase_secret(std::span(&digest_state, 1));
    }

    /**
     The digest of `input_bytes` at once, the state wiped.

     @param output_bytes The output. @param input_bytes The bytes. @param algorithm_options B, S and
     the form.
     @return Success, `input_too_long`, or backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> one_shot(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> input_bytes,
        digest_options<Digest> const& algorithm_options) noexcept {
        state digest_state{};
        auto init_result = init(digest_state, algorithm_options);
        if (init_result) {
            init_result = update(digest_state, input_bytes);
        }
        if (init_result) {
            init_result = finish(digest_state, output_bytes);
        }
        destroy(digest_state);
        return init_result;
    }
};

/**
 KMAC on backends::xkcp (its interface is @ref mac_engine); XKCP's `KMAC_Instance`, on the stack
 and wiped. The fixed-length form starts with L = `output.size()` and writes the tag at `final`;
 the XOF form starts with 0 and squeezes it. Every key and tag size the family accepts.

 @tparam Mac The tag. @tparam Functions The adapter's functions of its security strength.
*/
template <class Mac, class Functions>
struct xkcp_kmac_engine : full_engine {
    /**
     The tag of `input_bytes` under `key_bytes`, of `output_bytes.size()` bytes.

     @param output_bytes The tag. @param key_bytes The key. @param input_bytes The message.
     @param algorithm_options S and the form.
     @return Success, or backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> compute(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> key_bytes,
        std::span<std::uint8_t const> input_bytes,
        mac_options<Mac> const& algorithm_options) noexcept {
        xkcp_kmac_storage kmac_storage{};
        bool call_succeeded =
            Functions::initialize(kmac_storage.data(), key_bytes.data(), key_bytes.size(),
                                  algorithm_options.xof ? 0 : output_bytes.size(),
                                  algorithm_options.customisation.data(),
                                  algorithm_options.customisation.size()) == 0 &&
            Functions::update(kmac_storage.data(), input_bytes.data(), input_bytes.size()) == 0;
        if (call_succeeded) {
            call_succeeded = algorithm_options.xof
                                 ? Functions::final(kmac_storage.data(), nullptr) == 0 &&
                                       Functions::squeeze(kmac_storage.data(), output_bytes.data(),
                                                          output_bytes.size()) == 0
                                 : Functions::final(kmac_storage.data(), output_bytes.data()) == 0;
        }
        secure::erase_secret(std::span(&kmac_storage, 1));
        if (!call_succeeded) {
            return error::backend_failure;
        }
        return {};
    }
};

/**
 TurboSHAKE on backends::xkcp (its interface is @ref digest_engine); XKCP's `TurboSHAKE_Instance`
 in `xkcp_turboshake_storage`, with the domain byte, both wiped by `destroy`. `finish` absorbs D
 and squeezes `output.size()` bytes. The family's guard holds D within 0x01 to 0x7F (XKCP takes
 any byte but 0); any nonzero answer of XKCP's is `backend_failure`. Every option and output
 size the family accepts.

 @tparam Digest The tag. @tparam Capacity 256 for TurboSHAKE128, 512 for TurboSHAKE256.
*/
template <class Digest, unsigned int Capacity>
struct xkcp_turboshake_engine : full_engine {
    /** XKCP's instance and the domain byte `finish` absorbs. */
    struct state {
        /** XKCP's `TurboSHAKE_Instance`, in storage the adapter checks is large enough. */
        xkcp_turboshake_storage storage{};
        /** The domain separation byte D. */
        std::uint8_t domain = 0;
    };

    /**
     Starts a hash with the domain byte the options name.

     @param digest_state The state. @param algorithm_options D. @return Success, or backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> init(
        state& digest_state, digest_options<Digest> const& algorithm_options) noexcept {
        digest_state.domain = algorithm_options.domain;
        if (webcpp_hash_xkcp_turboshake_initialize(digest_state.storage.data(), Capacity) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /**
     Absorbs `input_bytes`. @param digest_state The state. @param input_bytes The bytes.
     @return Success, or backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> update(
        state& digest_state, std::span<std::uint8_t const> input_bytes) noexcept {
        if (webcpp_hash_xkcp_turboshake_update(digest_state.storage.data(), input_bytes.data(),
                                               input_bytes.size()) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /**
     Absorbs D and writes the first `output_bytes.size()` bytes of the stream.

     @param digest_state The state. @param output_bytes The output. @return Success, or
     backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> finish(
        state& digest_state, std::span<std::uint8_t> output_bytes) noexcept {
        if (webcpp_hash_xkcp_turboshake_final(digest_state.storage.data(), digest_state.domain) !=
                0 ||
            webcpp_hash_xkcp_turboshake_squeeze(digest_state.storage.data(), output_bytes.data(),
                                                output_bytes.size()) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /** Wipes the state. @param digest_state The state. */
    static void destroy(state& digest_state) noexcept {
        secure::erase_secret(std::span(&digest_state, 1));
    }

    /**
     The output of `input_bytes` at once, the state wiped.

     @param output_bytes The output. @param input_bytes The bytes. @param algorithm_options D.
     @return Success, or backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> one_shot(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> input_bytes,
        digest_options<Digest> const& algorithm_options) noexcept {
        state digest_state{};
        auto init_result = init(digest_state, algorithm_options);
        if (init_result) {
            init_result = update(digest_state, input_bytes);
        }
        if (init_result) {
            init_result = finish(digest_state, output_bytes);
        }
        destroy(digest_state);
        return init_result;
    }
};

/**
 KangarooTwelve on backends::xkcp (its interface is @ref digest_engine); XKCP's
 `KangarooTwelve_Instance` in `xkcp_kangarootwelve_storage`, started with no fixed output, the
 customisation's span, and the bytes counted so far, all wiped by `destroy`. XKCP takes C at
 `KangarooTwelve_Final`, so the state keeps the span `init` took (ruling R33) and `finish` reads
 it, then squeezes `output.size()` bytes. XKCP counts the 8,192-byte chunks of the message and C
 in a `size_t`, which on wasm32 would wrap past 32 TiB: the engine counts the bytes of C and the
 message in 64 bits and refuses the call that would take them past `kangarootwelve_max_bytes`
 with `input_too_long`, before XKCP sees the bytes, after which a hasher is spent and
 `digest_of`'s output zeroed. XKCP computes the chunks one after another (no parallel permutation
 is compiled). Every output size the family accepts.

 @tparam Digest The tag. @tparam SecurityLevel 128 for KT128, 256 for KT256.
*/
template <class Digest, int SecurityLevel>
struct xkcp_kangarootwelve_engine : full_engine {
    /** XKCP's instance, the customisation `finish` reads, and the bytes counted. */
    struct state {
        /** XKCP's `KangarooTwelve_Instance`, in storage the adapter checks is large enough. */
        xkcp_kangarootwelve_storage storage{};
        /** The customisation string C, which the caller keeps alive until `finish`. */
        std::span<std::uint8_t const> customisation{};
        /** The bytes of C and of the message so far, in 64 bits on every target. */
        std::uint64_t counted = 0;
    };

    /**
     Starts a hash, keeping the customisation's span for `finish`.

     @param digest_state The state. @param algorithm_options C.
     @return Success, `input_too_long` for a C past `kangarootwelve_max_bytes`, or
     backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> init(
        state& digest_state, digest_options<Digest> const& algorithm_options) noexcept {
        if (exceeds(algorithm_options.customisation.size(), kangarootwelve_max_bytes)) {
            return error::input_too_long;
        }
        digest_state.customisation = algorithm_options.customisation;
        digest_state.counted = algorithm_options.customisation.size();
        if (webcpp_hash_xkcp_kangarootwelve_initialize(digest_state.storage.data(), SecurityLevel,
                                                       0) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /**
     Absorbs `input_bytes`, unless it would take the message and C past `kangarootwelve_max_bytes`.

     @param digest_state The state. @param input_bytes The bytes.
     @return Success, `input_too_long`, or backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> update(
        state& digest_state, std::span<std::uint8_t const> input_bytes) noexcept {
        // hashed.counted never exceeds the limit, so the subtraction does not wrap.
        if (exceeds(input_bytes.size(), kangarootwelve_max_bytes - digest_state.counted)) {
            return error::input_too_long;
        }
        if (webcpp_hash_xkcp_kangarootwelve_update(digest_state.storage.data(), input_bytes.data(),
                                                   input_bytes.size()) != 0) {
            return error::backend_failure;
        }
        digest_state.counted += input_bytes.size();
        return {};
    }

    /**
     Absorbs C, ends the input, and writes the first `output_bytes.size()` bytes of the stream.

     @param digest_state The state. @param output_bytes The output. @return Success, or
     backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> finish(
        state& digest_state, std::span<std::uint8_t> output_bytes) noexcept {
        if (webcpp_hash_xkcp_kangarootwelve_final(digest_state.storage.data(), nullptr,
                                                  digest_state.customisation.data(),
                                                  digest_state.customisation.size()) != 0 ||
            webcpp_hash_xkcp_kangarootwelve_squeeze(
                digest_state.storage.data(), output_bytes.data(), output_bytes.size()) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /** Wipes the state. @param digest_state The state. */
    static void destroy(state& digest_state) noexcept {
        secure::erase_secret(std::span(&digest_state, 1));
    }

    /**
     The output of `input_bytes` at once, the state wiped.

     @param output_bytes The output. @param input_bytes The bytes. @param algorithm_options C.
     @return Success, `input_too_long`, or backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> one_shot(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> input_bytes,
        digest_options<Digest> const& algorithm_options) noexcept {
        state digest_state{};
        auto init_result = init(digest_state, algorithm_options);
        if (init_result) {
            init_result = update(digest_state, input_bytes);
        }
        if (init_result) {
            init_result = finish(digest_state, output_bytes);
        }
        destroy(digest_state);
        return init_result;
    }
};

/** `digests::turboshake_128` on backends::xkcp: XKCP's TurboSHAKE, capacity 256. */
template <>
struct digest_engine<backends::xkcp, digests::turboshake_128>
    : xkcp_turboshake_engine<digests::turboshake_128, 256> {};

/** `digests::turboshake_256` on backends::xkcp: XKCP's TurboSHAKE, capacity 512. */
template <>
struct digest_engine<backends::xkcp, digests::turboshake_256>
    : xkcp_turboshake_engine<digests::turboshake_256, 512> {};

/** `digests::kt128` on backends::xkcp: XKCP's KangarooTwelve at 128 bits. */
template <>
struct digest_engine<backends::xkcp, digests::kt128>
    : xkcp_kangarootwelve_engine<digests::kt128, 128> {};

/** `digests::kt256` on backends::xkcp: XKCP's KangarooTwelve at 256 bits. */
template <>
struct digest_engine<backends::xkcp, digests::kt256>
    : xkcp_kangarootwelve_engine<digests::kt256, 256> {};

/** `digests::cshake_128` on backends::xkcp: XKCP's cSHAKE128. */
template <>
struct digest_engine<backends::xkcp, digests::cshake_128>
    : xkcp_cshake_engine<digests::cshake_128, xkcp_cshake128_functions> {};

/** `digests::cshake_256` on backends::xkcp: XKCP's cSHAKE256. */
template <>
struct digest_engine<backends::xkcp, digests::cshake_256>
    : xkcp_cshake_engine<digests::cshake_256, xkcp_cshake256_functions> {};

/** `digests::tuplehash_128` on backends::xkcp: XKCP's TupleHash128 and TupleHashXOF128. */
template <>
struct digest_engine<backends::xkcp, digests::tuplehash_128>
    : xkcp_tuplehash_engine<digests::tuplehash_128, xkcp_tuplehash128_functions> {};

/** `digests::tuplehash_256` on backends::xkcp: XKCP's TupleHash256 and TupleHashXOF256. */
template <>
struct digest_engine<backends::xkcp, digests::tuplehash_256>
    : xkcp_tuplehash_engine<digests::tuplehash_256, xkcp_tuplehash256_functions> {};

/**
 `digests::parallelhash_128` on backends::xkcp: XKCP's ParallelHash128 and ParallelHashXOF128,
 a block size that is a power of two of at least 8 bytes.
*/
template <>
struct digest_engine<backends::xkcp, digests::parallelhash_128>
    : xkcp_parallelhash_engine<digests::parallelhash_128, xkcp_parallelhash128_functions> {};

/**
 `digests::parallelhash_256` on backends::xkcp: XKCP's ParallelHash256 and ParallelHashXOF256,
 a block size that is a power of two of at least 8 bytes.
*/
template <>
struct digest_engine<backends::xkcp, digests::parallelhash_256>
    : xkcp_parallelhash_engine<digests::parallelhash_256, xkcp_parallelhash256_functions> {};

/** `macs::kmac_128` on backends::xkcp: XKCP's KMAC128 and KMACXOF128. */
template <>
struct mac_engine<backends::xkcp, macs::kmac_128>
    : xkcp_kmac_engine<macs::kmac_128, xkcp_kmac128_functions> {};

/** `macs::kmac_256` on backends::xkcp: XKCP's KMAC256 and KMACXOF256. */
template <>
struct mac_engine<backends::xkcp, macs::kmac_256>
    : xkcp_kmac_engine<macs::kmac_256, xkcp_kmac256_functions> {};

}  // namespace webcpp::hash::detail

#endif  // WEBCPP_HASH_HAS_XKCP

#endif  // WEBCPP_HASH_BACKENDS_XKCP_HPP
