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
 `SP800-185`; all through webcpp's adapter (`detail/xkcp.hpp`). Increment 3 brings the rest of
 XKCP's functions here.

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

     @param hashed The state. @param options N and S. @return Success, or backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> init(
        state& hashed, digest_options<Digest> const& options) noexcept {
        if (Functions::initialize(hashed.data(), 0, options.function_name.data(),
                                  options.function_name.size(), options.customisation.data(),
                                  options.customisation.size()) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /**
     Absorbs `input`, which the adapter passes to XKCP in pieces of at most `SIZE_MAX / 8` bytes.

     @param hashed The state. @param input The bytes. @return Success, or backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> update(
        state& hashed, std::span<std::uint8_t const> input) noexcept {
        if (Functions::update(hashed.data(), input.data(), input.size()) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /**
     Writes the first `output.size()` bytes of the stream.

     @param hashed The state. @param output The output. @return Success, or backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> finish(
        state& hashed, std::span<std::uint8_t> output) noexcept {
        if (Functions::final(hashed.data(), nullptr) != 0 ||
            Functions::squeeze(hashed.data(), output.data(), output.size()) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /** Wipes the state. @param hashed The state. */
    static void destroy(state& hashed) noexcept { wipe_object(hashed); }

    /**
     The output of `input` at once, the state wiped.

     @param output The output. @param input The bytes. @param options N and S.
     @return Success, or backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> one_shot(
        std::span<std::uint8_t> output, std::span<std::uint8_t const> input,
        digest_options<Digest> const& options) noexcept {
        state hashed{};
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
 size, which writes it; in the XOF form, `final_length` with 0, then `output.size()` bytes
 squeezed. The output's size is L itself, so the length the digest encodes is always the one it
 writes.

 @tparam Functions The adapter's functions.
 @param hashed The state. @param output The output. @return Success, or backend_failure.
*/
template <class Functions, class State>
[[nodiscard]] boost::system::result<void> xkcp_finish_with_length(
    State& hashed, std::span<std::uint8_t> output) noexcept {
    bool const ended =
        hashed.xof
            ? Functions::final_length(hashed.storage.data(), nullptr, 0) == 0 &&
                  Functions::squeeze(hashed.storage.data(), output.data(), output.size()) == 0
            : Functions::final_length(hashed.storage.data(), output.data(), output.size()) == 0;
    if (!ended) {
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

     @param hashed The state. @param options S and the form. @return Success, or backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> init(
        state& hashed, digest_options<Digest> const& options) noexcept {
        hashed.xof = options.xof;
        if (Functions::initialize(hashed.storage.data(), 0, options.customisation.data(),
                                  options.customisation.size()) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /**
     Adds `input` to the tuple as its next element.

     @param hashed The state. @param input The element.
     @return Success, `input_too_long`, or backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> update(
        state& hashed, std::span<std::uint8_t const> input) noexcept {
        if (exceeds(input.size(), sp800_185_max_bytes)) {
            return error::input_too_long;
        }
        if (Functions::update(hashed.storage.data(), input.data(), input.size()) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /**
     Writes the digest of `output.size()` bytes, the form's.

     @param hashed The state. @param output The output. @return Success, or backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> finish(
        state& hashed, std::span<std::uint8_t> output) noexcept {
        return xkcp_finish_with_length<Functions>(hashed, output);
    }

    /** Wipes the state. @param hashed The state. */
    static void destroy(state& hashed) noexcept { wipe_object(hashed); }

    /**
     The digest of the tuple of one element, `input`, the state wiped.

     @param output The output. @param input The element. @param options S and the form.
     @return Success, `input_too_long`, or backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> one_shot(
        std::span<std::uint8_t> output, std::span<std::uint8_t const> input,
        digest_options<Digest> const& options) noexcept {
        state hashed{};
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

     @param options The options. @return Whether it does.
    */
    static constexpr bool accepts(digest_options<Digest> const& options) noexcept {
        auto const block_size = options.block_size;
        return block_size >= min_block_size && (block_size & (block_size - 1)) == 0;
    }

    /**
     Starts a hash with the block size and the customisation, in the form the options name.

     @param hashed The state. @param options B, S and the form.
     @return Success, or backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> init(
        state& hashed, digest_options<Digest> const& options) noexcept {
        hashed.xof = options.xof;
        if (Functions::initialize(hashed.storage.data(), options.block_size, 0,
                                  options.customisation.data(),
                                  options.customisation.size()) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /**
     Absorbs `input`, which the adapter passes to XKCP in pieces of at most `SIZE_MAX / 8` bytes,
     unless the whole input would pass `sp800_185_max_bytes`.

     @param hashed The state. @param input The bytes.
     @return Success, `input_too_long`, or backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> update(
        state& hashed, std::span<std::uint8_t const> input) noexcept {
        // hashed.absorbed never exceeds the limit, so the subtraction does not wrap.
        if (exceeds(input.size(), sp800_185_max_bytes - hashed.absorbed)) {
            return error::input_too_long;
        }
        if (Functions::update(hashed.storage.data(), input.data(), input.size()) != 0) {
            return error::backend_failure;
        }
        hashed.absorbed += input.size();
        return {};
    }

    /**
     Writes the digest of `output.size()` bytes, the form's.

     @param hashed The state. @param output The output. @return Success, or backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> finish(
        state& hashed, std::span<std::uint8_t> output) noexcept {
        return xkcp_finish_with_length<Functions>(hashed, output);
    }

    /** Wipes the state. @param hashed The state. */
    static void destroy(state& hashed) noexcept { wipe_object(hashed); }

    /**
     The digest of `input` at once, the state wiped.

     @param output The output. @param input The bytes. @param options B, S and the form.
     @return Success, `input_too_long`, or backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> one_shot(
        std::span<std::uint8_t> output, std::span<std::uint8_t const> input,
        digest_options<Digest> const& options) noexcept {
        state hashed{};
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

/**
 KMAC on backends::xkcp (its interface is @ref mac_engine); XKCP's `KMAC_Instance`, on the stack
 and wiped. The fixed-length form starts with L = `output.size()` and writes the tag at `final`;
 the XOF form starts with 0 and squeezes it. Every key and tag size the family accepts.

 @tparam Mac The tag. @tparam Functions The adapter's functions of its security strength.
*/
template <class Mac, class Functions>
struct xkcp_kmac_engine : full_engine {
    /**
     The tag of `input` under `key`, of `output.size()` bytes.

     @param output The tag. @param key The key. @param input The message.
     @param options S and the form.
     @return Success, or backend_failure.
    */
    [[nodiscard]] static boost::system::result<void> compute(
        std::span<std::uint8_t> output, std::span<std::uint8_t const> key,
        std::span<std::uint8_t const> input, mac_options<Mac> const& options) noexcept {
        xkcp_kmac_storage storage{};
        bool done = Functions::initialize(
                        storage.data(), key.data(), key.size(), options.xof ? 0 : output.size(),
                        options.customisation.data(), options.customisation.size()) == 0 &&
                    Functions::update(storage.data(), input.data(), input.size()) == 0;
        if (done) {
            done = options.xof
                       ? Functions::final(storage.data(), nullptr) == 0 &&
                             Functions::squeeze(storage.data(), output.data(), output.size()) == 0
                       : Functions::final(storage.data(), output.data()) == 0;
        }
        wipe_object(storage);
        if (!done) {
            return error::backend_failure;
        }
        return {};
    }
};

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
