// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `backends::xkcp`: the families' engines over XKCP, built from source by `/third_party//xkcp`, on
 every target: `digests::keccak_256` over webcpp's `keccak_256` (XKCP's Keccak-p[1600]). Increment
 3 brings the rest of XKCP's functions here.

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
#include <webcpp/hash/keccak.hpp>

#include <boost/system/result.hpp>

#include <cstdint>
#include <cstring>
#include <span>

namespace webcpp::hash::backends {

/** XKCP, the Keccak team's code, built from its sources by `/third_party//xkcp`. */
struct xkcp {};

}  // namespace webcpp::hash::backends

namespace webcpp::hash::detail {

/**
 `digests::keccak_256` on backends::xkcp (the engine's interface: @ref digest_engine): the state is
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

}  // namespace webcpp::hash::detail

#endif  // WEBCPP_HASH_HAS_XKCP

#endif  // WEBCPP_HASH_BACKENDS_XKCP_HPP
