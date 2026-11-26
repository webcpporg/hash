// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `backends::blake3`: the families' engine over BLAKE3's official C implementation, built from
 source by `/third_party//blake3`, on every target: `digests::blake3`, an extendable-output
 function, over webcpp's `blake3`.

 @see "BLAKE3", in the guide.
*/
#ifndef WEBCPP_HASH_BACKENDS_BLAKE3_HPP
#define WEBCPP_HASH_BACKENDS_BLAKE3_HPP

#include <webcpp/hash/config.hpp>

#ifndef WEBCPP_HASH_HAS_BLAKE3
// clang-format off
#error "webcpp::hash: backends::blake3 needs BLAKE3's C implementation. Add /third_party//blake3 to the program's Jamfile: exe app : app.cpp /webcpp/hash//hash /third_party//blake3 ;"
// clang-format on
#else

#include <webcpp/hash/blake3.hpp>
#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/secure/erase_secret.hpp>

#include <boost/system/result.hpp>

#include <cstdint>
#include <span>

namespace webcpp::hash::backends {

/** BLAKE3's official C implementation, built from its sources by `/third_party//blake3`. */
struct blake3 {};

}  // namespace webcpp::hash::backends

namespace webcpp::hash::detail {

/**
 `digests::blake3` on backends::blake3 (its interface is @ref digest_engine); the state is a
 `webcpp::hash::blake3`, wiped by `destroy`; the output, of any size, is the extendable output
 from its first byte.
*/
template <>
struct digest_engine<backends::blake3, digests::blake3> : full_engine {
    /** webcpp's BLAKE3 over the C implementation, which is all of the state. */
    using state = webcpp::hash::blake3;

    /** Starts a hash. @param digest_state The state. @return Success. */
    [[nodiscard]] static boost::system::result<void> init(
        state& digest_state,
        digest_options<digests::blake3> const& /*algorithm_options*/) noexcept {
        digest_state = webcpp::hash::blake3();
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
     Writes the first `output_bytes.size()` bytes of the extendable output.

     @param digest_state The state. @param output_bytes The output, of any size. @return Success.
    */
    [[nodiscard]] static boost::system::result<void> finish(
        state& digest_state, std::span<std::uint8_t> output_bytes) noexcept {
        digest_state.squeeze(output_bytes, 0);
        return {};
    }

    /** Wipes the state. @param digest_state The state. */
    static void destroy(state& digest_state) noexcept {
        secure::erase_secret(std::span(&digest_state, 1));
    }

    /**
     The output of `input_bytes` at once, the state wiped.

     @param output_bytes The output. @param input_bytes The bytes. @param algorithm_options None.
     @return Success.
    */
    [[nodiscard]] static boost::system::result<void> one_shot(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> input_bytes,
        digest_options<digests::blake3> const& algorithm_options) noexcept {
        state digest_state;
        static_cast<void>(init(digest_state, algorithm_options));
        static_cast<void>(update(digest_state, input_bytes));
        static_cast<void>(finish(digest_state, output_bytes));
        destroy(digest_state);
        return {};
    }
};

}  // namespace webcpp::hash::detail

#endif  // WEBCPP_HASH_HAS_BLAKE3

#endif  // WEBCPP_HASH_BACKENDS_BLAKE3_HPP
