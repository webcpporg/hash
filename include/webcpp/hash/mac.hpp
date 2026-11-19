// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The MAC family (spec 2.15): `mac`, the tag of a message under a key in one call, over a tag of
 `macs` and a backend, `default_backend` of the tag by default.

 The guards are the same on every backend and run before any work: a tag of a size the MAC does
 not produce is `invalid_output_size`, a key of a size it does not take `invalid_key_size`, a value
 the MAC accepts and the chosen backend does not `unsupported_by_backend`. A guard's refusal leaves
 the output as it was; a backend's failure zeroes it.

 A program checks a tag with `webcpp::crypto::equal`, which runs in constant time, never with
 `==`:

 @code
 std::array<std::uint8_t, 32> tag{};
 auto done = webcpp::hash::mac<webcpp::hash::macs::hmac<webcpp::hash::digests::sha2_256>>(
     tag, key, message);
 bool genuine = done && webcpp::crypto::equal(tag, received_tag);
 @endcode

 @see "Message authentication", in the guide.
*/
#ifndef WEBCPP_HASH_MAC_HPP
#define WEBCPP_HASH_MAC_HPP

#include <webcpp/hash/config.hpp>

#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/detail/limits.hpp>
#include <webcpp/hash/detail/wipe.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/kdf.hpp>

#include <boost/system/result.hpp>

#include <cstddef>
#include <cstdint>
#include <span>

namespace webcpp::hash {

/**
 The parameters of a MAC: none for most tags, which this primary template serves. A tag with
 parameters (KMAC's customisation and its extendable-output form) has its own specialisation, from
 the increment that brings its first backend.

 @tparam Mac A tag of `macs`.
*/
template <class Mac>
struct mac_options {};

/**
 KMAC128's parameters (NIST SP 800-185, section 4): the customisation string S, which separates
 one application's tags from another's under the same key, and the form, fixed-length or
 extendable-output (KMACXOF128).

 @code
 std::array<std::uint8_t, 32> tag{};
 auto done = webcpp::hash::mac<webcpp::hash::macs::kmac_128>(
     tag, key, message, {.customisation = app_name});
 @endcode

 The fixed-length form encodes the tag's length L, so that its tags of 16 and 32 bytes are
 unrelated; the XOF form encodes none, and its shorter tag is the start of its longer. S is at
 most `SIZE_MAX / 8` bytes (`input_too_long`), and is read during the call and not kept.
*/
template <>
struct mac_options<macs::kmac_128> {
    /** The customisation string S. */
    std::span<std::uint8_t const> customisation = {};

    /** The extendable-output form, KMACXOF128, in place of the fixed-length one. */
    bool xof = false;
};

/** KMAC256's parameters, as KMAC128's (@ref mac_options<macs::kmac_128>). */
template <>
struct mac_options<macs::kmac_256> {
    /** The customisation string S. */
    std::span<std::uint8_t const> customisation = {};

    /** The extendable-output form, KMACXOF256, in place of the fixed-length one. */
    bool xof = false;
};

namespace detail {

/**
 The sizes a MAC takes: its tag of `MinOutput` to `MaxOutput` bytes, its key of `MinKey` to
 `MaxKey` bytes, and no option to check.
*/
template <std::uint64_t MinOutput, std::uint64_t MaxOutput, std::uint64_t MinKey,
          std::uint64_t MaxKey>
struct mac_sizes {
    /** The shortest tag. */
    static constexpr std::uint64_t min_output = MinOutput;
    /** The longest tag. */
    static constexpr std::uint64_t max_output = MaxOutput;
    /** The shortest key. */
    static constexpr std::uint64_t min_key = MinKey;
    /** The longest key. */
    static constexpr std::uint64_t max_key = MaxKey;

    /**
     Checks a tag's options: none to check.

     @return Success.
    */
    template <class Options>
    [[nodiscard]] static constexpr boost::system::result<void> check(
        Options const& /*options*/) noexcept {
        return {};
    }
};

/** The shortest HMAC tag `mac` gives: 10 bytes, RFC 2104 section 5's 80 bits (ruling R23). */
inline constexpr std::uint64_t hmac_min_output = 10;

/**
 The family's guards of a tag of `macs`, in one place (spec 2.15): `min_output` and `max_output`
 (`invalid_output_size` outside them), `min_key` and `max_key` (`invalid_key_size`), and
 `check(options)`, the options' own guards (`input_too_long` for KMAC's customisation). Every tag of
 `macs` has a specialisation; the increment that gives a tag options adds their check to it.

 The primary template, reached only by a type that is not a tag, guards nothing: the engine's
 refusal is then the call's only error.

 @tparam Mac A tag of `macs`.
*/
template <class Mac>
struct mac_traits : mac_sizes<1, no_limit, 0, no_limit> {};

/**
 The longest HMAC tag over `Digest`: the digest's size; 0 for an extendable-output function, which
 has no digest size for HMAC to be defined over, so that every tag is `invalid_output_size`.
*/
template <class Digest>
inline constexpr std::uint64_t hmac_max_output =
    digest_traits<Digest>::max_output(digest_options<Digest>{}) == no_limit
        ? 0
        : digest_traits<Digest>::max_output(digest_options<Digest>{});

/**
 HMAC over `Digest` (RFC 2104): a key of any size; a tag of 10 bytes up to the digest's size, the
 digest cut to it (section 5; ruling R23); no tag over an extendable-output function.
*/
template <class Digest>
struct mac_traits<macs::hmac<Digest>>
    : mac_sizes<hmac_min_output, hmac_max_output<Digest>, 0, no_limit> {};

/** The shortest KMAC tag `mac` gives: 4 bytes, SP 800-185 section 8.4.2's 32 bits. */
inline constexpr std::uint64_t kmac_min_output = 4;

/**
 KMAC's guards (SP 800-185, section 4): a tag of at least 4 bytes, since section 8.4.2 forbids a
 MAC of fewer than 32 bits (as `mac` holds HMAC to RFC 2104's 80), and a key of any size, each at
 most `sp800_185_max_bytes`, the most whose length in bits a `size_t` holds
 (`invalid_output_size`, `invalid_key_size`); a customisation of at most as many bytes
 (`input_too_long`).

 @tparam Mac `macs::kmac_128` or `macs::kmac_256`.
*/
template <class Mac>
struct kmac_traits : mac_sizes<kmac_min_output, sp800_185_max_bytes, 0, sp800_185_max_bytes> {
    /**
     Checks the customisation.

     @param options The options. @return Success, or `input_too_long`.
    */
    [[nodiscard]] static boost::system::result<void> check(
        mac_options<Mac> const& options) noexcept {
        return check_sp800_185_string(options.customisation);
    }
};

/** KMAC128 (SP 800-185): any key, a tag from 4 bytes; its customisation checked. */
template <>
struct mac_traits<macs::kmac_128> : kmac_traits<macs::kmac_128> {};

/** KMAC256 (SP 800-185): any key, a tag from 4 bytes; its customisation checked. */
template <>
struct mac_traits<macs::kmac_256> : kmac_traits<macs::kmac_256> {};

// clang-format off
/** SipHash-2-4: a 16-byte key, an 8-byte tag. */
template <> struct mac_traits<macs::siphash_2_4> : mac_sizes<8, 8, 16, 16> {};
/** SipHash-2-4 with a 16-byte tag: a 16-byte key. */
template <> struct mac_traits<macs::siphash_2_4x> : mac_sizes<16, 16, 16, 16> {};
/** BLAKE2b keyed (RFC 7693): a key of 1 to 64 bytes, a tag of 1 to 64 bytes. */
template <> struct mac_traits<macs::blake2b_mac> : mac_sizes<1, 64, 1, 64> {};
/** BLAKE2s keyed (RFC 7693): a key of 1 to 32 bytes, a tag of 1 to 32 bytes. */
template <> struct mac_traits<macs::blake2s_mac> : mac_sizes<1, 32, 1, 32> {};
// clang-format on

/**
 The family's guards of `mac` (spec 2.15), without the backend's: the tag's size
 (`invalid_output_size`), the key's (`invalid_key_size`), then the options' own. What a backend
 that completes by itself (`backends::webcrypto`) checks before it starts the work.

 @tparam Mac A tag of `macs`. @param output_size The tag's size. @param key_size The key's size.
 @param options The MAC's parameters.
 @return Success, or the error of the first guard that fails, as `mac` returns it.
*/
template <class Mac>
[[nodiscard]] boost::system::result<void> mac_guards(std::size_t output_size, std::size_t key_size,
                                                     mac_options<Mac> const& options) {
    using traits = mac_traits<Mac>;
    // Each bound through exceeds, a function of two 64-bit values: a constant bound of 0 or of
    // no_limit compared with a size_t is a tautology the warnings refuse.
    if (exceeds(traits::min_output, output_size) || exceeds(output_size, traits::max_output)) {
        return error::invalid_output_size;
    }
    if (exceeds(traits::min_key, key_size) || exceeds(key_size, traits::max_key)) {
        return error::invalid_key_size;
    }
    return traits::check(options);
}

}  // namespace detail

/**
 The tag of `input` under `key`, with the MAC `Mac` on `Backend`.

 @code
 std::array<std::uint8_t, 32> tag{};
 auto done = webcpp::hash::mac<webcpp::hash::macs::hmac<webcpp::hash::digests::sha2_256>>(
     tag, key, message);
 @endcode

 @tparam Mac A tag of `macs`, as `macs::hmac<digests::sha2_256>`.
 @tparam Backend The backend; by default @ref default_backend of `Mac` (spec 4.1). A backend
 without the tag, or one the program does not link, refuses at compile time.
 @param output The tag: for HMAC, 10 bytes up to the digest's size (a shorter tag is the digest
 cut, RFC 2104 section 5); for the others, the size their traits give.
 @param key The key.
 @param input The message, of any size.
 @param options The MAC's parameters (none for most tags).
 @return Success; or the first guard's error (`invalid_output_size`, `invalid_key_size`, an
 option's error, `unsupported_by_backend`), `output` untouched; or the backend's failure,
 `output` zeroed.
*/
template <class Mac, class Backend = default_backend<Mac>>
[[nodiscard]] boost::system::result<void> mac(std::span<std::uint8_t> output,
                                              std::span<std::uint8_t const> key,
                                              std::span<std::uint8_t const> input,
                                              mac_options<Mac> const& options = {}) {
    using engine = detail::mac_engine<Backend, Mac>;
    auto checked = detail::mac_guards<Mac>(output.size(), key.size(), options);
    if (!checked) {
        return checked;
    }
    if (!engine::accepts(options, key.size(), output.size())) {
        return error::unsupported_by_backend;
    }
    auto computed = engine::compute(output, key, input, options);
    if (!computed) {
        detail::wipe(output);
    }
    return computed;
}

}  // namespace webcpp::hash

// The engines of each backend the program links, as digest.hpp includes them.
#ifdef WEBCPP_HASH_HAS_XKCP
#include <webcpp/hash/backends/xkcp.hpp>
#endif
#ifdef WEBCPP_HASH_HAS_BLAKE3
#include <webcpp/hash/backends/blake3.hpp>
#endif
#ifdef WEBCPP_HASH_HAS_SODIUM
#include <webcpp/hash/backends/sodium.hpp>
#endif
#ifdef WEBCPP_HASH_HAS_BEARSSL
#include <webcpp/hash/backends/bearssl.hpp>
#endif
#ifdef WEBCPP_HASH_HAS_OPENSSL
#include <webcpp/hash/backends/openssl.hpp>
#endif

#endif  // WEBCPP_HASH_MAC_HPP
