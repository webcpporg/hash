// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The digest family (spec 2.15): `digest_of`, a hash in one call, and `hasher`, the same hash fed in
 pieces, each over a tag of `digests` and a backend, `default_backend` of the tag by default.

 The guards are the same on every backend and run before any work: an output of a size the tag
 does not produce is `invalid_output_size` (a fixed-size digest takes exactly its size, an
 extendable-output function any size from 1 byte); a value the tag accepts and the chosen backend
 does not is `unsupported_by_backend`. A guard's refusal leaves the output as it was; a backend's
 failure zeroes it.

 @code
 std::array<std::uint8_t, 32> id{};
 auto done = webcpp::hash::digest_of<webcpp::hash::digests::sha2_256>(id, message);

 auto hashing = webcpp::hash::hasher<webcpp::hash::digests::sha2_256>::make();
 // hashing->update(piece) for each piece, then hashing->finish(id), once
 @endcode

 The Hash2-form types (`sha2_256`, `keccak_256`, `blake3`, ...) stay the types to use with
 `hash_append`; a family reaches every backend's implementation of the same algorithm.

 @see "Digests", in the guide.
*/
#ifndef WEBCPP_HASH_DIGEST_HPP
#define WEBCPP_HASH_DIGEST_HPP

#include <webcpp/hash/config.hpp>

#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/detail/limits.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/secure/erase_secret.hpp>
#include <webcpp/secure/timing_guard.hpp>

#include <boost/system/result.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

namespace webcpp::hash {

/**
 The parameters of a digest: none for most tags, which this primary template serves. A tag with
 parameters (BLAKE2b's key, salt and personalisation; cSHAKE's and the SP 800-185 functions' names
 and customisations; KT128's and KT256's customisation; TurboSHAKE's domain byte) has its own
 specialisation, from the increment that brings its first backend.

 @tparam Digest A tag of `digests`.
*/
template <class Digest>
struct digest_options {};

/**
 BLAKE2b's parameters (RFC 7693, section 2.5): a key, a salt, a personalisation and the output's
 size, each part of the parameter block that starts the hash, so that each gives another function.

 @code
 std::array<std::uint8_t, 32> id{};
 auto done = webcpp::hash::digest_of<webcpp::hash::digests::blake2b>(
     id, message, {.personalisation = app_tag, .output_size = 32});
 @endcode

 The output's size is an option, not the output span's alone: BLAKE2b-256 is not BLAKE2b-512 cut
 to 32 bytes, and a `hasher` must know it when it starts. `digest_of` and `hasher::finish` take an
 output of exactly `output_size` bytes (`invalid_output_size` otherwise).

 The spans are read during the call (`digest_of`, `hasher::make`) and not kept.
*/
template <>
struct digest_options<digests::blake2b> {
    /**
     The key, 0 to 64 bytes (`invalid_key_size` past 64); empty, BLAKE2b unkeyed.

     A keyed BLAKE2b is a MAC (`macs::blake2b_mac` names it as one).
    */
    std::span<std::uint8_t const> key = {};

    /** The salt: empty, or 16 bytes (`invalid_salt_size` otherwise). */
    std::span<std::uint8_t const> salt = {};

    /**
     The personalisation, a string that separates one application's hashes from another's: empty,
     or 16 bytes (`invalid_parameters` otherwise); a shorter tag is padded with zeros by the caller.
    */
    std::span<std::uint8_t const> personalisation = {};

    /** The output's size, 1 to 64 bytes (`invalid_output_size` otherwise); 64 by default. */
    std::size_t output_size = 64;
};

/**
 cSHAKE128's parameters (NIST SP 800-185, section 3): the function name N, which NIST reserves
 for functions it defines on cSHAKE, and the customisation string S, which an application
 chooses to separate its uses of the function from any other's. With both empty, cSHAKE128 is
 SHAKE128.

 @code
 std::array<std::uint8_t, 32> id{};
 auto done = webcpp::hash::digest_of<webcpp::hash::digests::cshake_128>(
     id, message, {.customisation = app_name});
 @endcode

 The output is any size from 1 byte, the first bytes of one stream: cSHAKE does not encode its
 length. Each string is at most `SIZE_MAX / 8` bytes (`input_too_long`), and is read during the
 call (`digest_of`, `hasher::make`) and not kept.
*/
template <>
struct digest_options<digests::cshake_128> {
    /** The function name N: empty unless NIST defines the function. */
    std::span<std::uint8_t const> function_name = {};

    /** The customisation string S. */
    std::span<std::uint8_t const> customisation = {};
};

/** cSHAKE256's parameters, as cSHAKE128's (@ref digest_options<digests::cshake_128>). */
template <>
struct digest_options<digests::cshake_256> {
    /** The function name N: empty unless NIST defines the function. */
    std::span<std::uint8_t const> function_name = {};

    /** The customisation string S. */
    std::span<std::uint8_t const> customisation = {};
};

/**
 TupleHash128's parameters (NIST SP 800-185, section 5): the customisation string S and the
 form, fixed-length or extendable-output (TupleHashXOF128). TupleHash hashes a tuple of byte
 strings so that their bounds count: ("ab", "c") and ("a", "bc") give different digests.
 `hasher::update` takes one element of the tuple per call; `digest_of` hashes the tuple of one
 element, its input.

 @code
 auto hashing = webcpp::hash::hasher<webcpp::hash::digests::tuplehash_128>::make();
 // hashing->update(element) for each element, then hashing->finish(digest), once
 @endcode

 The fixed-length form encodes the output's length L, so that its digests of 32 and 64 bytes are
 unrelated; the XOF form encodes none, and its shorter output is the start of its longer. The
 fixed-length output is at most `SIZE_MAX / 8` bytes (`invalid_output_size`), as is S
 (`input_too_long`), which is read during the call (`digest_of`, `hasher::make`) and not kept.
*/
template <>
struct digest_options<digests::tuplehash_128> {
    /** The customisation string S. */
    std::span<std::uint8_t const> customisation = {};

    /** The extendable-output form, TupleHashXOF128, in place of the fixed-length one. */
    bool xof = false;
};

/** TupleHash256's parameters, as TupleHash128's (@ref digest_options<digests::tuplehash_128>). */
template <>
struct digest_options<digests::tuplehash_256> {
    /** The customisation string S. */
    std::span<std::uint8_t const> customisation = {};

    /** The extendable-output form, TupleHashXOF256, in place of the fixed-length one. */
    bool xof = false;
};

/**
 ParallelHash128's parameters (NIST SP 800-185, section 6): the block size B in bytes, the
 customisation string S and the form, fixed-length or extendable-output (ParallelHashXOF128).
 ParallelHash cuts its input in blocks of B bytes, hashes each on its own (in parallel where an
 implementation can) and hashes the results: B is part of the function, and the same input
 under another B gives another digest.

 @code
 std::array<std::uint8_t, 32> digest{};
 auto done = webcpp::hash::digest_of<webcpp::hash::digests::parallelhash_128>(
     digest, file_bytes, {.block_size = 8192});
 @endcode

 SP 800-185 sets no default B: the call states it, and 0 is `invalid_parameters`. A backend may
 take fewer: XKCP takes a power of two of at least 8 bytes, and answers any other with
 `unsupported_by_backend`. The whole input, in one call or across a hasher's updates, is at most
 `SIZE_MAX / 8` bytes (`input_too_long`), since its length is counted in bits. The fixed-length
 form encodes the output's length, as TupleHash's does
 (@ref digest_options<digests::tuplehash_128>), and is at most `SIZE_MAX / 8` bytes
 (`invalid_output_size`), as is S (`input_too_long`), which is read during the call and not kept.
*/
template <>
struct digest_options<digests::parallelhash_128> {
    /** The block size B in bytes; no default (0 is `invalid_parameters`). */
    std::size_t block_size = 0;

    /** The customisation string S. */
    std::span<std::uint8_t const> customisation = {};

    /** The extendable-output form, ParallelHashXOF128, in place of the fixed-length one. */
    bool xof = false;
};

/**
 ParallelHash256's parameters, as ParallelHash128's
 (@ref digest_options<digests::parallelhash_128>).
*/
template <>
struct digest_options<digests::parallelhash_256> {
    /** The block size B in bytes; no default (0 is `invalid_parameters`). */
    std::size_t block_size = 0;

    /** The customisation string S. */
    std::span<std::uint8_t const> customisation = {};

    /** The extendable-output form, ParallelHashXOF256, in place of the fixed-length one. */
    bool xof = false;
};

/**
 KT128's parameter (RFC 9861, section 3): the customisation string C, which an application
 chooses to separate its uses of the function from any other's; empty by default. KT128 is a tree
 over TurboSHAKE128 that hashes a long input in chunks of 8,192 bytes, which an implementation
 may hash in parallel; its output is any size from 1 byte, the shorter the start of the longer.

 @code
 std::array<std::uint8_t, 32> digest{};
 auto done = webcpp::hash::digest_of<webcpp::hash::digests::kt128>(
     digest, file_bytes, {.customisation = app_name});
 @endcode

 KangarooTwelve absorbs C after the message, so `hasher` keeps the span `make` took and reads C at
 `finish`, not before: the caller keeps those bytes alive and unchanged until then (no copy, so no
 allocation). `digest_of` reads C during the call. On backends::xkcp where a `size_t` has 32 bits
 (wasm32), the message and C together are at most a little under 32 TiB (`input_too_long`, a
 refusal after which a hasher is spent), since XKCP counts the chunks in a `size_t`.
*/
template <>
struct digest_options<digests::kt128> {
    /** The customisation string C, read at `finish` by a hasher. */
    std::span<std::uint8_t const> customisation = {};
};

/** KT256's parameter, as KT128's (@ref digest_options<digests::kt128>), over TurboSHAKE256. */
template <>
struct digest_options<digests::kt256> {
    /** The customisation string C, read at `finish` by a hasher. */
    std::span<std::uint8_t const> customisation = {};
};

/**
 TurboSHAKE's parameter (RFC 9861, section 2.1): the domain separation byte D, which the sponge
 absorbs after the message, so that each value gives another function. The standard value is 0x1F;
 a protocol that builds several functions over TurboSHAKE gives each its own byte.

 @code
 std::array<std::uint8_t, 32> output{};
 auto done = webcpp::hash::digest_of<webcpp::hash::digests::turboshake_128>(
     output, message, {.domain = 0x0B});
 @endcode
*/
template <>
struct digest_options<digests::turboshake_128> {
    /** D, 0x01 to 0x7F (`invalid_parameters` otherwise); 0x1F by default. */
    std::uint8_t domain = 0x1F;
};

/** TurboSHAKE256's parameter, as TurboSHAKE128's (RFC 9861, section 2.1). */
template <>
struct digest_options<digests::turboshake_256> {
    /** D, 0x01 to 0x7F (`invalid_parameters` otherwise); 0x1F by default. */
    std::uint8_t domain = 0x1F;
};

namespace detail {

/** The output sizes of a digest of `Size` bytes, fixed: the output is exactly that. */
template <std::size_t Size>
struct fixed_output {
    /**
     The shortest output, the digest's size.

     @return `Size`.
    */
    template <class Options>
    static constexpr std::uint64_t min_output(Options const& /*options*/) noexcept {
        return Size;
    }

    /**
     The longest output, the digest's size.

     @return `Size`.
    */
    template <class Options>
    static constexpr std::uint64_t max_output(Options const& /*options*/) noexcept {
        return Size;
    }

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

/** The output sizes of an extendable-output function: any size from 1 byte. */
struct extendable_output {
    /**
     The shortest output, 1 byte.

     @return 1.
    */
    template <class Options>
    static constexpr std::uint64_t min_output(Options const& /*options*/) noexcept {
        return 1;
    }

    /**
     The longest output: no limit.

     @return `no_limit`.
    */
    template <class Options>
    static constexpr std::uint64_t max_output(Options const& /*options*/) noexcept {
        return no_limit;
    }

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

/**
 The family's guards of a tag of `digests`, in one place (spec 2.15): `min_output(options)` and
 `max_output(options)`, the output sizes the tag produces (`invalid_output_size` outside them);
 `check(options)`, the options' own guards (`invalid_parameters`, `invalid_key_size`,
 `invalid_salt_size` or `input_too_long`), success for a tag without options. Every tag of `digests`
 has a specialisation; the increment that gives a tag options adds their check to it.

 The primary template, reached only by a type that is not a tag, guards nothing: the engine's
 refusal is then the call's only error.

 @tparam Digest A tag of `digests`.
*/
template <class Digest>
struct digest_traits : extendable_output {};

// clang-format off
/** MD5: 16 bytes. */
template <> struct digest_traits<digests::md5> : fixed_output<16> {};
/** SHA-1: 20 bytes. */
template <> struct digest_traits<digests::sha1> : fixed_output<20> {};
/** SHA-224: 28 bytes. */
template <> struct digest_traits<digests::sha2_224> : fixed_output<28> {};
/** SHA-256: 32 bytes. */
template <> struct digest_traits<digests::sha2_256> : fixed_output<32> {};
/** SHA-384: 48 bytes. */
template <> struct digest_traits<digests::sha2_384> : fixed_output<48> {};
/** SHA-512: 64 bytes. */
template <> struct digest_traits<digests::sha2_512> : fixed_output<64> {};
/** SHA-512/224: 28 bytes. */
template <> struct digest_traits<digests::sha2_512_224> : fixed_output<28> {};
/** SHA-512/256: 32 bytes. */
template <> struct digest_traits<digests::sha2_512_256> : fixed_output<32> {};
/** SHA3-224: 28 bytes. */
template <> struct digest_traits<digests::sha3_224> : fixed_output<28> {};
/** SHA3-256: 32 bytes. */
template <> struct digest_traits<digests::sha3_256> : fixed_output<32> {};
/** SHA3-384: 48 bytes. */
template <> struct digest_traits<digests::sha3_384> : fixed_output<48> {};
/** SHA3-512: 64 bytes. */
template <> struct digest_traits<digests::sha3_512> : fixed_output<64> {};
/** SHAKE128: any size from 1 byte. */
template <> struct digest_traits<digests::shake_128> : extendable_output {};
/** SHAKE256: any size from 1 byte. */
template <> struct digest_traits<digests::shake_256> : extendable_output {};
/** Keccak-224: 28 bytes. */
template <> struct digest_traits<digests::keccak_224> : fixed_output<28> {};
/** Keccak-256: 32 bytes. */
template <> struct digest_traits<digests::keccak_256> : fixed_output<32> {};
/** Keccak-384: 48 bytes. */
template <> struct digest_traits<digests::keccak_384> : fixed_output<48> {};
/** Keccak-512: 64 bytes. */
template <> struct digest_traits<digests::keccak_512> : fixed_output<64> {};
/** KT128: any size from 1 byte, any customisation. */
template <> struct digest_traits<digests::kt128> : extendable_output {};
/** KT256: any size from 1 byte, any customisation. */
template <> struct digest_traits<digests::kt256> : extendable_output {};
/** BLAKE2s-256: 32 bytes. */
template <> struct digest_traits<digests::blake2s_256> : fixed_output<32> {};
/** BLAKE3: any size from 1 byte (its digest is the first 32). */
template <> struct digest_traits<digests::blake3> : extendable_output {};
/** RIPEMD-160: 20 bytes. */
template <> struct digest_traits<digests::ripemd_160> : fixed_output<20> {};
/** MD5 then SHA-1: 36 bytes. */
template <> struct digest_traits<digests::md5_sha1> : fixed_output<36> {};
/** SM3: 32 bytes. */
template <> struct digest_traits<digests::sm3> : fixed_output<32> {};
/** Streebog-256: 32 bytes. */
template <> struct digest_traits<digests::streebog_256> : fixed_output<32> {};
/** Streebog-512: 64 bytes. */
template <> struct digest_traits<digests::streebog_512> : fixed_output<64> {};
/** Whirlpool: 64 bytes. */
template <> struct digest_traits<digests::whirlpool> : fixed_output<64> {};
/** Skein-512: 64 bytes. */
template <> struct digest_traits<digests::skein_512> : fixed_output<64> {};
// clang-format on

/**
 BLAKE2b's guards (RFC 7693, ruling R21): the output of exactly `output_size` bytes, 1 to 64; a key
 of at most 64 bytes; a salt and a personalisation each empty or of 16 bytes.
*/
template <>
struct digest_traits<digests::blake2b> {
    /** BLAKE2b's longest output and key, and its salt's and personalisation's size, in bytes. */
    static constexpr std::size_t max_size = 64;
    /** The size of a salt or a personalisation that is not empty. */
    static constexpr std::size_t block_part_size = 16;

    /**
     The shortest output: the options' size, and at least 1.

     @param options The options. @return The size the output must have.
    */
    static constexpr std::uint64_t min_output(
        digest_options<digests::blake2b> const& options) noexcept {
        return options.output_size == 0 ? 1 : options.output_size;
    }

    /**
     The longest output: the options' size, and at most 64, so that an output size out of range
     refuses every output.

     @param options The options. @return The size the output must have.
    */
    static constexpr std::uint64_t max_output(
        digest_options<digests::blake2b> const& options) noexcept {
        return options.output_size > max_size ? max_size : options.output_size;
    }

    /**
     Checks the options, in order: the output size, the key, the salt, the personalisation.

     @param options The options.
     @return Success; or `invalid_output_size`, `invalid_key_size`, `invalid_salt_size` or
     `invalid_parameters`.
    */
    [[nodiscard]] static constexpr boost::system::result<void> check(
        digest_options<digests::blake2b> const& options) noexcept {
        if (options.output_size == 0 || options.output_size > max_size) {
            return error::invalid_output_size;
        }
        if (options.key.size() > max_size) {
            return error::invalid_key_size;
        }
        if (!options.salt.empty() && options.salt.size() != block_part_size) {
            return error::invalid_salt_size;
        }
        if (!options.personalisation.empty() && options.personalisation.size() != block_part_size) {
            return error::invalid_parameters;
        }
        return {};
    }
};

/**
 TurboSHAKE's guards (RFC 9861, ruling R25): any output size from 1 byte, and the domain byte within
 0x01 to 0x7F, which the RFC requires and which neither libsodium nor XKCP checks: the family
 refuses another before any engine, the same way on every backend.
*/
struct turboshake_traits : extendable_output {
    /** The smallest domain byte RFC 9861 allows. */
    static constexpr std::uint8_t min_domain = 0x01;
    /** The largest domain byte RFC 9861 allows. */
    static constexpr std::uint8_t max_domain = 0x7F;

    /**
     Checks the domain byte.

     @param options The options. @return Success, or `invalid_parameters`.
    */
    template <class Options>
    [[nodiscard]] static constexpr boost::system::result<void> check(
        Options const& options) noexcept {
        if (options.domain < min_domain || options.domain > max_domain) {
            return error::invalid_parameters;
        }
        return {};
    }
};

/** TurboSHAKE128: any size from 1 byte, a domain byte of 0x01 to 0x7F. */
template <>
struct digest_traits<digests::turboshake_128> : turboshake_traits {};

/** TurboSHAKE256: any size from 1 byte, a domain byte of 0x01 to 0x7F. */
template <>
struct digest_traits<digests::turboshake_256> : turboshake_traits {};

/**
 Whether a string of SP 800-185 is longer than its length in bits can be (`input_too_long`).

 @param string_bytes The string. @return Its refusal, or success.
*/
[[nodiscard]] inline boost::system::result<void> check_sp800_185_string(
    std::span<std::uint8_t const> string_bytes) noexcept {
    if (exceeds(string_bytes.size(), sp800_185_max_bytes)) {
        return error::input_too_long;
    }
    return {};
}

/**
 The guards of cSHAKE (SP 800-185, section 3): any output from 1 byte, a function name and a
 customisation of at most `sp800_185_max_bytes` each (`input_too_long`).

 @tparam Digest `digests::cshake_128` or `digests::cshake_256`.
*/
template <class Digest>
struct cshake_traits : extendable_output {
    /**
     Checks the function name, then the customisation.

     @param options The options. @return Success, or `input_too_long`.
    */
    [[nodiscard]] static boost::system::result<void> check(
        digest_options<Digest> const& options) noexcept {
        auto named = check_sp800_185_string(options.function_name);
        if (!named) {
            return named;
        }
        return check_sp800_185_string(options.customisation);
    }
};

/** cSHAKE128: any size from 1 byte; its strings checked. */
template <>
struct digest_traits<digests::cshake_128> : cshake_traits<digests::cshake_128> {};

/** cSHAKE256: any size from 1 byte; its strings checked. */
template <>
struct digest_traits<digests::cshake_256> : cshake_traits<digests::cshake_256> {};

/**
 The guards of TupleHash and ParallelHash (SP 800-185, sections 5 and 6): an output from 1 byte,
 at most `sp800_185_max_bytes` in the fixed-length form, whose length is encoded, and of any size
 in the XOF form; a customisation of at most `sp800_185_max_bytes` (`input_too_long`); for
 ParallelHash, a block size other than 0 (`invalid_parameters`).

 @tparam Digest A tag of TupleHash or ParallelHash.
*/
template <class Digest>
struct sp800_185_hash_traits {
    /**
     The shortest output, 1 byte.

     @return 1.
    */
    static constexpr std::uint64_t min_output(digest_options<Digest> const& /*options*/) noexcept {
        return 1;
    }

    /**
     The longest output: `sp800_185_max_bytes` in the fixed-length form, no limit in the XOF form.

     @param options The options. @return The longest output.
    */
    static constexpr std::uint64_t max_output(digest_options<Digest> const& options) noexcept {
        return options.xof ? no_limit : sp800_185_max_bytes;
    }

    /**
     Checks ParallelHash's block size, then the customisation.

     @param options The options.
     @return Success, `invalid_parameters` or `input_too_long`.
    */
    [[nodiscard]] static boost::system::result<void> check(
        digest_options<Digest> const& options) noexcept {
        if constexpr (requires { options.block_size; }) {
            if (options.block_size == 0) {
                return error::invalid_parameters;
            }
        }
        return check_sp800_185_string(options.customisation);
    }
};

/** TupleHash128: 1 byte up, the fixed-length form within `sp800_185_max_bytes`. */
template <>
struct digest_traits<digests::tuplehash_128> : sp800_185_hash_traits<digests::tuplehash_128> {};

/** TupleHash256: 1 byte up, the fixed-length form within `sp800_185_max_bytes`. */
template <>
struct digest_traits<digests::tuplehash_256> : sp800_185_hash_traits<digests::tuplehash_256> {};

/** ParallelHash128: as TupleHash, and a block size other than 0. */
template <>
struct digest_traits<digests::parallelhash_128> : sp800_185_hash_traits<digests::parallelhash_128> {
};

/** ParallelHash256: as TupleHash, and a block size other than 0. */
template <>
struct digest_traits<digests::parallelhash_256> : sp800_185_hash_traits<digests::parallelhash_256> {
};

/**
 The family's guard of `digest_of` and `hasher::finish` on an output of `output_size` bytes: the
 tag's sizes for its options (`invalid_output_size`).

 @param output_size The output's size. @param min_size The tag's shortest output for its options.
 @param max_size The tag's longest output for its options.
 @return Success, or `invalid_output_size`.
*/
[[nodiscard]] inline boost::system::result<void> check_output(std::size_t output_size,
                                                              std::uint64_t min_size,
                                                              std::uint64_t max_size) noexcept {
    if (output_size < min_size || exceeds(output_size, max_size)) {
        return error::invalid_output_size;
    }
    return {};
}

/**
 The family's guards of `digest_of` (spec 2.15), without the backend's: the output's size for the
 options (`invalid_output_size`), then the options' own. What a backend that completes by itself
 (`backends::webcrypto`) checks before it starts the work.

 @tparam Digest A tag of `digests`. @param output_size The output's size.
 @param options The digest's parameters.
 @return Success, or the error of the first guard that fails, as `digest_of` returns it.
*/
template <class Digest>
[[nodiscard]] boost::system::result<void> digest_guards(std::size_t output_size,
                                                        digest_options<Digest> const& options) {
    using traits = digest_traits<Digest>;
    auto sized =
        check_output(output_size, traits::min_output(options), traits::max_output(options));
    if (!sized) {
        return sized;
    }
    return traits::check(options);
}

/**
 The backend's guard of `digest_of` and `hasher::finish` on an output the family accepts: the
 engine's shortest and longest outputs (`unsupported_by_backend`). It runs after the options'
 guards, so that an option's error comes before the backend's refusal.

 @tparam Engine The tag's engine on the chosen backend.
 @param output_size The output's size.
 @return Success, or `unsupported_by_backend`.
*/
template <class Engine>
[[nodiscard]] boost::system::result<void> check_engine_output(std::size_t output_size) noexcept {
    if (exceeds(Engine::min_output, output_size) || exceeds(output_size, Engine::max_output)) {
        return error::unsupported_by_backend;
    }
    return {};
}

/**
 Whether a digest's options carry a key: a keyed BLAKE2b is a MAC, and holds the timing guard of
 one (design D1); every other digest computes on public data.

 @tparam Options A tag's `digest_options`. @param options The digest's parameters.
 @return Whether the options hold a non-empty `key`; `false` for options without one.
*/
template <class Options>
[[nodiscard]] constexpr bool options_keyed(Options const& options) noexcept {
    if constexpr (requires { options.key.empty(); }) {
        return !options.key.empty();
    } else {
        return false;
    }
}

}  // namespace detail

/**
 Hashes `input` into `output` with the digest `Digest` on `Backend`, in one call.

 @code
 std::array<std::uint8_t, 32> id{};
 auto done = webcpp::hash::digest_of<webcpp::hash::digests::sha2_256>(id, message);
 @endcode

 @tparam Digest A tag of `digests`, as `digests::sha2_256`.
 @tparam Backend The backend; by default @ref default_backend of `Digest` (spec 4.1). A backend
 without the tag, or one the program does not link, refuses at compile time, naming those that
 have it, or the Jamfile line to add.
 @param output The digest: exactly the digest's size for a fixed-size digest, any size from 1
 byte for an extendable-output function.
 @param input The data, of any size.
 @param options The digest's parameters (none for most tags).
 @return Success; or the first guard's error (`invalid_output_size`, an option's error,
 `unsupported_by_backend`), `output` untouched; or the backend's failure, `output` zeroed.
*/
template <class Digest, class Backend = default_backend<Digest>>
[[nodiscard]] boost::system::result<void> digest_of(std::span<std::uint8_t> output,
                                                    std::span<std::uint8_t const> input,
                                                    digest_options<Digest> const& options = {}) {
    secure::timing_guard const timing{detail::options_keyed(options)};
    using engine = detail::digest_engine<Backend, Digest>;
    auto checked = detail::digest_guards<Digest>(output.size(), options);
    if (!checked) {
        return checked;
    }
    auto served = detail::check_engine_output<engine>(output.size());
    if (!served) {
        return served;
    }
    if (!engine::accepts(options)) {
        return error::unsupported_by_backend;
    }
    auto hashed = engine::one_shot(output, input, options);
    if (!hashed) {
        secure::erase_secret(output);
    }
    return hashed;
}

// MSVC's warning C4324 ("structure was padded due to alignment specifier") is off for the hasher
// alone. A backend's state may carry an alignment specifier (libsodium's are CRYPTO_ALIGN(16) or
// CRYPTO_ALIGN(64)), so the hasher is padded after its last member to a multiple of that
// alignment, as the state requires, and no order of the members avoids it: the padding is the
// intended layout. MSVC for ARM64 reports that trailing padding under /W4, which /WX makes an
// error; MSVC for x64 reports only padding before an aligned member, never after the last one,
// and so is silent here (14.3 and 14.5 alike, msvc-lane's probe of 2026-11-23).
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4324)
#endif
/**
 A hash fed in pieces, with one result: `make`, `update` as often as the data comes, then `finish`
 once (spec 2.15).

 Unlike Boost.Hash2's types, the result is final: an `update` or a `finish` after `finish`, or on a
 hasher moved from, is `error::invalid_state`.

 A hasher made with a key (BLAKE2b's) holds the timing guard of a MAC in `make`, `update` and
 `finish`, as `digest_of` with a key does; one made without a key holds none (design D1, D2).

 Move-only. The state is wiped (and what the backend allocated for it freed) by `finish`, by the
 destructor, and in the hasher moved from.

 @code
 auto hashing = webcpp::hash::hasher<webcpp::hash::digests::sha2_256>::make();
 if (!hashing) {
     return hashing.error();
 }
 for (auto piece : pieces) {
     if (auto fed = hashing->update(piece); !fed) {
         return fed.error();
     }
 }
 std::array<std::uint8_t, 32> id{};
 auto done = hashing->finish(id);
 @endcode

 @tparam Digest A tag of `digests`.
 @tparam Backend The backend; by default @ref default_backend of `Digest`.
*/
template <class Digest, class Backend = default_backend<Digest>>
class hasher {
    using engine = detail::digest_engine<Backend, Digest>;
    using traits = detail::digest_traits<Digest>;

public:
    /**
     Starts a hash.

     @param options The digest's parameters (none for most tags).
     @return The hasher; or an option's error or `unsupported_by_backend`; or the backend's
     failure.
    */
    [[nodiscard]] static boost::system::result<hasher> make(
        digest_options<Digest> const& options = {}) noexcept {
        secure::timing_guard const timing{detail::options_keyed(options)};
        auto const checked = traits::check(options);
        if (!checked) {
            return checked.error();
        }
        if (!engine::accepts(options)) {
            return error::unsupported_by_backend;
        }
        hasher started;
        auto const initialised = engine::init(started.state_, options);
        if (!initialised) {
            engine::destroy(started.state_);
            started.phase_ = phase::spent;
            return initialised.error();
        }
        started.min_output_ = traits::min_output(options);
        started.max_output_ = traits::max_output(options);
        started.keyed_ = detail::options_keyed(options);
        started.phase_ = phase::hashing;
        return started;
    }

    /**
     Takes the hash of `moved_from`, which is wiped and then answers `invalid_state`.

     @param moved_from The hasher moved from.
    */
    hasher(hasher&& moved_from) noexcept
        : state_(std::move(moved_from.state_)),
          min_output_(moved_from.min_output_),
          max_output_(moved_from.max_output_),
          keyed_(moved_from.keyed_),
          phase_(moved_from.phase_) {
        moved_from.leave();
    }

    /**
     Ends this hash (its state wiped) and takes that of `moved_from`, which is wiped and then
     answers `invalid_state`.

     @param moved_from The hasher moved from.
     @return This hasher.
    */
    hasher& operator=(hasher&& moved_from) noexcept {
        if (this != &moved_from) {
            end();
            state_ = std::move(moved_from.state_);
            min_output_ = moved_from.min_output_;
            max_output_ = moved_from.max_output_;
            keyed_ = moved_from.keyed_;
            phase_ = moved_from.phase_;
            moved_from.leave();
        }
        return *this;
    }

    /** Not copyable: a copy would be a second result of one hash, and a second state to wipe. */
    hasher(hasher const&) = delete;
    /** Not copyable. @return Never. */
    hasher& operator=(hasher const&) = delete;

    /** Wipes the state, and frees what the backend allocated for it. */
    ~hasher() { end(); }

    /**
     Absorbs `input`.

     @param input The next piece of the data, of any size.
     @return Success; `invalid_state` after `finish` or once moved from; `input_too_long` when the
     input would pass a limit of the tag's options or of the backend (ParallelHash's whole input,
     a TupleHash element, KangarooTwelve's input on 32-bit XKCP); or the backend's failure. After
     either of the last two the hasher is spent (`invalid_state`).
    */
    [[nodiscard]] boost::system::result<void> update(std::span<std::uint8_t const> input) noexcept {
        secure::timing_guard const timing{keyed_};
        if (phase_ != phase::hashing) {
            return error::invalid_state;
        }
        auto absorbed = engine::update(state_, input);
        if (!absorbed) {
            end();
        }
        return absorbed;
    }

    /**
     Writes the hash's result into `output`, once.

     @param output The digest: exactly the digest's size for a fixed-size digest, any size from 1
     byte for an extendable-output function.
     @return Success, after which the hasher is spent; `invalid_state` after `finish` or once
     moved from; a guard's error (`invalid_output_size`, `unsupported_by_backend`), `output`
     untouched and the hasher still hashing; or the backend's failure, `output` zeroed and the
     hasher spent.
    */
    [[nodiscard]] boost::system::result<void> finish(std::span<std::uint8_t> output) noexcept {
        secure::timing_guard const timing{keyed_};
        if (phase_ != phase::hashing) {
            return error::invalid_state;
        }
        auto sized = detail::check_output(output.size(), min_output_, max_output_);
        if (!sized) {
            return sized;
        }
        auto served = detail::check_engine_output<engine>(output.size());
        if (!served) {
            return served;
        }
        auto finished = engine::finish(state_, output);
        if (!finished) {
            secure::erase_secret(output);
        }
        end();
        return finished;
    }

private:
    // hashing: make succeeded and finish has not run; spent: finished, failed or never started;
    // moved: the hash went to another hasher.
    enum class phase : unsigned char { spent, hashing, moved };

    hasher() noexcept = default;

    // Wipes the state of a hash in progress, which is then spent.
    void end() noexcept {
        if (phase_ == phase::hashing) {
            engine::destroy(state_);
            phase_ = phase::spent;
        }
    }

    // After its hash was moved out: what is left of the state is wiped.
    void leave() noexcept {
        if (phase_ == phase::hashing) {
            engine::destroy(state_);
        }
        phase_ = phase::moved;
    }

    engine::state state_{};
    std::uint64_t min_output_ = 0;
    std::uint64_t max_output_ = 0;
    bool keyed_ = false;  // made with a key: update and finish hold the timing guard
    phase phase_ = phase::spent;
};
#ifdef _MSC_VER
#pragma warning(pop)
#endif

}  // namespace webcpp::hash

// The engines of each backend the program links, so that `digest_of` and `hasher` reach them on a
// call that names the backend, and on the default: backends::hash2 above, always; the others when
// their target defines their WEBCPP_HASH_HAS_<NAME>.
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
#ifdef WEBCPP_HASH_HAS_BOTAN
#include <webcpp/hash/backends/botan.hpp>
#endif

#endif  // WEBCPP_HASH_DIGEST_HPP
