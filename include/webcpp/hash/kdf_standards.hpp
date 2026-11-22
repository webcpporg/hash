// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The key derivations of NIST's and ANSI's standards, which formats and protocols name by their
 standard: `kbkdf`, SP 800-108's key-based KDF in counter mode over an HMAC; `sskdf`, SP 800-56C's
 one-step KDF over a digest (its hash form); and `x963kdf`, ANSI X9.63's KDF, which ECIES and the
 elliptic-curve key agreements of SEC 1 use. Each has `backends::openssl` (OpenSSL 3.5.9's
 `EVP_KDF` implementations "KBKDF", "SSKDF" and "X963KDF"; the program links
 `/webcpp/hash//openssl`, native, wasip2 and wasip3) and `backends::botan` (Botan 3.14.1's
 "SP800-108-Counter", "SP800-56A" and "KDF2"; `/third_party//botan`, native and Emscripten, with
 exceptions), and never a default (design D34): the call names its backend.

 None of them is for a password (Argon2id is) nor a better choice than HKDF for a new design: they
 are here to derive the bytes a standard, a smart card or another library derives.

 Every guard runs before any work, and a guard's refusal leaves the output as it was; a backend's
 failure zeroes it.

 @code
 // key: the key-derivation key, K_IN; label and context name the derived key's purpose.
 std::array<std::uint8_t, 32> derived{};
 auto done = webcpp::hash::kbkdf<webcpp::hash::hmac_sha2_256, webcpp::hash::backends::openssl>(
     derived, key, {.label = label, .context = context});
 if (!done) {
     return done.error();  // derived is as it was, or zeroed when the backend failed
 }
 @endcode

 @see "Key derivations of standards", in the guide's chapter "Key derivation".
*/
#ifndef WEBCPP_HASH_KDF_STANDARDS_HPP
#define WEBCPP_HASH_KDF_STANDARDS_HPP

#include <webcpp/hash/config.hpp>

#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/detail/limits.hpp>
#include <webcpp/hash/detail/wipe.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/kdf.hpp>

#include <boost/system/result.hpp>

#include <cstddef>
#include <cstdint>
#include <span>

namespace webcpp::hash {

/**
 The fixed input of `kbkdf`, SP 800-108's FixedInputData, by default
 `Label || 0x00 || Context || [L]_32`, the form SP 800-108 (section 4) suggests; and the width of
 the counter. Each part can be left out, as OpenSSL's "KBKDF" allows, so that a format that fixes
 another form, or NIST's CAVP vectors (raw fixed input in `context`, `separator` and `length`
 false), are reached.
*/
struct kbkdf_options {
    /** The Label, which names the derived key's purpose; empty for none. */
    std::span<std::uint8_t const> label = {};
    /** The Context, which names the parties or the session; empty for none. */
    std::span<std::uint8_t const> context = {};
    /** r, the counter's width in bits, written big-endian before the fixed input: 8, 16, 24 or 32.
     */
    std::uint32_t counter_bits = 32;
    /** Whether the byte 0x00 separates the label from the context. */
    bool separator = true;
    /** Whether L, the output's length in bits, ends the fixed input, in 4 bytes big-endian. */
    bool length = true;
};

namespace detail {

/**
 What `sskdf` and `x963kdf` need of a digest: whether each standard takes it, its size, and the
 longest input of its padding. The primary template is every digest neither standard takes.

 @tparam Digest A tag of `digests`.
*/
template <class Digest>
struct standard_kdf_digest {
    /** Whether SP 800-56C's one-step KDF takes it (an approved hash function, FIPS 180-4 or 202).
     */
    static constexpr bool sskdf = false;
    /**
     Whether ANSI X9.63's KDF takes it: a hash function SEC 1 v2 lists (section 3.5, SHA-1,
     SHA-224, SHA-256, SHA-384 and SHA-512 of FIPS 180-2), which NIST SP 800-135r1 approves for it
     (section 5.1: a hash function of FIPS 180-3, which has no SHA-512/t).
    */
    static constexpr bool x963 = false;
    /** The digest's size, in bytes. */
    static constexpr std::uint64_t size = 1;
    /** The longest input it hashes, in bytes: `no_limit` where its padding's length is wider. */
    static constexpr std::uint64_t max_input = no_limit;
};

/**
 A digest of FIPS 180-4 whose padding holds its input's length in 64 bits: at most 2^64 - 1 bits,
 2^61 - 1 bytes.

 @tparam Size The digest's size, in bytes.
*/
template <std::uint64_t Size>
struct sha_64_bit_length {
    /** SP 800-56C takes it. */
    static constexpr bool sskdf = true;
    /** ANSI X9.63 takes it. */
    static constexpr bool x963 = true;
    /** The digest's size, in bytes. */
    static constexpr std::uint64_t size = Size;
    /** 2^61 - 1 bytes. */
    static constexpr std::uint64_t max_input = (std::uint64_t{1} << 61U) - 1;
};

/**
 A digest of FIPS 180-4 whose padding holds its input's length in 128 bits: no limit a `size_t`
 reaches.

 @tparam Size The digest's size, in bytes.
 @tparam X963 Whether ANSI X9.63 takes it: SHA-384 and SHA-512, not SHA-512/224 or SHA-512/256.
*/
template <std::uint64_t Size, bool X963>
struct sha_128_bit_length {
    /** SP 800-56C takes it. */
    static constexpr bool sskdf = true;
    /** Whether ANSI X9.63 takes it. */
    static constexpr bool x963 = X963;
    /** The digest's size, in bytes. */
    static constexpr std::uint64_t size = Size;
    /** No limit. */
    static constexpr std::uint64_t max_input = no_limit;
};

/**
 A digest of FIPS 202 (SHA-3), which has no input limit: SP 800-56C takes it, ANSI X9.63 does not.

 @tparam Size The digest's size, in bytes.
*/
template <std::uint64_t Size>
struct sha3_digest {
    /** SP 800-56C takes it. */
    static constexpr bool sskdf = true;
    /** ANSI X9.63 does not. */
    static constexpr bool x963 = false;
    /** The digest's size, in bytes. */
    static constexpr std::uint64_t size = Size;
    /** No limit. */
    static constexpr std::uint64_t max_input = no_limit;
};

/** SHA-1. */
template <>
struct standard_kdf_digest<digests::sha1> : sha_64_bit_length<20> {};

/** SHA-224. */
template <>
struct standard_kdf_digest<digests::sha2_224> : sha_64_bit_length<28> {};

/** SHA-256. */
template <>
struct standard_kdf_digest<digests::sha2_256> : sha_64_bit_length<32> {};

/** SHA-384. */
template <>
struct standard_kdf_digest<digests::sha2_384> : sha_128_bit_length<48, true> {};

/** SHA-512. */
template <>
struct standard_kdf_digest<digests::sha2_512> : sha_128_bit_length<64, true> {};

/** SHA-512/224, which ANSI X9.63 does not take. */
template <>
struct standard_kdf_digest<digests::sha2_512_224> : sha_128_bit_length<28, false> {};

/** SHA-512/256, which ANSI X9.63 does not take. */
template <>
struct standard_kdf_digest<digests::sha2_512_256> : sha_128_bit_length<32, false> {};

/** SHA3-224. */
template <>
struct standard_kdf_digest<digests::sha3_224> : sha3_digest<28> {};

/** SHA3-256. */
template <>
struct standard_kdf_digest<digests::sha3_256> : sha3_digest<32> {};

/** SHA3-384. */
template <>
struct standard_kdf_digest<digests::sha3_384> : sha3_digest<48> {};

/** SHA3-512. */
template <>
struct standard_kdf_digest<digests::sha3_512> : sha3_digest<64> {};

/** The most blocks of `sskdf` and `x963kdf`: their counter is 32 bits and starts at 1. */
inline constexpr std::uint64_t standard_kdf_max_blocks = 0xffffffffULL;

/** The counter's size in `sskdf`'s and `x963kdf`'s hash input, in bytes. */
inline constexpr std::uint64_t standard_kdf_counter_size = 4;

/**
 Whether `counter || secret || info` (in either order) is longer than `Digest` hashes (SP 800-56C
 section 4.1 and ANSI X9.63 section 5.6.3 refuse it), computed without overflow.

 @param secret_size The shared secret's size. @param info_size The info's size.
 @return Whether the input is too long.
*/
template <class Digest>
constexpr bool standard_kdf_input_too_long(std::uint64_t secret_size,
                                           std::uint64_t info_size) noexcept {
    constexpr std::uint64_t room =
        standard_kdf_digest<Digest>::max_input - standard_kdf_counter_size;
    return exceeds(secret_size, room) || exceeds(info_size, room - secret_size);
}

/**
 Whether `sskdf` takes `Digest`, refused at compile time otherwise.

 @tparam Digest Any type.
 @return Whether it is a digest of SP 800-56C.
*/
template <class Digest>
constexpr bool sskdf_takes() noexcept {
    static_assert(standard_kdf_digest<Digest>::sskdf,
                  "webcpp::hash: sskdf takes a digest of SP 800-56C: digests::sha1, "
                  "digests::sha2_224, sha2_256, sha2_384, sha2_512, sha2_512_224, sha2_512_256, "
                  "sha3_224, sha3_256, sha3_384 or sha3_512.");
    return standard_kdf_digest<Digest>::sskdf;
}

/**
 Whether `x963kdf` takes `Digest`, refused at compile time otherwise.

 @tparam Digest Any type.
 @return Whether it is a hash function of SEC 1 v2, section 3.5.
*/
template <class Digest>
constexpr bool x963kdf_takes() noexcept {
    static_assert(standard_kdf_digest<Digest>::x963,
                  "webcpp::hash: x963kdf takes a hash function of SEC 1 v2, section 3.5: "
                  "digests::sha1, digests::sha2_224, sha2_256, sha2_384 or sha2_512.");
    return standard_kdf_digest<Digest>::x963;
}

/** The longest output of `kbkdf` whose length in bits L fits its 32 bits: 2^29 - 1 bytes. */
inline constexpr std::uint64_t kbkdf_max_output_with_length = 0xffffffffULL / 8;

}  // namespace detail

/**
 SP 800-108's key-based key derivation (NIST SP 800-108r1, section 4.1, counter mode) over the
 HMAC `Hmac`: fills `output` from the key-derivation key `key`, each block an HMAC under `key` of
 the counter, then the fixed input `options` states.

 @code
 std::array<std::uint8_t, 32> derived{};
 auto done = webcpp::hash::kbkdf<webcpp::hash::hmac_sha2_256, webcpp::hash::backends::openssl>(
     derived, key, {.label = label, .context = context});
 @endcode

 @tparam Hmac The PRF, a Boost.Hash2 hmac, as `hmac_sha2_256`. SP 800-108r1 approves HMAC over
 an approved hash function (SHA-1, SHA-2, SHA-3); unlike `sskdf` and `x963kdf`, which refuse a
 digest their standard does not take, `kbkdf` takes every hmac its backend has, MD5's,
 RIPEMD-160's and BLAKE2's included, for the protocols outside NIST's approval that use them.
 Where approval matters, take HMAC over SHA-2 or SHA-3.
 @tparam Backend The backend; by default @ref default_backend of `kdfs::kbkdf_hmac`, which has
 none (design D34): the call names `backends::openssl`, which has every hmac of `hmac.hpp` but
 `hmac_ripemd_128`, or `backends::botan`, which has every one but `hmac_ripemd_128` and
 `hmac_sha2_512_224` and writes the separator and L always (`unsupported_by_backend` without
 either).
 @param output K_OUT, its size the length L: 1 byte up to (2^r - 1) digests, and, when
 `options.length`, at most 536,870,911 bytes (L in bits fits its 32 bits). It must not overlap the
 inputs.
 @param key K_IN, the key-derivation key: at least 1 byte (`backends::openssl`: at most `INT_MAX`,
 HMAC's key length in OpenSSL, `unsupported_by_backend` beyond).
 @param options The label, the context, the counter's width and which parts the fixed input holds.
 @return Success; or the first guard's error (`invalid_parameters` for a counter width other than
 8, 16, 24 or 32, `invalid_output_size`, `invalid_key_size`, `unsupported_by_backend`), `output`
 untouched; or `errc::not_enough_memory` or `backend_failure`, `output` zeroed.
*/
template <class Hmac, class Backend = default_backend<kdfs::kbkdf_hmac, Hmac>>
[[nodiscard]] boost::system::result<void> kbkdf(std::span<std::uint8_t> output,
                                                std::span<std::uint8_t const> key,
                                                kbkdf_options const& options = {}) {
    if constexpr (!detail::takes_hmac<Hmac>()) {
        return error::backend_failure;  // unreachable: takes_hmac has stopped the build
    } else {
        using engine = detail::kbkdf_engine<Backend, Hmac>;
        constexpr std::uint64_t digest_length = typename Hmac::result_type().size();
        if (options.counter_bits != 8 && options.counter_bits != 16 && options.counter_bits != 24 &&
            options.counter_bits != 32) {
            return error::invalid_parameters;
        }
        // n = ceil(L / h) blocks, each numbered by the counter, 1 to 2^r - 1 (section 4.1).
        std::uint64_t const max_blocks = (std::uint64_t{1} << options.counter_bits) - 1;
        if (output.empty() || detail::exceeds(output.size(), max_blocks * digest_length) ||
            (options.length &&
             detail::exceeds(output.size(), detail::kbkdf_max_output_with_length))) {
            return error::invalid_output_size;
        }
        if (key.empty()) {
            return error::invalid_key_size;
        }
        if (detail::exceeds(key.size(), engine::limits.max_key) ||
            detail::exceeds(output.size(), engine::limits.max_output)) {
            return error::unsupported_by_backend;
        }
        // A backend that writes one form of the fixed input alone (backends::botan: the
        // separator and L, always) refuses the others.
        if constexpr (requires { engine::accepts(options); }) {
            if (!engine::accepts(options)) {
                return error::unsupported_by_backend;
            }
        }
        auto derived = engine::derive(output, key, options);
        if (!derived) {
            detail::wipe(output);
        }
        return derived;
    }
}

/**
 SP 800-56C's one-step key derivation over the digest `Digest` (NIST SP 800-56C revision 2,
 section 4.1, with H a hash function): fills `output` from the shared secret `secret` and
 `fixed_info`, block after block, each `Digest(counter || secret || fixed_info)` with a 32-bit
 big-endian counter from 1.

 @code
 std::array<std::uint8_t, 32> derived{};
 auto done = webcpp::hash::sskdf<webcpp::hash::digests::sha2_256,
                                 webcpp::hash::backends::openssl>(derived, shared_secret, info);
 @endcode

 @tparam Digest An approved hash function: `digests::sha1`, a SHA-2 (`sha2_224` to
 `sha2_512_256`) or a SHA-3 (`sha3_224` to `sha3_512`); another refuses at compile time.
 @tparam Backend The backend; by default @ref default_backend of `kdfs::sskdf`, which has none
 (design D34): the call names `backends::openssl` or `backends::botan` (every digest but
 SHA-512/224, which Botan lacks: refused at compile time).
 @param output The derived keying material: 1 byte to 2^32 - 1 digests (`backends::openssl`: at
 most 2^30 bytes). It must not overlap the inputs.
 @param secret Z, the shared secret: at least 1 byte (`backends::openssl`: at most 2^30).
 @param fixed_info FixedInfo, which binds the derived key to its parties and purpose; empty for
 none (`backends::openssl`: at most 2^30 bytes).
 @return Success; or the first guard's error (`invalid_output_size`, `invalid_key_size`,
 `input_too_long` past what the digest hashes, `unsupported_by_backend` past the backend's
 limits), `output` untouched; or `errc::not_enough_memory` or `backend_failure`, `output` zeroed.
*/
template <class Digest, class Backend = default_backend<kdfs::sskdf>>
[[nodiscard]] boost::system::result<void> sskdf(std::span<std::uint8_t> output,
                                                std::span<std::uint8_t const> secret,
                                                std::span<std::uint8_t const> fixed_info = {}) {
    if constexpr (!detail::sskdf_takes<Digest>()) {
        return error::backend_failure;  // unreachable: sskdf_takes has stopped the build
    } else {
        using engine = detail::sskdf_engine<Backend, Digest>;
        using digest = detail::standard_kdf_digest<Digest>;
        // reps = ceil(L / H_outputBits) is at most 2^32 - 1 (section 4.1, step 2).
        if (output.empty() ||
            detail::exceeds(output.size(), detail::standard_kdf_max_blocks * digest::size)) {
            return error::invalid_output_size;
        }
        if (secret.empty()) {
            return error::invalid_key_size;
        }
        if (detail::standard_kdf_input_too_long<Digest>(secret.size(), fixed_info.size())) {
            return error::input_too_long;
        }
        if (detail::exceeds(secret.size(), engine::limits.max_key) ||
            detail::exceeds(fixed_info.size(), engine::limits.max_info) ||
            detail::exceeds(output.size(), engine::limits.max_output)) {
            return error::unsupported_by_backend;
        }
        auto derived = engine::derive(output, secret, fixed_info);
        if (!derived) {
            detail::wipe(output);
        }
        return derived;
    }
}

/**
 ANSI X9.63's key derivation (ANSI X9.63-2011, section 5.6.3; SEC 1 v2, section 3.6.1) over the
 digest `Digest`: fills `output` from the shared secret `secret` and `shared_info`, block after
 block, each `Digest(secret || counter || shared_info)` with a 32-bit big-endian counter from 1.

 ECIES and the elliptic-curve key agreements of SEC 1, BSI TR-03111 and smart cards use it.

 @code
 std::array<std::uint8_t, 32> derived{};
 auto done = webcpp::hash::x963kdf<webcpp::hash::digests::sha2_256,
                                   webcpp::hash::backends::openssl>(derived, shared_secret, info);
 @endcode

 @tparam Digest A hash function SEC 1 v2 lists (section 3.5) and NIST SP 800-135r1 approves for
 this KDF (section 5.1): `digests::sha1`, `sha2_224`, `sha2_256`, `sha2_384` or `sha2_512`;
 another, SHA-512/224 and SHA-512/256 included, refuses at compile time.
 @tparam Backend The backend; by default @ref default_backend of `kdfs::x963kdf`, which has none
 (design D34): the call names `backends::openssl` or `backends::botan`.
 @param output The derived keying material: 1 byte to 2^32 - 1 digests less 1 byte (the standard
 refuses keydatalen >= hashlen (2^32 - 1); `backends::openssl`: at most 2^30 bytes). It must not
 overlap the inputs.
 @param secret Z, the shared secret: at least 1 byte (`backends::openssl`: at most 2^30).
 @param shared_info SharedInfo, the data both parties share; empty for none
 (`backends::openssl`: at most 2^30 bytes).
 @return Success; or the first guard's error (`invalid_output_size`, `invalid_key_size`,
 `input_too_long` past what the digest hashes, `unsupported_by_backend` past the backend's
 limits), `output` untouched; or `errc::not_enough_memory` or `backend_failure`, `output` zeroed.
*/
template <class Digest, class Backend = default_backend<kdfs::x963kdf>>
[[nodiscard]] boost::system::result<void> x963kdf(std::span<std::uint8_t> output,
                                                  std::span<std::uint8_t const> secret,
                                                  std::span<std::uint8_t const> shared_info = {}) {
    if constexpr (!detail::x963kdf_takes<Digest>()) {
        return error::backend_failure;  // unreachable: x963kdf_takes has stopped the build
    } else {
        using engine = detail::x963kdf_engine<Backend, Digest>;
        using digest = detail::standard_kdf_digest<Digest>;
        if (output.empty() ||
            !detail::exceeds(detail::standard_kdf_max_blocks * digest::size, output.size())) {
            return error::invalid_output_size;
        }
        if (secret.empty()) {
            return error::invalid_key_size;
        }
        if (detail::standard_kdf_input_too_long<Digest>(secret.size(), shared_info.size())) {
            return error::input_too_long;
        }
        if (detail::exceeds(secret.size(), engine::limits.max_key) ||
            detail::exceeds(shared_info.size(), engine::limits.max_info) ||
            detail::exceeds(output.size(), engine::limits.max_output)) {
            return error::unsupported_by_backend;
        }
        auto derived = engine::derive(output, secret, shared_info);
        if (!derived) {
            detail::wipe(output);
        }
        return derived;
    }
}

}  // namespace webcpp::hash

// The backends of these functions, backends::openssl when the program links OpenSSL and
// backends::botan when it links Botan: a program that includes only this header gets their engines
// here.
#ifdef WEBCPP_HASH_HAS_OPENSSL
#include <webcpp/hash/backends/openssl.hpp>
#endif
#ifdef WEBCPP_HASH_HAS_BOTAN
#include <webcpp/hash/backends/botan.hpp>
#endif

#endif  // WEBCPP_HASH_KDF_STANDARDS_HPP
