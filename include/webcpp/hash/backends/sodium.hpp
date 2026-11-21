// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `backends::sodium`: HKDF (RFC 5869) over libsodium's `crypto_kdf_hkdf_sha256_*` and
 `crypto_kdf_hkdf_sha512_*`, Argon2id over `crypto_pwhash_argon2id`, scrypt over
 `crypto_pwhash_scryptsalsa208sha256_ll`, `digests::blake2b` (RFC 7693, with its key, salt,
 personalisation and output size) over `crypto_generichash_blake2b_*`, `macs::siphash_2_4` and
 `macs::siphash_2_4x` over `crypto_shorthash_siphash24` and `crypto_shorthash_siphashx24`,
 `macs::blake2b_mac` (keyed BLAKE2b, its default) over `crypto_generichash_blake2b_*`,
 `blake2b_subkey` over `crypto_kdf_blake2b_derive_from_key`, `digests::sha2_256`, `sha2_512`,
 `sha3_256` and `sha3_512` over `crypto_hash_*`, the extendable-output functions
 `digests::shake_128`, `shake_256`, `turboshake_128` and `turboshake_256` over `crypto_xof_*`, and
 `macs::hmac` over `sha2_256` and `sha2_512` over `crypto_auth_hmacsha256_*` and
 `crypto_auth_hmacsha512_*`, and the family `argon2`'s `kdfs::argon2i` and `kdfs::argon2id` over
 `crypto_pwhash_argon2i` and `crypto_pwhash_argon2id` (one lane, no secret, no associated data,
 Argon2i from 3 passes), built from source by `/third_party//sodium`, on every target. It
 has HKDF over `hmac_sha2_256` and `hmac_sha2_512` alone, and no PBKDF2; every other hmac and
 PBKDF2 refuse at compile time with spec 3.3's texts.

 Its limits beyond the spec's: scrypt's N at most 4,294,967,295 (libsodium refuses a larger one);
 `argon2`'s values libsodium does not take, which the family answers with
 `unsupported_by_backend`.
 Argon2's core holds the password's, salt's and tag's lengths in `uint32_t`, which spec 2.10's own
 guards already keep within (this header checks that they agree), and webcpp passes no secret or
 associated data; scrypt's and HKDF's lengths are `size_t`.

 On Emscripten `/third_party//sodium` links a program with `-sALLOW_MEMORY_GROWTH=1`: Argon2 and
 scrypt allocate the memory their costs name, past Emscripten's fixed 16 MiB.

 Every engine function that starts work on libsodium (`init`, `one_shot`, `compute`, `derive`,
 `extract`, `expand`) calls `sodium_init()` first (it returns 0 the first time and 1 after, both
 success), so that a program that never initialised libsodium is safe.

 @see "Key derivation", in the guide.
*/
#ifndef WEBCPP_HASH_BACKENDS_SODIUM_HPP
#define WEBCPP_HASH_BACKENDS_SODIUM_HPP

#include <webcpp/hash/config.hpp>

#ifndef WEBCPP_HASH_HAS_SODIUM
#error \
    "webcpp::hash: backends::sodium needs libsodium. Add /third_party//sodium to the program's Jamfile: exe app : app.cpp /webcpp/hash//hash /third_party//sodium ;"
#else

#include <webcpp/hash/detail/canary.h>
#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/blake2b_subkey.hpp>
#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/detail/limits.hpp>
#include <webcpp/hash/detail/wipe.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/hash/scrypt.hpp>

#include <boost/system/errc.hpp>
#include <boost/system/result.hpp>

#include <sodium/core.h>  // third_party/libs/libsodium, through /third_party//sodium
#include <sodium/crypto_auth_hmacsha256.h>              // the same
#include <sodium/crypto_auth_hmacsha512.h>              // the same
#include <sodium/crypto_generichash_blake2b.h>          // the same
#include <sodium/crypto_hash_sha256.h>                  // the same
#include <sodium/crypto_hash_sha3.h>                    // the same
#include <sodium/crypto_hash_sha512.h>                  // the same
#include <sodium/crypto_kdf_blake2b.h>                  // the same
#include <sodium/crypto_kdf_hkdf_sha256.h>              // the same
#include <sodium/crypto_kdf_hkdf_sha512.h>              // the same
#include <sodium/crypto_pwhash.h>                       // the same
#include <sodium/crypto_pwhash_argon2i.h>               // the same
#include <sodium/crypto_pwhash_argon2id.h>              // the same
#include <sodium/crypto_pwhash_scryptsalsa208sha256.h>  // the same
#include <sodium/crypto_shorthash_siphash24.h>          // the same
#include <sodium/crypto_xof_shake128.h>                 // the same
#include <sodium/crypto_xof_shake256.h>                 // the same
#include <sodium/crypto_xof_turboshake128.h>            // the same
#include <sodium/crypto_xof_turboshake256.h>            // the same
#include <sodium/randombytes.h>                         // the same

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <span>

#ifdef WEBCPP_HASH_SODIUM_CANARY_CONFIGURATION
/** The configuration the canary names: a test's, here. */
#define WEBCPP_HASH_DETAIL_SODIUM_CONFIGURATION WEBCPP_HASH_SODIUM_CANARY_CONFIGURATION
#else
/** The configuration the canary names: libsodium as `/third_party//sodium` builds it. */
#define WEBCPP_HASH_DETAIL_SODIUM_CONFIGURATION configured
#endif
/** The canary's name, which every function of this header that calls libsodium reads (spec 5.4). */
#define WEBCPP_HASH_DETAIL_SODIUM_CANARY                         \
    WEBCPP_HASH_DETAIL_CANARY(sodium, WEBCPP_HASH_SODIUM_COMMIT, \
                              WEBCPP_HASH_DETAIL_SODIUM_CONFIGURATION)

#ifdef _MSC_VER
#pragma detect_mismatch(                                                 \
    "webcpp_hash_backend_sodium",                                        \
    WEBCPP_HASH_DETAIL_MISMATCH_VALUE(sodium, WEBCPP_HASH_SODIUM_COMMIT, \
                                      WEBCPP_HASH_DETAIL_SODIUM_CONFIGURATION))
#endif

// A declaration: src/canary_sodium.c defines it, constant, in /third_party//sodium.
// NOLINTNEXTLINE(bugprone-dynamic-static-initializers)
extern "C" const char WEBCPP_HASH_DETAIL_SODIUM_CANARY;

namespace webcpp::hash {

namespace backends {

/**
 libsodium, built from its sources by `/third_party//sodium`: HKDF over SHA-256 and SHA-512,
 Argon2id, scrypt, BLAKE2b, SipHash-2-4, SipHash-2-4x, BLAKE2b subkeys, SHA-256, SHA-512, SHA3-256,
 SHA3-512, SHAKE128, SHAKE256, TurboSHAKE128, TurboSHAKE256, and HMAC over SHA-256 and SHA-512.
*/
struct sodium {};

}  // namespace backends

namespace detail {

/**
 Reads libsodium's canary with a volatile load, which no linker can drop: a program built without
 `/third_party//sodium`, or with one of another commit or configuration, then fails to link,
 naming the canary (spec 5.4).
*/
inline void touch_sodium_canary() noexcept {
    // The volatile glvalue is converted to a value: a discarded one is not read by gcc.
    char const canary_copy = *static_cast<char const volatile*>(&WEBCPP_HASH_DETAIL_SODIUM_CANARY);
    static_cast<void>(canary_copy);
}

/**
 Initialises libsodium, as every engine function that starts work on it does first: `sodium_init`
 returns 0 the first time and 1 after, both success, and -1 when it cannot initialise. On Emscripten
 with threads, libsodium's random source is a JavaScript function of the thread that set it, a Web
 Worker's own: `randombytes_stir` sets it on the calling thread when it has none, since libsodium's
 Argon2 draws random bytes (it fills the output first) on whichever thread runs it.

 @return Whether libsodium is ready.
*/
inline bool sodium_ready() noexcept {
    touch_sodium_canary();
    bool const ready = sodium_init() >= 0;
#if defined(WEBCPP_TARGET_EMSCRIPTEN) && defined(__EMSCRIPTEN_PTHREADS__)
    if (ready) {
        randombytes_stir();
    }
#endif
    return ready;
}

/**
 What a -1 of libsodium's password hashing means: `errc::not_enough_memory` when `errno` is
 `ENOMEM`, `error::backend_failure` otherwise. The caller sets `errno` to 0 before the call, since
 libsodium returns -1 without setting it when its core fails.

 @param status_code libsodium's return. @param saved_errno `errno` after the call.
 @return Success for 0, else the failure.
*/
[[nodiscard]] inline boost::system::result<void> sodium_pwhash_status(int status_code,
                                                                      int saved_errno) noexcept {
    if (status_code == 0) {
        return {};
    }
    if (saved_errno == ENOMEM) {
        return boost::system::errc::make_error_code(boost::system::errc::not_enough_memory);
    }
    return error::backend_failure;
}

/** libsodium's HKDF over SHA-256: the hmac and the two C functions it wraps. */
struct sodium_hkdf_sha256 {
    /** The hmac it serves. */
    using hmac_type = hmac_sha2_256;
    /** The PRK's size, libsodium's `crypto_kdf_hkdf_sha256_KEYBYTES`. */
    static constexpr std::size_t key_size = crypto_kdf_hkdf_sha256_KEYBYTES;

    /**
     `crypto_kdf_hkdf_sha256_extract`.

     @param prk_bytes The PRK. @param salt_bytes The salt. @param ikm_bytes The input keying
     material.
     @return libsodium's status, 0 on success.
    */
    static int extract(std::uint8_t* prk_bytes, std::span<std::uint8_t const> salt_bytes,
                       std::span<std::uint8_t const> ikm_bytes) noexcept {
        // SHA-256's extract declares the IKM nonnull; an empty span's data() may be null.
        return crypto_kdf_hkdf_sha256_extract(prk_bytes, salt_bytes.data(), salt_bytes.size(),
                                              nonnull(ikm_bytes), ikm_bytes.size());
    }

    /**
     `crypto_kdf_hkdf_sha256_expand`, whose context is the info.

     @param output_bytes The OKM. @param prk_bytes The PRK. @param info_bytes The info.
     @return libsodium's status, 0 on success.
    */
    static int expand(std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> prk_bytes,
                      std::span<std::uint8_t const> info_bytes) noexcept {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): libsodium types ctx as char
        return crypto_kdf_hkdf_sha256_expand(output_bytes.data(), output_bytes.size(),
                                             reinterpret_cast<char const*>(info_bytes.data()),
                                             info_bytes.size(), prk_bytes.data());
    }
};

/** libsodium's HKDF over SHA-512: the hmac and the two C functions it wraps. */
struct sodium_hkdf_sha512 {
    /** The hmac it serves. */
    using hmac_type = hmac_sha2_512;
    /** The PRK's size, libsodium's `crypto_kdf_hkdf_sha512_KEYBYTES`. */
    static constexpr std::size_t key_size = crypto_kdf_hkdf_sha512_KEYBYTES;

    /**
     `crypto_kdf_hkdf_sha512_extract`.

     @param prk_bytes The PRK. @param salt_bytes The salt. @param ikm_bytes The input keying
     material.
     @return libsodium's status, 0 on success.
    */
    static int extract(std::uint8_t* prk_bytes, std::span<std::uint8_t const> salt_bytes,
                       std::span<std::uint8_t const> ikm_bytes) noexcept {
        // SHA-512's extract declares no IKM nonnull; it is passed as SHA-256's is all the same, so
        // that the two traits are alike: a non-null pointer where null is allowed is harmless.
        return crypto_kdf_hkdf_sha512_extract(prk_bytes, salt_bytes.data(), salt_bytes.size(),
                                              nonnull(ikm_bytes), ikm_bytes.size());
    }

    /**
     `crypto_kdf_hkdf_sha512_expand`, whose context is the info.

     @param output_bytes The OKM. @param prk_bytes The PRK. @param info_bytes The info.
     @return libsodium's status, 0 on success.
    */
    static int expand(std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> prk_bytes,
                      std::span<std::uint8_t const> info_bytes) noexcept {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): libsodium types ctx as char
        return crypto_kdf_hkdf_sha512_expand(output_bytes.data(), output_bytes.size(),
                                             reinterpret_cast<char const*>(info_bytes.data()),
                                             info_bytes.size(), prk_bytes.data());
    }
};

/**
 The HKDF engine over one of libsodium's two hashes (the engine's interface: @ref hkdf_engine).

 @tparam Traits @ref sodium_hkdf_sha256 or @ref sodium_hkdf_sha512.
*/
template <class Traits>
struct sodium_hkdf_engine {
    /** The hmac's result, a `digest<N>`: the PRK. */
    using digest_type = Traits::hmac_type::result_type;
    static_assert(sizeof(digest_type) == Traits::key_size, "libsodium's PRK is the hmac's digest");

    /**
     RFC 5869, 2.2: PRK = HMAC-Hash(salt, IKM), by libsodium's `_extract`; an empty salt is
     HashLen zeros, which libsodium's hmac keys as zeros of the block, the same key.

     @param salt_bytes The salt. @param ikm_bytes The input keying material.
     @return The PRK, or `error::backend_failure`.
    */
    [[nodiscard]] static boost::system::result<digest_type> extract(
        std::span<std::uint8_t const> salt_bytes,
        std::span<std::uint8_t const> ikm_bytes) noexcept {
        // The PRK is built in the result returned and libsodium writes into it: a single return
        // path of the one named object, so that the result is constructed in the caller's place
        // (no copy or move, which would leave a PRK behind that nothing wipes).
        boost::system::result<digest_type> prk_bytes{boost::system::in_place_value};
        if (!sodium_ready() ||
            Traits::extract(prk_bytes.unsafe_value().data(), salt_bytes, ikm_bytes) != 0) {
            wipe_object(prk_bytes.unsafe_value());
            prk_bytes = boost::system::result<digest_type>(error::backend_failure);
        }
        return prk_bytes;
    }

    /**
     RFC 5869, 2.3, by libsodium's `_expand`.

     @param output_bytes The OKM, its size L. @param prk_bytes The PRK. @param info_bytes The info.
     @return Success, or `error::backend_failure`.
    */
    [[nodiscard]] static boost::system::result<void> expand(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> prk_bytes,
        std::span<std::uint8_t const> info_bytes) noexcept {
        if (!sodium_ready()) {
            return error::backend_failure;
        }
        if (Traits::expand(output_bytes, prk_bytes, info_bytes) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /**
     RFC 5869, 2: HKDF-Extract into a local PRK, HKDF-Expand, and the PRK wiped.

     @param output_bytes The OKM. @param salt_bytes The salt. @param ikm_bytes The input keying
     material.
     @param info_bytes The info.
     @return Success, or `error::backend_failure`.
    */
    [[nodiscard]] static boost::system::result<void> extract_and_expand(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> salt_bytes,
        std::span<std::uint8_t const> ikm_bytes,
        std::span<std::uint8_t const> info_bytes) noexcept {
        auto prk_bytes = extract(salt_bytes, ikm_bytes);
        if (!prk_bytes) {
            return prk_bytes.error();
        }
        digest_type& key_bytes = prk_bytes.unsafe_value();
        auto derive_result =
            expand(output_bytes, std::span<std::uint8_t const>(key_bytes.data(), key_bytes.size()),
                   info_bytes);
        wipe_object(key_bytes);
        return derive_result;
    }
};

/** HKDF on backends::sodium over HMAC-SHA-256: libsodium's `crypto_kdf_hkdf_sha256_*`. */
template <>
struct hkdf_engine<backends::sodium, hmac_sha2_256> : sodium_hkdf_engine<sodium_hkdf_sha256> {};

/** HKDF on backends::sodium over HMAC-SHA-512: libsodium's `crypto_kdf_hkdf_sha512_*`. */
template <>
struct hkdf_engine<backends::sodium, hmac_sha2_512> : sodium_hkdf_engine<sodium_hkdf_sha512> {};

/**
 HKDF on backends::sodium over an hmac it lacks: refuses with spec 3.3's text. The members exist
 so that the refusal is the only error.

 @tparam Hmac An hmac but `hmac_sha2_256` and `hmac_sha2_512`.
*/
template <class Hmac>
struct hkdf_engine<backends::sodium, Hmac> {
    static_assert(
        always_false<Hmac>,
        "webcpp::hash: backends::sodium has HKDF over hmac_sha2_256 and hmac_sha2_512 alone. "
        "Over this hmac, name backends::hash2 (every hmac), backends::openssl (every hmac but "
        "hmac_ripemd_128), backends::botan (every hmac but hmac_ripemd_128 and "
        "hmac_sha2_512_224) or backends::bearssl (MD5, SHA-1, SHA-224, SHA-256, SHA-384, "
        "SHA-512; hkdf alone).");

    /** Never called: the refusal has stopped the build. */
    [[nodiscard]] static boost::system::result<typename Hmac::result_type> extract(
        std::span<std::uint8_t const> /*salt_bytes*/,
        std::span<std::uint8_t const> /*ikm_bytes*/) noexcept {
        return error::backend_failure;
    }

    /** Never called: the refusal has stopped the build. */
    [[nodiscard]] static boost::system::result<void> expand(
        std::span<std::uint8_t> /*output_bytes*/, std::span<std::uint8_t const> /*prk_bytes*/,
        std::span<std::uint8_t const> /*info_bytes*/) noexcept {
        return error::backend_failure;
    }

    /** Never called: the refusal has stopped the build. */
    [[nodiscard]] static boost::system::result<void> extract_and_expand(
        std::span<std::uint8_t> /*output_bytes*/, std::span<std::uint8_t const> /*salt_bytes*/,
        std::span<std::uint8_t const> /*ikm_bytes*/,
        std::span<std::uint8_t const> /*info_bytes*/) noexcept {
        return error::backend_failure;
    }
};

/**
 PBKDF2 on backends::sodium: refuses with spec 3.3's text, libsodium having no PBKDF2. The member
 exists so that the refusal is the only error.

 @tparam Hmac Any hmac.
*/
template <class Hmac>
struct pbkdf2_engine<backends::sodium, Hmac> {
    static_assert(always_false<Hmac>,
                  "webcpp::hash: pbkdf2 is not in backends::sodium: libsodium has no PBKDF2. The "
                  "backends that have pbkdf2: backends::hash2 (every hmac), backends::openssl "
                  "(every hmac but hmac_ripemd_128) and backends::botan (every hmac but "
                  "hmac_ripemd_128 and hmac_sha2_512_224).");

    /** Never called: the refusal has stopped the build. */
    [[nodiscard]] static boost::system::result<void> derive(
        std::span<std::uint8_t> /*output_bytes*/, std::span<std::uint8_t const> /*password_bytes*/,
        std::span<std::uint8_t const> /*salt_bytes*/, std::uint64_t /*iteration_count*/) noexcept {
        return error::backend_failure;
    }
};

/**
 A pointer libsodium reads as "absent" for an empty span, the span's bytes otherwise: its salt and
 personalisation are 16 bytes or a null pointer.

 @param bytes The span. @return Null when `bytes` is empty, else its data.
*/
[[nodiscard]] inline std::uint8_t const* or_null(std::span<std::uint8_t const> bytes) noexcept {
    return bytes.empty() ? nullptr : bytes.data();
}

/**
 `digests::blake2b` on backends::sodium, libsodium's `crypto_generichash_blake2b_*` (its interface
 is @ref digest_engine), every option and output size the family accepts: the key (0 to 64 bytes),
 the salt and the personalisation (empty or 16 bytes, passed as null when empty) and the output's
 size (1 to 64 bytes), all of RFC 7693's parameter block but the tree hashing fields. The state is
 libsodium's, wiped by `destroy`. The one-shot form is
 `crypto_generichash_blake2b_salt_personal`, whose state lives in libsodium's own frame:
 libsodium's `blake2b_final` wipes its chaining value and its buffer, and does not wipe the rest of
 the state (counters, flags) or its local copy of the whole 64-byte result, which webcpp cannot
 reach.
*/
template <>
struct digest_engine<backends::sodium, digests::blake2b> : full_engine {
    /** libsodium's incremental state, 384 bytes aligned to 64, trivially copyable. */
    using state = crypto_generichash_blake2b_state;

    /**
     Starts a hash: `crypto_generichash_blake2b_init_salt_personal`.

     @param hashed The state. @param options The key, salt, personalisation and output size.
     @return Success, or `error::backend_failure`.
    */
    [[nodiscard]] static boost::system::result<void> init(
        state& hashed, digest_options<digests::blake2b> const& options) noexcept {
        if (!sodium_ready()) {
            return error::backend_failure;
        }
        if (crypto_generichash_blake2b_init_salt_personal(
                &hashed, or_null(options.key), options.key.size(), options.output_size,
                or_null(options.salt), or_null(options.personalisation)) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /**
     Absorbs `input`: `crypto_generichash_blake2b_update`.

     @param hashed The state. @param input The bytes. @return Success, or `error::backend_failure`.
    */
    [[nodiscard]] static boost::system::result<void> update(
        state& hashed, std::span<std::uint8_t const> input) noexcept {
        if (crypto_generichash_blake2b_update(&hashed, input.data(), input.size()) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /**
     Writes the digest, of the size the hash was started for (the family's guard holds it):
     `crypto_generichash_blake2b_final`.

     @param hashed The state. @param output The digest.
     @return Success, or `error::backend_failure`.
    */
    [[nodiscard]] static boost::system::result<void> finish(
        state& hashed, std::span<std::uint8_t> output) noexcept {
        if (crypto_generichash_blake2b_final(&hashed, output.data(), output.size()) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /** Wipes the state. @param hashed The state. */
    static void destroy(state& hashed) noexcept { wipe_object(hashed); }

    /**
     The digest of `input` at once: `crypto_generichash_blake2b_salt_personal`, whose output size
     is `output.size()`, equal to the options' (the family's guard).

     @param output The digest. @param input The bytes. @param options The key, salt and
     personalisation.
     @return Success, or `error::backend_failure`.
    */
    [[nodiscard]] static boost::system::result<void> one_shot(
        std::span<std::uint8_t> output, std::span<std::uint8_t const> input,
        digest_options<digests::blake2b> const& options) noexcept {
        if (!sodium_ready()) {
            return error::backend_failure;
        }
        if (crypto_generichash_blake2b_salt_personal(
                output.data(), output.size(), input.data(), input.size(), or_null(options.key),
                options.key.size(), or_null(options.salt), or_null(options.personalisation)) != 0) {
            return error::backend_failure;
        }
        return {};
    }
};

// The family's BLAKE2b guards are libsodium's bounds, so that libsodium never refuses what they
// pass (its *_BYTES_MIN and *_KEYBYTES_MIN, 16, are advice its functions do not check).
static_assert(digest_traits<digests::blake2b>::max_size == crypto_generichash_blake2b_BYTES_MAX);
static_assert(digest_traits<digests::blake2b>::max_size == crypto_generichash_blake2b_KEYBYTES_MAX);
static_assert(digest_traits<digests::blake2b>::block_part_size ==
              crypto_generichash_blake2b_SALTBYTES);
static_assert(digest_traits<digests::blake2b>::block_part_size ==
              crypto_generichash_blake2b_PERSONALBYTES);

/**
 The pieces of a digest engine over a libsodium hash whose incremental functions take a `State` and
 return libsodium's status, with the interface of @ref digest_engine. It gives `update` and
 `destroy`, and `one_shot` as `init`, `update` and `finish` on a state of its own frame that it
 wipes, so that no state is left unwiped.

 @tparam Engine The engine, which gives `init` and `finish`. @tparam Digest The tag of `digests`.
 @tparam State libsodium's state. @tparam Update libsodium's `_update`.
*/
template <class Engine, class Digest, class State,
          int (*Update)(State*, unsigned char const*, unsigned long long)>
struct sodium_incremental_engine : full_engine {
    /** libsodium's incremental state, trivially copyable. */
    using state = State;

    /**
     Absorbs `input`.

     @param hashed The state. @param input The bytes. @return Success, or `error::backend_failure`.
    */
    [[nodiscard]] static boost::system::result<void> update(
        state& hashed, std::span<std::uint8_t const> input) noexcept {
        if (Update(&hashed, nonnull(input), input.size()) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /** Wipes the state. @param hashed The state. */
    static void destroy(state& hashed) noexcept { wipe_object(hashed); }

    /**
     The digest of `input` at once, on a state of this frame, wiped before the return.

     @param output The digest. @param input The bytes. @param options The tag's options.
     @return Success, or `error::backend_failure`.
    */
    [[nodiscard]] static boost::system::result<void> one_shot(
        std::span<std::uint8_t> output, std::span<std::uint8_t const> input,
        digest_options<Digest> const& options) noexcept {
        state hashed{};
        auto done = Engine::init(hashed, options);
        if (done) {
            done = update(hashed, input);
        }
        if (done) {
            done = Engine::finish(hashed, output);
        }
        destroy(hashed);
        return done;
    }

private:
    // A base of Engine alone, never made by itself.
    sodium_incremental_engine() = default;
    friend Engine;
};

/**
 A fixed-size digest on backends::sodium, over libsodium's `crypto_hash_*`, with the interface of
 @ref digest_engine. It calls `_init`, `_update` and `_final`, which writes the whole digest, of the
 size the family's guard holds the output to. SHA-2's `_final` wipes the state, SHA-3's does not:
 `destroy` wipes it in every case, and for a hash that ends before `finish`.

 @tparam Digest The tag of `digests`. @tparam State libsodium's state. @tparam Size The digest's
 size, libsodium's `_BYTES`. @tparam Init libsodium's `_init`. @tparam Update libsodium's
 `_update`. @tparam Final libsodium's `_final`.
*/
template <class Digest, class State, std::size_t Size, int (*Init)(State*),
          int (*Update)(State*, unsigned char const*, unsigned long long),
          int (*Final)(State*, unsigned char*)>
struct sodium_fixed_digest_engine
    : sodium_incremental_engine<
          sodium_fixed_digest_engine<Digest, State, Size, Init, Update, Final>, Digest, State,
          Update> {
    /**
     Starts a hash.

     @param hashed The state. @return Success, or `error::backend_failure`.
    */
    [[nodiscard]] static boost::system::result<void> init(
        State& hashed, digest_options<Digest> const& /*options*/) noexcept {
        // The family's size is libsodium's, so that the guard passes exactly what _final writes.
        static_assert(digest_traits<Digest>::min_output(digest_options<Digest>{}) == Size &&
                      digest_traits<Digest>::max_output(digest_options<Digest>{}) == Size);
        if (!sodium_ready()) {
            return error::backend_failure;
        }
        if (Init(&hashed) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /**
     Writes the digest.

     @param hashed The state. @param output The digest, of `Size` bytes (the family's guard).
     @return Success, or `error::backend_failure`.
    */
    [[nodiscard]] static boost::system::result<void> finish(
        State& hashed, std::span<std::uint8_t> output) noexcept {
        if (Final(&hashed, output.data()) != 0) {
            return error::backend_failure;
        }
        return {};
    }
};

/** `digests::sha2_256` on backends::sodium: `crypto_hash_sha256_*`. */
template <>
struct digest_engine<backends::sodium, digests::sha2_256>
    : sodium_fixed_digest_engine<digests::sha2_256, crypto_hash_sha256_state,
                                 crypto_hash_sha256_BYTES, &crypto_hash_sha256_init,
                                 &crypto_hash_sha256_update, &crypto_hash_sha256_final> {};

/** `digests::sha2_512` on backends::sodium: `crypto_hash_sha512_*`. */
template <>
struct digest_engine<backends::sodium, digests::sha2_512>
    : sodium_fixed_digest_engine<digests::sha2_512, crypto_hash_sha512_state,
                                 crypto_hash_sha512_BYTES, &crypto_hash_sha512_init,
                                 &crypto_hash_sha512_update, &crypto_hash_sha512_final> {};

/** `digests::sha3_256` on backends::sodium: `crypto_hash_sha3256_*`. */
template <>
struct digest_engine<backends::sodium, digests::sha3_256>
    : sodium_fixed_digest_engine<digests::sha3_256, crypto_hash_sha3256_state,
                                 crypto_hash_sha3256_BYTES, &crypto_hash_sha3256_init,
                                 &crypto_hash_sha3256_update, &crypto_hash_sha3256_final> {};

/** `digests::sha3_512` on backends::sodium: `crypto_hash_sha3512_*`. */
template <>
struct digest_engine<backends::sodium, digests::sha3_512>
    : sodium_fixed_digest_engine<digests::sha3_512, crypto_hash_sha3512_state,
                                 crypto_hash_sha3512_BYTES, &crypto_hash_sha3512_init,
                                 &crypto_hash_sha3512_update, &crypto_hash_sha3512_final> {};

/**
 An extendable-output function on backends::sodium, over libsodium's `crypto_xof_*`, with the
 interface of @ref digest_engine. It calls `_init_with_domain`, `_update` and `_squeeze`, and
 serves every output size from 1 byte. The domain byte is TurboSHAKE's option (the family's guard
 holds it to 0x01..0x7F, which libsodium does not check), and SHAKE's own, 0x1F, for a tag without
 options. libsodium's `_squeeze` does not wipe the state, which may squeeze more: `destroy` wipes
 it.

 @tparam Digest The tag of `digests`. @tparam State libsodium's state. @tparam StandardDomain
 libsodium's `_DOMAIN_STANDARD`. @tparam Init libsodium's `_init_with_domain`. @tparam Update
 libsodium's `_update`. @tparam Squeeze libsodium's `_squeeze`.
*/
template <class Digest, class State, unsigned StandardDomain, int (*Init)(State*, unsigned char),
          int (*Update)(State*, unsigned char const*, unsigned long long),
          int (*Squeeze)(State*, unsigned char*, std::size_t)>
struct sodium_xof_engine
    : sodium_incremental_engine<
          sodium_xof_engine<Digest, State, StandardDomain, Init, Update, Squeeze>, Digest, State,
          Update> {
    /**
     The domain byte the sponge pads with: TurboSHAKE's option `domain`, or SHAKE's standard byte,
     0x1F, for a tag whose options have no domain.

     @param options The tag's options.
     @return The domain byte, D of RFC 9861 for TurboSHAKE.
    */
    static constexpr unsigned char domain_of(
        [[maybe_unused]] digest_options<Digest> const& options) noexcept {
        if constexpr (requires { options.domain; }) {
            return options.domain;
        } else {
            return StandardDomain;
        }
    }

    /**
     Starts a hash with the options' domain byte.

     @param hashed The state. @param options The tag's options.
     @return Success, or `error::backend_failure`.
    */
    [[nodiscard]] static boost::system::result<void> init(
        State& hashed, digest_options<Digest> const& options) noexcept {
        // SHAKE's and TurboSHAKE's standard byte, RFC 9861's default, is libsodium's.
        static_assert(StandardDomain == 0x1F);
        if (!sodium_ready()) {
            return error::backend_failure;
        }
        if (Init(&hashed, domain_of(options)) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /**
     Writes `output.size()` bytes of the output stream.

     @param hashed The state. @param output The output, of any size from 1 byte.
     @return Success, or `error::backend_failure`.
    */
    [[nodiscard]] static boost::system::result<void> finish(
        State& hashed, std::span<std::uint8_t> output) noexcept {
        if (Squeeze(&hashed, output.data(), output.size()) != 0) {
            return error::backend_failure;
        }
        return {};
    }
};

/** `digests::shake_128` on backends::sodium: `crypto_xof_shake128_*`, every output size. */
template <>
struct digest_engine<backends::sodium, digests::shake_128>
    : sodium_xof_engine<digests::shake_128, crypto_xof_shake128_state,
                        crypto_xof_shake128_DOMAIN_STANDARD, &crypto_xof_shake128_init_with_domain,
                        &crypto_xof_shake128_update, &crypto_xof_shake128_squeeze> {};

/** `digests::shake_256` on backends::sodium: `crypto_xof_shake256_*`, every output size. */
template <>
struct digest_engine<backends::sodium, digests::shake_256>
    : sodium_xof_engine<digests::shake_256, crypto_xof_shake256_state,
                        crypto_xof_shake256_DOMAIN_STANDARD, &crypto_xof_shake256_init_with_domain,
                        &crypto_xof_shake256_update, &crypto_xof_shake256_squeeze> {};

/**
 `digests::turboshake_128` on backends::sodium: `crypto_xof_turboshake128_*`, every output size
 and domain byte the family accepts.
*/
template <>
struct digest_engine<backends::sodium, digests::turboshake_128>
    : sodium_xof_engine<digests::turboshake_128, crypto_xof_turboshake128_state,
                        crypto_xof_turboshake128_DOMAIN_STANDARD,
                        &crypto_xof_turboshake128_init_with_domain,
                        &crypto_xof_turboshake128_update, &crypto_xof_turboshake128_squeeze> {};

/**
 `digests::turboshake_256` on backends::sodium: `crypto_xof_turboshake256_*`, every output size
 and domain byte the family accepts.
*/
template <>
struct digest_engine<backends::sodium, digests::turboshake_256>
    : sodium_xof_engine<digests::turboshake_256, crypto_xof_turboshake256_state,
                        crypto_xof_turboshake256_DOMAIN_STANDARD,
                        &crypto_xof_turboshake256_init_with_domain,
                        &crypto_xof_turboshake256_update, &crypto_xof_turboshake256_squeeze> {};

/**
 HMAC over a digest on backends::sodium, over libsodium's `crypto_auth_hmacsha*`, with the
 interface of @ref mac_engine. It calls `_init(state, key, keylen)`, which takes a key of any size
 (hashed first past the block, RFC 2104), `_update` and `_final`, every key and tag size the family
 accepts (ruling R23). libsodium's one-shot `crypto_auth_hmacsha*` take a 32-byte key alone, and
 are not used. The tag is the digest cut to the output's size (RFC 2104, section 5): `_final`
 writes the whole digest, into the output when it has the digest's size, else into a buffer of
 this frame that is wiped; the state is wiped before the return.

 @tparam Digest The tag of `digests`. @tparam State libsodium's state. @tparam Size The digest's
 size, libsodium's `_BYTES`. @tparam Init libsodium's `_init`. @tparam Update libsodium's
 `_update`. @tparam Final libsodium's `_final`.
*/
template <class Digest, class State, std::size_t Size,
          int (*Init)(State*, unsigned char const*, std::size_t),
          int (*Update)(State*, unsigned char const*, unsigned long long),
          int (*Final)(State*, unsigned char*)>
struct sodium_hmac_engine : full_engine {
    /**
     The tag of `input` under `key`.

     @param output The tag, 10 bytes to the digest's size (the family's guard). @param key The key,
     of any size. @param input The message.
     @return Success, or `error::backend_failure`.
    */
    [[nodiscard]] static boost::system::result<void> compute(
        std::span<std::uint8_t> output, std::span<std::uint8_t const> key,
        std::span<std::uint8_t const> input,
        mac_options<macs::hmac<Digest>> const& /*options*/) noexcept {
        // The family's longest tag is libsodium's digest. Checked here, where mac.hpp's traits are
        // complete whatever the order of includes.
        static_assert(mac_traits<macs::hmac<Digest>>::max_output == Size);
        if (!sodium_ready()) {
            return error::backend_failure;
        }
        State keyed{};
        std::array<std::uint8_t, Size> digest_bytes{};
        bool const whole = output.size() == Size;
        bool const computed = Init(&keyed, key.data(), key.size()) == 0 &&
                              Update(&keyed, nonnull(input), input.size()) == 0 &&
                              Final(&keyed, whole ? output.data() : digest_bytes.data()) == 0;
        if (computed && !whole) {
            std::copy_n(digest_bytes.begin(), output.size(), output.begin());
        }
        wipe_object(digest_bytes);
        wipe_object(keyed);
        if (!computed) {
            return error::backend_failure;
        }
        return {};
    }
};

/**
 `macs::hmac<digests::sha2_256>` on backends::sodium: `crypto_auth_hmacsha256_*`, a key of any
 size.
*/
template <>
struct mac_engine<backends::sodium, macs::hmac<digests::sha2_256>>
    : sodium_hmac_engine<digests::sha2_256, crypto_auth_hmacsha256_state,
                         crypto_auth_hmacsha256_BYTES, &crypto_auth_hmacsha256_init,
                         &crypto_auth_hmacsha256_update, &crypto_auth_hmacsha256_final> {};

/**
 `macs::hmac<digests::sha2_512>` on backends::sodium: `crypto_auth_hmacsha512_*`, a key of any
 size. libsodium's `crypto_auth_hmacsha512256` is this HMAC cut to 32 bytes, which `mac` gives with
 a 32-byte output; it is not HMAC over SHA-512/256 (`macs::hmac<digests::sha2_512_256>`), which
 libsodium does not have (ruling R23).
*/
template <>
struct mac_engine<backends::sodium, macs::hmac<digests::sha2_512>>
    : sodium_hmac_engine<digests::sha2_512, crypto_auth_hmacsha512_state,
                         crypto_auth_hmacsha512_BYTES, &crypto_auth_hmacsha512_init,
                         &crypto_auth_hmacsha512_update, &crypto_auth_hmacsha512_final> {};

/**
 What libsodium's SipHash one-shots, `crypto_shorthash_siphash24` and
 `crypto_shorthash_siphashx24`, have in common as engines of `mac`, whose interface is
 @ref mac_engine. They take every key and tag size the family accepts (a 16-byte key; an 8-byte
 or a 16-byte tag) and write the tag straight into the output. libsodium keeps SipHash's four state
 words in its own frame and does not wipe them; webcpp cannot reach them.

 @tparam Mac The tag of `macs`. @tparam Function The C function.
 @tparam TagSize libsodium's size of the tag. @tparam KeySize libsodium's size of the key.
*/
template <class Mac,
          int (*Function)(unsigned char*, unsigned char const*, unsigned long long,
                          unsigned char const*),
          std::size_t TagSize, std::size_t KeySize>
struct sodium_siphash_engine : full_engine {
    /**
     The tag of `input` under `key`.

     @param output The tag, of the tag's size (the family's guard). @param key The 16-byte key.
     @param input The message.
     @return Success, or `error::backend_failure`.
    */
    [[nodiscard]] static boost::system::result<void> compute(
        std::span<std::uint8_t> output, std::span<std::uint8_t const> key,
        std::span<std::uint8_t const> input, mac_options<Mac> const& /*options*/) noexcept {
        // The family's sizes are libsodium's, so that its guards pass exactly what libsodium
        // takes. Checked here, where mac.hpp's traits are complete whatever the order of includes.
        static_assert(mac_traits<Mac>::min_output == TagSize &&
                      mac_traits<Mac>::max_output == TagSize);
        static_assert(mac_traits<Mac>::min_key == KeySize && mac_traits<Mac>::max_key == KeySize);
        if (!sodium_ready()) {
            return error::backend_failure;
        }
        if (Function(output.data(), input.data(), input.size(), key.data()) != 0) {
            return error::backend_failure;
        }
        return {};
    }
};

/** `macs::siphash_2_4` on backends::sodium: `crypto_shorthash_siphash24`, an 8-byte tag. */
template <>
struct mac_engine<backends::sodium, macs::siphash_2_4>
    : sodium_siphash_engine<macs::siphash_2_4, &crypto_shorthash_siphash24,
                            crypto_shorthash_siphash24_BYTES, crypto_shorthash_siphash24_KEYBYTES> {
};

/** `macs::siphash_2_4x` on backends::sodium: `crypto_shorthash_siphashx24`, a 16-byte tag. */
template <>
struct mac_engine<backends::sodium, macs::siphash_2_4x>
    : sodium_siphash_engine<macs::siphash_2_4x, &crypto_shorthash_siphashx24,
                            crypto_shorthash_siphashx24_BYTES,
                            crypto_shorthash_siphashx24_KEYBYTES> {};

/**
 Keyed BLAKE2b (RFC 7693, section 2.5) on backends::sodium, `macs::blake2b_mac`'s engine, over
 libsodium's `crypto_generichash_blake2b_init`, `_update` and `_final`, with the interface of
 @ref mac_engine. It takes every key and tag size the family accepts, 1 to 64 bytes each:
 libsodium's functions check the same bounds (its `_BYTES_MIN` and `_KEYBYTES_MIN`, 16, are advice
 they do not check). The tag's size is a parameter of the hash, given to `_init`, and `_final`
 writes the tag straight into the output. The state lives in this frame and is wiped before the
 return; libsodium's `_final` wipes its chaining value and buffer, and the one-shot
 `crypto_generichash_blake2b`, whose state would live in libsodium's own frame, is not used.
 A template, so that it reads mac.hpp's traits, complete whatever the order of includes, when a
 call instantiates it.

 @tparam Mac `macs::blake2b_mac`.
*/
template <class Mac>
struct sodium_keyed_blake2b_engine : full_engine {
    /**
     The tag of `input` under `key`.

     @param output The tag, 1 to 64 bytes (the family's guard). @param key The key, 1 to 64 bytes
     (the family's guard). @param input The message.
     @return Success, or `error::backend_failure`.
    */
    [[nodiscard]] static boost::system::result<void> compute(
        std::span<std::uint8_t> output, std::span<std::uint8_t const> key,
        std::span<std::uint8_t const> input, mac_options<Mac> const& /*options*/) noexcept {
        // The family's sizes are libsodium's bounds, so that libsodium never refuses what its
        // guards pass. Checked here, where mac.hpp's traits are complete whatever the order of
        // includes.
        using traits = mac_traits<Mac>;
        static_assert(traits::min_output == 1 &&
                      traits::max_output == crypto_generichash_blake2b_BYTES_MAX);
        static_assert(traits::min_key == 1 &&
                      traits::max_key == crypto_generichash_blake2b_KEYBYTES_MAX);
        if (!sodium_ready()) {
            return error::backend_failure;
        }
        crypto_generichash_blake2b_state keyed{};
        bool const computed =
            crypto_generichash_blake2b_init(&keyed, key.data(), key.size(), output.size()) == 0 &&
            crypto_generichash_blake2b_update(&keyed, nonnull(input), input.size()) == 0 &&
            crypto_generichash_blake2b_final(&keyed, output.data(), output.size()) == 0;
        wipe_object(keyed);
        if (!computed) {
            return error::backend_failure;
        }
        return {};
    }
};

/** `macs::blake2b_mac` on backends::sodium, its default: keyed `crypto_generichash_blake2b_*`. */
template <>
struct mac_engine<backends::sodium, macs::blake2b_mac>
    : sodium_keyed_blake2b_engine<macs::blake2b_mac> {};

/**
 `blake2b_subkey` on backends::sodium: `crypto_kdf_blake2b_derive_from_key` (the engine's
 interface: @ref blake2b_subkey_engine). libsodium builds the salt and the personalisation in its
 own frame, and its BLAKE2b wipes its chaining value and buffer, as @ref digest_engine's one-shot
 on backends::sodium says.
*/
template <>
struct blake2b_subkey_engine<backends::sodium> {
    /**
     The subkey, by `crypto_kdf_blake2b_derive_from_key`.

     @param output_bytes The subkey, 16 to 64 bytes. @param master_key The 32-byte master key.
     @param subkey_id The subkey's id. @param context The 8-byte context.
     @return Success, or `error::backend_failure`.
    */
    [[nodiscard]] static boost::system::result<void> derive(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> master_key,
        std::uint64_t subkey_id, std::span<std::uint8_t const> context) noexcept {
        if (!sodium_ready()) {
            return error::backend_failure;
        }
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): libsodium types it char
        auto const* const context_chars = reinterpret_cast<char const*>(context.data());
        if (crypto_kdf_blake2b_derive_from_key(output_bytes.data(), output_bytes.size(), subkey_id,
                                               context_chars, master_key.data()) != 0) {
            return error::backend_failure;
        }
        return {};
    }
};

// blake2b_subkey.hpp's guards are libsodium's bounds, so that libsodium never refuses what they
// pass.
static_assert(blake2b_subkey_min_size == crypto_kdf_blake2b_BYTES_MIN);
static_assert(blake2b_subkey_max_size == crypto_kdf_blake2b_BYTES_MAX);
static_assert(blake2b_subkey_key_size == crypto_kdf_blake2b_KEYBYTES);
static_assert(blake2b_subkey_context_size == crypto_kdf_blake2b_CONTEXTBYTES);

/**
 Argon2id on backends::sodium: `crypto_pwhash_argon2id` with
 `crypto_pwhash_argon2id_ALG_ARGON2ID13`, one lane, libsodium's 16-byte salt (the engine's
 interface: @ref argon2id_engine).
*/
template <>
struct argon2id_engine<backends::sodium> {
    /** libsodium's `crypto_pwhash_argon2id_MEMLIMIT_MAX`: 4 TiB less 1 KiB, 2 GiB on wasm32. */
    static constexpr argon2id_limits limits{crypto_pwhash_argon2id_MEMLIMIT_MAX};

    /**
     The tag, by `crypto_pwhash_argon2id`, which libsodium computes in a buffer of its own that it
     wipes; webcpp holds no copy of a secret.

     @param output_bytes The tag. @param password_bytes The password. @param salt_bytes The 16-byte
     salt.
     @param pass_count t. @param memory_limit The memory in bytes, a multiple of 1,024.
     @return Success, `errc::not_enough_memory` or `error::backend_failure`.
    */
    [[nodiscard]] static boost::system::result<void> derive(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> password_bytes,
        std::span<std::uint8_t const> salt_bytes, std::uint64_t pass_count,
        std::size_t memory_limit) noexcept {
        if (!sodium_ready()) {
            return error::backend_failure;
        }
        errno = 0;
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): libsodium types it char
        auto const* const password_chars = reinterpret_cast<char const*>(nonnull(password_bytes));
        int const status_code = crypto_pwhash_argon2id(
            output_bytes.data(), output_bytes.size(), password_chars, password_bytes.size(),
            salt_bytes.data(), pass_count, memory_limit, crypto_pwhash_argon2id_ALG_ARGON2ID13);
        return sodium_pwhash_status(status_code, errno);
    }
};

/**
 Argon2 of one variant on backends::sodium, for the family `argon2` (the engine's interface is
 @ref argon2_engine), over libsodium's `crypto_pwhash_argon2i` or `crypto_pwhash_argon2id`, version
 0x13, which take one lane, no secret, no associated data, a 16-byte salt and a tag of 16 bytes or
 more; `argon2` answers every other value with `error::unsupported_by_backend` before the call.

 @tparam MinPasses libsodium's `_OPSLIMIT_MIN` of the variant. @tparam MaxMemory libsodium's
 `_MEMLIMIT_MAX` of the variant, in bytes. @tparam Algorithm libsodium's `_ALG_*` of the variant.
 @tparam Hash libsodium's `crypto_pwhash_argon2i` or `crypto_pwhash_argon2id`.
*/
template <std::uint32_t MinPasses, std::size_t MaxMemory, int Algorithm,
          int (*Hash)(unsigned char*, unsigned long long, char const*, unsigned long long,
                      unsigned char const*, unsigned long long, std::size_t, int)>
struct sodium_argon2_engine {
    /** One lane, no secret, no associated data, libsodium's salt and shortest tag. */
    static constexpr argon2_limits limits{
        .min_passes = MinPasses,
        .max_memory_kib = static_cast<std::uint32_t>(MaxMemory / argon2id_memory_unit),
        .max_lanes = 1,
        .min_output = argon2id_min_output_size,
        .min_salt = argon2id_salt_size,
        .max_salt = argon2id_salt_size,
        .secret = false,
        .associated_data = false,
    };

    /**
     The tag, by libsodium, which computes it in a buffer of its own that it wipes; webcpp holds no
     copy of a secret.

     @param output The tag. @param password The password. @param salt The 16-byte salt.
     @param parameters The passes and the memory in KiB, within `limits`.
     @return Success, `errc::not_enough_memory` or `error::backend_failure`.
    */
    [[nodiscard]] static boost::system::result<void> derive(
        std::span<std::uint8_t> output, std::span<std::uint8_t const> password,
        std::span<std::uint8_t const> salt, argon2_parameters const& parameters) noexcept {
        if (!sodium_ready()) {
            return error::backend_failure;
        }
        errno = 0;
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): libsodium types it char
        auto const* const password_chars = reinterpret_cast<char const*>(nonnull(password));
        // limits holds the memory to MaxMemory, a size_t, so the bytes never wrap.
        int const status_code =
            Hash(output.data(), output.size(), password_chars, password.size(), salt.data(),
                 parameters.passes, std::size_t{parameters.memory_kib} * argon2id_memory_unit,
                 Algorithm);
        return sodium_pwhash_status(status_code, errno);
    }
};

/** Argon2i on backends::sodium: `crypto_pwhash_argon2i`, from 3 passes. */
template <>
struct argon2_engine<backends::sodium, kdfs::argon2i>
    : sodium_argon2_engine<crypto_pwhash_argon2i_OPSLIMIT_MIN, crypto_pwhash_argon2i_MEMLIMIT_MAX,
                           crypto_pwhash_argon2i_ALG_ARGON2I13, &crypto_pwhash_argon2i> {};

/** Argon2id on backends::sodium: `crypto_pwhash_argon2id`, the function `argon2id`'s. */
template <>
struct argon2_engine<backends::sodium, kdfs::argon2id>
    : sodium_argon2_engine<crypto_pwhash_argon2id_OPSLIMIT_MIN, crypto_pwhash_argon2id_MEMLIMIT_MAX,
                           crypto_pwhash_argon2id_ALG_ARGON2ID13, &crypto_pwhash_argon2id> {};

/** scrypt on backends::sodium: `crypto_pwhash_scryptsalsa208sha256_ll`. */
template <>
struct scrypt_engine<backends::sodium> {
    /** libsodium's `_ll` refuses an N above `UINT32_MAX`. */
    static constexpr scrypt_limits limits{.n = 0xffffffffULL};

    /**
     The derived key, by `crypto_pwhash_scryptsalsa208sha256_ll`, which declares every pointer
     nonnull: an empty password or salt is passed through @ref nonnull.

     @param output_bytes The derived key. @param password_bytes The password. @param salt_bytes The
     salt.
     @param cost_n N. @param block_size_r r. @param parallelism_p p.
     @return Success, `errc::not_enough_memory` or `error::backend_failure`.
    */
    [[nodiscard]] static boost::system::result<void> derive(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> password_bytes,
        std::span<std::uint8_t const> salt_bytes, std::uint64_t cost_n, std::uint32_t block_size_r,
        std::uint32_t parallelism_p) noexcept {
        if (!sodium_ready()) {
            return error::backend_failure;
        }
        errno = 0;
        int const status_code = crypto_pwhash_scryptsalsa208sha256_ll(
            nonnull(password_bytes), password_bytes.size(), nonnull(salt_bytes), salt_bytes.size(),
            cost_n, block_size_r, parallelism_p, output_bytes.data(), output_bytes.size());
        return sodium_pwhash_status(status_code, errno);
    }
};

// argon2.hpp's presets are libsodium's.
static_assert(argon2id_interactive.passes == crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE &&
                  argon2id_interactive.memory == crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE,
              "argon2id_interactive is libsodium's interactive costs");
static_assert(argon2id_moderate.passes == crypto_pwhash_argon2id_OPSLIMIT_MODERATE &&
                  argon2id_moderate.memory == crypto_pwhash_argon2id_MEMLIMIT_MODERATE,
              "argon2id_moderate is libsodium's moderate costs");
static_assert(argon2id_sensitive.passes == crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE &&
                  argon2id_sensitive.memory == crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE,
              "argon2id_sensitive is libsodium's sensitive costs");
// argon2.hpp's guards are libsodium's bounds, so that libsodium never refuses what they pass and
// its uint32_t lengths never narrow.
static_assert(argon2id_salt_size == crypto_pwhash_argon2id_SALTBYTES);
static_assert(argon2id_min_output_size == crypto_pwhash_argon2id_BYTES_MIN);
// bugprone-branch-clone: libsodium's SODIUM_SIZE_MAX is SODIUM_MIN(UINT64_MAX, SIZE_MAX), whose
// two branches are one where size_t has 64 bits and both macros spell it alike (glibc).
// NOLINTNEXTLINE(bugprone-branch-clone)
static_assert(argon2id_max_size == crypto_pwhash_argon2id_BYTES_MAX);
static_assert(argon2id_max_size == crypto_pwhash_argon2id_PASSWD_MAX);
static_assert(argon2id_min_passes == crypto_pwhash_argon2id_OPSLIMIT_MIN);
static_assert(argon2id_max_passes == crypto_pwhash_argon2id_OPSLIMIT_MAX);
static_assert(argon2id_min_memory == crypto_pwhash_argon2id_MEMLIMIT_MIN);
static_assert(crypto_pwhash_argon2id_MEMLIMIT_MAX % argon2id_memory_unit == 0);
// The family's Argon2i is libsodium's crypto_pwhash with crypto_pwhash_ALG_ARGON2I13, on the
// bounds argon2id's guards already hold for Argon2id.
static_assert(crypto_pwhash_ALG_ARGON2I13 == crypto_pwhash_argon2i_ALG_ARGON2I13);
static_assert(argon2id_salt_size == crypto_pwhash_argon2i_SALTBYTES);
static_assert(argon2id_min_output_size == crypto_pwhash_argon2i_BYTES_MIN);
static_assert(argon2id_min_memory == crypto_pwhash_argon2i_MEMLIMIT_MIN);
static_assert(argon2id_max_size == crypto_pwhash_argon2i_PASSWD_MAX);
static_assert(argon2id_max_passes == crypto_pwhash_argon2i_OPSLIMIT_MAX);
static_assert(crypto_pwhash_argon2i_MEMLIMIT_MAX % argon2id_memory_unit == 0);
// The memory in KiB fits argon2_limits' uint32_t: 2^32 - 1 KiB natively, 2 GiB on wasm32.
static_assert(crypto_pwhash_argon2i_MEMLIMIT_MAX / argon2id_memory_unit <= 0xffffffffU);
static_assert(crypto_pwhash_argon2id_MEMLIMIT_MAX / argon2id_memory_unit <= 0xffffffffU);

}  // namespace detail

}  // namespace webcpp::hash

#endif  // WEBCPP_HASH_HAS_SODIUM
#endif  // WEBCPP_HASH_BACKENDS_SODIUM_HPP
