// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `backends::sodium`: HKDF (RFC 5869) over libsodium's `crypto_kdf_hkdf_sha256_*` and
 `crypto_kdf_hkdf_sha512_*`, Argon2id over `crypto_pwhash_argon2id` and scrypt over
 `crypto_pwhash_scryptsalsa208sha256_ll`, built from source by `/third_party//sodium`, on every
 target. It has HKDF over `hmac_sha2_256` and `hmac_sha2_512` alone, and no PBKDF2; every other
 hmac and PBKDF2 refuse at compile time with spec 3.3's texts.

 Its limits beyond the spec's: scrypt's N at most 4,294,967,295 (libsodium refuses a larger one).
 Argon2's core holds the password's, salt's and tag's lengths in `uint32_t`, which spec 2.10's own
 guards already keep within (this header checks that they agree), and webcpp passes no secret or
 associated data; scrypt's and HKDF's lengths are `size_t`.

 On Emscripten `/third_party//sodium` links a program with `-sALLOW_MEMORY_GROWTH=1`: Argon2id and
 scrypt allocate the memory their costs name, past Emscripten's fixed 16 MiB.

 Every engine function calls `sodium_init()` first (it returns 0 the first time and 1 after,
 both success), so that a program that never initialised libsodium is safe.

 @see "Key derivation", in the guide.
*/
#ifndef WEBCPP_HASH_BACKENDS_SODIUM_HPP
#define WEBCPP_HASH_BACKENDS_SODIUM_HPP

#include <webcpp/hash/config.hpp>

#ifndef WEBCPP_HASH_HAS_SODIUM
#error \
    "webcpp::hash: backends::sodium, argon2id and scrypt need libsodium. Add /third_party//sodium to the program's Jamfile: exe app : app.cpp /webcpp/hash//hash /third_party//sodium ;"
#else

#include <webcpp/hash/detail/canary.h>
#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/detail/limits.hpp>
#include <webcpp/hash/detail/wipe.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/scrypt.hpp>

#include <boost/system/errc.hpp>
#include <boost/system/result.hpp>

#include <sodium/core.h>  // third_party/libs/libsodium, through /third_party//sodium
#include <sodium/crypto_kdf_hkdf_sha256.h>              // the same
#include <sodium/crypto_kdf_hkdf_sha512.h>              // the same
#include <sodium/crypto_pwhash_argon2id.h>              // the same
#include <sodium/crypto_pwhash_scryptsalsa208sha256.h>  // the same

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

/** libsodium, built from its sources by `/third_party//sodium`: HKDF over SHA-256 and SHA-512. */
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
 Initialises libsodium, as every engine function does first: `sodium_init` returns 0 the first
 time and 1 after, both success, and -1 when it cannot initialise.

 @return Whether libsodium is ready.
*/
inline bool sodium_ready() noexcept {
    touch_sodium_canary();
    return sodium_init() >= 0;
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
        "hmac_ripemd_128) or backends::bearssl (MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512; "
        "hkdf alone).");

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
                  "backends that have pbkdf2: backends::hash2 (every hmac) and backends::openssl "
                  "(every hmac but hmac_ripemd_128).");

    /** Never called: the refusal has stopped the build. */
    [[nodiscard]] static boost::system::result<void> derive(
        std::span<std::uint8_t> /*output_bytes*/, std::span<std::uint8_t const> /*password_bytes*/,
        std::span<std::uint8_t const> /*salt_bytes*/, std::uint64_t /*iteration_count*/) noexcept {
        return error::backend_failure;
    }
};

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

/** scrypt on backends::sodium: `crypto_pwhash_scryptsalsa208sha256_ll`. */
template <>
struct scrypt_engine<backends::sodium> {
    /** libsodium's `_ll` refuses an N above `UINT32_MAX`. */
    static constexpr scrypt_limits limits{0xffffffffULL};

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
static_assert(argon2id_max_size == crypto_pwhash_argon2id_BYTES_MAX);
static_assert(argon2id_max_size == crypto_pwhash_argon2id_PASSWD_MAX);
static_assert(argon2id_min_passes == crypto_pwhash_argon2id_OPSLIMIT_MIN);
static_assert(argon2id_max_passes == crypto_pwhash_argon2id_OPSLIMIT_MAX);
static_assert(argon2id_min_memory == crypto_pwhash_argon2id_MEMLIMIT_MIN);
static_assert(crypto_pwhash_argon2id_MEMLIMIT_MAX % argon2id_memory_unit == 0);

}  // namespace detail

}  // namespace webcpp::hash

#endif  // WEBCPP_HASH_HAS_SODIUM
#endif  // WEBCPP_HASH_BACKENDS_SODIUM_HPP
