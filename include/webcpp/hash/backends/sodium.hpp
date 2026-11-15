// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `backends::sodium`: HKDF (RFC 5869) over libsodium's `crypto_kdf_hkdf_sha256_*` and
 `crypto_kdf_hkdf_sha512_*`, built from source by `/third_party//sodium`, on every target. It has
 HKDF over `hmac_sha2_256` and `hmac_sha2_512` alone, and no PBKDF2; every other hmac and PBKDF2
 refuse at compile time with spec 3.3's texts.

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
#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/detail/limits.hpp>
#include <webcpp/hash/detail/wipe.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hmac.hpp>

#include <boost/system/result.hpp>

#include <sodium/core.h>  // third_party/libs/libsodium, through /third_party//sodium
#include <sodium/crypto_kdf_hkdf_sha256.h>  // the same
#include <sodium/crypto_kdf_hkdf_sha512.h>  // the same

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
    char const value = *static_cast<char const volatile*>(&WEBCPP_HASH_DETAIL_SODIUM_CANARY);
    static_cast<void>(value);
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

/** libsodium's HKDF over SHA-256: the hmac and the two C functions it wraps. */
struct sodium_hkdf_sha256 {
    /** The hmac it serves. */
    using hmac_type = hmac_sha2_256;
    /** The PRK's size, libsodium's `crypto_kdf_hkdf_sha256_KEYBYTES`. */
    static constexpr std::size_t key_size = crypto_kdf_hkdf_sha256_KEYBYTES;

    /**
     `crypto_kdf_hkdf_sha256_extract`.

     @param prk The PRK. @param salt The salt. @param ikm The input keying material.
     @return libsodium's status, 0 on success.
    */
    static int extract(std::uint8_t* prk, std::span<std::uint8_t const> salt,
                       std::span<std::uint8_t const> ikm) noexcept {
        // SHA-256's extract declares the IKM nonnull; an empty span's data() may be null.
        return crypto_kdf_hkdf_sha256_extract(prk, salt.data(), salt.size(), nonnull(ikm),
                                              ikm.size());
    }

    /**
     `crypto_kdf_hkdf_sha256_expand`, whose context is the info.

     @param output The OKM. @param prk The PRK. @param info The info.
     @return libsodium's status, 0 on success.
    */
    static int expand(std::span<std::uint8_t> output, std::span<std::uint8_t const> prk,
                      std::span<std::uint8_t const> info) noexcept {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): libsodium types ctx as char
        return crypto_kdf_hkdf_sha256_expand(output.data(), output.size(),
                                             reinterpret_cast<char const*>(info.data()),
                                             info.size(), prk.data());
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

     @param prk The PRK. @param salt The salt. @param ikm The input keying material.
     @return libsodium's status, 0 on success.
    */
    static int extract(std::uint8_t* prk, std::span<std::uint8_t const> salt,
                       std::span<std::uint8_t const> ikm) noexcept {
        // SHA-512's extract declares no IKM nonnull; it is passed as SHA-256's is, so that the two
        // traits are alike (a deliberate step past R11's letter, harmless).
        return crypto_kdf_hkdf_sha512_extract(prk, salt.data(), salt.size(), nonnull(ikm),
                                              ikm.size());
    }

    /**
     `crypto_kdf_hkdf_sha512_expand`, whose context is the info.

     @param output The OKM. @param prk The PRK. @param info The info.
     @return libsodium's status, 0 on success.
    */
    static int expand(std::span<std::uint8_t> output, std::span<std::uint8_t const> prk,
                      std::span<std::uint8_t const> info) noexcept {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): libsodium types ctx as char
        return crypto_kdf_hkdf_sha512_expand(output.data(), output.size(),
                                             reinterpret_cast<char const*>(info.data()),
                                             info.size(), prk.data());
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

     @param salt The salt. @param ikm The input keying material.
     @return The PRK, or `error::backend_failure`.
    */
    static boost::system::result<digest_type> extract(std::span<std::uint8_t const> salt,
                                                      std::span<std::uint8_t const> ikm) noexcept {
        if (!sodium_ready()) {
            return error::backend_failure;
        }
        // The PRK is built in the result returned, whose wiping is the caller's: no local copy.
        boost::system::result<digest_type> prk(boost::system::in_place_value);
        if (Traits::extract(prk.unsafe_value().data(), salt, ikm) != 0) {
            wipe_object(prk.unsafe_value());
            return error::backend_failure;
        }
        return prk;
    }

    /**
     RFC 5869, 2.3, by libsodium's `_expand`.

     @param output The OKM, its size L. @param prk The PRK. @param info The info.
     @return Success, or `error::backend_failure`.
    */
    static boost::system::result<void> expand(std::span<std::uint8_t> output,
                                              std::span<std::uint8_t const> prk,
                                              std::span<std::uint8_t const> info) noexcept {
        if (!sodium_ready()) {
            return error::backend_failure;
        }
        if (Traits::expand(output, prk, info) != 0) {
            return error::backend_failure;
        }
        return {};
    }

    /**
     RFC 5869, 2: HKDF-Extract into a local PRK, HKDF-Expand, and the PRK wiped.

     @param output The OKM. @param salt The salt. @param ikm The input keying material.
     @param info The info.
     @return Success, or `error::backend_failure`.
    */
    static boost::system::result<void> extract_and_expand(
        std::span<std::uint8_t> output, std::span<std::uint8_t const> salt,
        std::span<std::uint8_t const> ikm, std::span<std::uint8_t const> info) noexcept {
        auto prk = extract(salt, ikm);
        if (!prk) {
            return prk.error();
        }
        digest_type& key = prk.unsafe_value();
        auto done = expand(output, std::span<std::uint8_t const>(key.data(), key.size()), info);
        wipe_object(key);
        return done;
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
    static boost::system::result<typename Hmac::result_type> extract(
        std::span<std::uint8_t const> /*salt*/, std::span<std::uint8_t const> /*ikm*/) noexcept {
        return error::backend_failure;
    }

    /** Never called: the refusal has stopped the build. */
    static boost::system::result<void> expand(std::span<std::uint8_t> /*output*/,
                                              std::span<std::uint8_t const> /*prk*/,
                                              std::span<std::uint8_t const> /*info*/) noexcept {
        return error::backend_failure;
    }

    /** Never called: the refusal has stopped the build. */
    static boost::system::result<void> extract_and_expand(
        std::span<std::uint8_t> /*output*/, std::span<std::uint8_t const> /*salt*/,
        std::span<std::uint8_t const> /*ikm*/, std::span<std::uint8_t const> /*info*/) noexcept {
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
    static boost::system::result<void> derive(std::span<std::uint8_t> /*output*/,
                                              std::span<std::uint8_t const> /*password*/,
                                              std::span<std::uint8_t const> /*salt*/,
                                              std::uint64_t /*iterations*/) noexcept {
        return error::backend_failure;
    }
};

}  // namespace detail

}  // namespace webcpp::hash

#endif  // WEBCPP_HASH_HAS_SODIUM
#endif  // WEBCPP_HASH_BACKENDS_SODIUM_HPP
