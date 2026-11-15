// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `backends::openssl`: HKDF (RFC 5869) and PBKDF2 (RFC 8018) of OpenSSL 3.5.9, its `EVP_KDF`s
 "HKDF" and "PBKDF2", built from `third_party/libs/openssl` by `/webcpp/hash//openssl`, static,
 on native, wasip2 and wasip3; never on Emscripten. It has every hmac of `hmac.hpp` but
 `hmac_ripemd_128` (spec section 3.2).

 Each call fetches the KDF, makes a context, sets the parameters, derives and frees both
 (spec section 3.4): OpenSSL allocates them through its own allocator, and webcpp keeps no
 OpenSSL object between calls (spec section 6.2). OpenSSL copies the key, the salt and the info
 into its context and clears them when the context is freed. Its default initialisation, on the
 first call, reads the configuration file of the directory it was configured with, as any
 program of OpenSSL does.

 The thread's error queue is left as the backend found it, through a mark set before the fetch
 and a pop after the frees. The queue is a ring of 16 slots (`ERR_NUM_ERRORS`), which holds 15
 entries: when the caller's entries and those OpenSSL raises between the mark and the pop are
 more than 15, the oldest are overwritten, the marked one among them, and the pop then empties
 the queue, the caller's entries with it.

 @see "Key derivation", in the guide.
*/
#ifndef WEBCPP_HASH_BACKENDS_OPENSSL_HPP
#define WEBCPP_HASH_BACKENDS_OPENSSL_HPP

#include <webcpp/hash/config.hpp>

#ifndef WEBCPP_HASH_HAS_OPENSSL
// clang-format off
#error "webcpp::hash: backends::openssl needs OpenSSL. Add /webcpp/hash//openssl to the program's Jamfile (native, wasip2 and wasip3): exe app : app.cpp /webcpp/hash//hash /webcpp/hash//openssl ;"
// clang-format on
#else

#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/detail/wipe.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hmac.hpp>

#include <boost/system/errc.hpp>
#include <boost/system/result.hpp>

#include <openssl/core.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>

namespace webcpp::hash::backends {

/** OpenSSL 3.5.9's HKDF and PBKDF2, through `/webcpp/hash//openssl`, on native, wasip2 and wasip3.
 */
struct openssl {};

}  // namespace webcpp::hash::backends

namespace webcpp::hash::detail {

/**
 OpenSSL's name of the digest of `Hmac` (spec section 3.2), its `value`. The primary template is
 reached by an hmac OpenSSL has no digest for, and refuses: `hmac_ripemd_128` with spec 3.3's
 text, any other with the general one.

 @tparam Hmac A Boost.Hash2 hmac over a digest.
*/
template <class Hmac>
struct openssl_digest_name {
    static_assert(!std::is_same_v<Hmac, hmac_ripemd_128>,
                  "webcpp::hash: backends::openssl has no hmac_ripemd_128 (OpenSSL 3.5 has no "
                  "RIPEMD-128). Name backends::hash2.");
    static_assert(std::is_same_v<Hmac, hmac_ripemd_128>,
                  "webcpp::hash: backends::openssl has HKDF and PBKDF2 over the hmacs of hmac.hpp "
                  "alone, hmac_ripemd_128 excepted. Over this hmac, name backends::hash2.");
    /** No name: the refusal is the only error. */
    static constexpr char const* value = "";
};

/** HMAC-MD5. */
template <>
struct openssl_digest_name<hmac_md5_128> {
    /** OpenSSL's name. */
    static constexpr char const* value = "MD5";
};

/** HMAC-SHA-1. */
template <>
struct openssl_digest_name<hmac_sha1_160> {
    /** OpenSSL's name. */
    static constexpr char const* value = "SHA1";
};

/** HMAC-SHA-224. */
template <>
struct openssl_digest_name<hmac_sha2_224> {
    /** OpenSSL's name. */
    static constexpr char const* value = "SHA2-224";
};

/** HMAC-SHA-256. */
template <>
struct openssl_digest_name<hmac_sha2_256> {
    /** OpenSSL's name. */
    static constexpr char const* value = "SHA2-256";
};

/** HMAC-SHA-384. */
template <>
struct openssl_digest_name<hmac_sha2_384> {
    /** OpenSSL's name. */
    static constexpr char const* value = "SHA2-384";
};

/** HMAC-SHA-512. */
template <>
struct openssl_digest_name<hmac_sha2_512> {
    /** OpenSSL's name. */
    static constexpr char const* value = "SHA2-512";
};

/** HMAC-SHA-512/224. */
template <>
struct openssl_digest_name<hmac_sha2_512_224> {
    /** OpenSSL's name. */
    static constexpr char const* value = "SHA2-512/224";
};

/** HMAC-SHA-512/256. */
template <>
struct openssl_digest_name<hmac_sha2_512_256> {
    /** OpenSSL's name. */
    static constexpr char const* value = "SHA2-512/256";
};

/** HMAC-SHA3-224. */
template <>
struct openssl_digest_name<hmac_sha3_224> {
    /** OpenSSL's name. */
    static constexpr char const* value = "SHA3-224";
};

/** HMAC-SHA3-256. */
template <>
struct openssl_digest_name<hmac_sha3_256> {
    /** OpenSSL's name. */
    static constexpr char const* value = "SHA3-256";
};

/** HMAC-SHA3-384. */
template <>
struct openssl_digest_name<hmac_sha3_384> {
    /** OpenSSL's name. */
    static constexpr char const* value = "SHA3-384";
};

/** HMAC-SHA3-512. */
template <>
struct openssl_digest_name<hmac_sha3_512> {
    /** OpenSSL's name. */
    static constexpr char const* value = "SHA3-512";
};

/** HMAC-RIPEMD-160. */
template <>
struct openssl_digest_name<hmac_ripemd_160> {
    /** OpenSSL's name. */
    static constexpr char const* value = "RIPEMD-160";
};

/** HMAC-BLAKE2b-512. */
template <>
struct openssl_digest_name<hmac_blake2b_512> {
    /** OpenSSL's name. */
    static constexpr char const* value = "BLAKE2B-512";
};

/** HMAC-BLAKE2s-256. */
template <>
struct openssl_digest_name<hmac_blake2s_256> {
    /** OpenSSL's name. */
    static constexpr char const* value = "BLAKE2S-256";
};

/**
 The digest name a call gives OpenSSL: `openssl_digest_name<Hmac>`'s, or, in a test that defines
 `WEBCPP_HASH_DETAIL_TEST_OPENSSL_DIGEST` (a string literal), that one, to provoke a failure.

 @tparam Hmac A Boost.Hash2 hmac over a digest.
 @return The name, for the parameter "digest".
*/
template <class Hmac>
constexpr char const* openssl_digest() noexcept {
    [[maybe_unused]] constexpr char const* name = openssl_digest_name<Hmac>::value;
#ifdef WEBCPP_HASH_DETAIL_TEST_OPENSSL_DIGEST
    return WEBCPP_HASH_DETAIL_TEST_OPENSSL_DIGEST;
#else
    return name;
#endif
}

/**
 The byte an empty input's parameter points at: OpenSSL refuses an octet string whose data is
 null, whatever its size.
*/
inline constexpr std::uint8_t openssl_empty = 0;

/**
 An octet-string parameter over `bytes`, which OpenSSL only reads.

 @param key The parameter's name. @param bytes Its value, possibly empty.
 @return The parameter.
*/
inline OSSL_PARAM openssl_octets(char const* key, std::span<std::uint8_t const> bytes) noexcept {
    void* data = const_cast<std::uint8_t*>(bytes.empty() ? &openssl_empty : bytes.data());
    return OSSL_PARAM_construct_octet_string(key, data, bytes.size());
}

/**
 A UTF-8 string parameter over `text`, which OpenSSL only reads.

 @param key The parameter's name. @param text Its value.
 @return The parameter.
*/
inline OSSL_PARAM openssl_text(char const* key, char const* text) noexcept {
    return OSSL_PARAM_construct_utf8_string(key, const_cast<char*>(text), 0);
}

/**
 Fetches the KDF named `kdf`, makes a context, and derives `output` from `params` (spec section
 3.4), freeing both; the thread's error queue is left as it was found.

 @param kdf OpenSSL's name of the KDF, "HKDF" or "PBKDF2".
 @param output What is derived, its whole size.
 @param params The parameters, ending with `OSSL_PARAM_construct_end()`.
 @return Success; `errc::not_enough_memory` when the last error OpenSSL raised is an allocation's;
 `error::backend_failure` for any other failure.
*/
inline boost::system::result<void> openssl_kdf(char const* kdf, std::span<std::uint8_t> output,
                                               std::span<OSSL_PARAM> params) noexcept {
    ERR_set_mark();
    EVP_KDF* algorithm = EVP_KDF_fetch(nullptr, kdf, nullptr);
    EVP_KDF_CTX* context = algorithm != nullptr ? EVP_KDF_CTX_new(algorithm) : nullptr;
    const bool derived = context != nullptr &&
                         EVP_KDF_derive(context, output.data(), output.size(), params.data()) == 1;
    // Only an error raised since the mark is OpenSSL's answer: an older one is the caller's.
    const bool out_of_memory = !derived && ERR_count_to_mark() > 0 &&
                               ERR_GET_REASON(ERR_peek_last_error()) == ERR_R_MALLOC_FAILURE;
    EVP_KDF_CTX_free(context);
    EVP_KDF_free(algorithm);
    ERR_pop_to_mark();
    if (derived) {
        return {};
    }
    if (out_of_memory) {
        return boost::system::errc::make_error_code(boost::system::errc::not_enough_memory);
    }
    return error::backend_failure;
}

/**
 HKDF on backends::openssl, OpenSSL's "HKDF" in its three modes (the engine's interface: @ref
 hkdf_engine).

 @tparam Hmac A Boost.Hash2 hmac over a digest that OpenSSL has.
*/
template <class Hmac>
struct hkdf_engine<backends::openssl, Hmac> {
    /** The hmac's result, a `digest<N>`: the PRK. */
    using digest_type = Hmac::result_type;

    /** OpenSSL's `EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND`. */
    static constexpr int both = 0;
    /** OpenSSL's `EVP_KDF_HKDF_MODE_EXTRACT_ONLY`. */
    static constexpr int extract_only = 1;
    /** OpenSSL's `EVP_KDF_HKDF_MODE_EXPAND_ONLY`. */
    static constexpr int expand_only = 2;

    /**
     RFC 5869, 2.2, in extract-only mode, which writes the PRK, HashLen bytes, into the digest.
     An empty salt is HashLen zeros, as OpenSSL's HMAC pads it.

     @param salt The salt. @param ikm The input keying material.
     @return The PRK, or OpenSSL's failure.
    */
    static boost::system::result<digest_type> extract(std::span<std::uint8_t const> salt,
                                                      std::span<std::uint8_t const> ikm) noexcept {
        int mode = extract_only;
        std::array<OSSL_PARAM, 5> params{
            openssl_text("digest", openssl_digest<Hmac>()),
            openssl_octets("key", ikm),
            openssl_octets("salt", salt),
            OSSL_PARAM_construct_int("mode", &mode),
            OSSL_PARAM_construct_end(),
        };
        // The PRK is stored in the result returned, whose wiping is the caller's.
        boost::system::result<digest_type> prk(boost::system::in_place_value);
        digest_type& key = prk.unsafe_value();
        const auto done =
            openssl_kdf("HKDF", std::span<std::uint8_t>(key.data(), key.size()), params);
        if (!done) {
            wipe_object(key);
            return done.error();
        }
        return prk;
    }

    /**
     RFC 5869, 2.3, in expand-only mode.

     @param output The OKM, its size L. @param prk The PRK. @param info The info.
     @return Success, or OpenSSL's failure.
    */
    static boost::system::result<void> expand(std::span<std::uint8_t> output,
                                              std::span<std::uint8_t const> prk,
                                              std::span<std::uint8_t const> info) noexcept {
        int mode = expand_only;
        std::array<OSSL_PARAM, 5> params{
            openssl_text("digest", openssl_digest<Hmac>()),
            openssl_octets("key", prk),
            openssl_octets("info", info),
            OSSL_PARAM_construct_int("mode", &mode),
            OSSL_PARAM_construct_end(),
        };
        return openssl_kdf("HKDF", output, params);
    }

    /**
     RFC 5869, 2, in extract-and-expand mode: the PRK stays inside OpenSSL's context.

     @param output The OKM. @param salt The salt. @param ikm The input keying material.
     @param info The info.
     @return Success, or OpenSSL's failure.
    */
    static boost::system::result<void> extract_and_expand(
        std::span<std::uint8_t> output, std::span<std::uint8_t const> salt,
        std::span<std::uint8_t const> ikm, std::span<std::uint8_t const> info) noexcept {
        int mode = both;
        std::array<OSSL_PARAM, 6> params{
            openssl_text("digest", openssl_digest<Hmac>()),
            openssl_octets("key", ikm),
            openssl_octets("salt", salt),
            openssl_octets("info", info),
            OSSL_PARAM_construct_int("mode", &mode),
            OSSL_PARAM_construct_end(),
        };
        return openssl_kdf("HKDF", output, params);
    }
};

/**
 PBKDF2 on backends::openssl, OpenSSL's "PBKDF2" with `pkcs5` set, so that SP 800-132's lower
 bounds (iterations, salt and output) do not apply and RFC 8018's are the guards of `pbkdf2.hpp`
 (the engine's interface: @ref pbkdf2_engine).

 @tparam Hmac A Boost.Hash2 hmac over a digest that OpenSSL has.
*/
template <class Hmac>
struct pbkdf2_engine<backends::openssl, Hmac> {
    /**
     RFC 8018, 5.2.

     @param output DK, its size dkLen. @param password P. @param salt S.
     @param iterations c.
     @return Success, or OpenSSL's failure.
    */
    static boost::system::result<void> derive(std::span<std::uint8_t> output,
                                              std::span<std::uint8_t const> password,
                                              std::span<std::uint8_t const> salt,
                                              std::uint64_t iterations) noexcept {
        int pkcs5 = 1;
        std::array<OSSL_PARAM, 6> params{
            openssl_text("digest", openssl_digest<Hmac>()),
            openssl_octets("pass", password),
            openssl_octets("salt", salt),
            OSSL_PARAM_construct_uint64("iter", &iterations),
            OSSL_PARAM_construct_int("pkcs5", &pkcs5),
            OSSL_PARAM_construct_end(),
        };
        return openssl_kdf("PBKDF2", output, params);
    }
};

}  // namespace webcpp::hash::detail

#endif  // WEBCPP_HASH_HAS_OPENSSL

#endif  // WEBCPP_HASH_BACKENDS_OPENSSL_HPP
