// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `backends::openssl`: HKDF (RFC 5869), PBKDF2 (RFC 8018), scrypt (RFC 7914) and Argon2 (RFC 9106)
 of OpenSSL 3.5.9, its `EVP_KDF`s "HKDF", "PBKDF2", "SCRYPT", "ARGON2D", "ARGON2I" and "ARGON2ID",
 the digests of its default provider through `EVP_MD` and its MACs through `EVP_MAC`, built from
 `third_party/libs/openssl` by `/webcpp/hash//openssl`, static, on native, wasip2 and wasip3;
 never on Emscripten, and never a default backend (design D34): a call names it. The key
 derivations have every hmac of `hmac.hpp` but `hmac_ripemd_128` (spec section 3.2). The digests
 are MD5, SHA-1, the six SHA-2, the four SHA-3, SHAKE128 and SHAKE256 (any output size),
 Keccak-224 to Keccak-512, BLAKE2s-256, BLAKE2b unkeyed (1 to 64 bytes), RIPEMD-160, MD5-SHA1
 and SM3; the default provider's SHA-256/192 and KMAC hashes have no tag, and Whirlpool, MD4 and
 MDC2 are in the legacy provider, which webcpp does not load (`doc/capabilities.json` says why).
 The MACs are HMAC over each of those digests but SHAKE and MD5-SHA1 (no standard defines an
 HMAC over it), KMAC128 and KMAC256 (fixed-length and XOF), keyed BLAKE2b and BLAKE2s, and
 SipHash-2-4 with an 8-byte or a 16-byte tag; its CMAC, GMAC and Poly1305 are not exposed. Its
 Argon2 has the three variants with every parameter of RFC 9106 (the family `argon2`) and serves
 the function `argon2id`; it computes the lanes one after the other in the calling thread. Its
 scrypt runs with its own memory limit, `maxmem_bytes`, at its largest.

 Each key derivation fetches the KDF, makes a context, sets the parameters, derives and frees
 both (spec section 3.4): OpenSSL allocates them through its own allocator, and webcpp keeps no
 OpenSSL object between calls (spec section 6.2). A digest allocates an `EVP_MD_CTX` and the
 digest's context the same way: `digest_of` frees them before it returns, and a `hasher` owns
 them until it finishes or is destroyed, so that a hash in pieces is the one OpenSSL object that
 outlives a call; it is the hasher's alone. A MAC fetches the MAC and makes an `EVP_MAC_CTX` in
 each call of `mac`, and frees both before it returns. OpenSSL copies the inputs into its
 context: the key (HKDF's IKM or PRK, PBKDF2's password) and the info are cleared when the
 context is freed; the salt is freed without being cleared (OpenSSL clears it only when built
 with `OPENSSL_PEDANTIC_ZEROIZATION`). OpenSSL documents `EVP_MD_CTX_free` as cleaning up and
 freeing a digest's context and `EVP_MAC_CTX_free` as freeing a MAC's, not as clearing them; as
 read at 3.5.9, its HMAC, KMAC and BLAKE2 MACs clear their copy of the key when freed, and its
 SipHash frees its keyed state without clearing it. Its default initialisation, on the first
 call, reads the configuration file of the directory it was configured with, as any program of
 OpenSSL does.

 Its limits: OpenSSL 3.5.9 holds some lengths in an `int`, so the public functions refuse,
 before OpenSSL is called, PBKDF2's output (`invalid_output_size`), password and salt
 (`input_too_long`), HKDF's salt (`input_too_long`) and scrypt's password, salt
 (`input_too_long`) and output (`invalid_output_size`) of more than `INT_MAX` bytes, scrypt's
 r p of 2^24 or more (`invalid_parameters`), and `mac` an HMAC key of more than `INT_MAX` bytes
 (`unsupported_by_backend`); its KMAC takes a key of 4 to 512 bytes, a customisation of at most
 512 and a tag of at most 2,097,151 (`unsupported_by_backend` otherwise); its Argon2 takes m in KiB
 as a `uint32_t` and sizes the memory in a `size_t`: `argon2` refuses m above 4,194,303 KiB on
 wasm32 (`unsupported_by_backend`), and `argon2id` a memory above 4 TiB less 1 KiB natively
 (`invalid_parameters`; on wasm32 no whole number of KiB in a `size_t` is past its limit).
 PBKDF2 keeps
 the output's and the salt's lengths in `int`s, and HMAC, through `HMAC_Init_ex`, its key's
 length, which is PBKDF2's password and HKDF-Extract's salt; HKDF-Expand's key, the PRK, takes
 the same path and is limited alike, though it is always one digest. HKDF's IKM, info and output
 stay in `size_t`.

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

#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/detail/limits.hpp>
#include <webcpp/hash/detail/wipe.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/kdf_standards.hpp>
#include <webcpp/hash/scrypt.hpp>

#include <boost/system/errc.hpp>
#include <boost/system/result.hpp>

#include <openssl/core.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <algorithm>
#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <type_traits>
#include <utility>

namespace webcpp::hash::backends {

/**
 OpenSSL 3.5.9's HKDF, PBKDF2, digests and MACs, through `/webcpp/hash//openssl`, on native,
 wasip2 and wasip3; never a default backend.
*/
struct openssl {};

}  // namespace webcpp::hash::backends

namespace webcpp::hash::detail {

/** OpenSSL's `INT_MAX`, the longest length it holds in an `int`. */
inline constexpr std::uint64_t openssl_int_max = INT_MAX;

/**
 The limits of backends::openssl: `INT_MAX` bytes wherever OpenSSL 3.5.9 holds a
 length in an `int` (this header's comment lists them), Argon2's `uint32_t` lengths; no limit
 elsewhere.
*/
template <>
struct backend_limits<backends::openssl> {
    /** HKDF-Extract's salt is HMAC's key, whose length `HMAC_Init_ex` takes as an `int`. */
    static constexpr std::uint64_t hkdf_salt = openssl_int_max;
    /** HKDF's IKM goes to `HMAC_Update` and its parameter in `size_t`s. */
    static constexpr std::uint64_t hkdf_ikm = no_limit;
    /** HKDF-Expand's PRK is HMAC's key, as the salt is (always one digest). */
    static constexpr std::uint64_t hkdf_prk = openssl_int_max;
    /** HKDF's info stays in a `size_t`, within OpenSSL's 32,768 bytes, `hkdf_max_info_size`. */
    static constexpr std::uint64_t hkdf_info = no_limit;
    /** HKDF-Expand's output stays in a `size_t`, within 255 digests. */
    static constexpr std::uint64_t hkdf_output = no_limit;
    /** PBKDF2's password is HMAC's key. */
    static constexpr std::uint64_t pbkdf2_password = openssl_int_max;
    /** PBKDF2's salt length is an `int` in `pbkdf2_derive`. */
    static constexpr std::uint64_t pbkdf2_salt = openssl_int_max;
    /** PBKDF2's output length is an `int` (`tkeylen`) in `pbkdf2_derive`. */
    static constexpr std::uint64_t pbkdf2_output = openssl_int_max;
    /** Argon2's password length is a `uint32_t` in OpenSSL, RFC 9106's own bound. */
    static constexpr std::uint64_t argon2id_password = 0xffffffffULL;
    /** Argon2's salt length is a `uint32_t` in OpenSSL, RFC 9106's own bound. */
    static constexpr std::uint64_t argon2id_salt = 0xffffffffULL;
    /** Argon2's tag length is a `uint32_t` in OpenSSL, RFC 9106's own bound. */
    static constexpr std::uint64_t argon2id_output = 0xffffffffULL;
    /** scrypt's password goes to PBKDF2 (`ossl_pkcs5_pbkdf2_hmac_ex`), whose length is an `int`. */
    static constexpr std::uint64_t scrypt_password = openssl_int_max;
    /** scrypt's salt goes to PBKDF2 alike. */
    static constexpr std::uint64_t scrypt_salt = openssl_int_max;
    /** scrypt's output is PBKDF2's, whose length is an `int`. */
    static constexpr std::uint64_t scrypt_output = openssl_int_max;
};

/**
 Whether a digest of OpenSSL is an extendable-output function, finished by `EVP_DigestFinalXOF`
 at any size, rather than by `EVP_DigestFinal_ex` at its own: the base of each
 @ref openssl_md_name.

 @tparam Xof Whether it is.
*/
template <bool Xof>
struct openssl_md_kind {
    /** Whether the digest is an extendable-output function. */
    static constexpr bool xof = Xof;
};

/**
 OpenSSL's name of a tag of `digests`, its `value`: the first of the names OpenSSL 3.5.9's default
 provider gives it (`providers/implementations/include/prov/names.h`, `PROV_NAMES_*`), which
 `EVP_MD_fetch` and the key derivations' parameter "digest" take; `xof`, whether
 `EVP_DigestFinalXOF` finishes it. Declared for every tag, defined for each tag of the default
 provider: the digest engines of backends::openssl and @ref openssl_digest_name read it.

 @tparam Digest A tag of `digests`.
*/
template <class Digest>
struct openssl_md_name;

/** MD5, RFC 1321: "MD5". */
template <>
struct openssl_md_name<digests::md5> : openssl_md_kind<false> {
    /** OpenSSL's name. */
    static constexpr char const* value = "MD5";
};

/** SHA-1: "SHA1". */
template <>
struct openssl_md_name<digests::sha1> : openssl_md_kind<false> {
    /** OpenSSL's name. */
    static constexpr char const* value = "SHA1";
};

/** SHA-224: "SHA2-224". */
template <>
struct openssl_md_name<digests::sha2_224> : openssl_md_kind<false> {
    /** OpenSSL's name. */
    static constexpr char const* value = "SHA2-224";
};

/** SHA-256: "SHA2-256". */
template <>
struct openssl_md_name<digests::sha2_256> : openssl_md_kind<false> {
    /** OpenSSL's name. */
    static constexpr char const* value = "SHA2-256";
};

/** SHA-384: "SHA2-384". */
template <>
struct openssl_md_name<digests::sha2_384> : openssl_md_kind<false> {
    /** OpenSSL's name. */
    static constexpr char const* value = "SHA2-384";
};

/** SHA-512: "SHA2-512". */
template <>
struct openssl_md_name<digests::sha2_512> : openssl_md_kind<false> {
    /** OpenSSL's name. */
    static constexpr char const* value = "SHA2-512";
};

/** SHA-512/224: "SHA2-512/224". */
template <>
struct openssl_md_name<digests::sha2_512_224> : openssl_md_kind<false> {
    /** OpenSSL's name. */
    static constexpr char const* value = "SHA2-512/224";
};

/** SHA-512/256: "SHA2-512/256". */
template <>
struct openssl_md_name<digests::sha2_512_256> : openssl_md_kind<false> {
    /** OpenSSL's name. */
    static constexpr char const* value = "SHA2-512/256";
};

/** SHA3-224: "SHA3-224". */
template <>
struct openssl_md_name<digests::sha3_224> : openssl_md_kind<false> {
    /** OpenSSL's name. */
    static constexpr char const* value = "SHA3-224";
};

/** SHA3-256: "SHA3-256". */
template <>
struct openssl_md_name<digests::sha3_256> : openssl_md_kind<false> {
    /** OpenSSL's name. */
    static constexpr char const* value = "SHA3-256";
};

/** SHA3-384: "SHA3-384". */
template <>
struct openssl_md_name<digests::sha3_384> : openssl_md_kind<false> {
    /** OpenSSL's name. */
    static constexpr char const* value = "SHA3-384";
};

/** SHA3-512: "SHA3-512". */
template <>
struct openssl_md_name<digests::sha3_512> : openssl_md_kind<false> {
    /** OpenSSL's name. */
    static constexpr char const* value = "SHA3-512";
};

/** SHAKE128: "SHAKE-128". */
template <>
struct openssl_md_name<digests::shake_128> : openssl_md_kind<true> {
    /** OpenSSL's name. */
    static constexpr char const* value = "SHAKE-128";
};

/** SHAKE256: "SHAKE-256". */
template <>
struct openssl_md_name<digests::shake_256> : openssl_md_kind<true> {
    /** OpenSSL's name. */
    static constexpr char const* value = "SHAKE-256";
};

/** Keccak-224: "KECCAK-224". */
template <>
struct openssl_md_name<digests::keccak_224> : openssl_md_kind<false> {
    /** OpenSSL's name. */
    static constexpr char const* value = "KECCAK-224";
};

/** Keccak-256: "KECCAK-256". */
template <>
struct openssl_md_name<digests::keccak_256> : openssl_md_kind<false> {
    /** OpenSSL's name. */
    static constexpr char const* value = "KECCAK-256";
};

/** Keccak-384: "KECCAK-384". */
template <>
struct openssl_md_name<digests::keccak_384> : openssl_md_kind<false> {
    /** OpenSSL's name. */
    static constexpr char const* value = "KECCAK-384";
};

/** Keccak-512: "KECCAK-512". */
template <>
struct openssl_md_name<digests::keccak_512> : openssl_md_kind<false> {
    /** OpenSSL's name. */
    static constexpr char const* value = "KECCAK-512";
};

/** BLAKE2b (its size set at init): "BLAKE2B-512". */
template <>
struct openssl_md_name<digests::blake2b> : openssl_md_kind<false> {
    /** OpenSSL's name. */
    static constexpr char const* value = "BLAKE2B-512";
};

/** BLAKE2s-256: "BLAKE2S-256". */
template <>
struct openssl_md_name<digests::blake2s_256> : openssl_md_kind<false> {
    /** OpenSSL's name. */
    static constexpr char const* value = "BLAKE2S-256";
};

/** RIPEMD-160: "RIPEMD-160". */
template <>
struct openssl_md_name<digests::ripemd_160> : openssl_md_kind<false> {
    /** OpenSSL's name. */
    static constexpr char const* value = "RIPEMD-160";
};

/** MD5-SHA1: "MD5-SHA1". */
template <>
struct openssl_md_name<digests::md5_sha1> : openssl_md_kind<false> {
    /** OpenSSL's name. */
    static constexpr char const* value = "MD5-SHA1";
};

/** SM3: "SM3". */
template <>
struct openssl_md_name<digests::sm3> : openssl_md_kind<false> {
    /** OpenSSL's name. */
    static constexpr char const* value = "SM3";
};

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
struct openssl_digest_name<hmac_md5_128> : openssl_md_name<digests::md5> {};

/** HMAC-SHA-1. */
template <>
struct openssl_digest_name<hmac_sha1_160> : openssl_md_name<digests::sha1> {};

/** HMAC-SHA-224. */
template <>
struct openssl_digest_name<hmac_sha2_224> : openssl_md_name<digests::sha2_224> {};

/** HMAC-SHA-256. */
template <>
struct openssl_digest_name<hmac_sha2_256> : openssl_md_name<digests::sha2_256> {};

/** HMAC-SHA-384. */
template <>
struct openssl_digest_name<hmac_sha2_384> : openssl_md_name<digests::sha2_384> {};

/** HMAC-SHA-512. */
template <>
struct openssl_digest_name<hmac_sha2_512> : openssl_md_name<digests::sha2_512> {};

/** HMAC-SHA-512/224. */
template <>
struct openssl_digest_name<hmac_sha2_512_224> : openssl_md_name<digests::sha2_512_224> {};

/** HMAC-SHA-512/256. */
template <>
struct openssl_digest_name<hmac_sha2_512_256> : openssl_md_name<digests::sha2_512_256> {};

/** HMAC-SHA3-224. */
template <>
struct openssl_digest_name<hmac_sha3_224> : openssl_md_name<digests::sha3_224> {};

/** HMAC-SHA3-256. */
template <>
struct openssl_digest_name<hmac_sha3_256> : openssl_md_name<digests::sha3_256> {};

/** HMAC-SHA3-384. */
template <>
struct openssl_digest_name<hmac_sha3_384> : openssl_md_name<digests::sha3_384> {};

/** HMAC-SHA3-512. */
template <>
struct openssl_digest_name<hmac_sha3_512> : openssl_md_name<digests::sha3_512> {};

/** HMAC-RIPEMD-160. */
template <>
struct openssl_digest_name<hmac_ripemd_160> : openssl_md_name<digests::ripemd_160> {};

/** HMAC-BLAKE2b-512. */
template <>
struct openssl_digest_name<hmac_blake2b_512> : openssl_md_name<digests::blake2b> {};

/** HMAC-BLAKE2s-256. */
template <>
struct openssl_digest_name<hmac_blake2s_256> : openssl_md_name<digests::blake2s_256> {};

/**
 The digest name a call gives OpenSSL: `openssl_digest_name<Hmac>`'s, or, in a test that defines
 `WEBCPP_HASH_DETAIL_TEST_OPENSSL_DIGEST` (a string literal), that one, to provoke a failure.

 @tparam Hmac A Boost.Hash2 hmac over a digest.
 @return The name, for the parameter "digest".
*/
template <class Hmac>
constexpr char const* openssl_digest() noexcept {
    [[maybe_unused]] constexpr char const* digest_name = openssl_digest_name<Hmac>::value;
#ifdef WEBCPP_HASH_DETAIL_TEST_OPENSSL_DIGEST
    return WEBCPP_HASH_DETAIL_TEST_OPENSSL_DIGEST;
#else
    return digest_name;
#endif
}

/**
 The byte an empty input's parameter points at: OpenSSL refuses an octet string whose data is
 null, whatever its size.
*/
inline constexpr std::uint8_t openssl_empty = 0;

/**
 An octet-string parameter over `octet_bytes`, which OpenSSL only reads.

 @param param_name The parameter's name. @param octet_bytes Its value, possibly empty.
 @return The parameter.
*/
inline OSSL_PARAM openssl_octets(char const* param_name,
                                 std::span<std::uint8_t const> octet_bytes) noexcept {
    void* data_bytes =
        const_cast<std::uint8_t*>(octet_bytes.empty() ? &openssl_empty : octet_bytes.data());
    return OSSL_PARAM_construct_octet_string(param_name, data_bytes, octet_bytes.size());
}

/**
 A UTF-8 string parameter over `text_value`, which OpenSSL only reads.

 @param param_name The parameter's name. @param text_value Its value.
 @return The parameter.
*/
inline OSSL_PARAM openssl_text(char const* param_name, char const* text_value) noexcept {
    return OSSL_PARAM_construct_utf8_string(param_name, const_cast<char*>(text_value), 0);
}

/**
 An error of OpenSSL's that means that the memory a call needs cannot be had, beside an
 allocation's failure: its library and its reason. The default names none.
*/
struct openssl_memory_error {
    /** The library, `ERR_LIB_*`; 0 for none. */
    int library = 0;
    /** The reason within the library. */
    int reason = 0;
};

/**
 OpenSSL's answer to a call made since the caller's `ERR_set_mark()`, whose mark it pops with every
 error raised since, so that the thread's error queue is left as it was found: only an error
 raised since the mark is OpenSSL's answer, an older one is the caller's. A call during which
 OpenSSL raised an error failed, whatever its functions returned: OpenSSL's Argon2 leaves some of
 its allocations unchecked and returns success over a wrong tag when one fails.

 @param succeeded Whether OpenSSL's functions returned success.
 @param memory_error An error that means the memory cannot be had, beside an allocation's.
 @return Success when OpenSSL succeeded and raised nothing; `errc::not_enough_memory` when an error
 raised since the mark is an allocation's or `memory_error`; `error::backend_failure` otherwise.
*/
[[nodiscard]] inline boost::system::result<void> openssl_outcome(
    bool succeeded, openssl_memory_error memory_error = {}) noexcept {
    // NOLINTNEXTLINE(bugprone-signed-bitwise): OpenSSL's macro ORs signed constants
    constexpr int malloc_failure_reason = ERR_R_MALLOC_FAILURE;
    const bool raised = ERR_count_to_mark() > 0;
    bool is_out_of_memory = false;
    while (ERR_count_to_mark() > 0) {
        unsigned long const error_code = ERR_peek_last_error();
        is_out_of_memory =
            is_out_of_memory || ERR_GET_REASON(error_code) == malloc_failure_reason ||
            (memory_error.library != 0 && ERR_GET_LIB(error_code) == memory_error.library &&
             ERR_GET_REASON(error_code) == memory_error.reason);
        ERR_pop();
    }
    ERR_pop_to_mark();
    if (succeeded && !raised) {
        return {};
    }
    if (is_out_of_memory) {
        return boost::system::errc::make_error_code(boost::system::errc::not_enough_memory);
    }
    return error::backend_failure;
}

/**
 Fetches the KDF named `kdf_name`, makes a context, and derives `output_bytes` from `ossl_params`
 (spec section 3.4), freeing both; the thread's error queue is left as it was found.

 @param kdf_name OpenSSL's name of the KDF: "HKDF", "PBKDF2", "SCRYPT", "ARGON2D", "ARGON2I"
 or "ARGON2ID".
 @param output_bytes What is derived, its whole size.
 @param ossl_params The parameters, ending with `OSSL_PARAM_construct_end()`.
 @param memory_error An error of the KDF's that means the memory cannot be had.
 @return As @ref openssl_outcome.
*/
[[nodiscard]] inline boost::system::result<void> openssl_kdf(
    char const* kdf_name, std::span<std::uint8_t> output_bytes, std::span<OSSL_PARAM> ossl_params,
    openssl_memory_error memory_error = {}) noexcept {
    ERR_set_mark();
    EVP_KDF* kdf_algorithm = EVP_KDF_fetch(nullptr, kdf_name, nullptr);
    EVP_KDF_CTX* kdf_context = kdf_algorithm != nullptr ? EVP_KDF_CTX_new(kdf_algorithm) : nullptr;
    const bool derive_status =
        kdf_context != nullptr && EVP_KDF_derive(kdf_context, output_bytes.data(),
                                                 output_bytes.size(), ossl_params.data()) == 1;
    // The frees raise no error: the outcome read after them is the derivation's.
    EVP_KDF_CTX_free(kdf_context);
    EVP_KDF_free(kdf_algorithm);
    return openssl_outcome(derive_status, memory_error);
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

     @param salt_bytes The salt. @param ikm_bytes The input keying material.
     @return The PRK, or OpenSSL's failure.
    */
    [[nodiscard]] static boost::system::result<digest_type> extract(
        std::span<std::uint8_t const> salt_bytes,
        std::span<std::uint8_t const> ikm_bytes) noexcept {
        int hkdf_mode = extract_only;
        std::array<OSSL_PARAM, 5> ossl_params{
            openssl_text("digest", openssl_digest<Hmac>()),
            openssl_octets("key", ikm_bytes),
            openssl_octets("salt", salt_bytes),
            OSSL_PARAM_construct_int("mode", &hkdf_mode),
            OSSL_PARAM_construct_end(),
        };
        // The PRK is derived into the result returned, whose wiping is the caller's: one return of
        // that one object, so that it is constructed in the caller's slot and no copy is left here.
        boost::system::result<digest_type> prk_bytes{boost::system::in_place_value};
        digest_type& param_name = prk_bytes.unsafe_value();
        const auto derive_result = openssl_kdf(
            "HKDF", std::span<std::uint8_t>(param_name.data(), param_name.size()), ossl_params);
        if (!derive_result) {
            wipe_object(param_name);
            prk_bytes = derive_result.error();
        }
        return prk_bytes;
    }

    /**
     RFC 5869, 2.3, in expand-only mode.

     @param output_bytes The OKM, its size L. @param prk_bytes The PRK. @param info_bytes The info.
     @return Success, or OpenSSL's failure.
    */
    [[nodiscard]] static boost::system::result<void> expand(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> prk_bytes,
        std::span<std::uint8_t const> info_bytes) noexcept {
        int hkdf_mode = expand_only;
        std::array<OSSL_PARAM, 5> ossl_params{
            openssl_text("digest", openssl_digest<Hmac>()),
            openssl_octets("key", prk_bytes),
            openssl_octets("info", info_bytes),
            OSSL_PARAM_construct_int("mode", &hkdf_mode),
            OSSL_PARAM_construct_end(),
        };
        return openssl_kdf("HKDF", output_bytes, ossl_params);
    }

    /**
     RFC 5869, 2, in extract-and-expand mode: the PRK stays inside OpenSSL's context.

     @param output_bytes The OKM. @param salt_bytes The salt. @param ikm_bytes The input keying
     material.
     @param info_bytes The info.
     @return Success, or OpenSSL's failure.
    */
    [[nodiscard]] static boost::system::result<void> extract_and_expand(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> salt_bytes,
        std::span<std::uint8_t const> ikm_bytes,
        std::span<std::uint8_t const> info_bytes) noexcept {
        int hkdf_mode = both;
        std::array<OSSL_PARAM, 6> ossl_params{
            openssl_text("digest", openssl_digest<Hmac>()),
            openssl_octets("key", ikm_bytes),
            openssl_octets("salt", salt_bytes),
            openssl_octets("info", info_bytes),
            OSSL_PARAM_construct_int("mode", &hkdf_mode),
            OSSL_PARAM_construct_end(),
        };
        return openssl_kdf("HKDF", output_bytes, ossl_params);
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

     @param output_bytes DK, its size dkLen. @param password_bytes P. @param salt_bytes S.
     @param iteration_count c.
     @return Success, or OpenSSL's failure.
    */
    [[nodiscard]] static boost::system::result<void> derive(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> password_bytes,
        std::span<std::uint8_t const> salt_bytes, std::uint64_t iteration_count) noexcept {
        int pkcs5_status = 1;
        std::array<OSSL_PARAM, 6> ossl_params{
            openssl_text("digest", openssl_digest<Hmac>()),
            openssl_octets("pass", password_bytes),
            openssl_octets("salt", salt_bytes),
            OSSL_PARAM_construct_uint64("iter", &iteration_count),
            OSSL_PARAM_construct_int("pkcs5", &pkcs5_status),
            OSSL_PARAM_construct_end(),
        };
        return openssl_kdf("PBKDF2", output_bytes, ossl_params);
    }
};

/**
 The most memory OpenSSL's Argon2 takes, in KiB: m is a `uint32_t`, and the memory, m blocks of
 1 KiB, a `size_t` (4,194,303 KiB on wasm32, where a larger m overflows it).
*/
inline constexpr std::uint32_t openssl_argon2_max_memory_kib = static_cast<std::uint32_t>(
    std::min<std::uint64_t>(0xffffffffULL, std::numeric_limits<std::size_t>::max() / 1024));

/**
 One Argon2 of OpenSSL, version 0x13 (its default), with one thread: OpenSSL's Argon2 runs its
 lanes in turn with one thread, and builds without threads where webcpp builds it `no-threads`.
 OpenSSL copies the password, the salt, the secret and the associated data into its context, and
 clears each copy when the context is freed.

 @param kdf_name "ARGON2D", "ARGON2I" or "ARGON2ID".
 @param output_bytes The tag. @param password_bytes The password. @param salt_bytes The salt.
 @param parameters t, m in KiB, p, the secret and the associated data, within RFC 9106's
 bounds and `openssl_argon2_max_memory_kib`.
 @return Success; `errc::not_enough_memory` when the memory cannot be allocated (OpenSSL raises
 its allocation's error, then its own "invalid memory size"); `error::backend_failure` otherwise.
*/
[[nodiscard]] inline boost::system::result<void> openssl_argon2(
    char const* kdf_name, std::span<std::uint8_t> output_bytes,
    std::span<std::uint8_t const> password_bytes, std::span<std::uint8_t const> salt_bytes,
    argon2_parameters const& parameters) noexcept {
    std::uint32_t pass_count = parameters.passes;
    std::uint32_t memory_kib = parameters.memory_kib;
    std::uint32_t lane_count = parameters.lanes;
    std::uint32_t thread_count = 1;
    // An empty secret or associated data is hashed as OpenSSL hashes none: its length, 0, alone.
    std::array<OSSL_PARAM, 9> ossl_params{
        openssl_octets("pass", password_bytes),
        openssl_octets("salt", salt_bytes),
        openssl_octets("secret", parameters.secret),
        openssl_octets("ad", parameters.associated_data),
        OSSL_PARAM_construct_uint32("iter", &pass_count),
        OSSL_PARAM_construct_uint32("memcost", &memory_kib),
        OSSL_PARAM_construct_uint32("lanes", &lane_count),
        OSSL_PARAM_construct_uint32("threads", &thread_count),
        OSSL_PARAM_construct_end(),
    };
    return openssl_kdf(kdf_name, output_bytes, ossl_params);
}

/**
 OpenSSL's name of an Argon2 variant, its `value`.

 @tparam Variant `kdfs::argon2d`, `kdfs::argon2i` or `kdfs::argon2id`.
*/
template <class Variant>
struct openssl_argon2_name;

/** Argon2d: "ARGON2D". */
template <>
struct openssl_argon2_name<kdfs::argon2d> {
    /** The name. */
    static constexpr char const* value = "ARGON2D";
};

/** Argon2i: "ARGON2I". */
template <>
struct openssl_argon2_name<kdfs::argon2i> {
    /** The name. */
    static constexpr char const* value = "ARGON2I";
};

/** Argon2id: "ARGON2ID". */
template <>
struct openssl_argon2_name<kdfs::argon2id> {
    /** The name. */
    static constexpr char const* value = "ARGON2ID";
};

/**
 Argon2 of the variant `Variant` on backends::openssl, OpenSSL's "ARGON2D", "ARGON2I" or
 "ARGON2ID" with every parameter of RFC 9106 (the engine's interface: @ref argon2_engine).

 @tparam Variant `kdfs::argon2d`, `kdfs::argon2i` or `kdfs::argon2id`.
*/
template <class Variant>
struct openssl_argon2_engine {
    /** RFC 9106's bounds, but the memory: at most `openssl_argon2_max_memory_kib`. */
    static constexpr argon2_limits limits{
        .max_memory_kib = openssl_argon2_max_memory_kib,
    };

    /**
     RFC 9106, version 0x13.

     @param output_bytes The tag. @param password_bytes The password. @param salt_bytes The salt.
     @param parameters The costs, the lanes, the secret and the associated data.
     @return Success, `errc::not_enough_memory` or `error::backend_failure`.
    */
    [[nodiscard]] static boost::system::result<void> derive(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> password_bytes,
        std::span<std::uint8_t const> salt_bytes, argon2_parameters const& parameters) noexcept {
        return openssl_argon2(openssl_argon2_name<Variant>::value, output_bytes, password_bytes,
                              salt_bytes, parameters);
    }
};

/** `kdfs::argon2d` on backends::openssl: "ARGON2D". */
template <>
struct argon2_engine<backends::openssl, kdfs::argon2d> : openssl_argon2_engine<kdfs::argon2d> {};

/** `kdfs::argon2i` on backends::openssl: "ARGON2I". */
template <>
struct argon2_engine<backends::openssl, kdfs::argon2i> : openssl_argon2_engine<kdfs::argon2i> {};

/** `kdfs::argon2id` on backends::openssl: "ARGON2ID". */
template <>
struct argon2_engine<backends::openssl, kdfs::argon2id> : openssl_argon2_engine<kdfs::argon2id> {};

/**
 The function argon2id on backends::openssl: "ARGON2ID" with one lane, no secret and no associated
 data, the memory in bytes given to OpenSSL in KiB (the engine's interface: @ref argon2id_engine).
*/
template <>
struct argon2id_engine<backends::openssl> {
    /** OpenSSL's m of at most 2^32 - 1 KiB, in bytes, within a `size_t` (4 GiB less 1 KiB on
     * wasm32). */
    static constexpr argon2id_limits limits{
        .memory = std::uint64_t{openssl_argon2_max_memory_kib} * argon2id_memory_unit,
    };

    /**
     The tag.

     @param output_bytes The tag. @param password_bytes The password. @param salt_bytes The 16-byte
     salt.
     @param pass_count t, at most 2^32 - 1. @param memory_limit The memory in bytes, a multiple of
     1,024 within `limits`.
     @return Success, `errc::not_enough_memory` or `error::backend_failure`.
    */
    [[nodiscard]] static boost::system::result<void> derive(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> password_bytes,
        std::span<std::uint8_t const> salt_bytes, std::uint64_t pass_count,
        std::size_t memory_limit) noexcept {
        return openssl_argon2(
            openssl_argon2_name<kdfs::argon2id>::value, output_bytes, password_bytes, salt_bytes,
            {
                .passes = static_cast<std::uint32_t>(pass_count),
                .memory_kib = static_cast<std::uint32_t>(memory_limit / argon2id_memory_unit),
            });
    }
};

/**
 scrypt on backends::openssl: OpenSSL's "SCRYPT", whose memory limit, `maxmem_bytes`, 1,025 MiB by
 default, is set to its largest (OpenSSL takes `SIZE_MAX` for it), so that it refuses no cost
 RFC 7914 allows that the address space holds (the engine's interface: @ref scrypt_engine).
 OpenSSL copies the password and the salt; it clears the password's copy when the context is freed,
 not the salt's.
*/
template <>
struct scrypt_engine<backends::openssl> {
    /**
     No N of its own; r p below 2^24, since OpenSSL passes PBKDF2 128 r p bytes as an `int`
     (`scrypt_alg`).
    */
    static constexpr scrypt_limits limits{
        .n = no_limit,
        .rp = (std::uint64_t{1} << 24U) - 1,
    };

    /**
     RFC 7914. OpenSSL's "memory limit exceeded", once the guards have passed, means that 128 r
     (N + p + 2) bytes are more than a `size_t` holds: `not_enough_memory`, as an allocation's
     failure. The spec's guard sizes 128 r (N + p) bytes, so on wasm32 costs within 256 r bytes
     of a `size_t` pass it and answer `not_enough_memory` here, before OpenSSL allocates.

     @param output_bytes The derived key. @param password_bytes The password. @param salt_bytes The
     salt.
     @param cost_n N. @param block_size_r r. @param parallelism_p p.
     @return Success, `errc::not_enough_memory` or `error::backend_failure`.
    */
    [[nodiscard]] static boost::system::result<void> derive(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> password_bytes,
        std::span<std::uint8_t const> salt_bytes, std::uint64_t cost_n, std::uint32_t block_size_r,
        std::uint32_t parallelism_p) noexcept {
        std::uint64_t memory_limit = std::numeric_limits<std::uint64_t>::max();
        std::array<OSSL_PARAM, 7> ossl_params{
            openssl_octets("pass", password_bytes),
            openssl_octets("salt", salt_bytes),
            OSSL_PARAM_construct_uint64("n", &cost_n),
            OSSL_PARAM_construct_uint32("r", &block_size_r),
            OSSL_PARAM_construct_uint32("p", &parallelism_p),
            OSSL_PARAM_construct_uint64("maxmem_bytes", &memory_limit),
            OSSL_PARAM_construct_end(),
        };
        return openssl_kdf("SCRYPT", output_bytes, ossl_params,
                           {.library = ERR_LIB_EVP, .reason = EVP_R_MEMORY_LIMIT_EXCEEDED});
    }
};

/**
 The digest name a digest engine gives `EVP_MD_fetch`: `openssl_md_name<Digest>`'s, or, in a test
 that defines `WEBCPP_HASH_DETAIL_TEST_OPENSSL_DIGEST` (a string literal), that one, to provoke a
 failure, as @ref openssl_digest does for the key derivations.

 @tparam Digest A tag of `digests` that OpenSSL has.
 @return The name.
*/
template <class Digest>
constexpr char const* openssl_md() noexcept {
    [[maybe_unused]] constexpr char const* digest_name = openssl_md_name<Digest>::value;
#ifdef WEBCPP_HASH_DETAIL_TEST_OPENSSL_DIGEST
    return WEBCPP_HASH_DETAIL_TEST_OPENSSL_DIGEST;
#else
    return digest_name;
#endif
}

/**
 The state of a digest on backends::openssl: the `EVP_MD_CTX` it owns, null before `init` and
 once freed or moved from. Freeing it is `EVP_MD_CTX_free`, which OpenSSL documents as cleaning
 up the context and freeing it.
*/
class openssl_md_state {
public:
    /** No context. */
    openssl_md_state() noexcept = default;

    /**
     Takes the context of `moved_from`, which owns none after.

     @param moved_from The state moved from.
    */
    openssl_md_state(openssl_md_state&& moved_from) noexcept
        : context_(std::exchange(moved_from.context_, nullptr)) {}

    /**
     Frees this state's context and takes that of `moved_from`, which owns none after.

     @param moved_from The state moved from.
     @return This state.
    */
    openssl_md_state& operator=(openssl_md_state&& moved_from) noexcept {
        if (this != &moved_from) {
            reset();
            context_ = std::exchange(moved_from.context_, nullptr);
        }
        return *this;
    }

    /** Not copyable: one context, one owner. */
    openssl_md_state(openssl_md_state const&) = delete;
    /** Not copyable. @return Never. */
    openssl_md_state& operator=(openssl_md_state const&) = delete;

    /** Frees the context, if any. */
    ~openssl_md_state() { reset(); }

    /**
     The context, null when there is none.

     @return The context.
    */
    [[nodiscard]] EVP_MD_CTX* get() const noexcept { return context_; }

    /**
     Owns `context` from here on, freeing the one it held.

     @param context A context of `EVP_MD_CTX_new`, or null.
    */
    void adopt(EVP_MD_CTX* context) noexcept {
        reset();
        context_ = context;
    }

    /** Frees the context; a state without one is left as it is. */
    void reset() noexcept {
        EVP_MD_CTX_free(context_);
        context_ = nullptr;
    }

private:
    EVP_MD_CTX* context_ = nullptr;
};

/**
 A digest of `digests` on backends::openssl (its interface is @ref digest_engine), over the
 `EVP_MD` of OpenSSL 3.5.9 that @ref openssl_md_name names. `init` makes an `EVP_MD_CTX`
 (`EVP_MD_CTX_new`, through OpenSSL's allocator), fetches the digest (`EVP_MD_fetch`) and starts it
 (`EVP_DigestInit_ex2`, which keeps its own reference to the digest); `update` is
 `EVP_DigestUpdate`; `finish` is `EVP_DigestFinal_ex`, or `EVP_DigestFinalXOF` for an
 extendable-output function; `destroy` frees the context. Each call leaves the thread's error
 queue as it found it.

 It serves every output size the family accepts: a fixed-size digest's own (checked against
 OpenSSL's size of the context before `EVP_DigestFinal_ex` writes), any size of SHAKE.

 @tparam Digest A tag of `digests` that OpenSSL's default provider has.
*/
template <class Digest>
struct openssl_digest_engine : full_engine {
    /** The context, owned. */
    using state = openssl_md_state;

    /**
     Starts a hash: a new context, the digest fetched, `EVP_DigestInit_ex2` with no parameter
     (BLAKE2b's engine gives its size).

     @param hashed The state, which owns the context from here on, even when the start fails.
     @param options The digest's parameters.
     @return Success; `errc::not_enough_memory`; or `error::backend_failure`.
    */
    [[nodiscard]] static boost::system::result<void> init(
        state& hashed, digest_options<Digest> const& options) noexcept {
        ERR_set_mark();
        hashed.adopt(EVP_MD_CTX_new());
        EVP_MD* digest_algorithm = hashed.get() != nullptr
                                       ? EVP_MD_fetch(nullptr, openssl_md<Digest>(), nullptr)
                                       : nullptr;
        const bool started =
            digest_algorithm != nullptr && start(hashed.get(), digest_algorithm, options);
        // The context holds its own reference to the digest from EVP_DigestInit_ex2 on.
        EVP_MD_free(digest_algorithm);
        return openssl_outcome(started);
    }

    /**
     Absorbs `input`: `EVP_DigestUpdate`, which returns at once on an empty input.

     @param hashed The state. @param input The bytes.
     @return Success, or OpenSSL's failure.
    */
    [[nodiscard]] static boost::system::result<void> update(
        state& hashed, std::span<std::uint8_t const> input) noexcept {
        ERR_set_mark();
        return openssl_outcome(EVP_DigestUpdate(hashed.get(), input.data(), input.size()) == 1);
    }

    /**
     Writes the result, of `output.size()` bytes: `EVP_DigestFinalXOF` for an extendable-output
     function; else `EVP_DigestFinal_ex`, once OpenSSL's size of the context is seen to be the
     output's (the family's guards hold it to the digest's size, or BLAKE2b's option).

     @param hashed The state. @param output The digest.
     @return Success, or OpenSSL's failure.
    */
    [[nodiscard]] static boost::system::result<void> finish(
        state& hashed, std::span<std::uint8_t> output) noexcept {
        ERR_set_mark();
        bool finished = false;
        if constexpr (openssl_md_name<Digest>::xof) {
            finished = EVP_DigestFinalXOF(hashed.get(), output.data(), output.size()) == 1;
        } else {
            const int context_size = EVP_MD_CTX_get_size(hashed.get());
            finished = context_size > 0 &&
                       static_cast<std::size_t>(context_size) == output.size() &&
                       EVP_DigestFinal_ex(hashed.get(), output.data(), nullptr) == 1;
        }
        return openssl_outcome(finished);
    }

    /**
     Frees the context (`EVP_MD_CTX_free`); a second call does nothing.

     @param hashed The state.
    */
    static void destroy(state& hashed) noexcept { hashed.reset(); }

    /**
     The digest of `input` at once: `init`, `update` and `finish` on a context freed before the
     return.

     @param output The digest. @param input The bytes. @param options The digest's parameters.
     @return Success, or OpenSSL's failure.
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

private:
    // EVP_DigestInit_ex2 with the digest's parameters: none, or BLAKE2b's output size. Options is
    // a template parameter so that digest_options<digests::blake2b>, which digest.hpp defines after
    // this header, is read only when the engine is used.
    template <class Options>
    static bool start(EVP_MD_CTX* context, EVP_MD const* digest_algorithm,
                      Options const& options) noexcept {
        if constexpr (std::is_same_v<Digest, digests::blake2b>) {
            std::size_t output_size = options.output_size;
            std::array<OSSL_PARAM, 2> const size_params{
                OSSL_PARAM_construct_size_t("size", &output_size),
                OSSL_PARAM_construct_end(),
            };
            return EVP_DigestInit_ex2(context, digest_algorithm, size_params.data()) == 1;
        } else {
            static_cast<void>(options);
            return EVP_DigestInit_ex2(context, digest_algorithm, nullptr) == 1;
        }
    }
};

/** `digests::md5` on backends::openssl: "MD5". */
template <>
struct digest_engine<backends::openssl, digests::md5> : openssl_digest_engine<digests::md5> {};

/** `digests::sha1` on backends::openssl: "SHA1". */
template <>
struct digest_engine<backends::openssl, digests::sha1> : openssl_digest_engine<digests::sha1> {};

/** `digests::sha2_224` on backends::openssl: "SHA2-224". */
template <>
struct digest_engine<backends::openssl, digests::sha2_224>
    : openssl_digest_engine<digests::sha2_224> {};

/** `digests::sha2_256` on backends::openssl: "SHA2-256". */
template <>
struct digest_engine<backends::openssl, digests::sha2_256>
    : openssl_digest_engine<digests::sha2_256> {};

/** `digests::sha2_384` on backends::openssl: "SHA2-384". */
template <>
struct digest_engine<backends::openssl, digests::sha2_384>
    : openssl_digest_engine<digests::sha2_384> {};

/** `digests::sha2_512` on backends::openssl: "SHA2-512". */
template <>
struct digest_engine<backends::openssl, digests::sha2_512>
    : openssl_digest_engine<digests::sha2_512> {};

/** `digests::sha2_512_224` on backends::openssl: "SHA2-512/224". */
template <>
struct digest_engine<backends::openssl, digests::sha2_512_224>
    : openssl_digest_engine<digests::sha2_512_224> {};

/** `digests::sha2_512_256` on backends::openssl: "SHA2-512/256". */
template <>
struct digest_engine<backends::openssl, digests::sha2_512_256>
    : openssl_digest_engine<digests::sha2_512_256> {};

/** `digests::sha3_224` on backends::openssl: "SHA3-224". */
template <>
struct digest_engine<backends::openssl, digests::sha3_224>
    : openssl_digest_engine<digests::sha3_224> {};

/** `digests::sha3_256` on backends::openssl: "SHA3-256". */
template <>
struct digest_engine<backends::openssl, digests::sha3_256>
    : openssl_digest_engine<digests::sha3_256> {};

/** `digests::sha3_384` on backends::openssl: "SHA3-384". */
template <>
struct digest_engine<backends::openssl, digests::sha3_384>
    : openssl_digest_engine<digests::sha3_384> {};

/** `digests::sha3_512` on backends::openssl: "SHA3-512". */
template <>
struct digest_engine<backends::openssl, digests::sha3_512>
    : openssl_digest_engine<digests::sha3_512> {};

/** `digests::shake_128` on backends::openssl: "SHAKE-128" with `EVP_DigestFinalXOF`, any output
 * size. */
template <>
struct digest_engine<backends::openssl, digests::shake_128>
    : openssl_digest_engine<digests::shake_128> {};

/** `digests::shake_256` on backends::openssl: "SHAKE-256" with `EVP_DigestFinalXOF`, any output
 * size. */
template <>
struct digest_engine<backends::openssl, digests::shake_256>
    : openssl_digest_engine<digests::shake_256> {};

/** `digests::keccak_224` on backends::openssl: "KECCAK-224", the original padding. */
template <>
struct digest_engine<backends::openssl, digests::keccak_224>
    : openssl_digest_engine<digests::keccak_224> {};

/** `digests::keccak_256` on backends::openssl: "KECCAK-256", the original padding (Ethereum's
 * hash). */
template <>
struct digest_engine<backends::openssl, digests::keccak_256>
    : openssl_digest_engine<digests::keccak_256> {};

/** `digests::keccak_384` on backends::openssl: "KECCAK-384", the original padding. */
template <>
struct digest_engine<backends::openssl, digests::keccak_384>
    : openssl_digest_engine<digests::keccak_384> {};

/** `digests::keccak_512` on backends::openssl: "KECCAK-512", the original padding. */
template <>
struct digest_engine<backends::openssl, digests::keccak_512>
    : openssl_digest_engine<digests::keccak_512> {};

/** `digests::blake2s_256` on backends::openssl: "BLAKE2S-256". */
template <>
struct digest_engine<backends::openssl, digests::blake2s_256>
    : openssl_digest_engine<digests::blake2s_256> {};

/** `digests::ripemd_160` on backends::openssl: "RIPEMD-160". */
template <>
struct digest_engine<backends::openssl, digests::ripemd_160>
    : openssl_digest_engine<digests::ripemd_160> {};

/** `digests::md5_sha1` on backends::openssl: "MD5-SHA1", MD5 then SHA-1 of the same input (TLS 1.0
 * and 1.1). */
template <>
struct digest_engine<backends::openssl, digests::md5_sha1>
    : openssl_digest_engine<digests::md5_sha1> {};

/** `digests::sm3` on backends::openssl: "SM3", GB/T 32905-2016. */
template <>
struct digest_engine<backends::openssl, digests::sm3> : openssl_digest_engine<digests::sm3> {};

/**
 `digests::blake2b` on backends::openssl, OpenSSL's "BLAKE2B-512" with its parameter "size", in
 part: unkeyed BLAKE2b at every output size from 1 to 64 bytes. A key, a salt or a
 personalisation is `unsupported_by_backend` (ruling R42): OpenSSL's BLAKE2B-512 digest takes
 none of them, and its keyed BLAKE2b is the MAC "BLAKE2BMAC", `macs::blake2b_mac`'s.
*/
template <>
struct digest_engine<backends::openssl, digests::blake2b>
    : openssl_digest_engine<digests::blake2b> {
    /**
     Whether OpenSSL's BLAKE2B-512 digest computes these options: no key, no salt, no
     personalisation. A template, so that it reads `digest_options<digests::blake2b>`, which
     digest.hpp defines after this header.

     @param options The options. @return Whether the options are unkeyed BLAKE2b's.
    */
    template <class Options>
    static constexpr bool accepts(Options const& options) noexcept {
        return options.key.empty() && options.salt.empty() && options.personalisation.empty();
    }
};

/**
 OpenSSL's name of a tag of `macs`, its `value`: the first of the names OpenSSL 3.5.9's default
 provider gives the MAC (`PROV_NAMES_*`), which `EVP_MAC_fetch` takes. Declared for every tag,
 defined for each tag backends::openssl has.

 @tparam Mac A tag of `macs`.
*/
template <class Mac>
struct openssl_mac_name;

/** HMAC over any digest: "HMAC", its digest the parameter "digest". */
template <class Digest>
struct openssl_mac_name<macs::hmac<Digest>> {
    /** OpenSSL's name. */
    static constexpr char const* value = "HMAC";
};

/** KMAC128: "KMAC-128". */
template <>
struct openssl_mac_name<macs::kmac_128> {
    /** OpenSSL's name. */
    static constexpr char const* value = "KMAC-128";
};

/** KMAC256: "KMAC-256". */
template <>
struct openssl_mac_name<macs::kmac_256> {
    /** OpenSSL's name. */
    static constexpr char const* value = "KMAC-256";
};

/** SipHash-2-4 with an 8-byte tag: "SIPHASH" (2 and 4 rounds by default). */
template <>
struct openssl_mac_name<macs::siphash_2_4> {
    /** OpenSSL's name. */
    static constexpr char const* value = "SIPHASH";
};

/** SipHash-2-4 with a 16-byte tag: "SIPHASH" with its parameter "size" at 16. */
template <>
struct openssl_mac_name<macs::siphash_2_4x> {
    /** OpenSSL's name. */
    static constexpr char const* value = "SIPHASH";
};

/** BLAKE2b keyed: "BLAKE2BMAC". */
template <>
struct openssl_mac_name<macs::blake2b_mac> {
    /** OpenSSL's name. */
    static constexpr char const* value = "BLAKE2BMAC";
};

/** BLAKE2s keyed: "BLAKE2SMAC". */
template <>
struct openssl_mac_name<macs::blake2s_mac> {
    /** OpenSSL's name. */
    static constexpr char const* value = "BLAKE2SMAC";
};

/**
 Fetches the MAC named `mac_name`, makes a context (`EVP_MAC_CTX_new`, through OpenSSL's
 allocator), and computes the tag of `input` under `key` into `output` with `ossl_params`:
 `EVP_MAC_init`, `EVP_MAC_update`, then `EVP_MAC_final` once OpenSSL's size of the tag is seen to
 be the output's; frees both before it returns. The thread's error queue is left as it was found.

 @param mac_name OpenSSL's name of the MAC.
 @param output The tag, its whole size. @param key The key, possibly empty (HMAC's).
 @param input The message. @param ossl_params The parameters, ending with
 `OSSL_PARAM_construct_end()`, which `EVP_MAC_init` sets before the key.
 @return Success; `errc::not_enough_memory` when the last error OpenSSL raised is an allocation's;
 `error::backend_failure` for any other failure.
*/
[[nodiscard]] inline boost::system::result<void> openssl_mac(
    char const* mac_name, std::span<std::uint8_t> output, std::span<std::uint8_t const> key,
    std::span<std::uint8_t const> input, OSSL_PARAM const* ossl_params) noexcept {
    ERR_set_mark();
    EVP_MAC* mac_algorithm = EVP_MAC_fetch(nullptr, mac_name, nullptr);
    EVP_MAC_CTX* mac_context = mac_algorithm != nullptr ? EVP_MAC_CTX_new(mac_algorithm) : nullptr;
    std::size_t written = 0;
    // A key's or an input's pointer is never null: OpenSSL takes a null key for "no key given".
    const bool computed = mac_context != nullptr &&
                          EVP_MAC_init(mac_context, nonnull(key), key.size(), ossl_params) == 1 &&
                          EVP_MAC_update(mac_context, nonnull(input), input.size()) == 1 &&
                          EVP_MAC_CTX_get_mac_size(mac_context) == output.size() &&
                          EVP_MAC_final(mac_context, output.data(), &written, output.size()) == 1 &&
                          written == output.size();
    // The frees raise no error: the outcome read after them is the computation's.
    EVP_MAC_CTX_free(mac_context);
    EVP_MAC_free(mac_algorithm);
    return openssl_outcome(computed);
}

/**
 HMAC over `Digest` on backends::openssl, OpenSSL's "HMAC" with the parameter "digest" that
 @ref openssl_md names (its interface is @ref mac_engine). OpenSSL writes the whole HMAC, which a
 shorter tag takes the start of (RFC 2104, section 5), the rest wiped. OpenSSL takes the key's
 length as an `int` (`HMAC_Init_ex`): a key of more than `INT_MAX` bytes is
 `unsupported_by_backend`.

 @tparam Digest A tag of `digests` of a fixed size that OpenSSL's default provider has.
*/
template <class Digest>
struct openssl_hmac_engine : full_engine {
    /**
     Whether OpenSSL takes a key of `key_size` bytes: at most `INT_MAX`.

     @param key_size The key's size. @return Whether it is taken.
    */
    template <class Options>
    static constexpr bool accepts(Options const& /*options*/, std::size_t key_size,
                                  std::size_t /*output_size*/) noexcept {
        return !exceeds(key_size, openssl_int_max);
    }

    /**
     The tag of `input` under `key`, the HMAC cut to `output.size()` bytes.

     @param output The tag. @param key The key. @param input The message.
     @return Success, or OpenSSL's failure.
    */
    template <class Options>
    [[nodiscard]] static boost::system::result<void> compute(std::span<std::uint8_t> output,
                                                             std::span<std::uint8_t const> key,
                                                             std::span<std::uint8_t const> input,
                                                             Options const& /*options*/) noexcept {
        constexpr std::uint64_t digest_size = mac_traits<macs::hmac<Digest>>::max_output;
        static_assert(digest_size <= EVP_MAX_MD_SIZE);
        std::array<OSSL_PARAM, 2> ossl_params{
            openssl_text("digest", openssl_md<Digest>()),
            OSSL_PARAM_construct_end(),
        };
        std::array<std::uint8_t, EVP_MAX_MD_SIZE> whole{};
        auto const tag = std::span(whole).first(digest_size);
        auto computed = openssl_mac("HMAC", tag, key, input, ossl_params.data());
        if (computed) {
            std::copy_n(tag.begin(), output.size(), output.begin());
        }
        wipe_object(whole);
        return computed;
    }
};

/**
 KMAC128 or KMAC256 on backends::openssl, OpenSSL's "KMAC-128" or "KMAC-256" with the
 parameters "size" (the tag's), "xof" and "custom" (the customisation); its interface is @ref
 mac_engine. Its limits are narrower than SP 800-185's (`providers/implementations/macs/
 kmac_prov.c`): a key of 4 to 512 bytes, a customisation of at most 512 bytes and a tag of at
 most 2,097,151 bytes (`0xFFFFFF / 8`, in either form); `mac` answers any other
 `unsupported_by_backend` (ruling R41).

 @tparam Mac `macs::kmac_128` or `macs::kmac_256`.
*/
template <class Mac>
struct openssl_kmac_engine : full_engine {
    /** OpenSSL's shortest key, `KMAC_MIN_KEY`. */
    static constexpr std::size_t min_key = 4;
    /** OpenSSL's longest key, `KMAC_MAX_KEY`. */
    static constexpr std::size_t max_key = 512;
    /** OpenSSL's longest customisation, `KMAC_MAX_CUSTOM`. */
    static constexpr std::size_t max_customisation = 512;
    /** OpenSSL's longest tag, `KMAC_MAX_OUTPUT_LEN`: 0xFFFFFF bits, in bytes. */
    static constexpr std::size_t max_tag = 0xFFFFFF / 8;

    /**
     Whether OpenSSL takes these options, key size and tag size. A template, so that it reads
     `mac_options<Mac>`, which mac.hpp defines after this header.

     @param options The customisation and the form. @param key_size The key's size.
     @param output_size The tag's size. @return Whether OpenSSL takes them.
    */
    template <class Options>
    static constexpr bool accepts(Options const& options, std::size_t key_size,
                                  std::size_t output_size) noexcept {
        return key_size >= min_key && key_size <= max_key &&
               options.customisation.size() <= max_customisation && output_size <= max_tag;
    }

    /**
     The tag of `input` under `key`, of `output.size()` bytes, in the form the options choose.

     @param output The tag. @param key The key. @param input The message.
     @param options The customisation and the form.
     @return Success, or OpenSSL's failure.
    */
    template <class Options>
    [[nodiscard]] static boost::system::result<void> compute(std::span<std::uint8_t> output,
                                                             std::span<std::uint8_t const> key,
                                                             std::span<std::uint8_t const> input,
                                                             Options const& options) noexcept {
        std::size_t tag_size = output.size();
        int xof_form = options.xof ? 1 : 0;
        std::array<OSSL_PARAM, 4> ossl_params{
            OSSL_PARAM_construct_size_t("size", &tag_size),
            OSSL_PARAM_construct_int("xof", &xof_form),
            openssl_octets("custom", options.customisation),
            OSSL_PARAM_construct_end(),
        };
        return openssl_mac(openssl_mac_name<Mac>::value, output, key, input, ossl_params.data());
    }
};

/**
 A MAC of backends::openssl whose one parameter is the tag's size, "size", whose interface is
 @ref mac_engine. It serves SipHash ("SIPHASH", 8 or 16 bytes, 2 and 4 rounds, OpenSSL's
 defaults) and keyed BLAKE2 ("BLAKE2BMAC", "BLAKE2SMAC", 1 to 64 or 32 bytes). Every key and tag
 size the family's guards accept is OpenSSL's.

 @tparam Mac `macs::siphash_2_4`, `siphash_2_4x`, `blake2b_mac` or `blake2s_mac`.
*/
template <class Mac>
struct openssl_sized_mac_engine : full_engine {
    /**
     The tag of `input` under `key`, of `output.size()` bytes.

     @param output The tag. @param key The key. @param input The message.
     @return Success, or OpenSSL's failure.
    */
    template <class Options>
    [[nodiscard]] static boost::system::result<void> compute(std::span<std::uint8_t> output,
                                                             std::span<std::uint8_t const> key,
                                                             std::span<std::uint8_t const> input,
                                                             Options const& /*options*/) noexcept {
        std::size_t tag_size = output.size();
        std::array<OSSL_PARAM, 2> ossl_params{
            OSSL_PARAM_construct_size_t("size", &tag_size),
            OSSL_PARAM_construct_end(),
        };
        return openssl_mac(openssl_mac_name<Mac>::value, output, key, input, ossl_params.data());
    }
};

/** `macs::hmac<digests::md5>` on backends::openssl: "HMAC" over "MD5". */
template <>
struct mac_engine<backends::openssl, macs::hmac<digests::md5>> : openssl_hmac_engine<digests::md5> {
};

/** `macs::hmac<digests::sha1>` on backends::openssl: "HMAC" over "SHA1". */
template <>
struct mac_engine<backends::openssl, macs::hmac<digests::sha1>>
    : openssl_hmac_engine<digests::sha1> {};

/** `macs::hmac<digests::sha2_224>` on backends::openssl: "HMAC" over "SHA2-224". */
template <>
struct mac_engine<backends::openssl, macs::hmac<digests::sha2_224>>
    : openssl_hmac_engine<digests::sha2_224> {};

/** `macs::hmac<digests::sha2_256>` on backends::openssl: "HMAC" over "SHA2-256". */
template <>
struct mac_engine<backends::openssl, macs::hmac<digests::sha2_256>>
    : openssl_hmac_engine<digests::sha2_256> {};

/** `macs::hmac<digests::sha2_384>` on backends::openssl: "HMAC" over "SHA2-384". */
template <>
struct mac_engine<backends::openssl, macs::hmac<digests::sha2_384>>
    : openssl_hmac_engine<digests::sha2_384> {};

/** `macs::hmac<digests::sha2_512>` on backends::openssl: "HMAC" over "SHA2-512". */
template <>
struct mac_engine<backends::openssl, macs::hmac<digests::sha2_512>>
    : openssl_hmac_engine<digests::sha2_512> {};

/** `macs::hmac<digests::sha2_512_224>` on backends::openssl: "HMAC" over "SHA2-512/224". */
template <>
struct mac_engine<backends::openssl, macs::hmac<digests::sha2_512_224>>
    : openssl_hmac_engine<digests::sha2_512_224> {};

/** `macs::hmac<digests::sha2_512_256>` on backends::openssl: "HMAC" over "SHA2-512/256". */
template <>
struct mac_engine<backends::openssl, macs::hmac<digests::sha2_512_256>>
    : openssl_hmac_engine<digests::sha2_512_256> {};

/** `macs::hmac<digests::sha3_224>` on backends::openssl: "HMAC" over "SHA3-224". */
template <>
struct mac_engine<backends::openssl, macs::hmac<digests::sha3_224>>
    : openssl_hmac_engine<digests::sha3_224> {};

/** `macs::hmac<digests::sha3_256>` on backends::openssl: "HMAC" over "SHA3-256". */
template <>
struct mac_engine<backends::openssl, macs::hmac<digests::sha3_256>>
    : openssl_hmac_engine<digests::sha3_256> {};

/** `macs::hmac<digests::sha3_384>` on backends::openssl: "HMAC" over "SHA3-384". */
template <>
struct mac_engine<backends::openssl, macs::hmac<digests::sha3_384>>
    : openssl_hmac_engine<digests::sha3_384> {};

/** `macs::hmac<digests::sha3_512>` on backends::openssl: "HMAC" over "SHA3-512". */
template <>
struct mac_engine<backends::openssl, macs::hmac<digests::sha3_512>>
    : openssl_hmac_engine<digests::sha3_512> {};

/** `macs::hmac<digests::keccak_224>` on backends::openssl: "HMAC" over "KECCAK-224". */
template <>
struct mac_engine<backends::openssl, macs::hmac<digests::keccak_224>>
    : openssl_hmac_engine<digests::keccak_224> {};

/** `macs::hmac<digests::keccak_256>` on backends::openssl: "HMAC" over "KECCAK-256". */
template <>
struct mac_engine<backends::openssl, macs::hmac<digests::keccak_256>>
    : openssl_hmac_engine<digests::keccak_256> {};

/** `macs::hmac<digests::keccak_384>` on backends::openssl: "HMAC" over "KECCAK-384". */
template <>
struct mac_engine<backends::openssl, macs::hmac<digests::keccak_384>>
    : openssl_hmac_engine<digests::keccak_384> {};

/** `macs::hmac<digests::keccak_512>` on backends::openssl: "HMAC" over "KECCAK-512". */
template <>
struct mac_engine<backends::openssl, macs::hmac<digests::keccak_512>>
    : openssl_hmac_engine<digests::keccak_512> {};

/** `macs::hmac<digests::ripemd_160>` on backends::openssl: "HMAC" over "RIPEMD-160". */
template <>
struct mac_engine<backends::openssl, macs::hmac<digests::ripemd_160>>
    : openssl_hmac_engine<digests::ripemd_160> {};

/** `macs::hmac<digests::blake2b>` on backends::openssl: "HMAC" over "BLAKE2B-512" (64 bytes). */
template <>
struct mac_engine<backends::openssl, macs::hmac<digests::blake2b>>
    : openssl_hmac_engine<digests::blake2b> {};

/** `macs::hmac<digests::blake2s_256>` on backends::openssl: "HMAC" over "BLAKE2S-256". */
template <>
struct mac_engine<backends::openssl, macs::hmac<digests::blake2s_256>>
    : openssl_hmac_engine<digests::blake2s_256> {};

/** `macs::hmac<digests::sm3>` on backends::openssl: "HMAC" over "SM3". */
template <>
struct mac_engine<backends::openssl, macs::hmac<digests::sm3>> : openssl_hmac_engine<digests::sm3> {
};

/** `macs::kmac_128` on backends::openssl: "KMAC-128" and its XOF form. */
template <>
struct mac_engine<backends::openssl, macs::kmac_128> : openssl_kmac_engine<macs::kmac_128> {};

/** `macs::kmac_256` on backends::openssl: "KMAC-256" and its XOF form. */
template <>
struct mac_engine<backends::openssl, macs::kmac_256> : openssl_kmac_engine<macs::kmac_256> {};

/** `macs::siphash_2_4` on backends::openssl: "SIPHASH" at 8 bytes. */
template <>
struct mac_engine<backends::openssl, macs::siphash_2_4>
    : openssl_sized_mac_engine<macs::siphash_2_4> {};

/** `macs::siphash_2_4x` on backends::openssl: "SIPHASH" at 16 bytes. */
template <>
struct mac_engine<backends::openssl, macs::siphash_2_4x>
    : openssl_sized_mac_engine<macs::siphash_2_4x> {};

/** `macs::blake2b_mac` on backends::openssl: "BLAKE2BMAC", a key and a tag of 1 to 64 bytes. */
template <>
struct mac_engine<backends::openssl, macs::blake2b_mac>
    : openssl_sized_mac_engine<macs::blake2b_mac> {};

/** `macs::blake2s_mac` on backends::openssl: "BLAKE2SMAC", a key and a tag of 1 to 32 bytes. */
template <>
struct mac_engine<backends::openssl, macs::blake2s_mac>
    : openssl_sized_mac_engine<macs::blake2s_mac> {};

/**
 The longest secret, info and output of OpenSSL's "SSKDF" and "X963KDF", 2^30 bytes
 (`SSKDF_MAX_INLEN` in `providers/implementations/kdfs/sskdf.c`).
*/
inline constexpr std::uint64_t openssl_sskdf_max_size = std::uint64_t{1} << 30U;

/**
 SP 800-108's KBKDF in counter mode on backends::openssl, OpenSSL's "KBKDF" with the MAC "HMAC"
 (the engine's interface: @ref kbkdf_engine). The label is OpenSSL's "salt", the context its
 "info", the counter's width its "r", and the separator and L its "use-separator" and "use-l".
 OpenSSL's HMAC takes the key's length as an `int` (`HMAC_Init_ex`): a longer key is refused
 before the call.

 @tparam Hmac A Boost.Hash2 hmac: an alias of `hmac.hpp` but `hmac_ripemd_128`, refused otherwise.
*/
template <class Hmac>
struct kbkdf_engine<backends::openssl, Hmac> {
    static_assert(openssl_hmac_v<Hmac>,
                  "webcpp::hash: backends::openssl has kbkdf over the hmacs of hmac.hpp alone, "
                  "hmac_ripemd_128 excepted, and no other backend has kbkdf.");

    /** HMAC's key length is an `int` in OpenSSL. */
    static constexpr kdf_standard_limits limits{.max_key = openssl_int_max};

    /**
     SP 800-108r1, section 4.1.

     @param output_bytes K_OUT, its size L. @param key_bytes K_IN.
     @param options The label, the context, r, and whether the separator and L are written.
     @return Success, or OpenSSL's failure.
    */
    [[nodiscard]] static boost::system::result<void> derive(std::span<std::uint8_t> output_bytes,
                                                            std::span<std::uint8_t const> key_bytes,
                                                            kbkdf_options const& options) noexcept {
        if constexpr (!openssl_hmac_v<Hmac>) {
            return error::backend_failure;  // unreachable: the refusal has stopped the build
        } else {
            int counter_bits = static_cast<int>(options.counter_bits);
            int use_separator = options.separator ? 1 : 0;
            int use_length = options.length ? 1 : 0;
            std::array<OSSL_PARAM, 10> ossl_params{
                openssl_text("mode", "counter"),
                openssl_text("mac", "HMAC"),
                openssl_text("digest", openssl_digest<Hmac>()),
                openssl_octets("key", key_bytes),
                openssl_octets("salt", options.label),
                openssl_octets("info", options.context),
                OSSL_PARAM_construct_int("r", &counter_bits),
                OSSL_PARAM_construct_int("use-separator", &use_separator),
                OSSL_PARAM_construct_int("use-l", &use_length),
                OSSL_PARAM_construct_end(),
            };
            return openssl_kdf("KBKDF", output_bytes, ossl_params);
        }
    }
};

/**
 What OpenSSL's "SSKDF" and "X963KDF" share: the digest by name, the secret, the info, and
 `SSKDF_MAX_INLEN` on each length.

 @tparam Digest A digest of the standard, which `kdf_standards.hpp` has checked.
*/
template <class Digest>
struct openssl_digest_kdf_engine {
    /** OpenSSL's 2^30 bytes on the secret, the info and the output. */
    static constexpr kdf_standard_limits limits{
        .max_key = openssl_sskdf_max_size,
        .max_info = openssl_sskdf_max_size,
        .max_output = openssl_sskdf_max_size,
    };

    /**
     The KDF `kdf_name` over `Digest`.

     @param kdf_name "SSKDF" or "X963KDF". @param output_bytes The output, its whole size.
     @param secret_bytes Z. @param info_bytes FixedInfo or SharedInfo.
     @return Success, or OpenSSL's failure.
    */
    [[nodiscard]] static boost::system::result<void> derive_with(
        char const* kdf_name, std::span<std::uint8_t> output_bytes,
        std::span<std::uint8_t const> secret_bytes,
        std::span<std::uint8_t const> info_bytes) noexcept {
        std::array<OSSL_PARAM, 4> ossl_params{
            openssl_text("digest", openssl_md_name<Digest>::value),
            openssl_octets("secret", secret_bytes),
            openssl_octets("info", info_bytes),
            OSSL_PARAM_construct_end(),
        };
        return openssl_kdf(kdf_name, output_bytes, ossl_params);
    }
};

/**
 SP 800-56C's one-step KDF, hash form, on backends::openssl: OpenSSL's "SSKDF" with a digest and
 no MAC (the engine's interface: @ref sskdf_engine).

 @tparam Digest A digest of SP 800-56C.
*/
template <class Digest>
struct sskdf_engine<backends::openssl, Digest> : openssl_digest_kdf_engine<Digest> {
    /**
     SP 800-56C Rev. 2, section 4.1.

     @param output_bytes The output. @param secret_bytes Z. @param fixed_info_bytes FixedInfo.
     @return Success, or OpenSSL's failure.
    */
    [[nodiscard]] static boost::system::result<void> derive(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> secret_bytes,
        std::span<std::uint8_t const> fixed_info_bytes) noexcept {
        return openssl_digest_kdf_engine<Digest>::derive_with("SSKDF", output_bytes, secret_bytes,
                                                              fixed_info_bytes);
    }
};

/**
 ANSI X9.63's KDF on backends::openssl: OpenSSL's "X963KDF" (the engine's interface: @ref
 x963kdf_engine).

 @tparam Digest A digest of FIPS 180-4.
*/
template <class Digest>
struct x963kdf_engine<backends::openssl, Digest> : openssl_digest_kdf_engine<Digest> {
    /**
     ANSI X9.63-2011, section 5.6.3.

     @param output_bytes The output. @param secret_bytes Z. @param shared_info_bytes SharedInfo.
     @return Success, or OpenSSL's failure.
    */
    [[nodiscard]] static boost::system::result<void> derive(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> secret_bytes,
        std::span<std::uint8_t const> shared_info_bytes) noexcept {
        return openssl_digest_kdf_engine<Digest>::derive_with("X963KDF", output_bytes, secret_bytes,
                                                              shared_info_bytes);
    }
};

}  // namespace webcpp::hash::detail

#endif  // WEBCPP_HASH_HAS_OPENSSL

#endif  // WEBCPP_HASH_BACKENDS_OPENSSL_HPP
