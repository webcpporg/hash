// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `backends::bearssl`: HKDF (RFC 5869) over BearSSL's `br_hkdf_*`, on every target, for six hmacs:
 `hmac_md5_128`, `hmac_sha1_160`, `hmac_sha2_224`, `hmac_sha2_256`, `hmac_sha2_384` and
 `hmac_sha2_512`. A program links it with `/third_party//bearssl`, webcpp::crypto's BearSSL, the
 one copy whichever library names it (spec section 5.5).

 BearSSL has `hkdf` alone: its context keeps the pseudorandom key and takes none in, so that
 `hkdf_extract` and `hkdf_expand` refuse at compile time, as `pbkdf2` does (spec section 3.3).
 Each call wipes BearSSL's context before it returns (spec section 6.1); BearSSL's own
 temporaries on its stack (the PRK of `br_hkdf_flip`, the padded keys of its HMAC) are not
 reached.
*/
#ifndef WEBCPP_HASH_BACKENDS_BEARSSL_HPP
#define WEBCPP_HASH_BACKENDS_BEARSSL_HPP

#include <webcpp/hash/config.hpp>

#ifndef WEBCPP_HASH_HAS_BEARSSL
// clang-format off
#error "webcpp::hash: backends::bearssl needs BearSSL. Add /third_party//bearssl to the program's Jamfile: exe app : app.cpp /webcpp/hash//hash /third_party//bearssl ;"
// clang-format on
#else

#include <webcpp/hash/detail/canary.h>
#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/detail/wipe.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hmac.hpp>

#include <boost/system/result.hpp>

#include <bearssl_hash.h>
#include <bearssl_kdf.h>

#include <cstddef>
#include <cstdint>
#include <span>

#ifdef WEBCPP_HASH_BEARSSL_CANARY_CONFIGURATION
/** The configuration the canary names: a test's, here. */
#define WEBCPP_HASH_DETAIL_BEARSSL_CONFIGURATION WEBCPP_HASH_BEARSSL_CANARY_CONFIGURATION
#elif defined(_WIN32)
/** The configuration the canary names: on Windows, BearSSL built with every seeder off. */
#define WEBCPP_HASH_DETAIL_BEARSSL_CONFIGURATION noseeder
#else
/** The configuration the canary names: elsewhere, BearSSL with its one system seeder. */
#define WEBCPP_HASH_DETAIL_BEARSSL_CONFIGURATION getentropy  // lint-world: a name, no call
#endif
/** The canary's name, which every function of this header that calls BearSSL reads (spec 5.4). */
#define WEBCPP_HASH_DETAIL_BEARSSL_CANARY                          \
    WEBCPP_HASH_DETAIL_CANARY(bearssl, WEBCPP_HASH_BEARSSL_COMMIT, \
                              WEBCPP_HASH_DETAIL_BEARSSL_CONFIGURATION)

#ifdef _MSC_VER
#pragma detect_mismatch(                                                   \
    "webcpp_hash_backend_bearssl",                                         \
    WEBCPP_HASH_DETAIL_MISMATCH_VALUE(bearssl, WEBCPP_HASH_BEARSSL_COMMIT, \
                                      WEBCPP_HASH_DETAIL_BEARSSL_CONFIGURATION))
#endif

// A declaration: src/canary_bearssl.c defines it, constant, in /third_party//bearssl.
// NOLINTNEXTLINE(bugprone-dynamic-static-initializers)
extern "C" const char WEBCPP_HASH_DETAIL_BEARSSL_CANARY;

namespace webcpp::hash::backends {

/** BearSSL's `br_hkdf_*`: `hkdf` alone, over six hmacs, on every target. */
struct bearssl {};

}  // namespace webcpp::hash::backends

namespace webcpp::hash::detail {

/**
 Reads BearSSL's canary of webcpp::hash with a volatile load, which no linker can drop: a program
 built without `/third_party//bearssl`, or with one of another commit or configuration, fails to
 link, naming the canary (spec section 5.4).
*/
inline void touch_bearssl_canary() noexcept {
    // The volatile glvalue is converted to a value: a discarded one is not read by gcc
    // ("conversion to void will not access object").
    char const value = *static_cast<char const volatile*>(&WEBCPP_HASH_DETAIL_BEARSSL_CANARY);
    static_cast<void>(value);
}

/** The byte whose address stands for an empty input: BearSSL copies its inputs with `memcpy`. */
inline constexpr std::uint8_t bearssl_no_input = 0;

/**
 The address BearSSL is given for `bytes`: its first byte, or @ref bearssl_no_input when it is
 empty, since C's `memcpy` takes no null pointer, even for no byte.

 @param bytes An input.
 @return A pointer that is never null.
*/
inline void const* bearssl_input(std::span<std::uint8_t const> bytes) noexcept {
    return bytes.empty() ? static_cast<void const*>(&bearssl_no_input) : bytes.data();
}

/**
 BearSSL's hash for an hmac, its `br_hash_class`; the primary template is reached by an hmac
 BearSSL has no hash for, and refuses with spec 3.3's text.

 @tparam Hmac A Boost.Hash2 hmac over a digest.
*/
template <class Hmac>
struct bearssl_hash_class {
    static_assert(always_false<Hmac>,
                  "webcpp::hash: backends::bearssl has HKDF over hmac_md5_128, hmac_sha1_160, "
                  "hmac_sha2_224, hmac_sha2_256, hmac_sha2_384 and hmac_sha2_512 alone. Over "
                  "this hmac, name backends::hash2 (every hmac) or backends::openssl (every hmac "
                  "but hmac_ripemd_128).");

    /**
     No hash: declared so that the refusal is the only error.

     @return Null.
    */
    static br_hash_class const* vtable() noexcept { return nullptr; }
};

/** MD5, BearSSL's `br_md5_vtable`. */
template <>
struct bearssl_hash_class<hmac_md5_128> {
    /** @return `&br_md5_vtable`. */
    static br_hash_class const* vtable() noexcept { return &br_md5_vtable; }
};

/** SHA-1, BearSSL's `br_sha1_vtable`. */
template <>
struct bearssl_hash_class<hmac_sha1_160> {
    /** @return `&br_sha1_vtable`. */
    static br_hash_class const* vtable() noexcept { return &br_sha1_vtable; }
};

/** SHA-224, BearSSL's `br_sha224_vtable`. */
template <>
struct bearssl_hash_class<hmac_sha2_224> {
    /** @return `&br_sha224_vtable`. */
    static br_hash_class const* vtable() noexcept { return &br_sha224_vtable; }
};

/** SHA-256, BearSSL's `br_sha256_vtable`. */
template <>
struct bearssl_hash_class<hmac_sha2_256> {
    /** @return `&br_sha256_vtable`. */
    static br_hash_class const* vtable() noexcept { return &br_sha256_vtable; }
};

/** SHA-384, BearSSL's `br_sha384_vtable`. */
template <>
struct bearssl_hash_class<hmac_sha2_384> {
    /** @return `&br_sha384_vtable`. */
    static br_hash_class const* vtable() noexcept { return &br_sha384_vtable; }
};

/** SHA-512, BearSSL's `br_sha512_vtable`. */
template <>
struct bearssl_hash_class<hmac_sha2_512> {
    /** @return `&br_sha512_vtable`. */
    static br_hash_class const* vtable() noexcept { return &br_sha512_vtable; }
};

/**
 HKDF on backends::bearssl (the engine's interface: @ref hkdf_engine), whose work is
 `extract_and_expand` alone; `extract` and `expand` refuse when called.

 @tparam Hmac One of the six hmacs of @ref bearssl_hash_class.
*/
template <class Hmac>
struct hkdf_engine<backends::bearssl, Hmac> {
    /** The hmac's result, a `digest<N>`. */
    using digest_type = Hmac::result_type;

    /**
     Not in BearSSL, whose context keeps the PRK: refuses with spec 3.3's text when called.

     @return Never: the program does not compile.
    */
    static boost::system::result<digest_type> extract(
        std::span<std::uint8_t const> /*salt*/, std::span<std::uint8_t const> /*ikm*/) noexcept {
        static_assert(always_false<Hmac>,
                      "webcpp::hash: hkdf_extract and hkdf_expand are not in backends::bearssl, "
                      "whose HKDF does both steps together: call hkdf, or name backends::hash2, "
                      "backends::sodium or backends::openssl.");
        return error::backend_failure;
    }

    /**
     Not in BearSSL, which takes no PRK in: refuses with spec 3.3's text when called.

     @return Never: the program does not compile.
    */
    static boost::system::result<void> expand(std::span<std::uint8_t> /*output*/,
                                              std::span<std::uint8_t const> /*prk*/,
                                              std::span<std::uint8_t const> /*info*/) noexcept {
        static_assert(always_false<Hmac>,
                      "webcpp::hash: hkdf_extract and hkdf_expand are not in backends::bearssl, "
                      "whose HKDF does both steps together: call hkdf, or name backends::hash2, "
                      "backends::sodium or backends::openssl.");
        return error::backend_failure;
    }

    /**
     RFC 5869, 2, by BearSSL: `br_hkdf_init` with the hash and the salt (an empty one of length
     0, which HMAC pads with zeros to the block, RFC 5869's HashLen zeros), `br_hkdf_inject`,
     `br_hkdf_flip`, `br_hkdf_produce` into `output`; then the context is wiped.

     @param output The OKM. @param salt The salt. @param ikm The input keying material.
     @param info The info.
     @return Success, or `error::backend_failure` when BearSSL produced fewer bytes than asked.
    */
    static boost::system::result<void> extract_and_expand(
        std::span<std::uint8_t> output, std::span<std::uint8_t const> salt,
        std::span<std::uint8_t const> ikm, std::span<std::uint8_t const> info) noexcept {
        touch_bearssl_canary();
        br_hkdf_context context;
        br_hkdf_init(&context, bearssl_hash_class<Hmac>::vtable(), bearssl_input(salt),
                     salt.size());
        br_hkdf_inject(&context, bearssl_input(ikm), ikm.size());
        br_hkdf_flip(&context);
        const std::size_t produced = br_hkdf_produce(&context, bearssl_input(info), info.size(),
                                                     output.data(), output.size());
        wipe_object(context);
        return produced == output.size() ? boost::system::result<void>()
                                         : boost::system::result<void>(error::backend_failure);
    }
};

/**
 PBKDF2 on backends::bearssl: BearSSL has none, and this specialisation refuses with spec 3.3's
 text for BearSSL rather than the primary template's.

 @tparam Hmac A Boost.Hash2 hmac over a digest.
*/
template <class Hmac>
struct pbkdf2_engine<backends::bearssl, Hmac> {
    static_assert(always_false<Hmac>,
                  "webcpp::hash: pbkdf2 is not in backends::bearssl: BearSSL has no PBKDF2. The "
                  "backends that have pbkdf2: backends::hash2 (every hmac) and backends::openssl "
                  "(every hmac but hmac_ripemd_128).");

    /**
     Not in BearSSL: declared so that the refusal is the only error.

     @return Never: the program does not compile.
    */
    static boost::system::result<void> derive(std::span<std::uint8_t> /*output*/,
                                              std::span<std::uint8_t const> /*password*/,
                                              std::span<std::uint8_t const> /*salt*/,
                                              std::uint64_t /*iterations*/) noexcept {
        return error::backend_failure;
    }
};

}  // namespace webcpp::hash::detail

#endif  // WEBCPP_HASH_HAS_BEARSSL

#endif  // WEBCPP_HASH_BACKENDS_BEARSSL_HPP
