// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `backends::bearssl`: BearSSL, on every target. A program links it with `/third_party//bearssl`,
 webcpp::crypto's BearSSL, the one copy whichever library names it (spec section 5.5). It is never
 a default (design D34): a call reaches it by naming `backends::bearssl`.

 - HKDF (RFC 5869) over `br_hkdf_*`, for six hmacs: `hmac_md5_128`, `hmac_sha1_160`,
   `hmac_sha2_224`, `hmac_sha2_256`, `hmac_sha2_384` and `hmac_sha2_512`. BearSSL has `hkdf`
   alone: its context keeps the pseudorandom key and takes none in, so that `hkdf_extract` and
   `hkdf_expand` refuse at compile time, as `pbkdf2` does (spec section 3.3).
 - HKDF over pieces (`hkdf_extract`, `hkdf_expand` and `hkdf` over `byte_pieces`) for the same six
   hmacs, over BearSSL's HMAC, Extract and Expand included.
 - The digests of `digest_of` and `hasher` (spec 2.15): MD5, SHA-1, SHA-224, SHA-256, SHA-384
   and SHA-512 over `br_<h>_init`, `br_<h>_update` and `br_<h>_out`; TLS 1.0's MD5-SHA1 (36
   bytes, MD5 followed by SHA-1) over `br_md5sha1_*`; SHAKE128 and SHAKE256, any output size,
   over `br_shake_*`.
 - HMAC over those six digests through `mac`, over `br_hmac_key_init`, `br_hmac_init`,
   `br_hmac_update` and `br_hmac_out`, the tag cut to its size by BearSSL (RFC 2104, section 5).

 Each call wipes BearSSL's contexts before it returns, and a hasher's state when it ends (spec
 section 6.1); BearSSL's own temporaries on its stack (the PRK of `br_hkdf_flip`, the padded keys
 of its HMAC, the inner digest of `br_hmac_out`) are not reached.
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
#include <webcpp/hash/detail/limits.hpp>
#include <webcpp/hash/detail/wipe.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/kdf.hpp>

#include <boost/system/result.hpp>

#include <bearssl_hash.h>
#include <bearssl_hmac.h>
#include <bearssl_kdf.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
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

// A declaration: src/canary_bearssl.c defines it, constant, in /third_party//bearssl, so its
// initialisation is static, never dynamic; constinit, on this declaration, states it.
extern "C" constinit const char WEBCPP_HASH_DETAIL_BEARSSL_CANARY;

namespace webcpp::hash::backends {

/**
 BearSSL on every target: `hkdf` alone over six hmacs, and HKDF's three functions over pieces;
 MD5, SHA-1, SHA-2, MD5-SHA1 and SHAKE through `digest_of` and `hasher`, and HMAC over MD5, SHA-1
 and SHA-2 through `mac`; never a default.
*/
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
    char const canary_copy = *static_cast<char const volatile*>(&WEBCPP_HASH_DETAIL_BEARSSL_CANARY);
    static_cast<void>(canary_copy);
}

/**
 BearSSL's functions for a digest of `digests`: its context, `init`, `update` and `out`, which
 writes the whole output; for a fixed-size digest `br_<h>_init`, `br_<h>_update` and `br_<h>_out`,
 with the `br_hash_class` HMAC runs over.

 Specialised for each tag BearSSL has; the primary template is never defined.

 @tparam Digest A tag of `digests`.
*/
template <class Digest>
struct bearssl_digest;

/** MD5: `br_md5_*`. */
template <>
struct bearssl_digest<digests::md5> {
    /** BearSSL's context. */
    using context = br_md5_context;

    /** Starts a hash. @param hashed The context. */
    static void init(context& hashed) noexcept { br_md5_init(&hashed); }

    /**
     Absorbs bytes.

     @param hashed The context. @param data The bytes. @param size Their number.
    */
    static void update(context& hashed, void const* data, std::size_t size) noexcept {
        br_md5_update(&hashed, data, size);
    }

    /** Writes the output. @param hashed The context. @param output The 16 bytes. */
    static void out(context& hashed, std::span<std::uint8_t> output) noexcept {
        br_md5_out(&hashed, output.data());
    }

    /** The hash HMAC runs over. @return `&br_md5_vtable`. */
    static br_hash_class const* vtable() noexcept { return &br_md5_vtable; }
};

/** SHA-1: `br_sha1_*`. */
template <>
struct bearssl_digest<digests::sha1> {
    /** BearSSL's context. */
    using context = br_sha1_context;

    /** Starts a hash. @param hashed The context. */
    static void init(context& hashed) noexcept { br_sha1_init(&hashed); }

    /**
     Absorbs bytes.

     @param hashed The context. @param data The bytes. @param size Their number.
    */
    static void update(context& hashed, void const* data, std::size_t size) noexcept {
        br_sha1_update(&hashed, data, size);
    }

    /** Writes the output. @param hashed The context. @param output The 20 bytes. */
    static void out(context& hashed, std::span<std::uint8_t> output) noexcept {
        br_sha1_out(&hashed, output.data());
    }

    /** The hash HMAC runs over. @return `&br_sha1_vtable`. */
    static br_hash_class const* vtable() noexcept { return &br_sha1_vtable; }
};

/** SHA-224: `br_sha224_*`. */
template <>
struct bearssl_digest<digests::sha2_224> {
    /** BearSSL's context. */
    using context = br_sha224_context;

    /** Starts a hash. @param hashed The context. */
    static void init(context& hashed) noexcept { br_sha224_init(&hashed); }

    /**
     Absorbs bytes.

     @param hashed The context. @param data The bytes. @param size Their number.
    */
    static void update(context& hashed, void const* data, std::size_t size) noexcept {
        br_sha224_update(&hashed, data, size);
    }

    /** Writes the output. @param hashed The context. @param output The 28 bytes. */
    static void out(context& hashed, std::span<std::uint8_t> output) noexcept {
        br_sha224_out(&hashed, output.data());
    }

    /** The hash HMAC runs over. @return `&br_sha224_vtable`. */
    static br_hash_class const* vtable() noexcept { return &br_sha224_vtable; }
};

/** SHA-256: `br_sha256_*`. */
template <>
struct bearssl_digest<digests::sha2_256> {
    /** BearSSL's context. */
    using context = br_sha256_context;

    /** Starts a hash. @param hashed The context. */
    static void init(context& hashed) noexcept { br_sha256_init(&hashed); }

    /**
     Absorbs bytes.

     @param hashed The context. @param data The bytes. @param size Their number.
    */
    static void update(context& hashed, void const* data, std::size_t size) noexcept {
        br_sha256_update(&hashed, data, size);
    }

    /** Writes the output. @param hashed The context. @param output The 32 bytes. */
    static void out(context& hashed, std::span<std::uint8_t> output) noexcept {
        br_sha256_out(&hashed, output.data());
    }

    /** The hash HMAC runs over. @return `&br_sha256_vtable`. */
    static br_hash_class const* vtable() noexcept { return &br_sha256_vtable; }
};

/** SHA-384: `br_sha384_*`. */
template <>
struct bearssl_digest<digests::sha2_384> {
    /** BearSSL's context. */
    using context = br_sha384_context;

    /** Starts a hash. @param hashed The context. */
    static void init(context& hashed) noexcept { br_sha384_init(&hashed); }

    /**
     Absorbs bytes.

     @param hashed The context. @param data The bytes. @param size Their number.
    */
    static void update(context& hashed, void const* data, std::size_t size) noexcept {
        br_sha384_update(&hashed, data, size);
    }

    /** Writes the output. @param hashed The context. @param output The 48 bytes. */
    static void out(context& hashed, std::span<std::uint8_t> output) noexcept {
        br_sha384_out(&hashed, output.data());
    }

    /** The hash HMAC runs over. @return `&br_sha384_vtable`. */
    static br_hash_class const* vtable() noexcept { return &br_sha384_vtable; }
};

/** SHA-512: `br_sha512_*`. */
template <>
struct bearssl_digest<digests::sha2_512> {
    /** BearSSL's context. */
    using context = br_sha512_context;

    /** Starts a hash. @param hashed The context. */
    static void init(context& hashed) noexcept { br_sha512_init(&hashed); }

    /**
     Absorbs bytes.

     @param hashed The context. @param data The bytes. @param size Their number.
    */
    static void update(context& hashed, void const* data, std::size_t size) noexcept {
        br_sha512_update(&hashed, data, size);
    }

    /** Writes the output. @param hashed The context. @param output The 64 bytes. */
    static void out(context& hashed, std::span<std::uint8_t> output) noexcept {
        br_sha512_out(&hashed, output.data());
    }

    /** The hash HMAC runs over. @return `&br_sha512_vtable`. */
    static br_hash_class const* vtable() noexcept { return &br_sha512_vtable; }
};

/** TLS 1.0's MD5-SHA1: `br_md5sha1_*`, MD5 followed by SHA-1. */
template <>
struct bearssl_digest<digests::md5_sha1> {
    /** BearSSL's context. */
    using context = br_md5sha1_context;

    /** Starts a hash. @param hashed The context. */
    static void init(context& hashed) noexcept { br_md5sha1_init(&hashed); }

    /**
     Absorbs bytes.

     @param hashed The context. @param data The bytes. @param size Their number.
    */
    static void update(context& hashed, void const* data, std::size_t size) noexcept {
        br_md5sha1_update(&hashed, data, size);
    }

    /** Writes the output. @param hashed The context. @param output The 36 bytes. */
    static void out(context& hashed, std::span<std::uint8_t> output) noexcept {
        br_md5sha1_out(&hashed, output.data());
    }

    /** The hash HMAC runs over. @return `&br_md5sha1_vtable`. */
    static br_hash_class const* vtable() noexcept { return &br_md5sha1_vtable; }
};

/**
 SHAKE's functions, `br_shake_*` from `bearssl_kdf.h`, any output size from 1 byte:
 `br_shake_init` at the security level, `br_shake_inject`, then `br_shake_flip` and
 `br_shake_produce` of the whole output.

 @tparam SecurityLevel 128 or 256, the bits BearSSL takes (its capacity is twice that).
*/
template <int SecurityLevel>
struct bearssl_shake {
    /** BearSSL's context. */
    using context = br_shake_context;

    /** Starts a hash. @param hashed The context. */
    static void init(context& hashed) noexcept { br_shake_init(&hashed, SecurityLevel); }

    /**
     Absorbs bytes.

     @param hashed The context. @param data The bytes. @param size Their number.
    */
    static void update(context& hashed, void const* data, std::size_t size) noexcept {
        br_shake_inject(&hashed, data, size);
    }

    /**
     Writes the output.

     @param hashed The context. @param output The output, of any size from 1 byte.
    */
    static void out(context& hashed, std::span<std::uint8_t> output) noexcept {
        br_shake_flip(&hashed);
        br_shake_produce(&hashed, output.data(), output.size());
    }
};

/** SHAKE128: `br_shake_*` at level 128. */
template <>
struct bearssl_digest<digests::shake_128> : bearssl_shake<128> {};

/** SHAKE256: `br_shake_*` at level 256. */
template <>
struct bearssl_digest<digests::shake_256> : bearssl_shake<256> {};

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
                  "this hmac, name backends::hash2 (every hmac), backends::openssl (every hmac "
                  "but hmac_ripemd_128) or backends::botan (every hmac but hmac_ripemd_128 and "
                  "hmac_sha2_512_224).");

    /**
     No hash: declared so that the refusal is the only error.

     @return Null.
    */
    static br_hash_class const* vtable() noexcept { return nullptr; }
};

/**
 The hash of one of the six hmacs BearSSL has HKDF over: the `br_hash_class` of its digest's tag
 (@ref digest_tag_of), the one HMAC through `mac` runs over.

 @tparam Hmac `hmac_md5_128`, `hmac_sha1_160` or `hmac_sha2_224` to `hmac_sha2_512`.
*/
template <class Hmac>
    requires bearssl_hmac_v<Hmac>
struct bearssl_hash_class<Hmac> {
    /** The hash of the hmac's digest. @return Its `br_<h>_vtable`. */
    static br_hash_class const* vtable() noexcept {
        return bearssl_digest<typename digest_tag_of<Hmac>::type>::vtable();
    }
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
    [[nodiscard]] static boost::system::result<digest_type> extract(
        std::span<std::uint8_t const> /*salt*/,
        std::span<std::uint8_t const> /*input_key_material*/) noexcept {
        static_assert(always_false<Hmac>,
                      "webcpp::hash: hkdf_extract and hkdf_expand are not in backends::bearssl, "
                      "whose HKDF does both steps together: call hkdf, or name backends::hash2, "
                      "backends::sodium, backends::openssl or backends::botan.");
        return error::backend_failure;
    }

    /**
     Not in BearSSL, which takes no PRK in: refuses with spec 3.3's text when called.

     @return Never: the program does not compile.
    */
    [[nodiscard]] static boost::system::result<void> expand(
        std::span<std::uint8_t> /*output_key_material*/,
        std::span<std::uint8_t const> /*pseudorandom_key*/,
        std::span<std::uint8_t const> /*application_info*/) noexcept {
        static_assert(always_false<Hmac>,
                      "webcpp::hash: hkdf_extract and hkdf_expand are not in backends::bearssl, "
                      "whose HKDF does both steps together: call hkdf, or name backends::hash2, "
                      "backends::sodium, backends::openssl or backends::botan.");
        return error::backend_failure;
    }

    /**
     RFC 5869, 2, by BearSSL: `br_hkdf_init` with the hash and the salt (an empty one of length
     0, which HMAC pads with zeros to the block, RFC 5869's HashLen zeros), `br_hkdf_inject`,
     `br_hkdf_flip`, `br_hkdf_produce` into `output_key_material`; then the context is wiped.

     @param output_key_material The OKM. @param salt The salt. @param input_key_material The input
     keying material.
     @param application_info The info.
     @return Success, or `error::backend_failure` when BearSSL produced fewer bytes than asked.
    */
    [[nodiscard]] static boost::system::result<void> extract_and_expand(
        std::span<std::uint8_t> output_key_material, std::span<std::uint8_t const> salt,
        std::span<std::uint8_t const> input_key_material,
        std::span<std::uint8_t const> application_info) noexcept {
        touch_bearssl_canary();
        br_hkdf_context hkdf_context;
        br_hkdf_init(&hkdf_context, bearssl_hash_class<Hmac>::vtable(), nonnull(salt), salt.size());
        br_hkdf_inject(&hkdf_context, nonnull(input_key_material), input_key_material.size());
        br_hkdf_flip(&hkdf_context);
        const std::size_t produced_count =
            br_hkdf_produce(&hkdf_context, nonnull(application_info), application_info.size(),
                            output_key_material.data(), output_key_material.size());
        wipe_object(hkdf_context);
        return produced_count == output_key_material.size()
                   ? boost::system::result<void>()
                   : boost::system::result<void>(error::backend_failure);
    }
};

/**
 HKDF over pieces on backends::bearssl (the engine's interface: @ref hkdf_pieces_engine), over
 BearSSL's HMAC rather than its HKDF, whose context keeps the pseudorandom key: RFC 5869 with
 every concatenation replaced by successive `br_hmac_update`s, so that BearSSL has Extract and
 Expand over pieces, while its single-buffer `hkdf_extract` and `hkdf_expand` stay refused. The
 `br_hmac_key_context` of a key is made once by `br_hmac_key_init`, and a `br_hmac_context` is
 started from it by `br_hmac_init` for each block (BearSSL copies what it needs, and modifies no
 key context); every context, each block T(i) and the pseudorandom key between the steps are
 wiped. `br_hmac_update` takes a `size_t`, which holds every slice of @ref hkdf_pieces_slice, so
 that a piece is sliced only by the test seam.

 @tparam Hmac One of the six hmacs of @ref bearssl_hash_class.
*/
template <class Hmac>
    requires bearssl_hmac_v<Hmac>
struct hkdf_pieces_engine<backends::bearssl, Hmac> {
    /** The hmac's result, a `digest<N>`: the PRK and each block T(i). */
    using digest_type = Hmac::result_type;

    /** The most bytes of one update. */
    static constexpr std::uint64_t slice_max = hkdf_pieces_slice<backends::bearssl>;
    static_assert(slice_max <= std::numeric_limits<std::size_t>::max(),
                  "br_hmac_update takes every slice's length");

    /**
     Feeds every byte of `pieces` to `mac_context`, in slices of at most @ref slice_max bytes.

     @param mac_context The HMAC context. @param pieces The pieces.
    */
    static void update_all(br_hmac_context& mac_context, byte_pieces pieces) noexcept {
        for_each_slice<slice_max>(pieces, [&](std::span<std::uint8_t const> slice) {
            br_hmac_update(&mac_context, slice.data(), slice.size());
        });
    }

    /**
     RFC 5869, 2.2: PRK = HMAC-Hash(salt, piece_1 | ... | piece_n). An empty salt, of length 0,
     is padded by HMAC with zeros to the block: RFC 5869's HashLen zeros.

     @param salt The salt. @param input_key_material The input keying material's pieces.
     @return The PRK, or `error::backend_failure` when BearSSL wrote another size than the digest's.
    */
    [[nodiscard]] static boost::system::result<digest_type> extract(
        std::span<std::uint8_t const> salt, byte_pieces input_key_material) noexcept {
        touch_bearssl_canary();
        // The PRK is built in the result returned and BearSSL writes into it: a single return path
        // of the one named object, so that no copy of the PRK is left behind unwiped.
        boost::system::result<digest_type> pseudorandom_key{boost::system::in_place_value};
        br_hmac_key_context key_context;
        br_hmac_key_init(&key_context, bearssl_hash_class<Hmac>::vtable(), nonnull(salt),
                         salt.size());
        br_hmac_context mac_context;
        br_hmac_init(&mac_context, &key_context, 0);
        update_all(mac_context, input_key_material);
        std::size_t const written_count =
            br_hmac_out(&mac_context, pseudorandom_key.unsafe_value().data());
        wipe_object(mac_context);
        wipe_object(key_context);
        if (written_count != pseudorandom_key.unsafe_value().size()) {
            wipe_object(pseudorandom_key.unsafe_value());
            pseudorandom_key = boost::system::result<digest_type>(error::backend_failure);
        }
        return pseudorandom_key;
    }

    /**
     RFC 5869, 2.3: T(0) = empty; T(i) = HMAC-Hash(PRK, T(i-1) | piece_1 | ... | piece_n | i);
     OKM = the first L octets of T(1) | T(2) | ... | T(N), N = ceil(L/HashLen).

     @param output_key_material The OKM, its size L. @param pseudorandom_key The PRK.
     @param application_info The info's pieces.
     @return Success, or `error::backend_failure` when BearSSL wrote another size than the digest's
     (the public function then zeroes the output).
    */
    [[nodiscard]] static boost::system::result<void> expand(
        std::span<std::uint8_t> output_key_material, std::span<std::uint8_t const> pseudorandom_key,
        byte_pieces application_info) noexcept {
        touch_bearssl_canary();
        br_hmac_key_context key_context;
        br_hmac_key_init(&key_context, bearssl_hash_class<Hmac>::vtable(), pseudorandom_key.data(),
                         pseudorandom_key.size());
        digest_type t_block{};
        bool computed = true;
        std::size_t written_count = 0;
        for (unsigned block_counter = 1; computed && written_count < output_key_material.size();
             ++block_counter) {
            br_hmac_context mac_context;
            br_hmac_init(&mac_context, &key_context, 0);
            if (block_counter > 1) {
                br_hmac_update(&mac_context, t_block.data(), t_block.size());
            }
            update_all(mac_context, application_info);
            auto const octet_value = static_cast<unsigned char>(block_counter);
            br_hmac_update(&mac_context, &octet_value, 1);
            computed = br_hmac_out(&mac_context, t_block.data()) == t_block.size();
            wipe_object(mac_context);
            if (computed) {
                std::size_t const copied_count =
                    std::min(t_block.size(), output_key_material.size() - written_count);
                std::copy_n(t_block.data(), copied_count,
                            output_key_material.data() + written_count);
                written_count += copied_count;
            }
        }
        wipe_object(t_block);
        wipe_object(key_context);
        if (!computed) {
            return error::backend_failure;
        }
        return {};
    }

    /**
     RFC 5869, 2: HKDF-Extract, then HKDF-Expand, over pieces; the PRK is wiped between them.

     @param output_key_material The OKM. @param salt The salt.
     @param input_key_material The input keying material's pieces.
     @param application_info The info's pieces.
     @return Success, or `error::backend_failure`.
    */
    [[nodiscard]] static boost::system::result<void> extract_and_expand(
        std::span<std::uint8_t> output_key_material, std::span<std::uint8_t const> salt,
        byte_pieces input_key_material, byte_pieces application_info) noexcept {
        auto pseudorandom_key = extract(salt, input_key_material);
        if (!pseudorandom_key) {
            return pseudorandom_key.error();
        }
        digest_type& key_bytes = pseudorandom_key.unsafe_value();
        auto derive_result = expand(
            output_key_material, std::span<std::uint8_t const>(key_bytes.data(), key_bytes.size()),
            application_info);
        wipe_object(key_bytes);
        return derive_result;
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
                  "backends that have pbkdf2: backends::hash2 (every hmac), backends::openssl "
                  "(every hmac but hmac_ripemd_128) and backends::botan (every hmac but "
                  "hmac_ripemd_128 and hmac_sha2_512_224).");

    /**
     Not in BearSSL: declared so that the refusal is the only error.

     @return Never: the program does not compile.
    */
    [[nodiscard]] static boost::system::result<void> derive(
        std::span<std::uint8_t> /*output_bytes*/, std::span<std::uint8_t const> /*password_bytes*/,
        std::span<std::uint8_t const> /*salt_bytes*/, std::uint64_t /*iteration_count*/) noexcept {
        return error::backend_failure;
    }
};

/**
 A digest of `digests` on backends::bearssl (its interface is @ref digest_engine); the state is
 BearSSL's context, wiped by `destroy`.

 The family's guards hold the output to the digest's size, which `br_<h>_out` writes, or, for
 SHAKE, to any size from 1 byte.

 @tparam Digest A tag of @ref bearssl_digest.
*/
template <class Digest>
struct bearssl_digest_engine : full_engine {
    /** BearSSL's context, which is all of the state. */
    using state = bearssl_digest<Digest>::context;

    /** Starts a hash. @param hashed The state. @return Success. */
    [[nodiscard]] static boost::system::result<void> init(
        state& hashed, digest_options<Digest> const& /*options*/) noexcept {
        touch_bearssl_canary();
        bearssl_digest<Digest>::init(hashed);
        return {};
    }

    /** Absorbs `input`. @param hashed The state. @param input The bytes. @return Success. */
    [[nodiscard]] static boost::system::result<void> update(
        state& hashed, std::span<std::uint8_t const> input) noexcept {
        bearssl_digest<Digest>::update(hashed, nonnull(input), input.size());
        return {};
    }

    /** Writes the digest. @param hashed The state. @param output The digest. @return Success. */
    [[nodiscard]] static boost::system::result<void> finish(
        state& hashed, std::span<std::uint8_t> output) noexcept {
        bearssl_digest<Digest>::out(hashed, output);
        return {};
    }

    /** Wipes the state. @param hashed The state. */
    static void destroy(state& hashed) noexcept { wipe_object(hashed); }

    /**
     The digest of `input` at once, BearSSL's context wiped.

     @param output The digest. @param input The bytes. @param options None.
     @return Success.
    */
    [[nodiscard]] static boost::system::result<void> one_shot(
        std::span<std::uint8_t> output, std::span<std::uint8_t const> input,
        digest_options<Digest> const& options) noexcept {
        state hashed;
        static_cast<void>(init(hashed, options));
        static_cast<void>(update(hashed, input));
        static_cast<void>(finish(hashed, output));
        destroy(hashed);
        return {};
    }
};

/** `digests::md5` on backends::bearssl: `br_md5_*`. */
template <>
struct digest_engine<backends::bearssl, digests::md5> : bearssl_digest_engine<digests::md5> {};

/** `digests::sha1` on backends::bearssl: `br_sha1_*`. */
template <>
struct digest_engine<backends::bearssl, digests::sha1> : bearssl_digest_engine<digests::sha1> {};

/** `digests::sha2_224` on backends::bearssl: `br_sha224_*`. */
template <>
struct digest_engine<backends::bearssl, digests::sha2_224>
    : bearssl_digest_engine<digests::sha2_224> {};

/** `digests::sha2_256` on backends::bearssl: `br_sha256_*`. */
template <>
struct digest_engine<backends::bearssl, digests::sha2_256>
    : bearssl_digest_engine<digests::sha2_256> {};

/** `digests::sha2_384` on backends::bearssl: `br_sha384_*`. */
template <>
struct digest_engine<backends::bearssl, digests::sha2_384>
    : bearssl_digest_engine<digests::sha2_384> {};

/** `digests::sha2_512` on backends::bearssl: `br_sha512_*`. */
template <>
struct digest_engine<backends::bearssl, digests::sha2_512>
    : bearssl_digest_engine<digests::sha2_512> {};

/** `digests::md5_sha1` on backends::bearssl: `br_md5sha1_*`, its one backend. */
template <>
struct digest_engine<backends::bearssl, digests::md5_sha1>
    : bearssl_digest_engine<digests::md5_sha1> {};

/** `digests::shake_128` on backends::bearssl: `br_shake_*` at level 128, any output size. */
template <>
struct digest_engine<backends::bearssl, digests::shake_128>
    : bearssl_digest_engine<digests::shake_128> {};

/** `digests::shake_256` on backends::bearssl: `br_shake_*` at level 256, any output size. */
template <>
struct digest_engine<backends::bearssl, digests::shake_256>
    : bearssl_digest_engine<digests::shake_256> {};

/**
 HMAC over a digest of @ref bearssl_digest on backends::bearssl, whose interface is @ref
 mac_engine.

 It runs `br_hmac_key_init` with the digest's `br_hash_class` and the key,
 `br_hmac_init` for a tag of `output.size()` bytes (BearSSL cuts the digest to it, RFC 2104
 section 5), `br_hmac_update` and `br_hmac_out`; both contexts are wiped.

 @tparam Digest The digest's tag.
*/
template <class Digest>
struct bearssl_hmac_engine : full_engine {
    /**
     The tag of `input` under `key`.

     @param output The tag, 10 bytes up to the digest's size. @param key The key, of any size.
     @param input The message.
     @return Success, or `error::backend_failure` when BearSSL wrote another size than asked.
    */
    [[nodiscard]] static boost::system::result<void> compute(
        std::span<std::uint8_t> output, std::span<std::uint8_t const> key,
        std::span<std::uint8_t const> input,
        mac_options<macs::hmac<Digest>> const& /*options*/) noexcept {
        touch_bearssl_canary();
        br_hmac_key_context key_context;
        br_hmac_key_init(&key_context, bearssl_digest<Digest>::vtable(), nonnull(key), key.size());
        br_hmac_context mac_context;
        br_hmac_init(&mac_context, &key_context, output.size());
        br_hmac_update(&mac_context, nonnull(input), input.size());
        std::size_t const written_count = br_hmac_out(&mac_context, output.data());
        wipe_object(mac_context);
        wipe_object(key_context);
        return written_count == output.size() ? boost::system::result<void>()
                                              : boost::system::result<void>(error::backend_failure);
    }
};

/** `macs::hmac<digests::md5>` on backends::bearssl: `br_hmac_*` over `br_md5_vtable`. */
template <>
struct mac_engine<backends::bearssl, macs::hmac<digests::md5>> : bearssl_hmac_engine<digests::md5> {
};

/** `macs::hmac<digests::sha1>` on backends::bearssl: `br_hmac_*` over `br_sha1_vtable`. */
template <>
struct mac_engine<backends::bearssl, macs::hmac<digests::sha1>>
    : bearssl_hmac_engine<digests::sha1> {};

/** `macs::hmac<digests::sha2_224>` on backends::bearssl: `br_hmac_*` over `br_sha224_vtable`. */
template <>
struct mac_engine<backends::bearssl, macs::hmac<digests::sha2_224>>
    : bearssl_hmac_engine<digests::sha2_224> {};

/** `macs::hmac<digests::sha2_256>` on backends::bearssl: `br_hmac_*` over `br_sha256_vtable`. */
template <>
struct mac_engine<backends::bearssl, macs::hmac<digests::sha2_256>>
    : bearssl_hmac_engine<digests::sha2_256> {};

/** `macs::hmac<digests::sha2_384>` on backends::bearssl: `br_hmac_*` over `br_sha384_vtable`. */
template <>
struct mac_engine<backends::bearssl, macs::hmac<digests::sha2_384>>
    : bearssl_hmac_engine<digests::sha2_384> {};

/** `macs::hmac<digests::sha2_512>` on backends::bearssl: `br_hmac_*` over `br_sha512_vtable`. */
template <>
struct mac_engine<backends::bearssl, macs::hmac<digests::sha2_512>>
    : bearssl_hmac_engine<digests::sha2_512> {};

}  // namespace webcpp::hash::detail

#endif  // WEBCPP_HASH_HAS_BEARSSL

#endif  // WEBCPP_HASH_BACKENDS_BEARSSL_HPP
