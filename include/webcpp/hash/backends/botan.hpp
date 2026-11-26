// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `backends::botan`: the digests, MACs, key derivations and password hashes of Botan 3.14.1, built
 from `third_party/libs/botan` by `/third_party//botan`, natively and on Emscripten, with exceptions
 only; never a default backend (design D34): a call names it. Its digests are MD5, SHA-1,
 SHA-224, SHA-256, SHA-384, SHA-512 and SHA-512/256 (Botan has no SHA-512/224), the four SHA-3,
 SHAKE128 and SHAKE256 of any output size (Botan's XOFs), Keccak-224 to Keccak-512, BLAKE2b of 1 to
 64 bytes, unkeyed or keyed, without a salt or a personalisation (Botan's BLAKE2b takes neither),
 BLAKE2s-256, RIPEMD-160, SM3, Streebog-256 and Streebog-512, Whirlpool and Skein-512 with a
 64-byte digest. Its MACs are HMAC over each of those digests but SHAKE, KMAC128 and KMAC256 (a key
 of at most 192 bytes, and no KMACXOF), SipHash-2-4 (an 8-byte tag) and keyed BLAKE2b. Botan's
 CMAC, GMAC, Poly1305 and X9.19-MAC, and the hashes hash has no tag for, are not exposed
 (`doc/capabilities.json` says why).
 Its key derivations are HKDF (also over pieces, on its HMAC), PBKDF2 and KBKDF (counter mode,
 with the separator and L) over every hmac of `hmac.hpp` but `hmac_ripemd_128` and
 `hmac_sha2_512_224`, SSKDF (the hash form) over every digest of SP 800-56C but SHA-512/224, ANSI
 X9.63's KDF (Botan's KDF2), scrypt (N of at most 2^22, r 256, p 1,024, 8 GiB and 2 MiB of memory),
 Argon2d, Argon2i and Argon2id with lanes (at most 128), a secret and associated data (at most
 8 GiB, the lanes computed in turn), serving the function `argon2id` too, bcrypt (a cost of at
 most 18) and bcrypt_pbkdf; on wasm32 PBKDF2 takes at most 2^32 - 1 iterations and Argon2 and
 scrypt at most 2 GiB. bcrypt's salt is the caller's, given to Botan through a generator that
 yields those 16 bytes alone: hash draws no random byte from Botan.

 Botan reports its errors by throwing, so this header declares nothing in a build without
 exceptions (`WEBCPP_HASH_NO_EXCEPTIONS`): a call on `backends::botan` then stops with the text
 that says so, and `backend_has_v` is false for every tag of `backends::botan`. Every engine
 function runs each call of Botan inside one `try` at its boundary: `std::bad_alloc` is
 `errc::not_enough_memory`, any other exception `error::backend_failure`, and the family then
 zeroes the output. No exception leaves webcpp::hash.

 Botan makes its objects with `operator new`, and the buffers of their state and secrets (Argon2's
 m KiB, scrypt's 128 r (N + p + 1) bytes) with the C library's `calloc`, through its secure
 allocator, which zeroes them when it frees them (spec section 6.2's departure): `digest_of` and
 `mac` make a Botan object (`HashFunction::create_or_throw`, `XOF::create_or_throw`,
 `MessageAuthenticationCode::create_or_throw`, by Botan's name of the algorithm), use it and
 release it before they return, its state cleared (`clear()`) first; a `hasher` owns its object
 until it finishes, is destroyed or is moved from, and clears it then.
 An HMAC key of more than 8,192 bytes, which Botan's `HMAC::key_spec` refuses, is hashed first, as
 RFC 2104 hashes every key longer than the hash's block: the same tag. So is every key Botan gives
 an HMAC in a key derivation: HKDF-Extract's salt, PBKDF2's and scrypt's password, KBKDF's key.
 A key derivation makes Botan's `KDF` or `PasswordHash` in each call and releases it before the
 call returns; Botan holds the keys, and the memory of scrypt and Argon2, in `secure_vector`s,
 which its secure allocator takes from `calloc` and zeroes when it frees them.

 @see "Backends", in the guide.
*/
#ifndef WEBCPP_HASH_BACKENDS_BOTAN_HPP
#define WEBCPP_HASH_BACKENDS_BOTAN_HPP

#include <webcpp/hash/config.hpp>

#ifndef WEBCPP_HASH_NO_EXCEPTIONS

#ifndef WEBCPP_HASH_HAS_BOTAN
// clang-format off
#error "webcpp::hash: backends::botan needs Botan. Add /third_party//botan to the program's Jamfile (native and Emscripten, with exceptions): exe app : app.cpp /webcpp/hash//hash /third_party//botan ;"
// clang-format on
#else

#include <webcpp/hash/detail/canary.h>
#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/detail/limits.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/hash/kdf_standards.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/secure/erase_secret.hpp>

#include <boost/system/errc.hpp>
#include <boost/system/result.hpp>
#include <boost/throw_exception.hpp>

#include <botan/bcrypt.h>   // third_party/libs/botan, through /third_party//botan
#include <botan/exceptn.h>  // the same
#include <botan/hash.h>     // the same
#include <botan/kdf.h>      // the same
#include <botan/mac.h>      // the same
#include <botan/pwdhash.h>  // the same
#include <botan/rng.h>      // the same
#include <botan/xof.h>      // the same

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <memory>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

/** The canary's name, which every engine function of this header reads (spec 5.4). */
#define WEBCPP_HASH_DETAIL_BOTAN_CANARY \
    WEBCPP_HASH_DETAIL_CANARY(botan, WEBCPP_HASH_BOTAN_COMMIT, configured)

#ifdef _MSC_VER
#pragma detect_mismatch(         \
    "webcpp_hash_backend_botan", \
    WEBCPP_HASH_DETAIL_MISMATCH_VALUE(botan, WEBCPP_HASH_BOTAN_COMMIT, configured))
#endif

// A declaration: src/canary_botan.cpp defines it, constant, in /third_party//botan, so its
// initialisation is static, never dynamic; constinit, on this declaration, states it.
extern "C" constinit const char WEBCPP_HASH_DETAIL_BOTAN_CANARY;

namespace webcpp::hash {

namespace backends {

/**
 Botan 3.14.1, built from its sources by `/third_party//botan`, natively and on Emscripten, with
 exceptions: the long tail of hash's digests and MACs (Streebog, Whirlpool, Skein-512 and their
 HMACs alone are Botan's); never a default backend.
*/
struct botan {};

}  // namespace backends

namespace detail {

/**
 The limits of backends::botan: none beyond the spec's, since Botan holds every length in a
 `size_t`, but PBKDF2's iteration count, which Botan holds in a `size_t` too: at most 2^32 - 1 on
 wasm32 (`invalid_iterations` beyond it).
*/
template <>
struct backend_limits<backends::botan> {
    /** HKDF's salt. */
    static constexpr std::uint64_t hkdf_salt = no_limit;
    /** HKDF's input keying material. */
    static constexpr std::uint64_t hkdf_input_key_material = no_limit;
    /** HKDF's pseudorandom key. */
    static constexpr std::uint64_t hkdf_pseudorandom_key = no_limit;
    /** HKDF's info. */
    static constexpr std::uint64_t hkdf_application_info = no_limit;
    /** HKDF's output. */
    static constexpr std::uint64_t hkdf_output = no_limit;
    /** PBKDF2's password. */
    static constexpr std::uint64_t pbkdf2_password = no_limit;
    /** PBKDF2's salt. */
    static constexpr std::uint64_t pbkdf2_salt = no_limit;
    /** PBKDF2's output. */
    static constexpr std::uint64_t pbkdf2_output = no_limit;
    /** PBKDF2's iteration count, a `size_t` of Botan's (`PBKDF2_Family::from_params`). */
    static constexpr std::uint64_t pbkdf2_iterations = std::numeric_limits<std::size_t>::max();
    /** Argon2id's password. */
    static constexpr std::uint64_t argon2id_password = no_limit;
    /** Argon2id's salt. */
    static constexpr std::uint64_t argon2id_salt = no_limit;
    /** Argon2id's output. */
    static constexpr std::uint64_t argon2id_output = no_limit;
    /** scrypt's password. */
    static constexpr std::uint64_t scrypt_password = no_limit;
    /** scrypt's salt. */
    static constexpr std::uint64_t scrypt_salt = no_limit;
    /** scrypt's output. */
    static constexpr std::uint64_t scrypt_output = no_limit;
};

/**
 Reads Botan's canary with a volatile load, which no linker can drop: a program built without
 `/third_party//botan`, or with one of another commit or configuration, then fails to link, naming
 the canary (spec 5.4).
*/
inline void touch_botan_canary() noexcept {
    // The volatile glvalue is converted to a value: a discarded one is not read by gcc.
    char const canary_copy = *static_cast<char const volatile*>(&WEBCPP_HASH_DETAIL_BOTAN_CANARY);
    static_cast<void>(canary_copy);
}

/**
 Runs `boundary_call`, every call of Botan an engine function makes, inside one `try`, after reading
 the canary: the boundary no exception crosses.

 @param boundary_call A callable that calls Botan.
 @return Success; `errc::not_enough_memory` when Botan or the standard library could not allocate
 (`std::bad_alloc`); `error::backend_failure` for any other exception.
*/
template <class Work>
[[nodiscard]] boost::system::result<void> botan_boundary(Work&& boundary_call) noexcept {
    touch_botan_canary();
    try {
        std::forward<Work>(boundary_call)();
    } catch (std::bad_alloc const&) {
        return boost::system::errc::make_error_code(boost::system::errc::not_enough_memory);
    } catch (...) {
        return error::backend_failure;
    }
    return {};
}

/**
 Makes the Botan object of `T` (`HashFunction`, `XOF` or `MessageAuthenticationCode`) Botan names
 `algorithm_name`, or, in a test that defines `WEBCPP_HASH_DETAIL_TEST_BOTAN_NAME` (a string
 literal), that one, to provoke a failure, as backends::openssl's seam does.

 @param algorithm_name Botan's name of the algorithm.
 @return The object; Botan throws `Lookup_Error` for a name it does not know.
*/
template <class T>
std::unique_ptr<T> botan_create(std::string_view algorithm_name) {
#ifdef WEBCPP_HASH_DETAIL_TEST_BOTAN_NAME
    static_cast<void>(algorithm_name);
    return T::create_or_throw(WEBCPP_HASH_DETAIL_TEST_BOTAN_NAME);
#else
    return T::create_or_throw(algorithm_name);
#endif
}

/**
 `name_prefix`, the decimal `output_bits` and ")": Botan's name of an algorithm of a chosen size, as
 "BLAKE2b(256)" or "KMAC-128(128)".

 @param name_prefix The name up to its argument, "(" included. @param output_bits The size in bits.
 @return The name.
*/
inline std::string botan_sized_name(std::string_view name_prefix, std::size_t output_bits) {
    std::string algorithm_name(name_prefix);
    algorithm_name += std::to_string(output_bits);
    algorithm_name += ')';
    return algorithm_name;
}

/**
 A Botan object a call or a hasher owns: null before it is made, once released and when moved
 from. Releasing it clears its state first (`clear()`, which Botan's algorithms implement by
 zeroing their buffers), then frees it.

 @tparam T `Botan::HashFunction`, `Botan::XOF` or `Botan::MessageAuthenticationCode`.
*/
template <class T>
class botan_owned {
public:
    /** No object. */
    botan_owned() noexcept = default;

    /**
     Takes the object of `moved_from`, which owns none after.

     @param moved_from The owner moved from.
    */
    botan_owned(botan_owned&& moved_from) noexcept : object_(std::move(moved_from.object_)) {}

    /**
     Clears and frees this owner's object and takes that of `moved_from`, which owns none after.

     @param moved_from The owner moved from.
     @return This owner.
    */
    botan_owned& operator=(botan_owned&& moved_from) noexcept {
        if (this != &moved_from) {
            reset();
            object_ = std::move(moved_from.object_);
        }
        return *this;
    }

    /** Not copyable: one object, one owner. */
    botan_owned(botan_owned const&) = delete;
    /** Not copyable. @return Never. */
    botan_owned& operator=(botan_owned const&) = delete;

    /** Clears and frees the object, if any. */
    ~botan_owned() { reset(); }

    /**
     Owns `botan_object` from here on, clearing and freeing the one it held.

     @param botan_object An object of Botan's.
    */
    void adopt(std::unique_ptr<T> botan_object) noexcept {
        reset();
        object_ = std::move(botan_object);
    }

    /**
     The object; the caller has made one.

     @return The object.
    */
    [[nodiscard]] T& get() const noexcept { return *object_; }

    /** Whether an object is owned. @return Whether it is. */
    [[nodiscard]] bool has_object() const noexcept { return object_ != nullptr; }

    /**
     Clears the object's state and frees it; an owner without one is left as it is. Botan's
     `clear()` of these algorithms zeroes buffers and throws nothing; a throw is caught all the
     same, and the object freed.
    */
    void reset() noexcept {
        if (object_ != nullptr) {
            try {
                object_->clear();
            } catch (...) {  // NOLINT(bugprone-empty-catch): the object is freed below all the same
            }
            object_ = nullptr;
        }
    }

private:
    std::unique_ptr<T> object_;
};

/**
 Botan's name of a tag of `digests` it has, its `value`, as `HashFunction::create` (or, for
 SHAKE, `XOF::create`) takes it at 3.14.1 (`src/lib/hash/hash.cpp`, `src/lib/xof/xof.cpp`).
 Declared for every tag, defined for each tag backends::botan has; BLAKE2b's is its 64-byte form,
 which HMAC uses, the digest family naming its own size.

 @tparam Digest A tag of `digests`.
*/
template <class Digest>
struct botan_hash_name;

/** MD5 (its module deprecated in Botan 3.14.1, still served). */
template <>
struct botan_hash_name<digests::md5> {
    /** Botan's name. */
    static constexpr std::string_view value = "MD5";
};

/** SHA-1. */
template <>
struct botan_hash_name<digests::sha1> {
    /** Botan's name. */
    static constexpr std::string_view value = "SHA-1";
};

/** SHA-224. */
template <>
struct botan_hash_name<digests::sha2_224> {
    /** Botan's name. */
    static constexpr std::string_view value = "SHA-224";
};

/** SHA-256. */
template <>
struct botan_hash_name<digests::sha2_256> {
    /** Botan's name. */
    static constexpr std::string_view value = "SHA-256";
};

/** SHA-384. */
template <>
struct botan_hash_name<digests::sha2_384> {
    /** Botan's name. */
    static constexpr std::string_view value = "SHA-384";
};

/** SHA-512. */
template <>
struct botan_hash_name<digests::sha2_512> {
    /** Botan's name. */
    static constexpr std::string_view value = "SHA-512";
};

/** SHA-512/256. */
template <>
struct botan_hash_name<digests::sha2_512_256> {
    /** Botan's name. */
    static constexpr std::string_view value = "SHA-512-256";
};

/** SHA3-224. */
template <>
struct botan_hash_name<digests::sha3_224> {
    /** Botan's name. */
    static constexpr std::string_view value = "SHA-3(224)";
};

/** SHA3-256. */
template <>
struct botan_hash_name<digests::sha3_256> {
    /** Botan's name. */
    static constexpr std::string_view value = "SHA-3(256)";
};

/** SHA3-384. */
template <>
struct botan_hash_name<digests::sha3_384> {
    /** Botan's name. */
    static constexpr std::string_view value = "SHA-3(384)";
};

/** SHA3-512. */
template <>
struct botan_hash_name<digests::sha3_512> {
    /** Botan's name. */
    static constexpr std::string_view value = "SHA-3(512)";
};

/** SHAKE128, Botan's XOF. */
template <>
struct botan_hash_name<digests::shake_128> {
    /** Botan's name. */
    static constexpr std::string_view value = "SHAKE-128";
};

/** SHAKE256, Botan's XOF. */
template <>
struct botan_hash_name<digests::shake_256> {
    /** Botan's name. */
    static constexpr std::string_view value = "SHAKE-256";
};

/** Keccak-224 (its module deprecated in Botan 3.14.1, still served). */
template <>
struct botan_hash_name<digests::keccak_224> {
    /** Botan's name. */
    static constexpr std::string_view value = "Keccak-1600(224)";
};

/** Keccak-256 (its module deprecated in Botan 3.14.1, still served). */
template <>
struct botan_hash_name<digests::keccak_256> {
    /** Botan's name. */
    static constexpr std::string_view value = "Keccak-1600(256)";
};

/** Keccak-384 (its module deprecated in Botan 3.14.1, still served). */
template <>
struct botan_hash_name<digests::keccak_384> {
    /** Botan's name. */
    static constexpr std::string_view value = "Keccak-1600(384)";
};

/** Keccak-512 (its module deprecated in Botan 3.14.1, still served). */
template <>
struct botan_hash_name<digests::keccak_512> {
    /** Botan's name. */
    static constexpr std::string_view value = "Keccak-1600(512)";
};

/** BLAKE2b with a 64-byte digest, the hash of `macs::hmac<digests::blake2b>`. */
template <>
struct botan_hash_name<digests::blake2b> {
    /** Botan's name. */
    static constexpr std::string_view value = "BLAKE2b(512)";
};

/** BLAKE2s-256. */
template <>
struct botan_hash_name<digests::blake2s_256> {
    /** Botan's name. */
    static constexpr std::string_view value = "BLAKE2s(256)";
};

/** RIPEMD-160. */
template <>
struct botan_hash_name<digests::ripemd_160> {
    /** Botan's name. */
    static constexpr std::string_view value = "RIPEMD-160";
};

/** SM3. */
template <>
struct botan_hash_name<digests::sm3> {
    /** Botan's name. */
    static constexpr std::string_view value = "SM3";
};

/** Streebog-256 (its module deprecated in Botan 3.14.1, still served). */
template <>
struct botan_hash_name<digests::streebog_256> {
    /** Botan's name. */
    static constexpr std::string_view value = "Streebog-256";
};

/** Streebog-512 (its module deprecated in Botan 3.14.1, still served). */
template <>
struct botan_hash_name<digests::streebog_512> {
    /** Botan's name. */
    static constexpr std::string_view value = "Streebog-512";
};

/** Whirlpool. */
template <>
struct botan_hash_name<digests::whirlpool> {
    /** Botan's name. */
    static constexpr std::string_view value = "Whirlpool";
};

/** Skein-512 with a 64-byte digest and no personalisation. */
template <>
struct botan_hash_name<digests::skein_512> {
    /** Botan's name. */
    static constexpr std::string_view value = "Skein-512(512)";
};

/**
 A digest of a fixed size on backends::botan (its interface is @ref digest_engine), over Botan's
 `HashFunction` that @ref botan_hash_name names: `init` makes the object, `update` is its
 `update`, `finish` its `final` into the output (whose size the family's guards hold to the
 digest's), and the object is cleared and released at `finish`, by `destroy` and when the state is
 moved from.

 @tparam Digest A tag of `digests` of a fixed size that Botan has.
*/
template <class Digest>
struct botan_hash_engine : full_engine {
    /** The object, owned. */
    using state = botan_owned<Botan::HashFunction>;

    /**
     Makes the hash.

     @param digest_state The state. @return Success, or the boundary's failure.
    */
    [[nodiscard]] static boost::system::result<void> init(
        state& digest_state, digest_options<Digest> const& /*algorithm_options*/) noexcept {
        return botan_boundary([&] {
            digest_state.adopt(botan_create<Botan::HashFunction>(botan_hash_name<Digest>::value));
        });
    }

    /**
     Absorbs `input_bytes`.

     @param digest_state The state. @param input_bytes The bytes. @return Success, or the boundary's
     failure.
    */
    [[nodiscard]] static boost::system::result<void> update(
        state& digest_state, std::span<std::uint8_t const> input_bytes) noexcept {
        return botan_boundary([&] { digest_state.get().update(input_bytes); });
    }

    /**
     Writes the digest, then clears and releases the object.

     @param digest_state The state. @param output_bytes The digest, of its size.
     @return Success, or the boundary's failure.
    */
    [[nodiscard]] static boost::system::result<void> finish(
        state& digest_state, std::span<std::uint8_t> output_bytes) noexcept {
        auto finish_result = botan_boundary([&] { digest_state.get().final(output_bytes); });
        digest_state.reset();
        return finish_result;
    }

    /** Clears and releases the object; a second call does nothing. @param digest_state The state.
     */
    static void destroy(state& digest_state) noexcept {
        touch_botan_canary();
        digest_state.reset();
    }

    /**
     The digest of `input_bytes` at once, on an object released before the return.

     @param output_bytes The digest. @param input_bytes The bytes. @param algorithm_options The
     digest's parameters.
     @return Success, or the boundary's failure.
    */
    [[nodiscard]] static boost::system::result<void> one_shot(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> input_bytes,
        digest_options<Digest> const& algorithm_options) noexcept {
        state digest_state;
        auto init_result = init(digest_state, algorithm_options);
        if (init_result) {
            init_result = update(digest_state, input_bytes);
        }
        if (init_result) {
            init_result = finish(digest_state, output_bytes);
        }
        destroy(digest_state);
        return init_result;
    }
};

/**
 SHAKE128 or SHAKE256 on backends::botan, Botan's `XOF` "SHAKE-128" or "SHAKE-256" (the module
 `shake_xof`): every output size, its `output` writing as many bytes as asked. Its interface is
 @ref digest_engine, as @ref botan_hash_engine's.

 @tparam Digest `digests::shake_128` or `digests::shake_256`.
*/
template <class Digest>
struct botan_xof_engine : full_engine {
    /** The object, owned. */
    using state = botan_owned<Botan::XOF>;

    /** Makes the XOF. @param digest_state The state. @return Success, or the boundary's failure. */
    [[nodiscard]] static boost::system::result<void> init(
        state& digest_state, digest_options<Digest> const& /*algorithm_options*/) noexcept {
        return botan_boundary(
            [&] { digest_state.adopt(botan_create<Botan::XOF>(botan_hash_name<Digest>::value)); });
    }

    /**
     Absorbs `input_bytes`.

     @param digest_state The state. @param input_bytes The bytes. @return Success, or the boundary's
     failure.
    */
    [[nodiscard]] static boost::system::result<void> update(
        state& digest_state, std::span<std::uint8_t const> input_bytes) noexcept {
        return botan_boundary([&] { digest_state.get().update(input_bytes); });
    }

    /**
     Squeezes `output_bytes.size()` bytes, then clears and releases the object.

     @param digest_state The state. @param output_bytes The output. @return Success, or the
     boundary's failure.
    */
    [[nodiscard]] static boost::system::result<void> finish(
        state& digest_state, std::span<std::uint8_t> output_bytes) noexcept {
        auto finish_result = botan_boundary([&] { digest_state.get().output(output_bytes); });
        digest_state.reset();
        return finish_result;
    }

    /** Clears and releases the object; a second call does nothing. @param digest_state The state.
     */
    static void destroy(state& digest_state) noexcept {
        touch_botan_canary();
        digest_state.reset();
    }

    /**
     The output of `input_bytes` at once, on an object released before the return.

     @param output_bytes The output. @param input_bytes The bytes. @param algorithm_options The
     digest's parameters.
     @return Success, or the boundary's failure.
    */
    [[nodiscard]] static boost::system::result<void> one_shot(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> input_bytes,
        digest_options<Digest> const& algorithm_options) noexcept {
        state digest_state;
        auto init_result = init(digest_state, algorithm_options);
        if (init_result) {
            init_result = update(digest_state, input_bytes);
        }
        if (init_result) {
            init_result = finish(digest_state, output_bytes);
        }
        destroy(digest_state);
        return init_result;
    }
};

// clang-format off
/** `digests::md5` on backends::botan: "MD5". */
template <> struct digest_engine<backends::botan, digests::md5> : botan_hash_engine<digests::md5> {};
/** `digests::sha1` on backends::botan: "SHA-1". */
template <> struct digest_engine<backends::botan, digests::sha1> : botan_hash_engine<digests::sha1> {};
/** `digests::sha2_224` on backends::botan: "SHA-224". */
template <> struct digest_engine<backends::botan, digests::sha2_224> : botan_hash_engine<digests::sha2_224> {};
/** `digests::sha2_256` on backends::botan: "SHA-256". */
template <> struct digest_engine<backends::botan, digests::sha2_256> : botan_hash_engine<digests::sha2_256> {};
/** `digests::sha2_384` on backends::botan: "SHA-384". */
template <> struct digest_engine<backends::botan, digests::sha2_384> : botan_hash_engine<digests::sha2_384> {};
/** `digests::sha2_512` on backends::botan: "SHA-512". */
template <> struct digest_engine<backends::botan, digests::sha2_512> : botan_hash_engine<digests::sha2_512> {};
/** `digests::sha2_512_256` on backends::botan: "SHA-512-256". */
template <> struct digest_engine<backends::botan, digests::sha2_512_256> : botan_hash_engine<digests::sha2_512_256> {};
/** `digests::sha3_224` on backends::botan: "SHA-3(224)". */
template <> struct digest_engine<backends::botan, digests::sha3_224> : botan_hash_engine<digests::sha3_224> {};
/** `digests::sha3_256` on backends::botan: "SHA-3(256)". */
template <> struct digest_engine<backends::botan, digests::sha3_256> : botan_hash_engine<digests::sha3_256> {};
/** `digests::sha3_384` on backends::botan: "SHA-3(384)". */
template <> struct digest_engine<backends::botan, digests::sha3_384> : botan_hash_engine<digests::sha3_384> {};
/** `digests::sha3_512` on backends::botan: "SHA-3(512)". */
template <> struct digest_engine<backends::botan, digests::sha3_512> : botan_hash_engine<digests::sha3_512> {};
/** `digests::shake_128` on backends::botan: the XOF "SHAKE-128", any output size. */
template <> struct digest_engine<backends::botan, digests::shake_128> : botan_xof_engine<digests::shake_128> {};
/** `digests::shake_256` on backends::botan: the XOF "SHAKE-256", any output size. */
template <> struct digest_engine<backends::botan, digests::shake_256> : botan_xof_engine<digests::shake_256> {};
/** `digests::keccak_224` on backends::botan: "Keccak-1600(224)". */
template <> struct digest_engine<backends::botan, digests::keccak_224> : botan_hash_engine<digests::keccak_224> {};
/** `digests::keccak_256` on backends::botan: "Keccak-1600(256)". */
template <> struct digest_engine<backends::botan, digests::keccak_256> : botan_hash_engine<digests::keccak_256> {};
/** `digests::keccak_384` on backends::botan: "Keccak-1600(384)". */
template <> struct digest_engine<backends::botan, digests::keccak_384> : botan_hash_engine<digests::keccak_384> {};
/** `digests::keccak_512` on backends::botan: "Keccak-1600(512)". */
template <> struct digest_engine<backends::botan, digests::keccak_512> : botan_hash_engine<digests::keccak_512> {};
/** `digests::blake2s_256` on backends::botan: "BLAKE2s(256)". */
template <> struct digest_engine<backends::botan, digests::blake2s_256> : botan_hash_engine<digests::blake2s_256> {};
/** `digests::ripemd_160` on backends::botan: "RIPEMD-160". */
template <> struct digest_engine<backends::botan, digests::ripemd_160> : botan_hash_engine<digests::ripemd_160> {};
/** `digests::sm3` on backends::botan: "SM3". */
template <> struct digest_engine<backends::botan, digests::sm3> : botan_hash_engine<digests::sm3> {};
/** `digests::streebog_256` on backends::botan: "Streebog-256". */
template <> struct digest_engine<backends::botan, digests::streebog_256> : botan_hash_engine<digests::streebog_256> {};
/** `digests::streebog_512` on backends::botan: "Streebog-512". */
template <> struct digest_engine<backends::botan, digests::streebog_512> : botan_hash_engine<digests::streebog_512> {};
/** `digests::whirlpool` on backends::botan: "Whirlpool". */
template <> struct digest_engine<backends::botan, digests::whirlpool> : botan_hash_engine<digests::whirlpool> {};
/** `digests::skein_512` on backends::botan: "Skein-512(512)". */
template <> struct digest_engine<backends::botan, digests::skein_512> : botan_hash_engine<digests::skein_512> {};
// clang-format on

/**
 The state of `digests::blake2b` on backends::botan: the unkeyed hash "BLAKE2b(<bits>)", or, for a
 key, the MAC of the same name (Botan's `BLAKE2bMAC`, keyed BLAKE2b); one of the two is owned
 between `init` and its release.
*/
struct botan_blake2b_state {
    /** The unkeyed hash. */
    botan_owned<Botan::HashFunction> unkeyed;
    /** The keyed hash. */
    botan_owned<Botan::MessageAuthenticationCode> keyed;
};

/**
 `digests::blake2b` on backends::botan, in part: BLAKE2b of 1 to 64 bytes, unkeyed
 (`HashFunction` "BLAKE2b(<bits>)") or keyed with 1 to 64 bytes (the MAC "BLAKE2b(<bits>)",
 `BLAKE2bMAC`). A salt or a personalisation is `unsupported_by_backend`: Botan's BLAKE2b takes
 neither (`blake2b.h`).
*/
template <>
struct digest_engine<backends::botan, digests::blake2b> : full_engine {
    /** The hash or the MAC, owned. */
    using state = botan_blake2b_state;

    /**
     Whether Botan's BLAKE2b computes these options: no salt, no personalisation. A template, so
     that it reads `digest_options<digests::blake2b>`, which digest.hpp defines after this header.

     @param algorithm_options The options. @return Whether they have no salt and no personalisation.
    */
    template <class Options>
    static constexpr bool accepts(Options const& algorithm_options) noexcept {
        return algorithm_options.salt.empty() && algorithm_options.personalisation.empty();
    }

    /**
     Makes the hash, or the MAC keyed with the options' key.

     @param digest_state The state. @param algorithm_options The key and the output's size.
     @return Success, or the boundary's failure.
    */
    template <class Options>
    [[nodiscard]] static boost::system::result<void> init(
        state& digest_state, Options const& algorithm_options) noexcept {
        return botan_boundary([&] {
            std::string const algorithm_name =
                botan_sized_name("BLAKE2b(", algorithm_options.output_size * 8);
            if (algorithm_options.key.empty()) {
                digest_state.unkeyed.adopt(botan_create<Botan::HashFunction>(algorithm_name));
            } else {
                digest_state.keyed.adopt(
                    botan_create<Botan::MessageAuthenticationCode>(algorithm_name));
                digest_state.keyed.get().set_key(algorithm_options.key);
            }
        });
    }

    /**
     Absorbs `input_bytes`.

     @param digest_state The state. @param input_bytes The bytes. @return Success, or the boundary's
     failure.
    */
    [[nodiscard]] static boost::system::result<void> update(
        state& digest_state, std::span<std::uint8_t const> input_bytes) noexcept {
        return botan_boundary([&] {
            if (digest_state.keyed.has_object()) {
                digest_state.keyed.get().update(input_bytes);
            } else {
                digest_state.unkeyed.get().update(input_bytes);
            }
        });
    }

    /**
     Writes the digest, of the options' size, then clears and releases the object.

     @param digest_state The state. @param output_bytes The digest. @return Success, or the
     boundary's failure.
    */
    [[nodiscard]] static boost::system::result<void> finish(
        state& digest_state, std::span<std::uint8_t> output_bytes) noexcept {
        auto finish_result = botan_boundary([&] {
            if (digest_state.keyed.has_object()) {
                digest_state.keyed.get().final(output_bytes);
            } else {
                digest_state.unkeyed.get().final(output_bytes);
            }
        });
        destroy(digest_state);
        return finish_result;
    }

    /** Clears and releases the object; a second call does nothing. @param digest_state The state.
     */
    static void destroy(state& digest_state) noexcept {
        touch_botan_canary();
        digest_state.unkeyed.reset();
        digest_state.keyed.reset();
    }

    /**
     The digest of `input_bytes` at once, on an object released before the return.

     @param output_bytes The digest. @param input_bytes The bytes. @param algorithm_options The
     digest's parameters.
     @return Success, or the boundary's failure.
    */
    template <class Options>
    [[nodiscard]] static boost::system::result<void> one_shot(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> input_bytes,
        Options const& algorithm_options) noexcept {
        state digest_state;
        auto init_result = init(digest_state, algorithm_options);
        if (init_result) {
            init_result = update(digest_state, input_bytes);
        }
        if (init_result) {
            init_result = finish(digest_state, output_bytes);
        }
        destroy(digest_state);
        return init_result;
    }
};

/**
 Computes a MAC on Botan's `MessageAuthenticationCode` named `algorithm_name`: makes it, keys it,
 starts it with `nonce_bytes` (KMAC's customisation; empty for the others), absorbs `input_bytes`,
 and writes its tag, of its whole size, into `tag_bytes`; the object is cleared and released before
 the return.

 @param algorithm_name Botan's name of the MAC. @param tag_bytes The tag, of the MAC's size.
 @param key_bytes The key. @param input_bytes The message. @param nonce_bytes What `start` takes.
 @return Success, or the boundary's failure.
*/
[[nodiscard]] inline boost::system::result<void> botan_mac(
    std::string_view algorithm_name, std::span<std::uint8_t> tag_bytes,
    std::span<std::uint8_t const> key_bytes, std::span<std::uint8_t const> input_bytes,
    std::span<std::uint8_t const> nonce_bytes) noexcept {
    botan_owned<Botan::MessageAuthenticationCode> mac_object;
    return botan_boundary([&] {
        mac_object.adopt(botan_create<Botan::MessageAuthenticationCode>(algorithm_name));
        mac_object.get().set_key(key_bytes);
        mac_object.get().start(nonce_bytes);
        mac_object.get().update(input_bytes);
        mac_object.get().final(tag_bytes);
    });
}

/** The longest key Botan's HMAC takes (`HMAC::key_spec`, 8,192 bytes); a longer one is hashed. */
inline constexpr std::size_t botan_hmac_max_key = 8192;

/**
 HMAC over `Digest` on backends::botan, Botan's "HMAC(<the digest's name>)", whose interface is
 @ref mac_engine, at every key and tag size the family accepts. Botan's HMAC refuses a key of more
 than 8,192 bytes, so such a key is hashed first with the same hash, as HMAC hashes every key
 longer than the hash's block (RFC 2104, section 2), which gives the same tag. Botan writes the
 whole HMAC, which a shorter tag takes the start of (RFC 2104, section 5), the rest wiped.

 @tparam Digest A tag of `digests` of a fixed size that Botan has.
*/
template <class Digest>
struct botan_hmac_engine : full_engine {
    /**
     The tag of `input_bytes` under `key_bytes`, the HMAC cut to `output_bytes.size()` bytes.

     @param output_bytes The tag. @param key_bytes The key. @param input_bytes The message.
     @return Success, or the boundary's failure.
    */
    template <class Options>
    [[nodiscard]] static boost::system::result<void> compute(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> key_bytes,
        std::span<std::uint8_t const> input_bytes, Options const& /*algorithm_options*/) noexcept {
        constexpr std::uint64_t digest_size = mac_traits<macs::hmac<Digest>>::max_output;
        std::array<std::uint8_t, 64> whole_tag{};
        static_assert(digest_size <= whole_tag.size());
        auto const tag_bytes = std::span(whole_tag).first(digest_size);
        std::array<std::uint8_t, 64> hashed_key{};
        auto used_key = key_bytes;
        auto compute_result = boost::system::result<void>{};
        if (key_bytes.size() > botan_hmac_max_key) {
            compute_result = digest_engine<backends::botan, Digest>::one_shot(
                std::span(hashed_key).first(digest_size), key_bytes, digest_options<Digest>{});
            used_key = std::span(hashed_key).first(digest_size);
        }
        if (compute_result) {
            std::string algorithm_name;
            compute_result = botan_boundary([&] {
                algorithm_name = "HMAC(";
                algorithm_name.append(botan_hash_name<Digest>::value) += ')';
            });
            if (compute_result) {
                compute_result = botan_mac(algorithm_name, tag_bytes, used_key, input_bytes, {});
            }
        }
        if (compute_result) {
            std::copy_n(tag_bytes.begin(), output_bytes.size(), output_bytes.begin());
        }
        secure::erase_secret(whole_tag);
        secure::erase_secret(hashed_key);
        return compute_result;
    }
};

/**
 KMAC128 or KMAC256 on backends::botan, Botan's "KMAC-128(<bits>)" or "KMAC-256(<bits>)", the
 customisation as its `start`'s nonce (its interface is @ref mac_engine), in part: Botan's KMAC
 takes a key of at most 192 bytes (`KMAC::key_spec`) and always encodes the output's length, so
 a longer key and the XOF form (KMACXOF) are `unsupported_by_backend` (`kmac.cpp`).

 @tparam Mac `macs::kmac_128` or `macs::kmac_256`.
*/
template <class Mac>
struct botan_kmac_engine : full_engine {
    /** Botan's longest KMAC key. */
    static constexpr std::size_t max_key = 192;

    /**
     Whether Botan's KMAC takes these options and key size. A template, so that it reads
     `mac_options<Mac>`, which mac.hpp defines after this header.

     @param algorithm_options The customisation and the form. @param key_size The key's size.
     @return Whether Botan takes them.
    */
    template <class Options>
    static constexpr bool accepts(Options const& algorithm_options, std::size_t key_size,
                                  std::size_t /*output_size*/) noexcept {
        return !algorithm_options.xof && key_size <= max_key;
    }

    /**
     The tag of `input_bytes` under `key_bytes`, of `output_bytes.size()` bytes, customised.

     @param output_bytes The tag. @param key_bytes The key. @param input_bytes The message.
     @param algorithm_options The customisation.
     @return Success, or the boundary's failure.
    */
    template <class Options>
    [[nodiscard]] static boost::system::result<void> compute(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> key_bytes,
        std::span<std::uint8_t const> input_bytes, Options const& algorithm_options) noexcept {
        constexpr std::string_view name_prefix =
            std::is_same_v<Mac, macs::kmac_128> ? "KMAC-128(" : "KMAC-256(";
        std::string algorithm_name;
        auto compute_result = botan_boundary(
            [&] { algorithm_name = botan_sized_name(name_prefix, output_bytes.size() * 8); });
        if (compute_result) {
            compute_result = botan_mac(algorithm_name, output_bytes, key_bytes, input_bytes,
                                       algorithm_options.customisation);
        }
        return compute_result;
    }
};

/** `macs::kmac_128` on backends::botan: "KMAC-128(<bits>)". */
template <>
struct mac_engine<backends::botan, macs::kmac_128> : botan_kmac_engine<macs::kmac_128> {};

/** `macs::kmac_256` on backends::botan: "KMAC-256(<bits>)". */
template <>
struct mac_engine<backends::botan, macs::kmac_256> : botan_kmac_engine<macs::kmac_256> {};

/** `macs::siphash_2_4` on backends::botan: "SipHash(2,4)", a 16-byte key, an 8-byte tag. */
template <>
struct mac_engine<backends::botan, macs::siphash_2_4> : full_engine {
    /**
     The tag of `input_bytes` under `key_bytes`.

     @param output_bytes The tag. @param key_bytes The key. @param input_bytes The message.
     @return Success, or the boundary's failure.
    */
    template <class Options>
    [[nodiscard]] static boost::system::result<void> compute(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> key_bytes,
        std::span<std::uint8_t const> input_bytes, Options const& /*algorithm_options*/) noexcept {
        return botan_mac("SipHash(2,4)", output_bytes, key_bytes, input_bytes, {});
    }
};

/**
 `macs::blake2b_mac` on backends::botan: the MAC "BLAKE2b(<bits>)" (`BLAKE2bMAC`), a key of 1 to 64
 bytes, a tag of 1 to 64 bytes.
*/
template <>
struct mac_engine<backends::botan, macs::blake2b_mac> : full_engine {
    /**
     The tag of `input_bytes` under `key_bytes`, of `output_bytes.size()` bytes.

     @param output_bytes The tag. @param key_bytes The key. @param input_bytes The message.
     @return Success, or the boundary's failure.
    */
    template <class Options>
    [[nodiscard]] static boost::system::result<void> compute(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> key_bytes,
        std::span<std::uint8_t const> input_bytes, Options const& /*algorithm_options*/) noexcept {
        std::string algorithm_name;
        auto compute_result = botan_boundary(
            [&] { algorithm_name = botan_sized_name("BLAKE2b(", output_bytes.size() * 8); });
        if (compute_result) {
            compute_result = botan_mac(algorithm_name, output_bytes, key_bytes, input_bytes, {});
        }
        return compute_result;
    }
};

// clang-format off
/** `macs::hmac<digests::md5>` on backends::botan: "HMAC(MD5)". */
template <> struct mac_engine<backends::botan, macs::hmac<digests::md5>> : botan_hmac_engine<digests::md5> {};
/** `macs::hmac<digests::sha1>` on backends::botan: "HMAC(SHA-1)". */
template <> struct mac_engine<backends::botan, macs::hmac<digests::sha1>> : botan_hmac_engine<digests::sha1> {};
/** `macs::hmac<digests::sha2_224>` on backends::botan: "HMAC(SHA-224)". */
template <> struct mac_engine<backends::botan, macs::hmac<digests::sha2_224>> : botan_hmac_engine<digests::sha2_224> {};
/** `macs::hmac<digests::sha2_256>` on backends::botan: "HMAC(SHA-256)". */
template <> struct mac_engine<backends::botan, macs::hmac<digests::sha2_256>> : botan_hmac_engine<digests::sha2_256> {};
/** `macs::hmac<digests::sha2_384>` on backends::botan: "HMAC(SHA-384)". */
template <> struct mac_engine<backends::botan, macs::hmac<digests::sha2_384>> : botan_hmac_engine<digests::sha2_384> {};
/** `macs::hmac<digests::sha2_512>` on backends::botan: "HMAC(SHA-512)". */
template <> struct mac_engine<backends::botan, macs::hmac<digests::sha2_512>> : botan_hmac_engine<digests::sha2_512> {};
/** `macs::hmac<digests::sha2_512_256>` on backends::botan: "HMAC(SHA-512-256)". */
template <> struct mac_engine<backends::botan, macs::hmac<digests::sha2_512_256>> : botan_hmac_engine<digests::sha2_512_256> {};
/** `macs::hmac<digests::sha3_224>` on backends::botan: "HMAC(SHA-3(224))". */
template <> struct mac_engine<backends::botan, macs::hmac<digests::sha3_224>> : botan_hmac_engine<digests::sha3_224> {};
/** `macs::hmac<digests::sha3_256>` on backends::botan: "HMAC(SHA-3(256))". */
template <> struct mac_engine<backends::botan, macs::hmac<digests::sha3_256>> : botan_hmac_engine<digests::sha3_256> {};
/** `macs::hmac<digests::sha3_384>` on backends::botan: "HMAC(SHA-3(384))". */
template <> struct mac_engine<backends::botan, macs::hmac<digests::sha3_384>> : botan_hmac_engine<digests::sha3_384> {};
/** `macs::hmac<digests::sha3_512>` on backends::botan: "HMAC(SHA-3(512))". */
template <> struct mac_engine<backends::botan, macs::hmac<digests::sha3_512>> : botan_hmac_engine<digests::sha3_512> {};
/** `macs::hmac<digests::ripemd_160>` on backends::botan: "HMAC(RIPEMD-160)". */
template <> struct mac_engine<backends::botan, macs::hmac<digests::ripemd_160>> : botan_hmac_engine<digests::ripemd_160> {};
/** `macs::hmac<digests::blake2b>` on backends::botan: "HMAC(BLAKE2b(512))". */
template <> struct mac_engine<backends::botan, macs::hmac<digests::blake2b>> : botan_hmac_engine<digests::blake2b> {};
/** `macs::hmac<digests::blake2s_256>` on backends::botan: "HMAC(BLAKE2s(256))". */
template <> struct mac_engine<backends::botan, macs::hmac<digests::blake2s_256>> : botan_hmac_engine<digests::blake2s_256> {};
/** `macs::hmac<digests::keccak_224>` on backends::botan: "HMAC(Keccak-1600(224))". */
template <> struct mac_engine<backends::botan, macs::hmac<digests::keccak_224>> : botan_hmac_engine<digests::keccak_224> {};
/** `macs::hmac<digests::keccak_256>` on backends::botan: "HMAC(Keccak-1600(256))". */
template <> struct mac_engine<backends::botan, macs::hmac<digests::keccak_256>> : botan_hmac_engine<digests::keccak_256> {};
/** `macs::hmac<digests::keccak_384>` on backends::botan: "HMAC(Keccak-1600(384))". */
template <> struct mac_engine<backends::botan, macs::hmac<digests::keccak_384>> : botan_hmac_engine<digests::keccak_384> {};
/** `macs::hmac<digests::keccak_512>` on backends::botan: "HMAC(Keccak-1600(512))". */
template <> struct mac_engine<backends::botan, macs::hmac<digests::keccak_512>> : botan_hmac_engine<digests::keccak_512> {};
/** `macs::hmac<digests::sm3>` on backends::botan: "HMAC(SM3)". */
template <> struct mac_engine<backends::botan, macs::hmac<digests::sm3>> : botan_hmac_engine<digests::sm3> {};
/** `macs::hmac<digests::streebog_256>` on backends::botan: "HMAC(Streebog-256)". */
template <> struct mac_engine<backends::botan, macs::hmac<digests::streebog_256>> : botan_hmac_engine<digests::streebog_256> {};
/** `macs::hmac<digests::streebog_512>` on backends::botan: "HMAC(Streebog-512)". */
template <> struct mac_engine<backends::botan, macs::hmac<digests::streebog_512>> : botan_hmac_engine<digests::streebog_512> {};
/** `macs::hmac<digests::whirlpool>` on backends::botan: "HMAC(Whirlpool)". */
template <> struct mac_engine<backends::botan, macs::hmac<digests::whirlpool>> : botan_hmac_engine<digests::whirlpool> {};
/** `macs::hmac<digests::skein_512>` on backends::botan: "HMAC(Skein-512(512))". */
template <> struct mac_engine<backends::botan, macs::hmac<digests::skein_512>> : botan_hmac_engine<digests::skein_512> {};
// clang-format on

// ---- The key derivations and password hashes ----

/**
 Whether backends::botan has HKDF, PBKDF2 and KBKDF over the Boost.Hash2 hmac `Hmac`: every alias
 of `hmac.hpp` but `hmac_ripemd_128` and `hmac_sha2_512_224` (Botan 3.14.1 has neither RIPEMD-128
 nor SHA-512/224).

 @tparam Hmac A Boost.Hash2 hmac.
*/
template <class Hmac>
inline constexpr bool botan_hmac_v =
    one_of_v<Hmac, hmac_md5_128, hmac_sha1_160, hmac_sha2_224, hmac_sha2_256, hmac_sha2_384,
             hmac_sha2_512, hmac_sha2_512_256, hmac_sha3_224, hmac_sha3_256, hmac_sha3_384,
             hmac_sha3_512, hmac_ripemd_160, hmac_blake2b_512, hmac_blake2s_256>;

/**
 The bytes of `source_bytes` as the characters Botan's password interfaces take (`std::string_view`,
 `const char*` with a length): the same bytes, any of them, a zero included.

 @param source_bytes The password. @return A view of its bytes.
*/
inline std::string_view botan_chars(std::span<std::uint8_t const> source_bytes) noexcept {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): char may alias any byte
    return {reinterpret_cast<char const*>(nonnull(source_bytes)), source_bytes.size()};
}

/**
 The key Botan's HMAC over `Digest` is given for `key_bytes`: `key_bytes` itself, or, when it is
 longer than the 8,192 bytes `HMAC::key_spec` takes, its digest under `Digest`, written into
 `digest_buffer`; as RFC 2104 hashes every key longer than the hash's block, the HMAC is the same.

 @tparam Digest A tag of `digests` of a fixed size that Botan has.
 @param key_bytes The key. @param digest_buffer Room for the digest, which the caller wipes.
 @return The key to give Botan, or the digest's failure.
*/
template <class Digest>
[[nodiscard]] boost::system::result<std::span<std::uint8_t const>> botan_hmac_key(
    std::span<std::uint8_t const> key_bytes, std::array<std::uint8_t, 64>& digest_buffer) noexcept {
    if (key_bytes.size() <= botan_hmac_max_key) {
        return key_bytes;
    }
    constexpr std::uint64_t digest_size = mac_traits<macs::hmac<Digest>>::max_output;
    static_assert(digest_size <= std::tuple_size_v<std::array<std::uint8_t, 64>>);
    auto const digest_bytes = std::span(digest_buffer).first(digest_size);
    auto const digest_result = digest_engine<backends::botan, Digest>::one_shot(
        digest_bytes, key_bytes, digest_options<Digest>{});
    if (!digest_result) {
        return digest_result.error();
    }
    return std::span<std::uint8_t const>(digest_bytes);
}

/**
 Runs `derive_call` with the key Botan's HMAC over `Digest` is given for `key_bytes` (@ref
 botan_hmac_key), the digest of a long key wiped after.

 @tparam Digest A tag of `digests` of a fixed size that Botan has.
 @param key_bytes The key. @param derive_call A callable taking the key Botan is given, `noexcept`.
 @return `derive_call`'s result, or the digest's failure.
*/
template <class Digest, class Derive>
[[nodiscard]] boost::system::result<void> botan_keyed(std::span<std::uint8_t const> key_bytes,
                                                      Derive const& derive_call) noexcept {
    std::array<std::uint8_t, 64> digest_buffer{};
    auto const key_result = botan_hmac_key<Digest>(key_bytes, digest_buffer);
    boost::system::result<void> derive_result{};
    if (key_result) {
        derive_result = derive_call(key_result.unsafe_value());
    } else {
        derive_result = key_result.error();
    }
    secure::erase_secret(digest_buffer);
    return derive_result;
}

/**
 Derives `output_bytes` by Botan's `KDF` whose name is the concatenation of `name_parts`: makes it,
 calls its `derive_key(output_bytes, secret_bytes, salt_bytes, label_bytes)` and releases it before
 the return. Botan's HMAC keeps its key in a `secure_vector`, which Botan zeroes when it frees it.

 @param name_parts Botan's name of the KDF, in parts. @param output_bytes What is derived, its whole
 size.
 @param secret_bytes The KDF's secret. @param salt_bytes Its salt. @param label_bytes Its label.
 @return Success, or the boundary's failure.
*/
[[nodiscard]] inline boost::system::result<void> botan_kdf(
    std::initializer_list<std::string_view> name_parts, std::span<std::uint8_t> output_bytes,
    std::span<std::uint8_t const> secret_bytes, std::span<std::uint8_t const> salt_bytes,
    std::span<std::uint8_t const> label_bytes) noexcept {
    return botan_boundary([&] {
        std::string joined_name;
        for (std::string_view const name_part : name_parts) {
            joined_name.append(name_part);
        }
        botan_create<Botan::KDF>(joined_name)
            ->derive_key(output_bytes, secret_bytes, salt_bytes, label_bytes);
    });
}

/**
 Derives `output_bytes` by Botan's `PasswordHash` of the family whose name is the concatenation of
 `name_parts`, from its parameters `i1`, `i2` and `i3` (Botan's `from_params`), over
 `password_bytes` and `salt_bytes`, and, for Argon2, `associated_data` and `secret_bytes`; both
 objects are released before the return.

 @param name_parts Botan's name of the family, in parts. @param cost_parameters `from_params`'s
 three.
 @param output_bytes The derived key. @param password_bytes The password. @param salt_bytes The
 salt.
 @param associated_data Argon2's X, else empty. @param secret_bytes Argon2's K, else empty.
 @return Success, or the boundary's failure.
*/
[[nodiscard]] inline boost::system::result<void> botan_password_hash(
    std::initializer_list<std::string_view> name_parts, std::array<std::size_t, 3> cost_parameters,
    std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> password_bytes,
    std::span<std::uint8_t const> salt_bytes, std::span<std::uint8_t const> associated_data = {},
    std::span<std::uint8_t const> secret_bytes = {}) noexcept {
    return botan_boundary([&] {
        std::string joined_name;
        for (std::string_view const name_part : name_parts) {
            joined_name.append(name_part);
        }
        auto const password_hash =
            botan_create<Botan::PasswordHashFamily>(joined_name)
                ->from_params(cost_parameters[0], cost_parameters[1], cost_parameters[2]);
        std::string_view const password_characters = botan_chars(password_bytes);
        if (associated_data.empty() && secret_bytes.empty()) {
            password_hash->derive_key(output_bytes.data(), output_bytes.size(),
                                      password_characters.data(), password_characters.size(),
                                      nonnull(salt_bytes), salt_bytes.size());
        } else {
            password_hash->derive_key(output_bytes.data(), output_bytes.size(),
                                      password_characters.data(), password_characters.size(),
                                      nonnull(salt_bytes), salt_bytes.size(),
                                      nonnull(associated_data), associated_data.size(),
                                      nonnull(secret_bytes), secret_bytes.size());
        }
    });
}

/**
 The text of Botan's refusal of HKDF, PBKDF2 or KBKDF over an hmac it lacks, and the members that
 make it the only error of the call.

 @tparam Hmac An hmac for which `botan_hmac_v` is false.
*/
template <class Hmac>
struct botan_refused_hmac_kdf {
    static_assert(always_false<Hmac>,
                  "webcpp::hash: backends::botan has HKDF and PBKDF2 over every hmac of hmac.hpp "
                  "but hmac_ripemd_128 and hmac_sha2_512_224 (Botan 3.14.1 lacks RIPEMD-128 and "
                  "SHA-512/224). Over this hmac, name backends::hash2 (every hmac) or "
                  "backends::openssl (every hmac but hmac_ripemd_128).");

    /** Never called: the refusal has stopped the build. */
    [[nodiscard]] static boost::system::result<typename Hmac::result_type> extract(
        std::span<std::uint8_t const> /*salt_bytes*/,
        std::span<std::uint8_t const> /*input_key_material*/) noexcept {
        return error::backend_failure;
    }

    /** Never called: the refusal has stopped the build. */
    [[nodiscard]] static boost::system::result<void> expand(
        std::span<std::uint8_t> /*output_key_material*/,
        std::span<std::uint8_t const> /*pseudorandom_key*/,
        std::span<std::uint8_t const> /*application_info*/) noexcept {
        return error::backend_failure;
    }

    /** Never called: the refusal has stopped the build. */
    [[nodiscard]] static boost::system::result<void> extract_and_expand(
        std::span<std::uint8_t> /*output_key_material*/,
        std::span<std::uint8_t const> /*salt_bytes*/,
        std::span<std::uint8_t const> /*input_key_material*/,
        std::span<std::uint8_t const> /*application_info*/) noexcept {
        return error::backend_failure;
    }

    /** Never called: the refusal has stopped the build. */
    [[nodiscard]] static boost::system::result<void> derive(
        std::span<std::uint8_t> /*output_bytes*/, std::span<std::uint8_t const> /*password_bytes*/,
        std::span<std::uint8_t const> /*salt_bytes*/, std::uint64_t /*iteration_count*/) noexcept {
        return error::backend_failure;
    }
};

/**
 HKDF on backends::botan over an hmac it has: Botan's "HKDF-Extract(HMAC(<h>))",
 "HKDF-Expand(HMAC(<h>))" and "HKDF(HMAC(<h>))" (the engine's interface: @ref hkdf_engine). The
 salt is HMAC's key in HKDF-Extract, hashed first when it is longer than Botan's HMAC takes.

 @tparam Hmac A Boost.Hash2 hmac for which `botan_hmac_v` holds.
*/
template <class Hmac>
struct botan_hkdf_engine {
    /** The hmac's result, a `digest<N>`: the PRK. */
    using digest_type = Hmac::result_type;
    /** The tag of the hmac's hash. */
    using digest = digest_tag_of<Hmac>::type;

    /**
     RFC 5869, 2.2: the PRK, HashLen bytes; an empty salt is HashLen zeros, as Botan keys it.

     @param salt_bytes The salt. @param input_key_material The input keying material.
     @return The PRK, or Botan's failure.
    */
    [[nodiscard]] static boost::system::result<digest_type> extract(
        std::span<std::uint8_t const> salt_bytes,
        std::span<std::uint8_t const> input_key_material) noexcept {
        // The PRK is derived into the result returned, whose wiping is the caller's.
        boost::system::result<digest_type> pseudorandom_key{boost::system::in_place_value};
        digest_type& pseudorandom_key_digest = pseudorandom_key.unsafe_value();
        auto const derive_result =
            botan_keyed<digest>(salt_bytes, [&](std::span<std::uint8_t const> key_bytes) noexcept {
                return botan_kdf({"HKDF-Extract(HMAC(", botan_hash_name<digest>::value, "))"},
                                 std::span<std::uint8_t>(pseudorandom_key_digest.data(),
                                                         pseudorandom_key_digest.size()),
                                 input_key_material, key_bytes, {});
            });
        if (!derive_result) {
            secure::erase_secret(std::span(&pseudorandom_key_digest, 1));
            pseudorandom_key = derive_result.error();
        }
        return pseudorandom_key;
    }

    /**
     RFC 5869, 2.3: the PRK as the secret, the info as the label.

     @param output_key_material The OKM. @param pseudorandom_key The PRK. @param application_info
     The info.
     @return Success, or Botan's failure.
    */
    [[nodiscard]] static boost::system::result<void> expand(
        std::span<std::uint8_t> output_key_material, std::span<std::uint8_t const> pseudorandom_key,
        std::span<std::uint8_t const> application_info) noexcept {
        return botan_kdf({"HKDF-Expand(HMAC(", botan_hash_name<digest>::value, "))"},
                         output_key_material, pseudorandom_key, {}, application_info);
    }

    /**
     RFC 5869, 2: both steps, the PRK inside Botan's KDF.

     @param output_key_material The OKM. @param salt_bytes The salt. @param input_key_material The
     input keying material. @param application_info The info.
     @return Success, or Botan's failure.
    */
    [[nodiscard]] static boost::system::result<void> extract_and_expand(
        std::span<std::uint8_t> output_key_material, std::span<std::uint8_t const> salt_bytes,
        std::span<std::uint8_t const> input_key_material,
        std::span<std::uint8_t const> application_info) noexcept {
        return botan_keyed<digest>(
            salt_bytes, [&](std::span<std::uint8_t const> key_bytes) noexcept {
                return botan_kdf({"HKDF(HMAC(", botan_hash_name<digest>::value, "))"},
                                 output_key_material, input_key_material, key_bytes,
                                 application_info);
            });
    }
};

/** Botan's PBKDF2 derives at most 2^32 - 2 blocks (`pbkdf2.cpp`), one fewer than RFC 8018. */
template <>
inline constexpr std::uint64_t pbkdf2_max_blocks<backends::botan> = 0xfffffffeULL;

/** HKDF on backends::botan: Botan's over the hmacs it has, a refusal over the others. */
template <class Hmac>
struct hkdf_engine<backends::botan, Hmac>
    : std::conditional_t<botan_hmac_v<Hmac>, botan_hkdf_engine<Hmac>,
                         botan_refused_hmac_kdf<Hmac>> {};

/**
 HKDF over pieces on backends::botan (the engine's interface: @ref hkdf_pieces_engine), over Botan's
 `MessageAuthenticationCode` "HMAC(<hash>)" rather than its KDF "HKDF", which takes the input keying
 material and the info whole: RFC 5869 with every concatenation replaced by successive `update`s.
 Each call makes the HMAC (`create_or_throw`, through @ref botan_create), keys it (`set_key`) and
 computes with `update` and `final`; Expand re-keys it for each block, `clear` then `set_key` with
 the pseudorandom key. Every call of Botan runs inside @ref botan_boundary, which answers an
 exception with `errc::not_enough_memory` (`std::bad_alloc`) or `error::backend_failure`. The object
 is cleared and freed (@ref botan_owned) and Botan keeps its keys in `secure_vector`s, which it
 zeroes when it frees them; hash wipes the room of a long salt's digest, each block T(i) and the
 pseudorandom key between the steps, on success and on failure. A salt longer than the 8,192 bytes
 Botan's HMAC takes is hashed first (@ref botan_keyed), as RFC 2104 hashes every key longer than the
 hash's block. Botan's `update` takes a `size_t`, which holds every slice of @ref hkdf_pieces_slice,
 so that a piece is sliced only by the test seam.

 @tparam Hmac A Boost.Hash2 hmac for which `botan_hmac_v` holds.
*/
template <class Hmac>
    requires botan_hmac_v<Hmac>
struct hkdf_pieces_engine<backends::botan, Hmac> {
    /** The hmac's result, a `digest<N>`: the PRK and each block T(i). */
    using digest_type = Hmac::result_type;
    /** The tag of the hmac's hash. */
    using digest = digest_tag_of<Hmac>::type;

    /** The most bytes of one update. */
    static constexpr std::uint64_t slice_max = hkdf_pieces_slice<backends::botan>;
    static_assert(slice_max <= std::numeric_limits<std::size_t>::max(),
                  "Botan's update takes every slice's length");

    /**
     Makes Botan's HMAC over the hmac's hash, "HMAC(<hash>)", into `mac_object`; Botan throws
     for a name it does not know, and the standard library's string may throw `std::bad_alloc`.

     @param mac_object The owner of the HMAC made.
    */
    static void make(botan_owned<Botan::MessageAuthenticationCode>& mac_object) {
        std::string algorithm_name = "HMAC(";
        algorithm_name.append(botan_hash_name<digest>::value) += ')';
        mac_object.adopt(botan_create<Botan::MessageAuthenticationCode>(algorithm_name));
    }

    /**
     Feeds every byte of `input_pieces` to `mac_instance`, in slices of at most @ref slice_max
     bytes.

     @param mac_instance The keyed HMAC. @param input_pieces The pieces.
    */
    static void update_all(Botan::MessageAuthenticationCode& mac_instance,
                           byte_pieces input_pieces) {
        for_each_slice<slice_max>(input_pieces, [&](std::span<std::uint8_t const> slice_bytes) {
            mac_instance.update(slice_bytes);
        });
    }

    /**
     RFC 5869, 2.2: PRK = HMAC-Hash(salt, piece_1 | ... | piece_n). An empty salt, of length 0,
     is padded by HMAC with zeros to the block: RFC 5869's HashLen zeros.

     @param salt_bytes The salt. @param input_key_material The input keying material's pieces.
     @return The PRK, or Botan's failure.
    */
    [[nodiscard]] static boost::system::result<digest_type> extract(
        std::span<std::uint8_t const> salt_bytes, byte_pieces input_key_material) noexcept {
        // The PRK is built in the result returned and Botan writes into it: a single return path
        // of the one named object, so that no copy of the PRK is left behind unwiped.
        boost::system::result<digest_type> pseudorandom_key{boost::system::in_place_value};
        digest_type& pseudorandom_key_digest = pseudorandom_key.unsafe_value();
        auto const derive_result =
            botan_keyed<digest>(salt_bytes, [&](std::span<std::uint8_t const> key_bytes) noexcept {
                botan_owned<Botan::MessageAuthenticationCode> mac_object;
                return botan_boundary([&] {
                    make(mac_object);
                    mac_object.get().set_key(key_bytes);
                    update_all(mac_object.get(), input_key_material);
                    mac_object.get().final(std::span<std::uint8_t>(pseudorandom_key_digest.data(),
                                                                   pseudorandom_key_digest.size()));
                });
            });
        if (!derive_result) {
            secure::erase_secret(std::span(&pseudorandom_key_digest, 1));
            pseudorandom_key = derive_result.error();
        }
        return pseudorandom_key;
    }

    /**
     RFC 5869, 2.3: T(0) = empty; T(i) = HMAC-Hash(PRK, T(i-1) | piece_1 | ... | piece_n | i);
     OKM = the first L octets of T(1) | T(2) | ... | T(N), N = ceil(L/HashLen). The HMAC is
     cleared and keyed by the PRK again for each block.

     @param output_key_material The OKM, its size L. @param pseudorandom_key The PRK.
     @param application_info The info's pieces.
     @return Success, or Botan's failure (the public function then zeroes the output).
    */
    [[nodiscard]] static boost::system::result<void> expand(
        std::span<std::uint8_t> output_key_material, std::span<std::uint8_t const> pseudorandom_key,
        byte_pieces application_info) noexcept {
        digest_type t_block{};
        botan_owned<Botan::MessageAuthenticationCode> mac_object;
        auto const derive_result = botan_boundary([&] {
            make(mac_object);
            Botan::MessageAuthenticationCode& mac_instance = mac_object.get();
            std::size_t written_count = 0;
            for (unsigned block_counter = 1; written_count < output_key_material.size();
                 ++block_counter) {
                mac_instance.clear();
                mac_instance.set_key(pseudorandom_key);
                if (block_counter > 1) {
                    mac_instance.update(
                        std::span<std::uint8_t const>(t_block.data(), t_block.size()));
                }
                update_all(mac_instance, application_info);
                mac_instance.update(static_cast<std::uint8_t>(block_counter));
                mac_instance.final(std::span<std::uint8_t>(t_block.data(), t_block.size()));
                std::size_t const copied_count =
                    std::min(t_block.size(), output_key_material.size() - written_count);
                std::copy_n(t_block.data(), copied_count,
                            output_key_material.data() + written_count);
                written_count += copied_count;
            }
        });
        mac_object.reset();
        secure::erase_secret(std::span(&t_block, 1));
        return derive_result;
    }

    /**
     RFC 5869, 2: HKDF-Extract, then HKDF-Expand, over pieces; the PRK is wiped between them.

     @param output_key_material The OKM. @param salt_bytes The salt.
     @param input_key_material The input keying material's pieces.
     @param application_info The info's pieces.
     @return Success, or Botan's failure.
    */
    [[nodiscard]] static boost::system::result<void> extract_and_expand(
        std::span<std::uint8_t> output_key_material, std::span<std::uint8_t const> salt_bytes,
        byte_pieces input_key_material, byte_pieces application_info) noexcept {
        return hkdf_pieces_extract_and_expand<hkdf_pieces_engine<backends::botan, Hmac>>(
            output_key_material, salt_bytes, input_key_material, application_info);
    }
};

/**
 PBKDF2 on backends::botan over an hmac it has: Botan's "PBKDF2(HMAC(<h>))" (the engine's
 interface: @ref pbkdf2_engine). The password is HMAC's key, hashed first when it is longer than
 Botan's HMAC takes; the count reaches Botan as a `size_t`, within `backend_limits`; Botan derives
 at most 2^32 - 2 blocks, one fewer than RFC 8018 allows, so a longer output is
 `invalid_output_size` (`pbkdf2_max_blocks`).

 @tparam Hmac A Boost.Hash2 hmac for which `botan_hmac_v` holds.
*/
template <class Hmac>
struct botan_pbkdf2_engine {
    /** The tag of the hmac's hash. */
    using digest = digest_tag_of<Hmac>::type;

    /**
     RFC 8018, 5.2.

     @param output_key_material DK. @param password_bytes P. @param salt_bytes S. @param
     iteration_count c.
     @return Success, or Botan's failure.
    */
    [[nodiscard]] static boost::system::result<void> derive(
        std::span<std::uint8_t> output_key_material, std::span<std::uint8_t const> password_bytes,
        std::span<std::uint8_t const> salt_bytes, std::uint64_t iteration_count) noexcept {
        return botan_keyed<digest>(
            password_bytes, [&](std::span<std::uint8_t const> key_bytes) noexcept {
                return botan_password_hash({"PBKDF2(HMAC(", botan_hash_name<digest>::value, "))"},
                                           {static_cast<std::size_t>(iteration_count), 0, 0},
                                           output_key_material, key_bytes, salt_bytes);
            });
    }
};

/** PBKDF2 on backends::botan: Botan's over the hmacs it has, a refusal over the others. */
template <class Hmac>
struct pbkdf2_engine<backends::botan, Hmac>
    : std::conditional_t<botan_hmac_v<Hmac>, botan_pbkdf2_engine<Hmac>,
                         botan_refused_hmac_kdf<Hmac>> {};

/** The most memory of Botan's Argon2, in KiB: 8 GiB, 2 GiB on wasm32 (`MAX_ARGON_MEMORY_GB`). */
inline constexpr std::uint32_t botan_argon2_max_memory_kibibytes =
    (sizeof(std::size_t) == 4 ? 2U : 8U) * 1024U * 1024U;

/** Botan's most lanes of Argon2 (`Argon2::Argon2`'s check, `m_p <= 128`). */
inline constexpr std::uint32_t botan_argon2_max_lanes = 128;

/**
 Botan's name of an Argon2 variant, its `value`, as `PasswordHashFamily::create` takes it.

 @tparam Variant `kdfs::argon2d`, `kdfs::argon2i` or `kdfs::argon2id`.
*/
template <class Variant>
struct botan_argon2_name;

/** Argon2d. */
template <>
struct botan_argon2_name<kdfs::argon2d> {
    /** The name. */
    static constexpr std::string_view value = "Argon2d";
};

/** Argon2i. */
template <>
struct botan_argon2_name<kdfs::argon2i> {
    /** The name. */
    static constexpr std::string_view value = "Argon2i";
};

/** Argon2id. */
template <>
struct botan_argon2_name<kdfs::argon2id> {
    /** The name. */
    static constexpr std::string_view value = "Argon2id";
};

/**
 Argon2 of the variant `Variant` on backends::botan, Botan's "Argon2d", "Argon2i" or "Argon2id",
 version 0x13, with the secret and the associated data (`derive_key` with `key` and `ad`), the
 lanes computed in turn in the calling thread (Botan's build loads no `thread_utils`) (the engine's
 interface: @ref argon2_engine). Botan allocates the m KiB through its secure allocator
 (`calloc`), zeroed when freed (`secure_vector`).

 @tparam Variant `kdfs::argon2d`, `kdfs::argon2i` or `kdfs::argon2id`.
*/
template <class Variant>
struct botan_argon2_engine {
    /** RFC 9106's bounds, but at most 128 lanes and `botan_argon2_max_memory_kibibytes`. */
    static constexpr argon2_limits limits{
        .max_memory_kibibytes = botan_argon2_max_memory_kibibytes,
        .max_lanes = botan_argon2_max_lanes,
    };

    /**
     RFC 9106, version 0x13.

     @param output_bytes The tag. @param password_bytes The password. @param salt_bytes The salt.
     @param cost_parameters The costs, the lanes, the secret and the associated data.
     @return Success, `errc::not_enough_memory` or `error::backend_failure`.
    */
    [[nodiscard]] static boost::system::result<void> derive(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> password_bytes,
        std::span<std::uint8_t const> salt_bytes,
        argon2_parameters const& cost_parameters) noexcept {
        return botan_password_hash(
            {botan_argon2_name<Variant>::value},
            {cost_parameters.memory_kibibytes, cost_parameters.passes, cost_parameters.lanes},
            output_bytes, password_bytes, salt_bytes, cost_parameters.associated_data,
            cost_parameters.secret);
    }
};

/** `kdfs::argon2d` on backends::botan: "Argon2d". */
template <>
struct argon2_engine<backends::botan, kdfs::argon2d> : botan_argon2_engine<kdfs::argon2d> {};

/** `kdfs::argon2i` on backends::botan: "Argon2i". */
template <>
struct argon2_engine<backends::botan, kdfs::argon2i> : botan_argon2_engine<kdfs::argon2i> {};

/** `kdfs::argon2id` on backends::botan: "Argon2id". */
template <>
struct argon2_engine<backends::botan, kdfs::argon2id> : botan_argon2_engine<kdfs::argon2id> {};

/**
 The function argon2id on backends::botan: "Argon2id" with one lane, no secret and no associated
 data, the memory in bytes given to Botan in KiB (the engine's interface: @ref argon2id_engine).
*/
template <>
struct argon2id_engine<backends::botan> {
    /** Botan's 8 GiB, 2 GiB on wasm32, in bytes. */
    static constexpr argon2id_limits limits{
        .memory = std::uint64_t{botan_argon2_max_memory_kibibytes} * argon2id_memory_unit,
    };

    /**
     The tag.

     @param output_bytes The tag. @param password_bytes The password. @param salt_bytes The 16-byte
     salt. @param pass_count t, at most 2^32 - 1. @param memory_limit The memory in bytes, a
     multiple of 1,024 within `limits`.
     @return Success, `errc::not_enough_memory` or `error::backend_failure`.
    */
    [[nodiscard]] static boost::system::result<void> derive(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> password_bytes,
        std::span<std::uint8_t const> salt_bytes, std::uint64_t pass_count,
        std::size_t memory_limit) noexcept {
        return botan_password_hash(
            {botan_argon2_name<kdfs::argon2id>::value},
            {memory_limit / argon2id_memory_unit, static_cast<std::size_t>(pass_count), 1},
            output_bytes, password_bytes, salt_bytes);
    }
};

/**
 scrypt on backends::botan: Botan's "Scrypt", in part, of the interface @ref
 scrypt_engine declares. Botan computes an N of at most 2^22, an r of at most 256, a p of at most
 1,024 and at most 8 GiB and 2 MiB of memory, 2 GiB and 2 MiB on wasm32 (`scrypt.cpp`), and refuses
 the rest, which `scrypt` answers with `unsupported_by_backend`. The password keys Botan's
 HMAC-SHA-256, hashed first when it is longer than Botan's HMAC takes. Botan allocates the
 128 r (N + p + 1) bytes through its secure allocator (`calloc`), zeroed when freed.
*/
template <>
struct scrypt_engine<backends::botan> {
    /** Botan's bounds: `MAX_SCRYPT_N`, r, p and `MAX_SCRYPT_MEMORY_BYTES`. */
    static constexpr scrypt_limits limits{
        .served_n = std::uint64_t{1} << 22U,
        .served_r = 256,
        .served_p = 1024,
        .served_memory = ((sizeof(std::size_t) == 4 ? std::uint64_t{2} : std::uint64_t{8}) << 30U) +
                         (std::uint64_t{2} << 20U),
    };

    /**
     RFC 7914.

     @param output_bytes The derived key. @param password_bytes The password. @param salt_bytes The
     salt. @param cost_n N. @param block_size_r r. @param parallelism_p p.
     @return Success, `errc::not_enough_memory` or `error::backend_failure`.
    */
    [[nodiscard]] static boost::system::result<void> derive(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> password_bytes,
        std::span<std::uint8_t const> salt_bytes, std::uint64_t cost_n, std::uint32_t block_size_r,
        std::uint32_t parallelism_p) noexcept {
        return botan_keyed<digests::sha2_256>(
            password_bytes, [&](std::span<std::uint8_t const> key_bytes) noexcept {
                return botan_password_hash(
                    {"Scrypt"}, {static_cast<std::size_t>(cost_n), block_size_r, parallelism_p},
                    output_bytes, key_bytes, salt_bytes);
            });
    }
};

/**
 The random number generator Botan's bcrypt draws its salt from, which is the caller's: it yields
 the 16 bytes it was given, once, and nothing else (no input taken, always seeded); a second draw,
 or a draw of another size, throws, which the boundary answers with `backend_failure`. No
 generator of Botan's, `System_RNG` or `AutoSeeded_RNG`, is in the program: hash draws no random
 byte (ruling P6).
*/
class botan_salt final : public Botan::RandomNumberGenerator {
public:
    /**
     The generator of `salt_bytes`, which outlives it.

     @param salt_bytes The 16 bytes of the salt.
    */
    explicit botan_salt(std::span<std::uint8_t const> salt_bytes) noexcept : salt_(salt_bytes) {}

    /** Takes no input. @return false. */
    [[nodiscard]] bool accepts_input() const override { return false; }

    /** Its name. @return "webcpp::hash's bcrypt salt". */
    [[nodiscard]] std::string name() const override { return "webcpp::hash's bcrypt salt"; }

    /** Holds no state to clear: the salt is the caller's. */
    void clear() override {}

    /** Always seeded: its one draw is the caller's salt. @return true. */
    [[nodiscard]] bool is_seeded() const override { return true; }

protected:
    /**
     Writes the salt into `output_bytes`, the one draw; throws on a second draw or another size.

     @param output_bytes The 16 bytes drawn.
    */
    void fill_bytes_with_input(std::span<std::uint8_t> output_bytes,
                               std::span<std::uint8_t const> /*input_bytes*/) override {
        if (output_bytes.empty()) {
            return;
        }
        if (drawn_ || output_bytes.size() != salt_.size()) {
            boost::throw_exception(
                Botan::Invalid_State("webcpp::hash's bcrypt salt is drawn once, whole"));
        }
        std::ranges::copy(salt_, output_bytes.begin());
        drawn_ = true;
    }

private:
    std::span<std::uint8_t const> salt_;
    bool drawn_ = false;
};

/**
 `kdfs::bcrypt` on backends::botan, in part, of the interface @ref bcrypt_engine declares. Botan's
 `generate_bcrypt`, given the caller's salt through @ref botan_salt, and `check_bcrypt`, which
 compares in constant time; Botan computes a cost of at most 18 (`make_bcrypt`), where bcrypt's
 format allows 31. Botan keys Blowfish with the password and its terminating zero, cut at 72
 bytes: a password of at most 72 bytes without a zero byte, as the guards hold it, is OpenBSD's
 key.
*/
template <>
struct bcrypt_engine<backends::botan> {
    /** Botan's highest cost (`make_bcrypt`'s check). */
    static constexpr std::uint32_t max_cost = 18;

    /**
     The 60 characters.

     @param output_characters The string. @param password_bytes The password. @param salt_bytes The
     16-byte salt.
     @param bcrypt_cost The cost, 4 to 18. @param version_character 'a', 'b' or 'y'.
     @return Success, or the boundary's failure.
    */
    [[nodiscard]] static boost::system::result<void> generate(
        std::span<char> output_characters, std::span<std::uint8_t const> password_bytes,
        std::span<std::uint8_t const> salt_bytes, std::uint32_t bcrypt_cost,
        char version_character) noexcept {
        return botan_boundary([&] {
            botan_salt salt_generator(salt_bytes);
            std::string const made_hash =
                Botan::generate_bcrypt(botan_chars(password_bytes), salt_generator,
                                       static_cast<std::uint16_t>(bcrypt_cost), version_character);
            if (made_hash.size() != output_characters.size()) {
                boost::throw_exception(
                    Botan::Invalid_State("bcrypt's string is not 60 characters"));
            }
            std::ranges::copy(made_hash, output_characters.begin());
        });
    }

    /**
     Whether `password_bytes` gives `encoded_hash`.

     @param password_bytes The password. @param encoded_hash The string, of bcrypt's form and a cost
     of at most 18.
     @return Whether it does, or the boundary's failure.
    */
    [[nodiscard]] static boost::system::result<bool> verify(
        std::span<std::uint8_t const> password_bytes, std::string_view encoded_hash) noexcept {
        bool same_hash = false;
        auto const boundary_result = botan_boundary(
            [&] { same_hash = Botan::check_bcrypt(botan_chars(password_bytes), encoded_hash); });
        if (!boundary_result) {
            return boundary_result.error();
        }
        return same_hash;
    }
};

/**
 `kdfs::bcrypt_pbkdf` on backends::botan: Botan's "Bcrypt-PBKDF" (`PasswordHashFamily`), whose
 bounds (rounds of 1 or more, at most 10 MiB of output) hold OpenBSD's, which the guards apply (the
 engine's interface: @ref bcrypt_pbkdf_engine).
*/
template <>
struct bcrypt_pbkdf_engine<backends::botan> {
    /**
     OpenBSD's bcrypt_pbkdf.

     @param output_bytes The derived key. @param password_bytes The password. @param salt_bytes The
     salt.
     @param round_count The rounds.
     @return Success, or the boundary's failure.
    */
    [[nodiscard]] static boost::system::result<void> derive(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> password_bytes,
        std::span<std::uint8_t const> salt_bytes, std::uint32_t round_count) noexcept {
        return botan_password_hash({"Bcrypt-PBKDF"}, {round_count, 0, 0}, output_bytes,
                                   password_bytes, salt_bytes);
    }
};

/**
 r, the counter's width in bits, as Botan's name of SP 800-108's counter mode takes it.

 @param counter_bits 8, 16, 24 or 32, as `kbkdf`'s guard holds it. @return Its decimal digits.
*/
constexpr std::string_view botan_counter_width(std::uint32_t counter_bits) noexcept {
    switch (counter_bits) {
        case 8: return "8";
        case 16: return "16";
        case 24: return "24";
        default: return "32";
    }
}

/**
 SP 800-108's KBKDF in counter mode on backends::botan over an hmac it has, in part: Botan's
 "SP800-108-Counter(HMAC(<h>),<r>,32)", the context as its salt and the label as its label, which
 always writes the separator and L in 32 bits (`sp800_108.cpp`), so that a fixed input without
 either is `unsupported_by_backend` (the engine's interface: @ref kbkdf_engine). The key is hashed
 first when it is longer than Botan's HMAC takes.

 @tparam Hmac A Boost.Hash2 hmac for which `botan_hmac_v` holds.
*/
template <class Hmac>
struct botan_kbkdf_engine {
    /** The tag of the hmac's hash. */
    using digest = digest_tag_of<Hmac>::type;

    /** No limit of Botan's beyond the standard's. */
    static constexpr kdf_standard_limits limits{};

    /**
     Whether Botan writes this fixed input: with the separator and L.

     @param algorithm_options The fixed input. @return Whether both are on.
    */
    static constexpr bool accepts(kbkdf_options const& algorithm_options) noexcept {
        return algorithm_options.separator && algorithm_options.length;
    }

    /**
     K_OUT.

     @param output_bytes K_OUT. @param key_bytes K_IN. @param algorithm_options The label, the
     context and r.
     @return Success, or the boundary's failure.
    */
    [[nodiscard]] static boost::system::result<void> derive(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> key_bytes,
        kbkdf_options const& algorithm_options) noexcept {
        return botan_keyed<digest>(key_bytes, [&](std::span<std::uint8_t const> used_key) noexcept {
            return botan_kdf(
                {
                    "SP800-108-Counter(HMAC(",
                    botan_hash_name<digest>::value,
                    "),",
                    botan_counter_width(algorithm_options.counter_bits),
                    ",32)",
                },
                output_bytes, used_key, algorithm_options.context, algorithm_options.label);
        });
    }
};

/**
 The refusal of KBKDF on backends::botan over an hmac it lacks, and the members that make it the
 only error of the call.

 @tparam Hmac An hmac for which `botan_hmac_v` is false.
*/
template <class Hmac>
struct botan_refused_kbkdf {
    static_assert(always_false<Hmac>,
                  "webcpp::hash: backends::botan has kbkdf over the hmacs of hmac.hpp alone, "
                  "hmac_ripemd_128 and hmac_sha2_512_224 excepted. Over hmac_sha2_512_224, name "
                  "backends::openssl; no backend has kbkdf over hmac_ripemd_128.");

    /** Never read. */
    static constexpr kdf_standard_limits limits{};

    /** Never called. @return backend_failure. */
    [[nodiscard]] static boost::system::result<void> derive(
        std::span<std::uint8_t> /*output_bytes*/, std::span<std::uint8_t const> /*key_bytes*/,
        kbkdf_options const& /*algorithm_options*/) noexcept {
        return error::backend_failure;
    }
};

/** KBKDF on backends::botan: Botan's over the hmacs it has, a refusal over the others. */
template <class Hmac>
struct kbkdf_engine<backends::botan, Hmac>
    : std::conditional_t<botan_hmac_v<Hmac>, botan_kbkdf_engine<Hmac>, botan_refused_kbkdf<Hmac>> {
};

/**
 SP 800-56C's one-step KDF over a digest on backends::botan: Botan's "SP800-56A(<h>)", the hash
 form, the fixed info as its label (the engine's interface: @ref sskdf_engine).

 @tparam Digest A digest of SP 800-56C that Botan has.
*/
template <class Digest>
struct botan_sskdf_engine {
    /** No limit of Botan's beyond the standard's. */
    static constexpr kdf_standard_limits limits{};

    /**
     The derived keying material.

     @param output_bytes The output. @param secret_bytes Z. @param fixed_info FixedInfo.
     @return Success, or the boundary's failure.
    */
    [[nodiscard]] static boost::system::result<void> derive(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> secret_bytes,
        std::span<std::uint8_t const> fixed_info) noexcept {
        return botan_kdf({"SP800-56A(", botan_hash_name<Digest>::value, ")"}, output_bytes,
                         secret_bytes, {}, fixed_info);
    }
};

/**
 The refusal of sskdf over SHA-512/224 on backends::botan, which Botan lacks.

 @tparam Digest `digests::sha2_512_224`.
*/
template <class Digest>
struct botan_refused_sskdf : refused_digest_kdf_engine {
    static_assert(always_false<Digest>,
                  "webcpp::hash: backends::botan has no SHA-512/224 (Botan 3.14.1 lacks it): name "
                  "backends::openssl.");
};

/** sskdf on backends::botan: over every digest of SP 800-56C but SHA-512/224, refused. */
template <class Digest>
struct sskdf_engine<backends::botan, Digest>
    : std::conditional_t<std::is_same_v<Digest, digests::sha2_512_224>, botan_refused_sskdf<Digest>,
                         botan_sskdf_engine<Digest>> {};

/**
 ANSI X9.63's KDF over a digest on backends::botan, in part: Botan's "KDF2(<h>)", `h(Z || counter
 || label || salt)` from counter 1, the shared info as its salt and no label, of at most 2^32 - 2
 blocks, an output of more `unsupported_by_backend` (the engine's interface: @ref
 x963kdf_engine).

 @tparam Digest A hash function of SEC 1 v2, section 3.5.
*/
template <class Digest>
struct x963kdf_engine<backends::botan, Digest> {
    /** Botan's KDF2 derives at most 2^32 - 2 blocks (`kdf2.cpp`), one fewer than ANSI X9.63. */
    static constexpr kdf_standard_limits limits{
        .max_output = 0xfffffffeULL * standard_kdf_digest<Digest>::size,
    };

    /**
     The derived keying material.

     @param output_bytes The output. @param secret_bytes Z. @param shared_info SharedInfo.
     @return Success, or the boundary's failure.
    */
    [[nodiscard]] static boost::system::result<void> derive(
        std::span<std::uint8_t> output_bytes, std::span<std::uint8_t const> secret_bytes,
        std::span<std::uint8_t const> shared_info) noexcept {
        return botan_kdf({"KDF2(", botan_hash_name<Digest>::value, ")"}, output_bytes, secret_bytes,
                         shared_info, {});
    }
};

}  // namespace detail

// The cells of backends::botan (spec 3.5, design D44): declared here, so that a program that
// cannot have Botan (not linked, or built without exceptions) has none.

// clang-format off
/** backends::botan has `digests::md5` (Botan 3.14.1's `HashFunction`). */
template <> inline constexpr bool backend_has_v<backends::botan, digests::md5, void> = true;
/** backends::botan has `digests::sha1`. */
template <> inline constexpr bool backend_has_v<backends::botan, digests::sha1, void> = true;
/** backends::botan has `digests::sha2_224`. */
template <> inline constexpr bool backend_has_v<backends::botan, digests::sha2_224, void> = true;
/** backends::botan has `digests::sha2_256`. */
template <> inline constexpr bool backend_has_v<backends::botan, digests::sha2_256, void> = true;
/** backends::botan has `digests::sha2_384`. */
template <> inline constexpr bool backend_has_v<backends::botan, digests::sha2_384, void> = true;
/** backends::botan has `digests::sha2_512`. */
template <> inline constexpr bool backend_has_v<backends::botan, digests::sha2_512, void> = true;
/** backends::botan has `digests::sha2_512_256`. */
template <> inline constexpr bool backend_has_v<backends::botan, digests::sha2_512_256, void> = true;
/** backends::botan has `digests::sha3_224`. */
template <> inline constexpr bool backend_has_v<backends::botan, digests::sha3_224, void> = true;
/** backends::botan has `digests::sha3_256`. */
template <> inline constexpr bool backend_has_v<backends::botan, digests::sha3_256, void> = true;
/** backends::botan has `digests::sha3_384`. */
template <> inline constexpr bool backend_has_v<backends::botan, digests::sha3_384, void> = true;
/** backends::botan has `digests::sha3_512`. */
template <> inline constexpr bool backend_has_v<backends::botan, digests::sha3_512, void> = true;
/** backends::botan has `digests::shake_128` (Botan 3.14.1's `XOF`), any output size. */
template <> inline constexpr bool backend_has_v<backends::botan, digests::shake_128, void> = true;
/** backends::botan has `digests::shake_256` (Botan 3.14.1's `XOF`), any output size. */
template <> inline constexpr bool backend_has_v<backends::botan, digests::shake_256, void> = true;
/** backends::botan has `digests::keccak_224`. */
template <> inline constexpr bool backend_has_v<backends::botan, digests::keccak_224, void> = true;
/** backends::botan has `digests::keccak_256`. */
template <> inline constexpr bool backend_has_v<backends::botan, digests::keccak_256, void> = true;
/** backends::botan has `digests::keccak_384`. */
template <> inline constexpr bool backend_has_v<backends::botan, digests::keccak_384, void> = true;
/** backends::botan has `digests::keccak_512`. */
template <> inline constexpr bool backend_has_v<backends::botan, digests::keccak_512, void> = true;
/** backends::botan has `digests::blake2b`, in part: no salt, no personalisation. */
template <> inline constexpr bool backend_has_v<backends::botan, digests::blake2b, void> = true;
/** backends::botan has `digests::blake2s_256`. */
template <> inline constexpr bool backend_has_v<backends::botan, digests::blake2s_256, void> = true;
/** backends::botan has `digests::ripemd_160`. */
template <> inline constexpr bool backend_has_v<backends::botan, digests::ripemd_160, void> = true;
/** backends::botan has `digests::sm3`. */
template <> inline constexpr bool backend_has_v<backends::botan, digests::sm3, void> = true;
/** backends::botan has `digests::streebog_256`. */
template <> inline constexpr bool backend_has_v<backends::botan, digests::streebog_256, void> = true;
/** backends::botan has `digests::streebog_512`. */
template <> inline constexpr bool backend_has_v<backends::botan, digests::streebog_512, void> = true;
/** backends::botan has `digests::whirlpool`. */
template <> inline constexpr bool backend_has_v<backends::botan, digests::whirlpool, void> = true;
/** backends::botan has `digests::skein_512`. */
template <> inline constexpr bool backend_has_v<backends::botan, digests::skein_512, void> = true;
/** backends::botan has `macs::hmac<digests::md5>` (Botan 3.14.1's `MessageAuthenticationCode`). */
template <> inline constexpr bool backend_has_v<backends::botan, macs::hmac<digests::md5>, void> = true;
/** backends::botan has `macs::hmac<digests::sha1>`. */
template <> inline constexpr bool backend_has_v<backends::botan, macs::hmac<digests::sha1>, void> = true;
/** backends::botan has `macs::hmac<digests::sha2_224>`. */
template <> inline constexpr bool backend_has_v<backends::botan, macs::hmac<digests::sha2_224>, void> = true;
/** backends::botan has `macs::hmac<digests::sha2_256>`. */
template <> inline constexpr bool backend_has_v<backends::botan, macs::hmac<digests::sha2_256>, void> = true;
/** backends::botan has `macs::hmac<digests::sha2_384>`. */
template <> inline constexpr bool backend_has_v<backends::botan, macs::hmac<digests::sha2_384>, void> = true;
/** backends::botan has `macs::hmac<digests::sha2_512>`. */
template <> inline constexpr bool backend_has_v<backends::botan, macs::hmac<digests::sha2_512>, void> = true;
/** backends::botan has `macs::hmac<digests::sha2_512_256>`. */
template <> inline constexpr bool backend_has_v<backends::botan, macs::hmac<digests::sha2_512_256>, void> = true;
/** backends::botan has `macs::hmac<digests::sha3_224>`. */
template <> inline constexpr bool backend_has_v<backends::botan, macs::hmac<digests::sha3_224>, void> = true;
/** backends::botan has `macs::hmac<digests::sha3_256>`. */
template <> inline constexpr bool backend_has_v<backends::botan, macs::hmac<digests::sha3_256>, void> = true;
/** backends::botan has `macs::hmac<digests::sha3_384>`. */
template <> inline constexpr bool backend_has_v<backends::botan, macs::hmac<digests::sha3_384>, void> = true;
/** backends::botan has `macs::hmac<digests::sha3_512>`. */
template <> inline constexpr bool backend_has_v<backends::botan, macs::hmac<digests::sha3_512>, void> = true;
/** backends::botan has `macs::hmac<digests::ripemd_160>`. */
template <> inline constexpr bool backend_has_v<backends::botan, macs::hmac<digests::ripemd_160>, void> = true;
/** backends::botan has `macs::hmac<digests::blake2b>`. */
template <> inline constexpr bool backend_has_v<backends::botan, macs::hmac<digests::blake2b>, void> = true;
/** backends::botan has `macs::hmac<digests::blake2s_256>`. */
template <> inline constexpr bool backend_has_v<backends::botan, macs::hmac<digests::blake2s_256>, void> = true;
/** backends::botan has `macs::hmac<digests::keccak_224>`. */
template <> inline constexpr bool backend_has_v<backends::botan, macs::hmac<digests::keccak_224>, void> = true;
/** backends::botan has `macs::hmac<digests::keccak_256>`. */
template <> inline constexpr bool backend_has_v<backends::botan, macs::hmac<digests::keccak_256>, void> = true;
/** backends::botan has `macs::hmac<digests::keccak_384>`. */
template <> inline constexpr bool backend_has_v<backends::botan, macs::hmac<digests::keccak_384>, void> = true;
/** backends::botan has `macs::hmac<digests::keccak_512>`. */
template <> inline constexpr bool backend_has_v<backends::botan, macs::hmac<digests::keccak_512>, void> = true;
/** backends::botan has `macs::hmac<digests::sm3>`. */
template <> inline constexpr bool backend_has_v<backends::botan, macs::hmac<digests::sm3>, void> = true;
/** backends::botan has `macs::hmac<digests::streebog_256>`. */
template <> inline constexpr bool backend_has_v<backends::botan, macs::hmac<digests::streebog_256>, void> = true;
/** backends::botan has `macs::hmac<digests::streebog_512>`. */
template <> inline constexpr bool backend_has_v<backends::botan, macs::hmac<digests::streebog_512>, void> = true;
/** backends::botan has `macs::hmac<digests::whirlpool>`. */
template <> inline constexpr bool backend_has_v<backends::botan, macs::hmac<digests::whirlpool>, void> = true;
/** backends::botan has `macs::hmac<digests::skein_512>`. */
template <> inline constexpr bool backend_has_v<backends::botan, macs::hmac<digests::skein_512>, void> = true;
/** backends::botan has `macs::kmac_128`, in part: a key of at most 192 bytes, no KMACXOF. */
template <> inline constexpr bool backend_has_v<backends::botan, macs::kmac_128, void> = true;
/** backends::botan has `macs::kmac_256`, in part: a key of at most 192 bytes, no KMACXOF. */
template <> inline constexpr bool backend_has_v<backends::botan, macs::kmac_256, void> = true;
/** backends::botan has `macs::siphash_2_4`. */
template <> inline constexpr bool backend_has_v<backends::botan, macs::siphash_2_4, void> = true;
/** backends::botan has `macs::blake2b_mac`. */
template <> inline constexpr bool backend_has_v<backends::botan, macs::blake2b_mac, void> = true;
/** backends::botan has the function argon2id (Botan 3.14.1's `PasswordHashFamily` "Argon2id"). */
template <> inline constexpr bool backend_has_v<backends::botan, kdfs::argon2id, void> = true;
/** backends::botan has scrypt ("Scrypt"), in part: N of at most 2^22, r 256, p 1,024, 8 GiB. */
template <> inline constexpr bool backend_has_v<backends::botan, kdfs::scrypt, void> = true;
/** backends::botan has Argon2d ("Argon2d"), in part: at most 128 lanes and 8 GiB (2 on wasm32). */
template <> inline constexpr bool backend_has_v<backends::botan, kdfs::argon2d, argon2_parameters> = true;
/** backends::botan has Argon2i ("Argon2i"), in part, as Argon2d. */
template <> inline constexpr bool backend_has_v<backends::botan, kdfs::argon2i, argon2_parameters> = true;
/** backends::botan has Argon2id ("Argon2id"), in part, as Argon2d. */
template <> inline constexpr bool backend_has_v<backends::botan, kdfs::argon2id, argon2_parameters> = true;
/** backends::botan has bcrypt (`generate_bcrypt`, `check_bcrypt`), in part: a cost up to 18. */
template <> inline constexpr bool backend_has_v<backends::botan, kdfs::bcrypt, void> = true;
/** backends::botan has bcrypt_pbkdf ("Bcrypt-PBKDF"). */
template <> inline constexpr bool backend_has_v<backends::botan, kdfs::bcrypt_pbkdf, void> = true;
/** backends::botan has sskdf ("SP800-56A(<h>)"), over SP 800-56C's digests but SHA-512/224. */
template <> inline constexpr bool backend_has_v<backends::botan, kdfs::sskdf, void> = true;
/** backends::botan has x963kdf ("KDF2(<h>)"), in part: at most 2^32 - 2 blocks. */
template <> inline constexpr bool backend_has_v<backends::botan, kdfs::x963kdf, void> = true;
// clang-format on

/** backends::botan has HKDF ("HKDF(HMAC(<h>))") over the hmacs of `detail::botan_hmac_v`. */
template <class Hmac>
inline constexpr bool backend_has_v<backends::botan, kdfs::hkdf, Hmac> = detail::botan_hmac_v<Hmac>;

/**
 backends::botan has HKDF over pieces over the hmacs of `detail::botan_hmac_v`, those of its HMAC
 cells it has HKDF over, on its `MessageAuthenticationCode` "HMAC(<h>)" (its KDF "HKDF" takes the
 input keying material and the info whole, and is not used).
*/
template <class Hmac>
inline constexpr bool backend_has_v<backends::botan, kdfs::hkdf_pieces, Hmac> =
    detail::botan_hmac_v<Hmac>;

/** backends::botan has HKDF-Extract over pieces wherever it has HKDF over pieces. */
template <class Hmac>
inline constexpr bool backend_has_v<backends::botan, kdfs::hkdf_extract_pieces, Hmac> =
    backend_has_v<backends::botan, kdfs::hkdf_pieces, Hmac>;

/** backends::botan has HKDF-Expand over pieces wherever it has HKDF over pieces. */
template <class Hmac>
inline constexpr bool backend_has_v<backends::botan, kdfs::hkdf_expand_pieces, Hmac> =
    backend_has_v<backends::botan, kdfs::hkdf_pieces, Hmac>;

/**
 backends::botan has PBKDF2 ("PBKDF2(HMAC(<h>))") over the hmacs of `detail::botan_hmac_v`, in
 part: at most 2^32 - 2 blocks of output, and on wasm32 at most 2^32 - 1 iterations.
*/
template <class Hmac>
inline constexpr bool backend_has_v<backends::botan, kdfs::pbkdf2, Hmac> =
    detail::botan_hmac_v<Hmac>;

/**
 backends::botan has KBKDF ("SP800-108-Counter(HMAC(<h>),<r>,32)") over the hmacs of
 `detail::botan_hmac_v`, in part: with the separator and L.
*/
template <class Hmac>
inline constexpr bool backend_has_v<backends::botan, kdfs::kbkdf_hmac, Hmac> =
    detail::botan_hmac_v<Hmac>;

}  // namespace webcpp::hash

#endif  // WEBCPP_HASH_HAS_BOTAN

#endif  // WEBCPP_HASH_NO_EXCEPTIONS

#endif  // WEBCPP_HASH_BACKENDS_BOTAN_HPP
