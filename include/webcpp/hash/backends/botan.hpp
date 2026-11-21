// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `backends::botan`: the digests and MACs of Botan 3.14.1, built from `third_party/libs/botan` by
 `/third_party//botan`, natively and on Emscripten, with exceptions only; never a default backend
 (design D34): a call names it. Its digests are MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 and
 SHA-512/256 (Botan has no SHA-512/224), the four SHA-3, SHAKE128 and SHAKE256 of any output size
 (Botan's XOFs), Keccak-224 to Keccak-512, BLAKE2b of 1 to 64 bytes, unkeyed or keyed, without a
 salt or a personalisation (Botan's BLAKE2b takes neither), BLAKE2s-256, RIPEMD-160, SM3,
 Streebog-256 and Streebog-512, Whirlpool and Skein-512 with a 64-byte digest. Its MACs are HMAC
 over each of those digests but SHAKE, KMAC128 and KMAC256 (a key of at most 192 bytes, and no
 KMACXOF), SipHash-2-4 (an 8-byte tag) and keyed BLAKE2b. Botan's CMAC, GMAC, Poly1305 and
 X9.19-MAC, and the hashes hash has no tag for, are not exposed (`doc/capabilities.json` says why).

 Botan reports its errors by throwing, so this header declares nothing in a build without
 exceptions (`WEBCPP_HASH_NO_EXCEPTIONS`): a call on `backends::botan` then stops with the text
 that says so, and `backend_has_v` is false for every tag of `backends::botan`. Every engine
 function runs each call of Botan inside one `try` at its boundary: `std::bad_alloc` is
 `errc::not_enough_memory`, any other exception `error::backend_failure`, and the family then
 zeroes the output. No exception leaves webcpp::hash.

 Botan allocates its objects and their state through `operator new` (spec section 6.2's
 departure): `digest_of` and `mac` make a Botan object (`HashFunction::create_or_throw`,
 `XOF::create_or_throw`, `MessageAuthenticationCode::create_or_throw`, by Botan's name of the
 algorithm), use it and release it before they return, its state cleared (`clear()`) first; a
 `hasher` owns its object until it finishes, is destroyed or is moved from, and clears it then.
 An HMAC key of more than 8,192 bytes, which Botan's `HMAC::key_spec` refuses, is hashed first, as
 RFC 2104 hashes every key longer than the hash's block: the same tag.

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
#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/detail/limits.hpp>
#include <webcpp/hash/detail/wipe.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/hash/mac.hpp>

#include <boost/system/errc.hpp>
#include <boost/system/result.hpp>

#include <botan/hash.h>  // third_party/libs/botan, through /third_party//botan
#include <botan/mac.h>   // the same
#include <botan/xof.h>   // the same

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
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

// A declaration: src/canary_botan.cpp defines it, constant, in /third_party//botan.
// NOLINTNEXTLINE(bugprone-dynamic-static-initializers)
extern "C" const char WEBCPP_HASH_DETAIL_BOTAN_CANARY;

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
 `size_t`.
*/
template <>
struct backend_limits<backends::botan> {
    /** HKDF's salt. */
    static constexpr std::uint64_t hkdf_salt = no_limit;
    /** HKDF's input keying material. */
    static constexpr std::uint64_t hkdf_ikm = no_limit;
    /** HKDF's pseudorandom key. */
    static constexpr std::uint64_t hkdf_prk = no_limit;
    /** HKDF's info. */
    static constexpr std::uint64_t hkdf_info = no_limit;
    /** HKDF's output. */
    static constexpr std::uint64_t hkdf_output = no_limit;
    /** PBKDF2's password. */
    static constexpr std::uint64_t pbkdf2_password = no_limit;
    /** PBKDF2's salt. */
    static constexpr std::uint64_t pbkdf2_salt = no_limit;
    /** PBKDF2's output. */
    static constexpr std::uint64_t pbkdf2_output = no_limit;
    /** PBKDF2's iteration count. */
    static constexpr std::uint64_t pbkdf2_iterations = no_limit;
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
 Runs `work`, every call of Botan an engine function makes, inside one `try`, after reading the
 canary: the boundary no exception crosses.

 @param work A callable that calls Botan.
 @return Success; `errc::not_enough_memory` when Botan or the standard library could not allocate
 (`std::bad_alloc`); `error::backend_failure` for any other exception.
*/
template <class Work>
[[nodiscard]] boost::system::result<void> botan_boundary(Work&& work) noexcept {
    touch_botan_canary();
    try {
        std::forward<Work>(work)();
    } catch (std::bad_alloc const&) {
        return boost::system::errc::make_error_code(boost::system::errc::not_enough_memory);
    } catch (...) {
        return error::backend_failure;
    }
    return {};
}

/**
 Makes the Botan object of `T` (`HashFunction`, `XOF` or `MessageAuthenticationCode`) Botan names
 `name`, or, in a test that defines `WEBCPP_HASH_DETAIL_TEST_BOTAN_NAME` (a string literal), that
 one, to provoke a failure, as backends::openssl's seam does.

 @param name Botan's name of the algorithm.
 @return The object; Botan throws `Lookup_Error` for a name it does not know.
*/
template <class T>
std::unique_ptr<T> botan_create(std::string_view name) {
#ifdef WEBCPP_HASH_DETAIL_TEST_BOTAN_NAME
    static_cast<void>(name);
    return T::create_or_throw(WEBCPP_HASH_DETAIL_TEST_BOTAN_NAME);
#else
    return T::create_or_throw(name);
#endif
}

/**
 `prefix`, the decimal `bits` and ")": Botan's name of an algorithm of a chosen size, as
 "BLAKE2b(256)" or "KMAC-128(128)".

 @param prefix The name up to its argument, "(" included. @param bits The size in bits.
 @return The name.
*/
inline std::string botan_sized_name(std::string_view prefix, std::size_t bits) {
    std::string name(prefix);
    name += std::to_string(bits);
    name += ')';
    return name;
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
     Owns `object` from here on, clearing and freeing the one it held.

     @param object An object of Botan's.
    */
    void adopt(std::unique_ptr<T> object) noexcept {
        reset();
        object_ = std::move(object);
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
 Declared for every tag, defined for each tag backends::botan has but BLAKE2b, whose name carries
 its size.

 @tparam Digest A tag of `digests`.
*/
template <class Digest>
struct botan_hash_name;

// clang-format off
/** MD5. */
template <> struct botan_hash_name<digests::md5> { static constexpr std::string_view value = "MD5"; };
/** SHA-1. */
template <> struct botan_hash_name<digests::sha1> { static constexpr std::string_view value = "SHA-1"; };
/** SHA-224. */
template <> struct botan_hash_name<digests::sha2_224> { static constexpr std::string_view value = "SHA-224"; };
/** SHA-256. */
template <> struct botan_hash_name<digests::sha2_256> { static constexpr std::string_view value = "SHA-256"; };
/** SHA-384. */
template <> struct botan_hash_name<digests::sha2_384> { static constexpr std::string_view value = "SHA-384"; };
/** SHA-512. */
template <> struct botan_hash_name<digests::sha2_512> { static constexpr std::string_view value = "SHA-512"; };
/** SHA-512/256. */
template <> struct botan_hash_name<digests::sha2_512_256> { static constexpr std::string_view value = "SHA-512-256"; };
/** SHA3-224. */
template <> struct botan_hash_name<digests::sha3_224> { static constexpr std::string_view value = "SHA-3(224)"; };
/** SHA3-256. */
template <> struct botan_hash_name<digests::sha3_256> { static constexpr std::string_view value = "SHA-3(256)"; };
/** SHA3-384. */
template <> struct botan_hash_name<digests::sha3_384> { static constexpr std::string_view value = "SHA-3(384)"; };
/** SHA3-512. */
template <> struct botan_hash_name<digests::sha3_512> { static constexpr std::string_view value = "SHA-3(512)"; };
/** SHAKE128, Botan's XOF. */
template <> struct botan_hash_name<digests::shake_128> { static constexpr std::string_view value = "SHAKE-128"; };
/** SHAKE256, Botan's XOF. */
template <> struct botan_hash_name<digests::shake_256> { static constexpr std::string_view value = "SHAKE-256"; };
/** Keccak-224 (deprecated in Botan 3.14.1, still served). */
template <> struct botan_hash_name<digests::keccak_224> { static constexpr std::string_view value = "Keccak-1600(224)"; };
/** Keccak-256. */
template <> struct botan_hash_name<digests::keccak_256> { static constexpr std::string_view value = "Keccak-1600(256)"; };
/** Keccak-384. */
template <> struct botan_hash_name<digests::keccak_384> { static constexpr std::string_view value = "Keccak-1600(384)"; };
/** Keccak-512. */
template <> struct botan_hash_name<digests::keccak_512> { static constexpr std::string_view value = "Keccak-1600(512)"; };
/** BLAKE2b with a 64-byte digest, the hash of `macs::hmac<digests::blake2b>`. */
template <> struct botan_hash_name<digests::blake2b> { static constexpr std::string_view value = "BLAKE2b(512)"; };
/** BLAKE2s-256. */
template <> struct botan_hash_name<digests::blake2s_256> { static constexpr std::string_view value = "BLAKE2s(256)"; };
/** RIPEMD-160. */
template <> struct botan_hash_name<digests::ripemd_160> { static constexpr std::string_view value = "RIPEMD-160"; };
/** SM3. */
template <> struct botan_hash_name<digests::sm3> { static constexpr std::string_view value = "SM3"; };
/** Streebog-256. */
template <> struct botan_hash_name<digests::streebog_256> { static constexpr std::string_view value = "Streebog-256"; };
/** Streebog-512 (deprecated in Botan 3.14.1, still served). */
template <> struct botan_hash_name<digests::streebog_512> { static constexpr std::string_view value = "Streebog-512"; };
/** Whirlpool. */
template <> struct botan_hash_name<digests::whirlpool> { static constexpr std::string_view value = "Whirlpool"; };
/** Skein-512 with a 64-byte digest and no personalisation. */
template <> struct botan_hash_name<digests::skein_512> { static constexpr std::string_view value = "Skein-512(512)"; };
// clang-format on

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

     @param hashed The state. @return Success, or the boundary's failure.
    */
    [[nodiscard]] static boost::system::result<void> init(
        state& hashed, digest_options<Digest> const& /*options*/) noexcept {
        return botan_boundary([&] {
            hashed.adopt(botan_create<Botan::HashFunction>(botan_hash_name<Digest>::value));
        });
    }

    /**
     Absorbs `input`.

     @param hashed The state. @param input The bytes. @return Success, or the boundary's failure.
    */
    [[nodiscard]] static boost::system::result<void> update(
        state& hashed, std::span<std::uint8_t const> input) noexcept {
        return botan_boundary([&] { hashed.get().update(input); });
    }

    /**
     Writes the digest, then clears and releases the object.

     @param hashed The state. @param output The digest, of its size.
     @return Success, or the boundary's failure.
    */
    [[nodiscard]] static boost::system::result<void> finish(
        state& hashed, std::span<std::uint8_t> output) noexcept {
        auto done = botan_boundary([&] { hashed.get().final(output); });
        hashed.reset();
        return done;
    }

    /** Clears and releases the object; a second call does nothing. @param hashed The state. */
    static void destroy(state& hashed) noexcept {
        touch_botan_canary();
        hashed.reset();
    }

    /**
     The digest of `input` at once, on an object released before the return.

     @param output The digest. @param input The bytes. @param options The digest's parameters.
     @return Success, or the boundary's failure.
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

    /** Makes the XOF. @param hashed The state. @return Success, or the boundary's failure. */
    [[nodiscard]] static boost::system::result<void> init(
        state& hashed, digest_options<Digest> const& /*options*/) noexcept {
        return botan_boundary(
            [&] { hashed.adopt(botan_create<Botan::XOF>(botan_hash_name<Digest>::value)); });
    }

    /**
     Absorbs `input`.

     @param hashed The state. @param input The bytes. @return Success, or the boundary's failure.
    */
    [[nodiscard]] static boost::system::result<void> update(
        state& hashed, std::span<std::uint8_t const> input) noexcept {
        return botan_boundary([&] { hashed.get().update(input); });
    }

    /**
     Squeezes `output.size()` bytes, then clears and releases the object.

     @param hashed The state. @param output The output. @return Success, or the boundary's failure.
    */
    [[nodiscard]] static boost::system::result<void> finish(
        state& hashed, std::span<std::uint8_t> output) noexcept {
        auto done = botan_boundary([&] { hashed.get().output(output); });
        hashed.reset();
        return done;
    }

    /** Clears and releases the object; a second call does nothing. @param hashed The state. */
    static void destroy(state& hashed) noexcept {
        touch_botan_canary();
        hashed.reset();
    }

    /**
     The output of `input` at once, on an object released before the return.

     @param output The output. @param input The bytes. @param options The digest's parameters.
     @return Success, or the boundary's failure.
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

     @param options The options. @return Whether they have no salt and no personalisation.
    */
    template <class Options>
    static constexpr bool accepts(Options const& options) noexcept {
        return options.salt.empty() && options.personalisation.empty();
    }

    /**
     Makes the hash, or the MAC keyed with the options' key.

     @param hashed The state. @param options The key and the output's size.
     @return Success, or the boundary's failure.
    */
    template <class Options>
    [[nodiscard]] static boost::system::result<void> init(state& hashed,
                                                          Options const& options) noexcept {
        return botan_boundary([&] {
            std::string const name = botan_sized_name("BLAKE2b(", options.output_size * 8);
            if (options.key.empty()) {
                hashed.unkeyed.adopt(botan_create<Botan::HashFunction>(name));
            } else {
                hashed.keyed.adopt(botan_create<Botan::MessageAuthenticationCode>(name));
                hashed.keyed.get().set_key(options.key);
            }
        });
    }

    /**
     Absorbs `input`.

     @param hashed The state. @param input The bytes. @return Success, or the boundary's failure.
    */
    [[nodiscard]] static boost::system::result<void> update(
        state& hashed, std::span<std::uint8_t const> input) noexcept {
        return botan_boundary([&] {
            if (hashed.keyed.has_object()) {
                hashed.keyed.get().update(input);
            } else {
                hashed.unkeyed.get().update(input);
            }
        });
    }

    /**
     Writes the digest, of the options' size, then clears and releases the object.

     @param hashed The state. @param output The digest. @return Success, or the boundary's failure.
    */
    [[nodiscard]] static boost::system::result<void> finish(
        state& hashed, std::span<std::uint8_t> output) noexcept {
        auto done = botan_boundary([&] {
            if (hashed.keyed.has_object()) {
                hashed.keyed.get().final(output);
            } else {
                hashed.unkeyed.get().final(output);
            }
        });
        destroy(hashed);
        return done;
    }

    /** Clears and releases the object; a second call does nothing. @param hashed The state. */
    static void destroy(state& hashed) noexcept {
        touch_botan_canary();
        hashed.unkeyed.reset();
        hashed.keyed.reset();
    }

    /**
     The digest of `input` at once, on an object released before the return.

     @param output The digest. @param input The bytes. @param options The digest's parameters.
     @return Success, or the boundary's failure.
    */
    template <class Options>
    [[nodiscard]] static boost::system::result<void> one_shot(std::span<std::uint8_t> output,
                                                              std::span<std::uint8_t const> input,
                                                              Options const& options) noexcept {
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
};

/**
 Computes a MAC on Botan's `MessageAuthenticationCode` named `name`: makes it, keys it, starts it
 with `nonce` (KMAC's customisation; empty for the others), absorbs `input`, and writes its tag,
 of its whole size, into `tag`; the object is cleared and released before the return.

 @param name Botan's name of the MAC. @param tag The tag, of the MAC's size.
 @param key The key. @param input The message. @param nonce What `start` takes.
 @return Success, or the boundary's failure.
*/
[[nodiscard]] inline boost::system::result<void> botan_mac(
    std::string_view name, std::span<std::uint8_t> tag, std::span<std::uint8_t const> key,
    std::span<std::uint8_t const> input, std::span<std::uint8_t const> nonce) noexcept {
    botan_owned<Botan::MessageAuthenticationCode> mac_object;
    return botan_boundary([&] {
        mac_object.adopt(botan_create<Botan::MessageAuthenticationCode>(name));
        mac_object.get().set_key(key);
        mac_object.get().start(nonce);
        mac_object.get().update(input);
        mac_object.get().final(tag);
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
     The tag of `input` under `key`, the HMAC cut to `output.size()` bytes.

     @param output The tag. @param key The key. @param input The message.
     @return Success, or the boundary's failure.
    */
    template <class Options>
    [[nodiscard]] static boost::system::result<void> compute(std::span<std::uint8_t> output,
                                                             std::span<std::uint8_t const> key,
                                                             std::span<std::uint8_t const> input,
                                                             Options const& /*options*/) noexcept {
        constexpr std::uint64_t digest_size = mac_traits<macs::hmac<Digest>>::max_output;
        std::array<std::uint8_t, 64> whole{};
        static_assert(digest_size <= whole.size());
        auto const tag = std::span(whole).first(digest_size);
        std::array<std::uint8_t, 64> hashed_key{};
        auto used_key = key;
        auto computed = boost::system::result<void>{};
        if (key.size() > botan_hmac_max_key) {
            computed = digest_engine<backends::botan, Digest>::one_shot(
                std::span(hashed_key).first(digest_size), key, digest_options<Digest>{});
            used_key = std::span(hashed_key).first(digest_size);
        }
        if (computed) {
            std::string name;
            computed = botan_boundary([&] {
                name = "HMAC(";
                name.append(botan_hash_name<Digest>::value) += ')';
            });
            if (computed) {
                computed = botan_mac(name, tag, used_key, input, {});
            }
        }
        if (computed) {
            std::copy_n(tag.begin(), output.size(), output.begin());
        }
        wipe_object(whole);
        wipe_object(hashed_key);
        return computed;
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

     @param options The customisation and the form. @param key_size The key's size.
     @return Whether Botan takes them.
    */
    template <class Options>
    static constexpr bool accepts(Options const& options, std::size_t key_size,
                                  std::size_t /*output_size*/) noexcept {
        return !options.xof && key_size <= max_key;
    }

    /**
     The tag of `input` under `key`, of `output.size()` bytes, customised.

     @param output The tag. @param key The key. @param input The message.
     @param options The customisation.
     @return Success, or the boundary's failure.
    */
    template <class Options>
    [[nodiscard]] static boost::system::result<void> compute(std::span<std::uint8_t> output,
                                                             std::span<std::uint8_t const> key,
                                                             std::span<std::uint8_t const> input,
                                                             Options const& options) noexcept {
        constexpr std::string_view prefix =
            std::is_same_v<Mac, macs::kmac_128> ? "KMAC-128(" : "KMAC-256(";
        std::string name;
        auto computed = botan_boundary([&] { name = botan_sized_name(prefix, output.size() * 8); });
        if (computed) {
            computed = botan_mac(name, output, key, input, options.customisation);
        }
        return computed;
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
     The tag of `input` under `key`.

     @param output The tag. @param key The key. @param input The message.
     @return Success, or the boundary's failure.
    */
    template <class Options>
    [[nodiscard]] static boost::system::result<void> compute(std::span<std::uint8_t> output,
                                                             std::span<std::uint8_t const> key,
                                                             std::span<std::uint8_t const> input,
                                                             Options const& /*options*/) noexcept {
        return botan_mac("SipHash(2,4)", output, key, input, {});
    }
};

/**
 `macs::blake2b_mac` on backends::botan: the MAC "BLAKE2b(<bits>)" (`BLAKE2bMAC`), a key of 1 to 64
 bytes, a tag of 1 to 64 bytes.
*/
template <>
struct mac_engine<backends::botan, macs::blake2b_mac> : full_engine {
    /**
     The tag of `input` under `key`, of `output.size()` bytes.

     @param output The tag. @param key The key. @param input The message.
     @return Success, or the boundary's failure.
    */
    template <class Options>
    [[nodiscard]] static boost::system::result<void> compute(std::span<std::uint8_t> output,
                                                             std::span<std::uint8_t const> key,
                                                             std::span<std::uint8_t const> input,
                                                             Options const& /*options*/) noexcept {
        std::string name;
        auto computed =
            botan_boundary([&] { name = botan_sized_name("BLAKE2b(", output.size() * 8); });
        if (computed) {
            computed = botan_mac(name, output, key, input, {});
        }
        return computed;
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
// clang-format on

}  // namespace webcpp::hash

#endif  // WEBCPP_HASH_HAS_BOTAN

#endif  // WEBCPP_HASH_NO_EXCEPTIONS

#endif  // WEBCPP_HASH_BACKENDS_BOTAN_HPP
