// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

#ifndef WEBCPP_HASH_DETAIL_ENGINES_HPP
#define WEBCPP_HASH_DETAIL_ENGINES_HPP

#include <webcpp/hash/config.hpp>

#include <webcpp/hash/error.hpp>

#include <boost/hash2/has_constant_size.hpp>
#include <boost/hash2/hmac.hpp>
#include <boost/system/result.hpp>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <type_traits>

namespace webcpp::hash {

/**
 The parameters of a digest (spec 2.15), defined in `digest.hpp`; declared here for the engines,
 which take them.

 @tparam Digest A tag of `digests`.
*/
template <class Digest>
struct digest_options;

/**
 The parameters of a MAC (spec 2.15), defined in `mac.hpp`; declared here for the engines.

 @tparam Mac A tag of `macs`.
*/
template <class Mac>
struct mac_options;

/** Argon2's parameters (spec 2.15), defined in `argon2.hpp`; declared here for the engines. */
struct argon2_parameters;

}  // namespace webcpp::hash

namespace webcpp::hash::detail {

/** False for every `T`: a `static_assert` that fires only when its template is instantiated. */
template <class T>
inline constexpr bool always_false = false;

/** No limit beyond the spec's own: the largest 64-bit size. */
inline constexpr std::uint64_t no_limit = std::numeric_limits<std::uint64_t>::max();

/**
 The longest input and output a backend's C library takes, in bytes, where its interface holds a
 length in a narrower type than `std::size_t`. The public functions' guards read it
 after the spec's own guards and before any call of the backend, and refuse a longer output with
 `invalid_output_size`, a longer input with `input_too_long` and more iterations with
 `invalid_iterations`, the output untouched. The
 primary template, every backend's unless its header specialises it, has no limit; a
 specialisation gives every member.

 @tparam Backend A backend of `backends`.
*/
template <class Backend>
struct backend_limits {
    /** HKDF's salt (`hkdf_extract`, `hkdf`). */
    static constexpr std::uint64_t hkdf_salt = no_limit;
    /** HKDF's input keying material (`hkdf_extract`, `hkdf`). */
    static constexpr std::uint64_t hkdf_ikm = no_limit;
    /** HKDF's pseudorandom key (`hkdf_expand`). */
    static constexpr std::uint64_t hkdf_prk = no_limit;
    /** HKDF's info (`hkdf_expand`, `hkdf`), within `hkdf_max_info_size`. */
    static constexpr std::uint64_t hkdf_info = no_limit;
    /** HKDF's output (`hkdf_expand`, `hkdf`), within 255 digests. */
    static constexpr std::uint64_t hkdf_output = no_limit;
    /** PBKDF2's password. */
    static constexpr std::uint64_t pbkdf2_password = no_limit;
    /** PBKDF2's salt. */
    static constexpr std::uint64_t pbkdf2_salt = no_limit;
    /** PBKDF2's output, within (2^32 - 1) digests. */
    static constexpr std::uint64_t pbkdf2_output = no_limit;
    /**
     PBKDF2's iteration count (`invalid_iterations` beyond it); a specialisation that does not
     declare it has no limit of iterations.
    */
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
 The HKDF of a backend over an hmac (spec section 2.12), which the backend's header specialises
 for each hmac it has. The primary template is reached only by a backend without HKDF, and
 refuses with spec 3.3's text.

 A specialisation has three static member functions, each `noexcept`, called by the public
 functions of `hkdf.hpp` only after every guard of spec 2.8 has passed; an engine does the work
 and no check, and wipes every intermediate it makes, on success and on failure:

 @code
 using digest_type = typename Hmac::result_type;
 // RFC 5869 2.2: the PRK of `ikm` under `salt` (empty: HashLen zeros).
 static boost::system::result<digest_type> extract(std::span<std::uint8_t const> salt,
                                                   std::span<std::uint8_t const> ikm) noexcept;
 // RFC 5869 2.3: `output` (1 to 255 digests) from `prk` (one digest) and `info` (at most
 // hkdf_max_info_size bytes).
 static boost::system::result<void> expand(std::span<std::uint8_t> output,
                                           std::span<std::uint8_t const> prk,
                                           std::span<std::uint8_t const> info) noexcept;
 // Both steps.
 static boost::system::result<void> extract_and_expand(std::span<std::uint8_t> output,
                                                       std::span<std::uint8_t const> salt,
                                                       std::span<std::uint8_t const> ikm,
                                                       std::span<std::uint8_t const> info) noexcept;
 @endcode

 A failure is `error::backend_failure`, or `errc::not_enough_memory` when the library could not
 allocate; the public function then zeroes the output. A backend that has `hkdf` alone
 (BearSSL) gives `extract` and `expand` a `static_assert` of their own (spec 3.3).

 @tparam Backend A backend of `backends`. @tparam Hmac A Boost.Hash2 hmac over a digest.
*/
template <class Backend, class Hmac>
struct hkdf_engine {
    // clang-format off
    static_assert(!std::is_same_v<Backend, backends::webcrypto>,
                  "webcpp::hash: backends::webcrypto is asynchronous: call async_hkdf (or async_pbkdf2, async_digest, async_hmac) with a completion token, or name a synchronous backend.");
    // clang-format on
    static_assert(
        std::is_same_v<Backend, backends::webcrypto>,
        "webcpp::hash: this backend has no HKDF. The backends that have HKDF: "
        "backends::hash2 (every hmac), backends::openssl (every hmac but "
        "hmac_ripemd_128), backends::sodium (hmac_sha2_256, hmac_sha2_512) and "
        "backends::bearssl (MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512; hkdf alone).");
};

/**
 The PBKDF2 of a backend over an hmac (spec section 2.12), specialised as @ref hkdf_engine is.
 A specialisation has one static member function, called after the guards of spec 2.9:

 @code
 // RFC 8018 5.2: `output` (1 to (2^32 - 1) digests) from `password` and `salt`, by
 // `iterations` (at least 1) rounds of Hmac.
 static boost::system::result<void> derive(std::span<std::uint8_t> output,
                                           std::span<std::uint8_t const> password,
                                           std::span<std::uint8_t const> salt,
                                           std::uint64_t iterations) noexcept;
 @endcode

 @tparam Backend A backend of `backends`. @tparam Hmac A Boost.Hash2 hmac over a digest.
*/
template <class Backend, class Hmac>
struct pbkdf2_engine {
    // clang-format off
    static_assert(!std::is_same_v<Backend, backends::webcrypto>,
                  "webcpp::hash: backends::webcrypto is asynchronous: call async_hkdf (or async_pbkdf2, async_digest, async_hmac) with a completion token, or name a synchronous backend.");
    // clang-format on
    static_assert(std::is_same_v<Backend, backends::webcrypto>,
                  "webcpp::hash: this backend has no PBKDF2. The backends that have pbkdf2: "
                  "backends::hash2 (every hmac) and backends::openssl (every hmac but "
                  "hmac_ripemd_128).");
};

/** The costs an Argon2id engine accepts beyond spec section 2.10's lower bounds. */
struct argon2id_limits {
    /** The most memory, in bytes (libsodium's `crypto_pwhash_argon2id_MEMLIMIT_MAX`). */
    std::uint64_t memory;
};

/** The costs a scrypt engine accepts beyond RFC 7914's conditions. */
struct scrypt_limits {
    /** The largest N (libsodium's `_ll` refuses an N above `UINT32_MAX`). */
    std::uint64_t n;
};

/**
 The Argon2id of a backend (spec sections 2.10 and 2.12), which `backends::sodium` alone
 specialises. The primary template refuses every other backend with spec 3.3's text; its members
 exist so that the refusal is the only error.

 A specialisation has a constant and a static member function, called by `argon2id` only after
 every guard of spec 2.10 has passed, the memory a multiple of 1,024 bytes within `limits`:

 @code
 static constexpr argon2id_limits limits{...};
 static boost::system::result<void> derive(std::span<std::uint8_t> output,
                                           std::span<std::uint8_t const> password,
                                           std::span<std::uint8_t const> salt,
                                           std::uint64_t passes, std::size_t memory) noexcept;
 @endcode

 A failure is `error::backend_failure`, or `errc::not_enough_memory` when the library could not
 allocate; the public function then zeroes the output.

 @tparam Backend A backend of `backends`.
*/
template <class Backend>
struct argon2id_engine {
    // backends::sodium, the default, reaches this template only when the program does not link
    // libsodium, whose header specialises it: the refusal is then sodium.hpp's own (spec 5.7).
    static_assert(!std::is_same_v<Backend, backends::sodium>,
                  "webcpp::hash: backends::sodium, argon2id and scrypt need libsodium. Add "
                  "/third_party//sodium to the program's Jamfile: exe app : app.cpp "
                  "/webcpp/hash//hash /third_party//sodium ;");
    static_assert(std::is_same_v<Backend, backends::sodium>,
                  "webcpp::hash: argon2id is in backends::sodium alone. Name backends::sodium "
                  "and add /third_party//sodium to the program's Jamfile.");

    /** Never read: the refusal has stopped the build. */
    static constexpr argon2id_limits limits{0};

    /** Never called: the refusal has stopped the build. */
    [[nodiscard]] static boost::system::result<void> derive(
        std::span<std::uint8_t> /*output_bytes*/, std::span<std::uint8_t const> /*password_bytes*/,
        std::span<std::uint8_t const> /*salt_bytes*/, std::uint64_t /*pass_count*/,
        std::size_t /*memory_limit*/) noexcept {
        return error::backend_failure;
    }
};

/**
 The scrypt of a backend (spec sections 2.11 and 2.12), which `backends::sodium` alone
 specialises, as @ref argon2id_engine is. A specialisation's `derive` is called by `scrypt` only
 after every guard of spec 2.11 has passed, N within `limits`:

 @code
 static constexpr scrypt_limits limits{...};
 static boost::system::result<void> derive(std::span<std::uint8_t> output,
                                           std::span<std::uint8_t const> password,
                                           std::span<std::uint8_t const> salt, std::uint64_t n,
                                           std::uint32_t r, std::uint32_t p) noexcept;
 @endcode

 @tparam Backend A backend of `backends`.
*/
template <class Backend>
struct scrypt_engine {
    // backends::sodium, the default, reaches this template only when the program does not link
    // libsodium, whose header specialises it: the refusal is then sodium.hpp's own (spec 5.7).
    static_assert(!std::is_same_v<Backend, backends::sodium>,
                  "webcpp::hash: backends::sodium, argon2id and scrypt need libsodium. Add "
                  "/third_party//sodium to the program's Jamfile: exe app : app.cpp "
                  "/webcpp/hash//hash /third_party//sodium ;");
    static_assert(std::is_same_v<Backend, backends::sodium>,
                  "webcpp::hash: scrypt is in backends::sodium alone. Name backends::sodium and "
                  "add /third_party//sodium to the program's Jamfile.");

    /** Never read: the refusal has stopped the build. */
    static constexpr scrypt_limits limits{0};

    /** Never called: the refusal has stopped the build. */
    [[nodiscard]] static boost::system::result<void> derive(
        std::span<std::uint8_t> /*output_bytes*/, std::span<std::uint8_t const> /*password_bytes*/,
        std::span<std::uint8_t const> /*salt_bytes*/, std::uint64_t /*cost_n*/,
        std::uint32_t /*block_size_r*/, std::uint32_t /*parallelism_p*/) noexcept {
        return error::backend_failure;
    }
};

/**
 Whether `Hmac` is a Boost.Hash2 hmac over a hash whose result is a digest: what every key
 derivation takes (spec section 3.3).

 @tparam Hmac Any type.
*/
template <class Hmac>
struct is_digest_hmac : std::false_type {};

/** A Boost.Hash2 hmac is a digest hmac when its hash's result has a constant size. */
template <class H>
struct is_digest_hmac<boost::hash2::hmac<H>>
    : std::bool_constant<boost::hash2::has_constant_size<typename H::result_type>::value &&
                         !std::is_integral_v<typename H::result_type>> {};

/** Whether the program links `Backend`: backends::hash2 always, another when its target says so. */
template <class Backend>
inline constexpr bool linked_v = false;

/** backends::hash2 needs no library. */
template <>
inline constexpr bool linked_v<backends::hash2> = true;

#ifdef WEBCPP_HASH_HAS_XKCP
/** `/third_party//xkcp` defines `WEBCPP_HASH_HAS_XKCP`. */
template <>
inline constexpr bool linked_v<backends::xkcp> = true;
#endif

#ifdef WEBCPP_HASH_HAS_BLAKE3
/** `/third_party//blake3` defines `WEBCPP_HASH_HAS_BLAKE3`. */
template <>
inline constexpr bool linked_v<backends::blake3> = true;
#endif

#ifdef WEBCPP_HASH_HAS_SODIUM
/** `/third_party//sodium` defines `WEBCPP_HASH_HAS_SODIUM`. */
template <>
inline constexpr bool linked_v<backends::sodium> = true;
#endif

#ifdef WEBCPP_HASH_HAS_BEARSSL
/** `/third_party//bearssl` defines `WEBCPP_HASH_HAS_BEARSSL`. */
template <>
inline constexpr bool linked_v<backends::bearssl> = true;
#endif

#ifdef WEBCPP_HASH_HAS_OPENSSL
/** `/webcpp/hash//openssl` defines `WEBCPP_HASH_HAS_OPENSSL`. */
template <>
inline constexpr bool linked_v<backends::openssl> = true;
#endif

/**
 The default backend of a tag that has none (spec 4.1, design D34): no backend of
 `backends::hash2`, `backends::xkcp`, `backends::blake3` and `backends::sodium` has it, so a call
 names its backend. Each family's engines refuse it with the text "... has no default backend.
 Name one of: ...".
*/
struct no_default {};

/** Whether `Backend` is the backend of a C library, which a program links by its Jamfile line. */
template <class Backend>
inline constexpr bool library_backend_v =
    std::is_same_v<Backend, backends::xkcp> || std::is_same_v<Backend, backends::blake3> ||
    std::is_same_v<Backend, backends::sodium> || std::is_same_v<Backend, backends::bearssl> ||
    std::is_same_v<Backend, backends::openssl>;

/** Whether `Backend` is a C library's backend that the program does not link. */
template <class Backend>
inline constexpr bool missing_library_v = library_backend_v<Backend> && !linked_v<Backend>;

/**
 Whether the refusal of a family's tag on `Backend` is another text than the tag's own "not in
 this backend": @ref needs_library's, for a library the program does not link or for
 `backends::webcrypto`, which no synchronous function takes, or the tag's "no default backend",
 for @ref no_default. Each tag's refusal states its text only when this is false, so that a
 refused call shows one message.
*/
template <class Backend>
inline constexpr bool refused_elsewhere_v =
    missing_library_v<Backend> || std::is_same_v<Backend, no_default> ||
    std::is_same_v<Backend, backends::webcrypto>;

/**
 Stops a call of the families on a C library's backend that the program does not link, with the
 Jamfile line to add (spec 5.7), whichever tag the call names: the backend's header, which holds
 its engines, is included only when the program links it; and a call on `backends::webcrypto`,
 which only the asynchronous family takes (spec 11.2), on every target. A base of each tag's
 refusal; it is empty for every other backend.

 @tparam Backend A backend of `backends`.
*/
template <class Backend>
struct needs_library {
    // clang-format off
    static_assert(!(std::is_same_v<Backend, backends::xkcp> && missing_library_v<Backend>),
                  "webcpp::hash: backends::xkcp needs XKCP. Add /third_party//xkcp to the program's Jamfile: exe app : app.cpp /webcpp/hash//hash /third_party//xkcp ;");
    static_assert(!(std::is_same_v<Backend, backends::blake3> && missing_library_v<Backend>),
                  "webcpp::hash: backends::blake3 needs BLAKE3's C implementation. Add /third_party//blake3 to the program's Jamfile: exe app : app.cpp /webcpp/hash//hash /third_party//blake3 ;");
    static_assert(!(std::is_same_v<Backend, backends::sodium> && missing_library_v<Backend>),
                  "webcpp::hash: backends::sodium, argon2id and scrypt need libsodium. Add /third_party//sodium to the program's Jamfile: exe app : app.cpp /webcpp/hash//hash /third_party//sodium ;");
    static_assert(!(std::is_same_v<Backend, backends::bearssl> && missing_library_v<Backend>),
                  "webcpp::hash: backends::bearssl needs BearSSL. Add /third_party//bearssl to the program's Jamfile: exe app : app.cpp /webcpp/hash//hash /third_party//bearssl ;");
    static_assert(!(std::is_same_v<Backend, backends::openssl> && missing_library_v<Backend>),
                  "webcpp::hash: backends::openssl needs OpenSSL. Add /webcpp/hash//openssl to the program's Jamfile (native, wasip2 and wasip3): exe app : app.cpp /webcpp/hash//hash /webcpp/hash//openssl ;");
    static_assert(!std::is_same_v<Backend, backends::webcrypto>,
                  "webcpp::hash: backends::webcrypto is asynchronous: call async_hkdf (or async_pbkdf2, async_digest, async_hmac) with a completion token, or name a synchronous backend.");
    // clang-format on
};

/**
 What an engine that serves every value the family's guards accept declares (spec 2.15): no
 narrower limit. A digest or MAC engine inherits it, or declares the same members with its own
 limits, which the public functions read after their own guards and answer with
 `error::unsupported_by_backend` (rulings R14, R41).
*/
struct full_engine {
    /** The shortest output the engine produces: the family's own limit. */
    static constexpr std::uint64_t min_output = 0;

    /** The longest output the engine produces: the family's own limit. */
    static constexpr std::uint64_t max_output = no_limit;

    /**
     Whether the engine takes these options (a digest's): every option, here.

     @return true.
    */
    template <class Options>
    static constexpr bool accepts(Options const& /*options*/) noexcept {
        return true;
    }

    /**
     Whether the engine takes these options, key size and output size (a MAC's): all, here.

     @return true.
    */
    template <class Options>
    static constexpr bool accepts(Options const& /*options*/, std::size_t /*key_size*/,
                                  std::size_t /*output_size*/) noexcept {
        return true;
    }
};

/**
 The digest of a backend (spec 2.15), behind `digest_of` and `hasher`, which the backend's header
 specialises fully for each tag of `digests` it has (one tag at a time: a partial specialisation
 over several tags would be ambiguous with the tags' refusals below). The primary template is
 reached only by a type that is not a tag of `digests`, which it refuses; each tag's partial
 specialisation below refuses a backend without the tag, naming those that have it.

 A specialisation has these members, each function `noexcept`, called by the public functions
 only after every guard of the family has passed (the output size within the tag's
 `detail::digest_traits` and within `min_output` and `max_output`, the options checked by the traits
 and accepted by `accepts`); an engine does the work and no check, and wipes every intermediate it
 makes:

 @code
 // The incremental state: default-constructible, nothrow move-constructible and move-assignable.
 // It may own a resource (OpenSSL's EVP_MD_CTX*, a Botan object); a moved-from state owns none.
 using state = ...;
 // The shortest and the longest output the backend produces, 0 and no_limit when they are the
 // family's (a fixed-size digest's guards already hold the output to its size); an output outside
 // them is unsupported_by_backend.
 static constexpr std::uint64_t min_output = ...;
 static constexpr std::uint64_t max_output = ...;
 // Whether the backend takes these options, every one the family accepts or fewer.
 static bool accepts(digest_options<Digest> const& options) noexcept;
 // Starts a hash in `hashed`, a default-constructed state.
 static boost::system::result<void> init(state& hashed, digest_options<Digest> const& options)
 noexcept;
 // Absorbs `input`, of any size.
 static boost::system::result<void> update(state& hashed, std::span<std::uint8_t const> input)
 noexcept;
 // Writes the result, of output.size() bytes; called once per init.
 static boost::system::result<void> finish(state& hashed, std::span<std::uint8_t> output) noexcept;
 // Wipes the state and frees what it owns: called once after every init, whether init, update
 // and finish succeeded or not, and on each state moved from; a second call does nothing.
 static void destroy(state& hashed) noexcept;
 // init, update and finish at once, the state wiped.
 static boost::system::result<void> one_shot(std::span<std::uint8_t> output,
                                             std::span<std::uint8_t const> input,
                                             digest_options<Digest> const& options) noexcept;
 @endcode

 @ref full_engine gives `min_output`, `max_output` and `accepts` to an engine without narrower
 limits. A failure is `error::backend_failure`, or `errc::not_enough_memory` when the library could
 not allocate;
 the public function then zeroes the output, and a `hasher` is spent.

 @tparam Backend A backend of `backends`. @tparam Digest A tag of `digests`.
*/
template <class Backend, class Digest>
struct digest_engine;

/**
 The members a refused digest engine gives, so that its refusal is the only error of the call:
 never called, since the refusal has stopped the build.

 @tparam Digest The tag refused.
*/
template <class Digest>
struct refused_digest_engine : full_engine {
    /** No state. */
    struct state {};

    /** Never called. @return backend_failure. */
    [[nodiscard]] static boost::system::result<void> init(
        state& /*hashed*/, digest_options<Digest> const& /*options*/) noexcept {
        return error::backend_failure;
    }

    /** Never called. @return backend_failure. */
    [[nodiscard]] static boost::system::result<void> update(
        state& /*hashed*/, std::span<std::uint8_t const> /*input*/) noexcept {
        return error::backend_failure;
    }

    /** Never called. @return backend_failure. */
    [[nodiscard]] static boost::system::result<void> finish(
        state& /*hashed*/, std::span<std::uint8_t> /*output*/) noexcept {
        return error::backend_failure;
    }

    /** Never called. */
    static void destroy(state& /*hashed*/) noexcept {}

    /** Never called. @return backend_failure. */
    [[nodiscard]] static boost::system::result<void> one_shot(
        std::span<std::uint8_t> /*output*/, std::span<std::uint8_t const> /*input*/,
        digest_options<Digest> const& /*options*/) noexcept {
        return error::backend_failure;
    }
};

/** A type that is not a tag of `digests`: refused (spec 3.3). */
template <class Backend, class Digest>
struct digest_engine : refused_digest_engine<Digest> {
    static_assert(always_false<Digest>,
                  "webcpp::hash: digest_of and hasher take a tag of webcpp::hash::digests, as "
                  "digests::sha2_256.");
};

// The refusal of each tag of `digests` on a backend that lacks it (spec 3.3): the text names the
// backends of its row of doc/capabilities.json, which capabilities_test checks.

/** `digests::md5` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::md5> : refused_digest_engine<digests::md5>,
                                              needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::md5 is not in this backend. Name one of: "
                  "backends::hash2.");
};

/** `digests::sha1` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::sha1> : refused_digest_engine<digests::sha1>,
                                               needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::sha1 is not in this backend. Name one of: "
                  "backends::hash2.");
};

/** `digests::sha2_224` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::sha2_224> : refused_digest_engine<digests::sha2_224>,
                                                   needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::sha2_224 is not in this backend. Name one of: "
                  "backends::hash2.");
};

/** `digests::sha2_256` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::sha2_256> : refused_digest_engine<digests::sha2_256>,
                                                   needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::sha2_256 is not in this backend. Name one of: "
                  "backends::hash2.");
};

/** `digests::sha2_384` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::sha2_384> : refused_digest_engine<digests::sha2_384>,
                                                   needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::sha2_384 is not in this backend. Name one of: "
                  "backends::hash2.");
};

/** `digests::sha2_512` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::sha2_512> : refused_digest_engine<digests::sha2_512>,
                                                   needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::sha2_512 is not in this backend. Name one of: "
                  "backends::hash2.");
};

/** `digests::sha2_512_224` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::sha2_512_224> : refused_digest_engine<digests::sha2_512_224>,
                                                       needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::sha2_512_224 is not in this backend. Name one of: "
                  "backends::hash2.");
};

/** `digests::sha2_512_256` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::sha2_512_256> : refused_digest_engine<digests::sha2_512_256>,
                                                       needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::sha2_512_256 is not in this backend. Name one of: "
                  "backends::hash2.");
};

/** `digests::sha3_224` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::sha3_224> : refused_digest_engine<digests::sha3_224>,
                                                   needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::sha3_224 is not in this backend. Name one of: "
                  "backends::hash2.");
};

/** `digests::sha3_256` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::sha3_256> : refused_digest_engine<digests::sha3_256>,
                                                   needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::sha3_256 is not in this backend. Name one of: "
                  "backends::hash2.");
};

/** `digests::sha3_384` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::sha3_384> : refused_digest_engine<digests::sha3_384>,
                                                   needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::sha3_384 is not in this backend. Name one of: "
                  "backends::hash2.");
};

/** `digests::sha3_512` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::sha3_512> : refused_digest_engine<digests::sha3_512>,
                                                   needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::sha3_512 is not in this backend. Name one of: "
                  "backends::hash2.");
};

/** `digests::shake_128` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::shake_128> : refused_digest_engine<digests::shake_128>,
                                                    needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::shake_128 is not in this backend. Name one of: "
                  "backends::hash2 (at most 32 bytes).");
};

/** `digests::shake_256` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::shake_256> : refused_digest_engine<digests::shake_256>,
                                                    needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::shake_256 is not in this backend. Name one of: "
                  "backends::hash2 (at most 64 bytes).");
};

/** `digests::keccak_224` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::keccak_224> : refused_digest_engine<digests::keccak_224>,
                                                     needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::keccak_224 is in no backend yet.");
};

/** `digests::keccak_256` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::keccak_256> : refused_digest_engine<digests::keccak_256>,
                                                     needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::keccak_256 is not in this backend. Name one of: "
                  "backends::xkcp.");
};

/** `digests::keccak_384` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::keccak_384> : refused_digest_engine<digests::keccak_384>,
                                                     needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::keccak_384 is in no backend yet.");
};

/** `digests::keccak_512` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::keccak_512> : refused_digest_engine<digests::keccak_512>,
                                                     needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::keccak_512 is in no backend yet.");
};

/** `digests::cshake_128` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::cshake_128> : refused_digest_engine<digests::cshake_128>,
                                                     needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::cshake_128 is in no backend yet.");
};

/** `digests::cshake_256` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::cshake_256> : refused_digest_engine<digests::cshake_256>,
                                                     needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::cshake_256 is in no backend yet.");
};

/** `digests::kt128` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::kt128> : refused_digest_engine<digests::kt128>,
                                                needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::kt128 is in no backend yet.");
};

/** `digests::kt256` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::kt256> : refused_digest_engine<digests::kt256>,
                                                needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::kt256 is in no backend yet.");
};

/** `digests::turboshake_128` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::turboshake_128>
    : refused_digest_engine<digests::turboshake_128>, needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::turboshake_128 is in no backend yet.");
};

/** `digests::turboshake_256` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::turboshake_256>
    : refused_digest_engine<digests::turboshake_256>, needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::turboshake_256 is in no backend yet.");
};

/** `digests::tuplehash_128` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::tuplehash_128>
    : refused_digest_engine<digests::tuplehash_128>, needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::tuplehash_128 is in no backend yet.");
};

/** `digests::tuplehash_256` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::tuplehash_256>
    : refused_digest_engine<digests::tuplehash_256>, needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::tuplehash_256 is in no backend yet.");
};

/** `digests::parallelhash_128` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::parallelhash_128>
    : refused_digest_engine<digests::parallelhash_128>, needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::parallelhash_128 is in no backend yet.");
};

/** `digests::parallelhash_256` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::parallelhash_256>
    : refused_digest_engine<digests::parallelhash_256>, needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::parallelhash_256 is in no backend yet.");
};

/** `digests::blake2b` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::blake2b> : refused_digest_engine<digests::blake2b>,
                                                  needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::blake2b is not in this backend. Name one of: "
                  "backends::hash2.");
};

/** `digests::blake2s_256` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::blake2s_256> : refused_digest_engine<digests::blake2s_256>,
                                                      needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::blake2s_256 is not in this backend. Name one of: "
                  "backends::hash2.");
};

/** `digests::blake3` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::blake3> : refused_digest_engine<digests::blake3>,
                                                 needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::blake3 is not in this backend. Name one of: "
                  "backends::blake3.");
};

/** `digests::ripemd_160` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::ripemd_160> : refused_digest_engine<digests::ripemd_160>,
                                                     needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::ripemd_160 is not in this backend. Name one of: "
                  "backends::hash2.");
};

/** `digests::md5_sha1` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::md5_sha1> : refused_digest_engine<digests::md5_sha1>,
                                                   needs_library<Backend> {
    static_assert(!std::is_same_v<Backend, no_default>,
                  "webcpp::hash: digests::md5_sha1 has no default backend, and no backend has it "
                  "yet.");
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::md5_sha1 is in no backend yet.");
};

/** `digests::sm3` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::sm3> : refused_digest_engine<digests::sm3>,
                                              needs_library<Backend> {
    static_assert(!std::is_same_v<Backend, no_default>,
                  "webcpp::hash: digests::sm3 has no default backend, and no backend has it yet.");
    static_assert(refused_elsewhere_v<Backend>, "webcpp::hash: digests::sm3 is in no backend yet.");
};

/** `digests::streebog_256` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::streebog_256> : refused_digest_engine<digests::streebog_256>,
                                                       needs_library<Backend> {
    static_assert(!std::is_same_v<Backend, no_default>,
                  "webcpp::hash: digests::streebog_256 has no default backend, and no backend has "
                  "it yet.");
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::streebog_256 is in no backend yet.");
};

/** `digests::streebog_512` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::streebog_512> : refused_digest_engine<digests::streebog_512>,
                                                       needs_library<Backend> {
    static_assert(!std::is_same_v<Backend, no_default>,
                  "webcpp::hash: digests::streebog_512 has no default backend, and no backend has "
                  "it yet.");
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::streebog_512 is in no backend yet.");
};

/** `digests::whirlpool` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::whirlpool> : refused_digest_engine<digests::whirlpool>,
                                                    needs_library<Backend> {
    static_assert(!std::is_same_v<Backend, no_default>,
                  "webcpp::hash: digests::whirlpool has no default backend, and no backend has it "
                  "yet.");
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::whirlpool is in no backend yet.");
};

/** `digests::skein_512` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct digest_engine<Backend, digests::skein_512> : refused_digest_engine<digests::skein_512>,
                                                    needs_library<Backend> {
    static_assert(!std::is_same_v<Backend, no_default>,
                  "webcpp::hash: digests::skein_512 has no default backend, and no backend has it "
                  "yet.");
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: digests::skein_512 is in no backend yet.");
};

/**
 The MAC of a backend (spec 2.15), behind `mac`, which the backend's header specialises fully for
 each tag of `macs` it has, as @ref digest_engine is. The primary template is reached only by a
 type that is not a tag of `macs`, which it refuses; each tag's partial specialisation below
 refuses a backend without the tag, naming those that have it, and `macs::hmac<D>` over a digest
 no backend has HMAC over refuses with its own text.

 A specialisation has these members, each function `noexcept`, called by `mac` only after every
 guard of the family has passed (the output and key sizes within the tag's `detail::mac_traits`,
 the options checked by the traits and accepted by `accepts`):

 @code
 // Whether the backend takes these options, a key of key_size bytes and a tag of output_size
 // bytes, every one the family accepts or fewer; refused: unsupported_by_backend.
 static bool accepts(mac_options<Mac> const& options, std::size_t key_size,
                     std::size_t output_size) noexcept;
 // The tag of `input` under `key`, of output.size() bytes (for HMAC, the digest cut to it: RFC
 2104,
 // section 5), every intermediate wiped.
 static boost::system::result<void> compute(std::span<std::uint8_t> output,
                                            std::span<std::uint8_t const> key,
                                            std::span<std::uint8_t const> input,
                                            mac_options<Mac> const& options) noexcept;
 @endcode

 @ref full_engine gives `accepts` to an engine without narrower limits. A failure is
 `error::backend_failure`, or `errc::not_enough_memory`; `mac` then zeroes the output.

 @tparam Backend A backend of `backends`. @tparam Mac A tag of `macs`.
*/
template <class Backend, class Mac>
struct mac_engine;

/**
 The members a refused MAC engine gives, so that its refusal is the only error of the call.

 @tparam Mac The tag refused.
*/
template <class Mac>
struct refused_mac_engine : full_engine {
    /** Never called. @return backend_failure. */
    [[nodiscard]] static boost::system::result<void> compute(
        std::span<std::uint8_t> /*output*/, std::span<std::uint8_t const> /*key*/,
        std::span<std::uint8_t const> /*input*/, mac_options<Mac> const& /*options*/) noexcept {
        return error::backend_failure;
    }
};

/** A type that is not a tag of `macs`: refused (spec 3.3). */
template <class Backend, class Mac>
struct mac_engine : refused_mac_engine<Mac> {
    static_assert(always_false<Mac>,
                  "webcpp::hash: mac takes a tag of webcpp::hash::macs, as "
                  "macs::hmac<digests::sha2_256>.");
};

/** HMAC over a digest no backend has HMAC over (spec 3.3). */
template <class Backend, class Digest>
struct mac_engine<Backend, macs::hmac<Digest>> : refused_mac_engine<macs::hmac<Digest>>,
                                                 needs_library<Backend> {
    static_assert(!std::is_same_v<Backend, no_default>,
                  "webcpp::hash: macs::hmac over this digest has no default backend, and no "
                  "backend has it yet.");
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: macs::hmac over this digest is in no backend yet.");
};

// The refusal of each tag of `macs` on a backend that lacks it (spec 3.3), as the digests'.

/** `macs::hmac<digests::md5>` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct mac_engine<Backend, macs::hmac<digests::md5>> : refused_mac_engine<macs::hmac<digests::md5>>,
                                                       needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: macs::hmac<digests::md5> is not in this backend. Name one of: "
                  "backends::hash2.");
};

/** `macs::hmac<digests::sha1>` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct mac_engine<Backend, macs::hmac<digests::sha1>>
    : refused_mac_engine<macs::hmac<digests::sha1>>, needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: macs::hmac<digests::sha1> is not in this backend. Name one of: "
                  "backends::hash2.");
};

/** `macs::hmac<digests::sha2_224>` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct mac_engine<Backend, macs::hmac<digests::sha2_224>>
    : refused_mac_engine<macs::hmac<digests::sha2_224>>, needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: macs::hmac<digests::sha2_224> is not in this backend. Name one "
                  "of: backends::hash2.");
};

/** `macs::hmac<digests::sha2_256>` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct mac_engine<Backend, macs::hmac<digests::sha2_256>>
    : refused_mac_engine<macs::hmac<digests::sha2_256>>, needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: macs::hmac<digests::sha2_256> is not in this backend. Name one "
                  "of: backends::hash2.");
};

/** `macs::hmac<digests::sha2_384>` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct mac_engine<Backend, macs::hmac<digests::sha2_384>>
    : refused_mac_engine<macs::hmac<digests::sha2_384>>, needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: macs::hmac<digests::sha2_384> is not in this backend. Name one "
                  "of: backends::hash2.");
};

/** `macs::hmac<digests::sha2_512>` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct mac_engine<Backend, macs::hmac<digests::sha2_512>>
    : refused_mac_engine<macs::hmac<digests::sha2_512>>, needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: macs::hmac<digests::sha2_512> is not in this backend. Name one "
                  "of: backends::hash2.");
};

/** `macs::hmac<digests::sha2_512_224>` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct mac_engine<Backend, macs::hmac<digests::sha2_512_224>>
    : refused_mac_engine<macs::hmac<digests::sha2_512_224>>, needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: macs::hmac<digests::sha2_512_224> is not in this backend. Name "
                  "one of: backends::hash2.");
};

/** `macs::hmac<digests::sha2_512_256>` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct mac_engine<Backend, macs::hmac<digests::sha2_512_256>>
    : refused_mac_engine<macs::hmac<digests::sha2_512_256>>, needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: macs::hmac<digests::sha2_512_256> is not in this backend. Name "
                  "one of: backends::hash2.");
};

/** `macs::hmac<digests::sha3_224>` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct mac_engine<Backend, macs::hmac<digests::sha3_224>>
    : refused_mac_engine<macs::hmac<digests::sha3_224>>, needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: macs::hmac<digests::sha3_224> is not in this backend. Name one "
                  "of: backends::hash2.");
};

/** `macs::hmac<digests::sha3_256>` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct mac_engine<Backend, macs::hmac<digests::sha3_256>>
    : refused_mac_engine<macs::hmac<digests::sha3_256>>, needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: macs::hmac<digests::sha3_256> is not in this backend. Name one "
                  "of: backends::hash2.");
};

/** `macs::hmac<digests::sha3_384>` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct mac_engine<Backend, macs::hmac<digests::sha3_384>>
    : refused_mac_engine<macs::hmac<digests::sha3_384>>, needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: macs::hmac<digests::sha3_384> is not in this backend. Name one "
                  "of: backends::hash2.");
};

/** `macs::hmac<digests::sha3_512>` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct mac_engine<Backend, macs::hmac<digests::sha3_512>>
    : refused_mac_engine<macs::hmac<digests::sha3_512>>, needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: macs::hmac<digests::sha3_512> is not in this backend. Name one "
                  "of: backends::hash2.");
};

/** `macs::hmac<digests::ripemd_160>` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct mac_engine<Backend, macs::hmac<digests::ripemd_160>>
    : refused_mac_engine<macs::hmac<digests::ripemd_160>>, needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: macs::hmac<digests::ripemd_160> is not in this backend. Name one "
                  "of: backends::hash2.");
};

/** `macs::hmac<digests::blake2b>` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct mac_engine<Backend, macs::hmac<digests::blake2b>>
    : refused_mac_engine<macs::hmac<digests::blake2b>>, needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: macs::hmac<digests::blake2b> is not in this backend. Name one "
                  "of: backends::hash2.");
};

/** `macs::hmac<digests::blake2s_256>` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct mac_engine<Backend, macs::hmac<digests::blake2s_256>>
    : refused_mac_engine<macs::hmac<digests::blake2s_256>>, needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: macs::hmac<digests::blake2s_256> is not in this backend. Name "
                  "one of: backends::hash2.");
};

/** `macs::kmac_128` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct mac_engine<Backend, macs::kmac_128> : refused_mac_engine<macs::kmac_128>,
                                             needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: macs::kmac_128 is in no backend yet.");
};

/** `macs::kmac_256` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct mac_engine<Backend, macs::kmac_256> : refused_mac_engine<macs::kmac_256>,
                                             needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: macs::kmac_256 is in no backend yet.");
};

/** `macs::siphash_2_4` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct mac_engine<Backend, macs::siphash_2_4> : refused_mac_engine<macs::siphash_2_4>,
                                                needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: macs::siphash_2_4 is not in this backend. Name one of: "
                  "backends::hash2.");
};

/** `macs::siphash_2_4x` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct mac_engine<Backend, macs::siphash_2_4x> : refused_mac_engine<macs::siphash_2_4x>,
                                                 needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: macs::siphash_2_4x is in no backend yet.");
};

/** `macs::blake2b_mac` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct mac_engine<Backend, macs::blake2b_mac> : refused_mac_engine<macs::blake2b_mac>,
                                                needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: macs::blake2b_mac is in no backend yet.");
};

/** `macs::blake2s_mac` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct mac_engine<Backend, macs::blake2s_mac> : refused_mac_engine<macs::blake2s_mac>,
                                                needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: macs::blake2s_mac is not in this backend. Name one of: "
                  "backends::hash2.");
};

/**
 The values of RFC 9106 an Argon2 engine takes, within those `argon2` accepts (spec 2.15): a value
 the family accepts outside them is `error::unsupported_by_backend` (rulings R16, R24). Each
 member's default is RFC 9106's own bound, which an engine without that limit keeps.
*/
struct argon2_limits {
    /** The fewest passes, t (RFC 9106: 1). */
    std::uint32_t min_passes = 1;
    /** The most memory, m, in KiB (RFC 9106: 2^32 - 1). */
    std::uint32_t max_memory_kib = 0xffffffffU;
    /** The most lanes, p (RFC 9106: 2^24 - 1). */
    std::uint32_t max_lanes = 0xffffffU;
    /** The shortest tag, in bytes (RFC 9106: 4). */
    std::uint64_t min_output = 4;
    /** The shortest salt, in bytes (RFC 9106: 8). */
    std::uint64_t min_salt = 8;
    /** The longest salt, in bytes (RFC 9106: 2^32 - 1). */
    std::uint64_t max_salt = 0xffffffffULL;
    /** Whether the engine takes a secret, K. */
    bool secret = true;
    /** Whether the engine takes associated data, X. */
    bool associated_data = true;
};

/**
 Argon2 of one variant on a backend (spec 2.15), behind `argon2`, which the backend's header
 specialises fully for each variant it has. The primary template is reached only by a type that is
 not `kdfs::argon2d`, `kdfs::argon2i` or `kdfs::argon2id`, which it refuses; each variant's partial
 specialisation below refuses a backend without it.

 A specialisation has a constant and a static member function, called by `argon2` only after every
 guard of RFC 9106 and every limit of `limits` has passed:

 @code
 static constexpr argon2_limits limits{...};
 // RFC 9106, version 0x13: the tag of output.size() bytes.
 static boost::system::result<void> derive(std::span<std::uint8_t> output,
                                           std::span<std::uint8_t const> password,
                                           std::span<std::uint8_t const> salt,
                                           argon2_parameters const& parameters) noexcept;
 @endcode

 A failure is `error::backend_failure`, or `errc::not_enough_memory` when the memory cannot be
 allocated; `argon2` then zeroes the output.

 @tparam Backend A backend of `backends`. @tparam Variant `kdfs::argon2d`, `kdfs::argon2i` or
 `kdfs::argon2id`.
*/
template <class Backend, class Variant>
struct argon2_engine;

/**
 The members a refused Argon2 engine gives, so that its refusal is the only error of the call.

 @tparam Variant The variant refused.
*/
template <class Variant>
struct refused_argon2_engine {
    /** Never read. */
    static constexpr argon2_limits limits{};

    /** Never called. @return backend_failure. */
    [[nodiscard]] static boost::system::result<void> derive(
        std::span<std::uint8_t> /*output*/, std::span<std::uint8_t const> /*password*/,
        std::span<std::uint8_t const> /*salt*/, argon2_parameters const& /*parameters*/) noexcept {
        return error::backend_failure;
    }
};

/** A type that is not a variant of Argon2: refused (spec 3.3). */
template <class Backend, class Variant>
struct argon2_engine : refused_argon2_engine<Variant> {
    static_assert(always_false<Variant>,
                  "webcpp::hash: argon2 takes kdfs::argon2d, kdfs::argon2i or kdfs::argon2id.");
};

// The refusal of each variant on a backend that lacks it (spec 3.3), as the digests'.

/** `kdfs::argon2d` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct argon2_engine<Backend, kdfs::argon2d> : refused_argon2_engine<kdfs::argon2d>,
                                               needs_library<Backend> {
    static_assert(!std::is_same_v<Backend, no_default>,
                  "webcpp::hash: kdfs::argon2d has no default backend, and no backend has it yet.");
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: kdfs::argon2d is in no backend yet.");
};

/** `kdfs::argon2i` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct argon2_engine<Backend, kdfs::argon2i> : refused_argon2_engine<kdfs::argon2i>,
                                               needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: kdfs::argon2i is in no backend yet.");
};

/** `kdfs::argon2id` on a backend without it (spec 3.3, design D34). */
template <class Backend>
struct argon2_engine<Backend, kdfs::argon2id> : refused_argon2_engine<kdfs::argon2id>,
                                                needs_library<Backend> {
    static_assert(refused_elsewhere_v<Backend>,
                  "webcpp::hash: kdfs::argon2id is in no backend of argon2 yet: call the function "
                  "argon2id.");
};

}  // namespace webcpp::hash::detail

#endif  // WEBCPP_HASH_DETAIL_ENGINES_HPP
