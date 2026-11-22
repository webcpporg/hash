// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 bcrypt, OpenBSD's password hash (Provos and Mazieres, 1999): `bcrypt`, the modular crypt string
 of a password under the caller's 16-byte salt, `bcrypt_verify`, which checks a password against
 such a string, and `bcrypt_pbkdf`, OpenBSD's key derivation over bcrypt's hash, as OpenSSH's
 private keys use it. Each has `backends::botan` alone and no default (design D34): the call
 names it, and the program links `/third_party//botan` (native and Emscripten, with exceptions).

 bcrypt reads at most 72 bytes of a password, and OpenBSD's C stops at a zero byte, where Botan
 does not: `bcrypt` refuses a longer password and one with a zero byte, rather than give a string
 another implementation would not. For a new design Argon2id (`argon2id`) is the better choice;
 bcrypt is here to check and make the strings that systems already store.

 Every call holds the data-independent-timing guard (`detail::timing_guard`): where the CPU has
 DIT, the call sets it and leaves the thread's state as it found it.

 Every guard runs before any work, and a guard's refusal leaves the output as it was; a backend's
 failure zeroes it. The caller gives every input, the salt included: hash draws no random byte.

 @code
 // password: std::span<std::uint8_t const>; salt: 16 random bytes
 std::array<char, webcpp::hash::bcrypt_hash_size> stored{};
 auto made = webcpp::hash::bcrypt<webcpp::hash::backends::botan>(stored, password, salt);
 if (!made) {
     return made.error();  // stored is as it was, or zeroed when the backend failed
 }
 auto same = webcpp::hash::bcrypt_verify<webcpp::hash::backends::botan>(
     password, std::string_view(stored.data(), stored.size()));
 @endcode

 @see "Password hashing", in the guide.
*/
#ifndef WEBCPP_HASH_BCRYPT_HPP
#define WEBCPP_HASH_BCRYPT_HPP

#include <webcpp/hash/config.hpp>

#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/detail/timing.hpp>
#include <webcpp/hash/detail/wipe.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/kdf.hpp>

#include <boost/system/result.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace webcpp::hash {

/** bcrypt's salt, 16 bytes (128 bits). */
inline constexpr std::size_t bcrypt_salt_size = 16;
/** bcrypt's string, 60 characters: "$2b$", the cost in two digits, "$", 22 of salt, 31 of hash. */
inline constexpr std::size_t bcrypt_hash_size = 60;
/** The longest password bcrypt reads, 72 bytes. */
inline constexpr std::size_t bcrypt_max_password_size = 72;

/** bcrypt's cost (2^cost rounds, 4 to 31) and the version written, 'a', 'b' or 'y'. */
struct bcrypt_parameters {
    /** The cost: 2^cost rounds of the key schedule, 4 to 31 (`backends::botan`: at most 18). */
    std::uint32_t cost = 12;
    /**
     The version of the string, 'a', 'b' or 'y': the three are one algorithm for a password of at
     most 72 bytes without a zero byte.
    */
    char version = 'b';
};

namespace detail {

/** The lowest cost of bcrypt's format. */
inline constexpr std::uint32_t bcrypt_min_cost = 4;
/** The highest cost of bcrypt's format. */
inline constexpr std::uint32_t bcrypt_max_cost = 31;
/** The longest output of `bcrypt_pbkdf`, 1,024 bytes (OpenBSD's 32 blocks of 32). */
inline constexpr std::size_t bcrypt_pbkdf_max_output = 1024;
/** The longest salt of `bcrypt_pbkdf`, 1,048,576 bytes (OpenBSD's 1 << 20). */
inline constexpr std::size_t bcrypt_pbkdf_max_salt = 1048576;

/**
 Whether `version` is one bcrypt writes.

 @param version The character after "$2". @return Whether it is 'a', 'b' or 'y'.
*/
constexpr bool bcrypt_version(char version) noexcept {
    return version == 'a' || version == 'b' || version == 'y';
}

/**
 Whether `c` is a character of bcrypt's base-64 alphabet, "./A-Za-z0-9".

 @param c The character. @return Whether bcrypt's encoding writes it.
*/
constexpr bool bcrypt_base64(char c) noexcept {
    return c == '.' || c == '/' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9');
}

/**
 The cost of `hash` when it has bcrypt's form: 60 characters, "$2", a version, "$", a cost of 04
 to 31 in two digits, "$", then 53 characters of bcrypt's base-64 alphabet.

 @param hash The string. @return Its cost; 0 when it does not have the form.
*/
constexpr std::uint32_t bcrypt_cost_of(std::string_view hash) noexcept {
    constexpr std::size_t cost_at = 4;
    constexpr std::size_t encoded_at = 7;
    if (hash.size() != bcrypt_hash_size || hash[0] != '$' || hash[1] != '2' ||
        !bcrypt_version(hash[2]) || hash[3] != '$' || hash[6] != '$') {
        return 0;
    }
    char const tens = hash[cost_at];
    char const units = hash[cost_at + 1];
    if (tens < '0' || tens > '9' || units < '0' || units > '9') {
        return 0;
    }
    constexpr std::uint32_t decimal = 10;
    std::uint32_t const cost = (static_cast<std::uint32_t>(tens - '0') * decimal) +
                               static_cast<std::uint32_t>(units - '0');
    if (cost < bcrypt_min_cost || cost > bcrypt_max_cost) {
        return 0;
    }
    for (std::size_t index = encoded_at; index < hash.size(); ++index) {
        if (!bcrypt_base64(hash[index])) {
            return 0;
        }
    }
    return cost;
}

/**
 The guards of a password of bcrypt: at most 72 bytes (`input_too_long`) and without a zero byte
 (`invalid_parameters`).

 @param password The password. @return Success, or the guard's error.
*/
[[nodiscard]] inline boost::system::result<void> bcrypt_password_guards(
    std::span<std::uint8_t const> password) noexcept {
    if (password.size() > bcrypt_max_password_size) {
        return error::input_too_long;
    }
    if (std::ranges::find(password, std::uint8_t{0}) != password.end()) {
        return error::invalid_parameters;
    }
    return {};
}

/**
 The guards of `bcrypt`, then `Backend`'s limits, without the work: what `async_bcrypt` checks
 before it posts the work to another thread.

 @tparam Backend The backend.
 @param output_size The output's size. @param password The password.
 @param salt_size The salt's size. @param parameters The cost and the version.
 @return Success, or the error of the first guard that fails, as `bcrypt` returns it.
*/
template <class Backend>
[[nodiscard]] boost::system::result<void> bcrypt_guards(
    std::size_t output_size, std::span<std::uint8_t const> password, std::size_t salt_size,
    bcrypt_parameters const& parameters) noexcept {
    if (output_size != bcrypt_hash_size) {
        return error::invalid_output_size;
    }
    if (salt_size != bcrypt_salt_size) {
        return error::invalid_salt_size;
    }
    auto const password_guarded = bcrypt_password_guards(password);
    if (!password_guarded) {
        return password_guarded;
    }
    if (parameters.cost < bcrypt_min_cost || parameters.cost > bcrypt_max_cost ||
        !bcrypt_version(parameters.version)) {
        return error::invalid_parameters;
    }
    if (parameters.cost > bcrypt_engine<Backend>::max_cost) {
        return error::unsupported_by_backend;
    }
    return {};
}

/**
 The guards of `bcrypt_verify`, then `Backend`'s limits, without the work: what
 `async_bcrypt_verify` checks before it posts the work to another thread.

 @tparam Backend The backend.
 @param password The password. @param hash The string.
 @return Success, or the error of the first guard that fails, as `bcrypt_verify` returns it.
*/
template <class Backend>
[[nodiscard]] boost::system::result<void> bcrypt_verify_guards(
    std::span<std::uint8_t const> password, std::string_view hash) noexcept {
    auto const password_guarded = bcrypt_password_guards(password);
    if (!password_guarded) {
        return password_guarded;
    }
    std::uint32_t const cost = bcrypt_cost_of(hash);
    if (cost == 0) {
        return error::invalid_parameters;
    }
    if (cost > bcrypt_engine<Backend>::max_cost) {
        return error::unsupported_by_backend;
    }
    return {};
}

/**
 The guards of `bcrypt_pbkdf`, OpenBSD's limits, without the work: what `async_bcrypt_pbkdf`
 checks before it posts the work to another thread.

 @param output_size The output's size. @param password_size The password's size.
 @param salt_size The salt's size. @param rounds The rounds.
 @return Success, or the error of the first guard that fails, as `bcrypt_pbkdf` returns it.
*/
[[nodiscard]] inline boost::system::result<void> bcrypt_pbkdf_guards(
    std::size_t output_size, std::size_t password_size, std::size_t salt_size,
    std::uint32_t rounds) noexcept {
    if (output_size == 0 || output_size > bcrypt_pbkdf_max_output) {
        return error::invalid_output_size;
    }
    if (salt_size == 0 || salt_size > bcrypt_pbkdf_max_salt) {
        return error::invalid_salt_size;
    }
    if (password_size == 0) {
        return error::invalid_key_size;
    }
    if (rounds == 0) {
        return error::invalid_iterations;
    }
    return {};
}

}  // namespace detail

/**
 The modular crypt string of `password` under the caller's 16-byte `salt`, into 60 chars:
 "$2", the version, "$", the cost in two digits, "$", the salt then the hash in bcrypt's base 64.

 @tparam Backend The backend; @ref default_backend of `kdfs::bcrypt` has none (design D34): the
 call names `backends::botan`.
 @param output The string, exactly `bcrypt_hash_size` characters, not terminated by a zero.
 @param password The password, at most `bcrypt_max_password_size` bytes, without a zero byte.
 @param salt The salt, exactly `bcrypt_salt_size` random bytes.
 @param parameters The cost (4 to 31) and the version ('a', 'b' or 'y').
 @return Success; or the first guard's error (`invalid_output_size`, `invalid_salt_size`,
 `input_too_long`, `invalid_parameters`, then the backend's `unsupported_by_backend`:
 `backends::botan`'s cost above 18), `output` untouched; or `errc::not_enough_memory` or
 `backend_failure`, `output` zeroed.
*/
template <class Backend = default_backend<kdfs::bcrypt>>
[[nodiscard]] boost::system::result<void> bcrypt(std::span<char> output,
                                                 std::span<std::uint8_t const> password,
                                                 std::span<std::uint8_t const> salt,
                                                 bcrypt_parameters const& parameters = {}) {
    detail::timing_guard const timing;
    auto guarded = detail::bcrypt_guards<Backend>(output.size(), password, salt.size(), parameters);
    if (!guarded) {
        return guarded;
    }
    auto made = detail::bcrypt_engine<Backend>::generate(output, password, salt, parameters.cost,
                                                         parameters.version);
    if (!made) {
        detail::wipe(output.data(), output.size());
    }
    return made;
}

/**
 Whether `password` gives `hash`, a modular crypt string of bcrypt, compared in constant time.

 A caller that checks strings made by an implementation that silently cuts a longer password (at
 72 bytes, as OpenBSD's and most others do) passes the first 72 bytes of the password: bcrypt reads
 no more, so the answer is the same, where the whole password is refused with `input_too_long`.

 @tparam Backend The backend; the call names `backends::botan`, as for @ref bcrypt.
 @param password The password, at most `bcrypt_max_password_size` bytes, without a zero byte.
 @param hash The string, `bcrypt_hash_size` characters of bcrypt's form.
 @return `true` when the password gives the string, `false` otherwise; or the first guard's error
 (`input_too_long` or `invalid_parameters` for the password, `invalid_parameters` for a string not
 of bcrypt's form, then the backend's `unsupported_by_backend`: `backends::botan`'s cost above 18);
 or `errc::not_enough_memory` or `backend_failure`.
*/
template <class Backend = default_backend<kdfs::bcrypt>>
[[nodiscard]] boost::system::result<bool> bcrypt_verify(std::span<std::uint8_t const> password,
                                                        std::string_view hash) {
    detail::timing_guard const timing;
    auto const guarded = detail::bcrypt_verify_guards<Backend>(password, hash);
    if (!guarded) {
        return guarded.error();
    }
    return detail::bcrypt_engine<Backend>::verify(password, hash);
}

/**
 OpenBSD's bcrypt_pbkdf, as OpenSSH's keys use it: fills `output` from `password` and `salt` by
 `rounds` rounds of bcrypt's hash over their SHA-512 digests, its blocks interleaved.

 @tparam Backend The backend; @ref default_backend of `kdfs::bcrypt_pbkdf` has none (design D34):
 the call names `backends::botan`.
 @param output The derived key, 1 to 1,024 bytes.
 @param password The password, 1 byte or more.
 @param salt The salt, 1 to 1,048,576 bytes.
 @param rounds The rounds, 1 or more.
 @return Success; or the first guard's error (`invalid_output_size`, `invalid_salt_size`,
 `invalid_key_size`, `invalid_iterations`), `output` untouched; or `errc::not_enough_memory` or
 `backend_failure`, `output` zeroed.
*/
template <class Backend = default_backend<kdfs::bcrypt_pbkdf>>
[[nodiscard]] boost::system::result<void> bcrypt_pbkdf(std::span<std::uint8_t> output,
                                                       std::span<std::uint8_t const> password,
                                                       std::span<std::uint8_t const> salt,
                                                       std::uint32_t rounds) {
    detail::timing_guard const timing;
    auto guarded = detail::bcrypt_pbkdf_guards(output.size(), password.size(), salt.size(), rounds);
    if (!guarded) {
        return guarded;
    }
    auto derived = detail::bcrypt_pbkdf_engine<Backend>::derive(output, password, salt, rounds);
    if (!derived) {
        detail::wipe(output);
    }
    return derived;
}

}  // namespace webcpp::hash

// backends::botan, the one backend of these functions, when the program links Botan: a program
// that includes only this header gets its engines here.
#ifdef WEBCPP_HASH_HAS_BOTAN
#include <webcpp/hash/backends/botan.hpp>
#endif

#endif  // WEBCPP_HASH_BCRYPT_HPP
