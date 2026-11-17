// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 BLAKE2b subkeys, libsodium's `crypto_kdf`: `blake2b_subkey`, many keys from one 32-byte master
 key, each named by a 64-bit id and an 8-byte context, on `backends::sodium`
 (`crypto_kdf_blake2b_derive_from_key`).

 A subkey is BLAKE2b (RFC 7693) of the empty message, keyed with the master key, of the subkey's
 length, with the id in 8 little-endian bytes then 8 zero bytes as the salt, and the context then 8
 zero bytes as the personalisation: the bytes libsodium's `crypto_kdf_derive_from_key` gives, so
 that a program and a libsodium peer derive the same keys.

 Every guard runs before any work, and a guard's refusal leaves the output as it was; a backend's
 failure zeroes it.

 @code
 // master_key: 32 secret bytes, as from webcpp::crypto::random_device; context: the 8 bytes of
 // "vault v1".
 std::array<std::uint8_t, 32> file_key{};
 auto done = webcpp::hash::blake2b_subkey(file_key, master_key, 1, context);
 if (!done) {
     return done.error();  // file_key is as it was, or zeroed when the backend failed
 }
 @endcode

 @see "BLAKE2b subkeys", in the guide's chapter "Key derivation".
*/
#ifndef WEBCPP_HASH_BLAKE2B_SUBKEY_HPP
#define WEBCPP_HASH_BLAKE2B_SUBKEY_HPP

#include <webcpp/hash/config.hpp>

#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/detail/wipe.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/kdf.hpp>

#include <boost/system/result.hpp>

#include <cstddef>
#include <cstdint>
#include <span>

namespace webcpp::hash {

/** The shortest subkey `blake2b_subkey` derives, in bytes (libsodium's `crypto_kdf_BYTES_MIN`). */
inline constexpr std::size_t blake2b_subkey_min_size = 16;
/** The longest subkey `blake2b_subkey` derives, in bytes (libsodium's `crypto_kdf_BYTES_MAX`). */
inline constexpr std::size_t blake2b_subkey_max_size = 64;
/** The size of `blake2b_subkey`'s master key, in bytes (libsodium's `crypto_kdf_KEYBYTES`). */
inline constexpr std::size_t blake2b_subkey_key_size = 32;
/** The size of `blake2b_subkey`'s context, in bytes (libsodium's `crypto_kdf_CONTEXTBYTES`). */
inline constexpr std::size_t blake2b_subkey_context_size = 8;

/**
 The subkey `subkey_id` of `master_key` in `context`, libsodium's `crypto_kdf_derive_from_key`:
 keys for different purposes from one master key, each unrelated to the others and to the master
 key without it.

 @code
 std::array<std::uint8_t, 32> file_key{};
 auto done = webcpp::hash::blake2b_subkey(file_key, master_key, 1, context);  // context: 8 bytes
 @endcode

 @tparam Backend The backend; by default @ref default_backend of `kdfs::blake2b_subkey` (spec
 4.1), `backends::sodium`, the only one that has it. Another backend, or a program that does not
 link libsodium, refuses at compile time.
 @param output The subkey, 16 to 64 bytes; it must not overlap `master_key` or `context`. Its
 length is a parameter of BLAKE2b: a subkey of 32 bytes is not the first 32 bytes of the one of 64.
 @param master_key The master key, 32 bytes, secret and uniformly random.
 @param subkey_id The subkey's number, any 64-bit value: one per key the application needs.
 @param context 8 bytes naming the application or its purpose, as "vault v1": the same id in
 another context gives an unrelated subkey. Not secret.
 @return Success; or the first guard's error (`invalid_output_size`, `invalid_key_size`,
 `invalid_parameters` for the context), `output` untouched; or `backend_failure`, `output`
 zeroed.
*/
template <class Backend = default_backend<kdfs::blake2b_subkey>>
[[nodiscard]] boost::system::result<void> blake2b_subkey(std::span<std::uint8_t> output,
                                                         std::span<std::uint8_t const> master_key,
                                                         std::uint64_t subkey_id,
                                                         std::span<std::uint8_t const> context) {
    using engine = detail::blake2b_subkey_engine<Backend>;
    if (output.size() < blake2b_subkey_min_size || output.size() > blake2b_subkey_max_size) {
        return error::invalid_output_size;
    }
    if (master_key.size() != blake2b_subkey_key_size) {
        return error::invalid_key_size;
    }
    if (context.size() != blake2b_subkey_context_size) {
        return error::invalid_parameters;
    }
    auto derived = engine::derive(output, master_key, subkey_id, context);
    if (!derived) {
        detail::wipe(output);
    }
    return derived;
}

}  // namespace webcpp::hash

// backends::sodium when the program links libsodium: a program that includes only this header
// gets blake2b_subkey's default backend complete here.
#ifdef WEBCPP_HASH_HAS_SODIUM
#include <webcpp/hash/backends/sodium.hpp>
#endif

#endif  // WEBCPP_HASH_BLAKE2B_SUBKEY_HPP
