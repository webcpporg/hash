// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

#ifndef WEBCPP_HASH_DETAIL_LIMITS_HPP
#define WEBCPP_HASH_DETAIL_LIMITS_HPP

#include <webcpp/hash/config.hpp>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>

namespace webcpp::hash::detail {

/**
 Whether `checked_value` is above `size_limit`, both in 64 bits.

 Tip: a `size_t` compared with a 64-bit limit is a tautology on wasm32, which clang reports as an
 error under `<warnings-as-errors>on`; a function of two `uint64_t` is not.

 @param checked_value The size, widened.
 @param size_limit The limit.
 @return `value > limit`.
*/
inline bool exceeds(std::uint64_t checked_value, std::uint64_t size_limit) noexcept {
    return checked_value > size_limit;
}

#ifdef WEBCPP_HASH_DETAIL_TEST_SP800_185_MAX_BYTES
// The test seam's value; the Doc Comment is in the #else branch, the one the reference reads.
inline constexpr std::uint64_t sp800_185_max_bytes = WEBCPP_HASH_DETAIL_TEST_SP800_185_MAX_BYTES;
#else
/**
 The longest string, key or fixed-length output of SP 800-185's functions, in bytes: the most
 whose length in bits a `size_t` holds, `SIZE_MAX / 8` (2^61 - 1 natively, 2^29 - 1, 512 MiB, on
 wasm32). SP 800-185 encodes each length in bits, and its implementations hold them in a
 `size_t`; the families refuse a longer one before any backend sees it, on every target
 (`input_too_long` for a string, `invalid_key_size` for a KMAC key, `invalid_output_size` for an
 output). The test seam `WEBCPP_HASH_DETAIL_TEST_SP800_185_MAX_BYTES` lowers it.
*/
inline constexpr std::uint64_t sp800_185_max_bytes = std::numeric_limits<std::size_t>::max() / 8;
#endif

/** The byte @ref nonnull points at for an empty span: a constant, never written. */
inline constexpr std::uint8_t nonnull_byte = 0;

/**
 The pointer to pass where a C library takes no null pointer: the span's `data()`, or the address
 of @ref nonnull_byte when the span is empty, since an empty span's `data()` may be null. The
 length passed with it stays the span's, zero. Two kinds of pointer go through it: those libsodium
 declares nonnull (SHA-256 HKDF-Extract's IKM, scrypt's password and salt, Argon2id's password;
 SHA-512's extract takes its IKM through it too, for symmetry), and BearSSL's HKDF inputs, which
 it copies with C's `memcpy`, which takes no null pointer even for no byte.

 @param byte_span The input.
 @return A pointer that is never null.
*/
inline std::uint8_t const* nonnull(std::span<std::uint8_t const> byte_span) noexcept {
    return byte_span.empty() ? &nonnull_byte : byte_span.data();
}

}  // namespace webcpp::hash::detail

#endif  // WEBCPP_HASH_DETAIL_LIMITS_HPP
