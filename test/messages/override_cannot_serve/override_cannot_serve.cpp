// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// An override whose backend lacks the function over the hmac used (spec 4.1):
// WEBCPP_HASH_DEFAULT_BACKEND_HKDF_SODIUM and hkdf over hmac_sha2_384 stop with libsodium's
// text of spec 3.3, and with no other error.

// clang-format off
// expected-error@webcpp/hash/backends/sodium.hpp:* {{webcpp::hash: backends::sodium has HKDF over hmac_sha2_256 and hmac_sha2_512 alone. Over this hmac, name backends::hash2 (every hmac), backends::openssl (every hmac but hmac_ripemd_128) or backends::bearssl (MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512; hkdf alone).}}
// clang-format on
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 48> output{};
    std::array<std::uint8_t, 4> input{};
    auto done = webcpp::hash::hkdf<webcpp::hash::hmac_sha2_384>(output, input, input, input);
    return done ? 0 : 1;
}
