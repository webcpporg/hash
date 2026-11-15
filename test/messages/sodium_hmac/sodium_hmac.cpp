// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// hkdf over an hmac libsodium has no HKDF for stops with spec section 3.3's text for
// backends::sodium.

// clang-format off
// expected-error@webcpp/hash/backends/sodium.hpp:* {{webcpp::hash: backends::sodium has HKDF over hmac_sha2_256 and hmac_sha2_512 alone. Over this hmac, name backends::hash2 (every hmac), backends::openssl (every hmac but hmac_ripemd_128) or backends::bearssl (MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512; hkdf alone).}}
// clang-format on
#include <webcpp/hash/hkdf.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 20> output{};
    std::array<std::uint8_t, 4> input{};
    auto done = webcpp::hash::hkdf<webcpp::hash::hmac_sha1_160, webcpp::hash::backends::sodium>(
        output, input, input, input);
    return done ? 0 : 1;
}
