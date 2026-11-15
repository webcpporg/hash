// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// pbkdf2 on backends::bearssl, which has no PBKDF2, stops with spec section 3.3's text for
// BearSSL, not the primary template's, and with no other error.

// clang-format off
// expected-error@webcpp/hash/backends/bearssl.hpp:* {{webcpp::hash: pbkdf2 is not in backends::bearssl: BearSSL has no PBKDF2. The backends that have pbkdf2: backends::hash2 (every hmac) and backends::openssl (every hmac but hmac_ripemd_128).}}
// clang-format on
#include <webcpp/hash/backends/bearssl.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/pbkdf2.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 32> output{};
    std::array<std::uint8_t, 4> input{};
    auto done = webcpp::hash::pbkdf2<webcpp::hash::hmac_sha2_256, webcpp::hash::backends::bearssl>(
        output, input, input, 1);
    return done ? 0 : 1;
}
