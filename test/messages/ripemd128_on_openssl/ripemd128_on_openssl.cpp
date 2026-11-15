// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// hkdf over hmac_ripemd_128 on backends::openssl stops with spec 3.3's text: OpenSSL 3.5 has no
// RIPEMD-128.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so the
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/hash/backends/openssl.hpp:* {{webcpp::hash: backends::openssl has no hmac_ripemd_128 (OpenSSL 3.5 has no RIPEMD-128). Name backends::hash2.}}
// clang-format on
#include <webcpp/hash/backends/openssl.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 16> output{};
    std::array<std::uint8_t, 4> const input{};
    const auto done =
        webcpp::hash::hkdf<webcpp::hash::hmac_ripemd_128, webcpp::hash::backends::openssl>(
            output, input, input, input);
    return done ? 0 : 1;
}
