// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// kbkdf over hmac_ripemd_128, which backends::openssl lacks (OpenSSL 3.5 has no RIPEMD-128), and
// which no other backend has kbkdf over, stops (spec 3.3).

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so the
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/hash/backends/openssl.hpp:* {{webcpp::hash: backends::openssl has kbkdf over the hmacs of hmac.hpp alone, hmac_ripemd_128 excepted, and no backend has kbkdf over this hmac.}}
// clang-format on
#include <webcpp/hash/backends/openssl.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/kdf_standards.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace hash = webcpp::hash;
    std::array<std::uint8_t, 32> output{};
    std::array<std::uint8_t, 16> const key{1};
    auto const done = hash::kbkdf<hash::hmac_ripemd_128, hash::backends::openssl>(output, key);
    return done ? 0 : 1;
}
