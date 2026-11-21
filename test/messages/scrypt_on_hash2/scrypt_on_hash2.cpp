// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// scrypt on another backend than backends::sodium, backends::openssl and backends::botan stops
// with spec section 3.3's text.

// clang-format off
// expected-error@webcpp/hash/detail/engines.hpp:* {{webcpp::hash: scrypt is in backends::sodium, backends::openssl and backends::botan alone. Name one, and add /third_party//sodium, /webcpp/hash//openssl or /third_party//botan to the program's Jamfile.}}
// clang-format on
#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/scrypt.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 64> output{};
    auto done = webcpp::hash::scrypt<webcpp::hash::backends::hash2>(output, {}, {}, {16, 1, 1});
    return done ? 0 : 1;
}
