// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// argon2 over kdfs::argon2d on backends::sodium, which has no Argon2d, stops naming the backends
// that have it (spec 3.3, the tag's row of doc/capabilities.json).

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so the
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/hash/detail/engines.hpp:* {{webcpp::hash: kdfs::argon2d is not in this backend. Name one of: backends::openssl, backends::botan.}}
// clang-format on
#include <webcpp/hash/argon2.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 32> output{};
    std::array<std::uint8_t, 16> salt{};
    auto done = webcpp::hash::argon2<webcpp::hash::kdfs::argon2d, webcpp::hash::backends::sodium>(
        output, {}, salt, {.passes = 3, .memory_kib = 65536});
    return done ? 0 : 1;
}
