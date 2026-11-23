// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// argon2 over a type that is not a variant of Argon2 stops with the family's refusal (spec 3.3).

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so the
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/hash/detail/engines.hpp:* {{webcpp::hash: argon2 takes kdfs::argon2d, kdfs::argon2i or kdfs::argon2id.}}
// clang-format on
#include <webcpp/hash/argon2.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 32> output{};
    std::array<std::uint8_t, 16> salt{};
    auto done =
        webcpp::hash::argon2<int>(output, {}, salt, {.passes = 3, .memory_kibibytes = 65536});
    return done ? 0 : 1;
}
