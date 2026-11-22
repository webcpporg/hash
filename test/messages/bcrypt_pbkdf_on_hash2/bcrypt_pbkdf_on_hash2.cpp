// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// bcrypt_pbkdf named on backends::hash2, which has no bcrypt_pbkdf, stops naming the backend that
// has it (spec 3.3).

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so the
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/hash/detail/engines.hpp:* {{webcpp::hash: kdfs::bcrypt_pbkdf is not in this backend. Name one of: backends::botan.}}
// clang-format on
#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/bcrypt.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 32> output{};
    std::array<std::uint8_t, 16> const password{1};
    std::array<std::uint8_t, 16> const salt{2};
    auto const done =
        webcpp::hash::bcrypt_pbkdf<webcpp::hash::backends::hash2>(output, password, salt, 16);
    return done ? 0 : 1;
}
