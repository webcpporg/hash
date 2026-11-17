// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// mac over a type that is not a tag of macs stops with the family's refusal (spec 3.3).

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so the
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/hash/detail/engines.hpp:* {{webcpp::hash: mac takes a tag of webcpp::hash::macs, as macs::hmac<digests::sha2_256>.}}
// clang-format on
#include <webcpp/hash/mac.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 32> output{};
    auto done = webcpp::hash::mac<int>(output, {}, {});
    return done ? 0 : 1;
}
