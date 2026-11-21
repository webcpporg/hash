// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// digest_of over a tag with no default backend, on its default, stops: the call names its backend
// (design D34).

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so the
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/hash/detail/engines.hpp:* {{webcpp::hash: digests::whirlpool has no default backend. Name one of: backends::botan.}}
// clang-format on
#include <webcpp/hash/digest.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 64> output{};
    auto done = webcpp::hash::digest_of<webcpp::hash::digests::whirlpool>(output, {});
    return done ? 0 : 1;
}
