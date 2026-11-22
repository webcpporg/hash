// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// digest_of on backends::botan in a program that does not link Botan stops with the instruction to
// add /third_party//botan (spec section 5.7).

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so the
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/hash/detail/engines.hpp:* {{webcpp::hash: backends::botan needs Botan. Add /third_party//botan to the program's Jamfile (native and Emscripten, with exceptions): exe app : app.cpp /webcpp/hash//hash /third_party//botan ;}}
// clang-format on
#include <webcpp/hash/digest.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 64> output{};
    auto done =
        webcpp::hash::digest_of<webcpp::hash::digests::whirlpool, webcpp::hash::backends::botan>(
            output, {});
    return done ? 0 : 1;
}
