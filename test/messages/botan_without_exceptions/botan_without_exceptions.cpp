// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// digest_of on backends::botan in a build without exceptions (WEBCPP_HASH_NO_EXCEPTIONS), Botan
// linked, stops: Botan reports its errors by throwing, and backends/botan.hpp declares nothing
// without exceptions (ruling P4).

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so the
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/hash/detail/engines.hpp:* {{webcpp::hash: backends::botan needs exceptions: Botan reports its errors by throwing, and its header declares nothing without them. Build with exception-handling=on, or name another backend.}}
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
