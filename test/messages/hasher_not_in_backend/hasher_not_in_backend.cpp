// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A hasher over a tag the named backend does not have stops naming the backends that have it
// (spec 3.3, the tag's row of doc/capabilities.json), with no other error: the class's members
// and make reach the refused engine's members, which it gives for that reason.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so the
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/hash/detail/engines.hpp:* {{webcpp::hash: digests::blake3 is not in this backend. Name one of: backends::blake3.}}
// clang-format on
#include <webcpp/hash/digest.hpp>

#include <array>
#include <cstdint>

int main() {
    using hasher =
        webcpp::hash::hasher<webcpp::hash::digests::blake3, webcpp::hash::backends::hash2>;
    auto hashing = hasher::make();
    if (!hashing) {
        return 1;
    }
    std::array<std::uint8_t, 32> output{};
    auto fed = hashing->update(output);
    auto done = hashing->finish(output);
    return fed && done ? 0 : 1;
}
