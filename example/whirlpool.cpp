// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Whirlpool (ISO/IEC 10118-3) on backends::botan, the one backend that has it, named in the call:
// the digest of "abc", checked against the one Botan's own test file (whirlpool.vec) gives; then
// the same digest from a hasher fed in two pieces.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/digest.hpp>

#include <array>
#include <cstdint>
#include <iostream>

int main() {
    namespace hash = webcpp::hash;
    using hash::backends::botan;

    std::array<std::uint8_t, 64> once{};
    if (!hash::digest_of<hash::digests::whirlpool, botan>(once, example::bytes("abc"))) {
        return 1;
    }
    std::cout << "whirlpool " << example::hex(once) << '\n';
    if (example::hex(once) !=
        "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c"
        "7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5") {
        return 1;
    }

    // The same digest in pieces: the hasher owns Botan's object until it finishes.
    auto hashing = hash::hasher<hash::digests::whirlpool, botan>::make();
    std::array<std::uint8_t, 64> pieces{};
    if (!hashing || !hashing->update(example::bytes("a")) ||
        !hashing->update(example::bytes("bc")) || !hashing->finish(pieces)) {
        return 1;
    }
    std::cout << "hasher " << (pieces == once ? "same" : "different") << '\n';
}

// end::example[]
