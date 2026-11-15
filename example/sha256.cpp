// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// SHA-256 (FIPS 180-4) of "abc", checked against the digest FIPS 180-4 publishes for it
// (Appendix B.1), then the same message fed in two pieces: a hash does not depend on how its
// input is split into update() calls.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/algorithms.hpp>

#include <iostream>
#include <string_view>

int main() {
    std::string_view const message = "abc";

    webcpp::hash::sha2_256 whole;
    whole.update(message.data(), message.size());
    auto const digest = whole.result();
    std::cout << "sha2_256(abc) " << example::hex(digest) << '\n';

    // The standard's own value: a program that prints something else has a bug, not a new hash.
    if (example::hex(digest) !=
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") {
        return 1;
    }

    // Data that arrives in chunks (a socket, a file read in blocks) is hashed as it comes, without
    // collecting it first.
    webcpp::hash::sha2_256 pieces;
    pieces.update("a", 1);
    pieces.update("bc", 2);
    std::cout << "in two pieces " << (pieces.result() == digest ? "same" : "different") << '\n';
}

// end::example[]
