// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Keccak-256 as Ethereum uses it, next to SHA3-256 (FIPS 202). They run the same permutation and
// differ in one padding byte, so the same input gives different digests. The Keccak-256 values
// are the Keccak team's published ones (as listed by Ethereum for "" and "abc"); the SHA3-256
// value is FIPS 202's.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/algorithms.hpp>
#include <webcpp/hash/keccak.hpp>

#include <iostream>
#include <string_view>

int main() {
    std::string_view const empty;
    std::string_view const abc = "abc";

    webcpp::hash::keccak_256 keccak_of_empty;
    keccak_of_empty.update(empty.data(), empty.size());
    auto const empty_digest = example::hex(keccak_of_empty.result());
    std::cout << "keccak_256() " << empty_digest << '\n';

    webcpp::hash::keccak_256 keccak_of_abc;
    keccak_of_abc.update(abc.data(), abc.size());
    auto const abc_digest = example::hex(keccak_of_abc.result());
    std::cout << "keccak_256(abc) " << abc_digest << '\n';

    if (empty_digest != "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" ||
        abc_digest != "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45") {
        return 1;
    }

    // Not the same function. Keccak-256 pads with the byte 0x01, SHA3-256 with 0x06, so a
    // program that calls one where a protocol names the other computes a digest nobody else
    // computes, and the error shows only as a signature or an address that does not match.
    webcpp::hash::sha3_256 sha3_of_empty;
    sha3_of_empty.update(empty.data(), empty.size());
    std::cout << "sha3_256() " << example::hex(sha3_of_empty.result()) << '\n';
}

// end::example[]
