// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Bitcoin's hash160, as a domain library such as webcpp::bitcoin would compute it from
// webcpp::hash's SHA-256 and RIPEMD-160: RIPEMD-160 of the SHA-256 of a public key, the
// 20 bytes an address encodes. webcpp::hash itself has no hash160 function. The key is the
// compressed public key of secret key 1 (the prefix 02 and the x coordinate of the generator),
// whose hash160 is the well-known 751e76e8199196d454941c45d1b3a323f1433bd6; it agrees with
// Python's hashlib.sha256 and a pure Python RIPEMD-160.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/algorithms.hpp>

#include <iostream>

int main() {
    auto const public_key =
        example::from_hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");

    // Two functions in a row: the second hashes the first's digest, not the key. Skipping the
    // SHA-256 gives a 20-byte value that no Bitcoin node computes.
    webcpp::hash::sha2_256 first;
    first.update(public_key.data(), public_key.size());
    auto const inner = first.result();

    webcpp::hash::ripemd_160 second;
    second.update(inner.data(), inner.size());
    auto const hash160 = example::hex(second.result());
    std::cout << "hash160 " << hash160 << '\n';

    if (hash160 != "751e76e8199196d454941c45d1b3a323f1433bd6") {
        return 1;
    }
}

// end::example[]
