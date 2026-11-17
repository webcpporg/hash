// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The Keccak family through digest_of on XKCP: Keccak-512 of "abc" on its default backend,
// backends::xkcp, checked against the Keccak team's value; SHA3-256 of "abc" on backends::xkcp,
// named in the call, checked against FIPS 202's example (and so equal to Boost.Hash2's); and 200
// bytes of SHAKE128 on backends::xkcp, more than one 168-byte block of the stream.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/digest.hpp>

#include <array>
#include <cstdint>
#include <iostream>
#include <span>

int main() {
    namespace hash = webcpp::hash;
    auto const message = example::bytes("abc");

    // Keccak-512, the SHA-3 submission's padding: its default backend is XKCP.
    std::array<std::uint8_t, 64> keccak{};
    if (!hash::digest_of<hash::digests::keccak_512>(keccak, message)) {
        return 1;
    }
    std::cout << "keccak_512(abc) " << example::hex(keccak) << '\n';
    if (example::hex(keccak) !=
        "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5"
        "d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96") {
        return 1;
    }

    // SHA3-256 on XKCP, named in the call: the same digest as on backends::hash2.
    std::array<std::uint8_t, 32> sha3{};
    if (!hash::digest_of<hash::digests::sha3_256, hash::backends::xkcp>(sha3, message)) {
        return 1;
    }
    std::cout << "sha3_256(abc) " << example::hex(sha3) << '\n';
    if (example::hex(sha3) != "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532") {
        return 1;
    }

    // SHAKE128 on XKCP: any length, here 200 bytes, past the first block of 168.
    std::array<std::uint8_t, 200> shake{};
    if (!hash::digest_of<hash::digests::shake_128, hash::backends::xkcp>(shake, message)) {
        return 1;
    }
    std::cout << "shake_128(abc), bytes 168 to 199: " << example::hex(std::span(shake).subspan(168))
              << '\n';
}

// end::example[]
