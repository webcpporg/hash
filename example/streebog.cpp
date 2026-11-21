// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Streebog-256 and Streebog-512 (GOST R 34.11-2012) on backends::botan, the one backend that has
// them, named in the call: RFC 6986's first example, M1, checked against the digests the RFC gives,
// read as the bytes an implementation writes; and the 256-bit digest beside the 512-bit one, which
// it does not start.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/digest.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>

int main() {
    namespace hash = webcpp::hash;
    using hash::backends::botan;
    // M1 of RFC 6986, section 10.1: 63 digits.
    auto const message =
        example::bytes("012345678901234567890123456789012345678901234567890123456789012");

    // Streebog has no default backend: the call names Botan, which the Jamfile links.
    std::array<std::uint8_t, 32> short_digest{};
    std::array<std::uint8_t, 64> long_digest{};
    if (!hash::digest_of<hash::digests::streebog_256, botan>(short_digest, message) ||
        !hash::digest_of<hash::digests::streebog_512, botan>(long_digest, message)) {
        return 1;
    }
    std::cout << "streebog_256 " << example::hex(short_digest) << '\n';
    std::cout << "streebog_512 " << example::hex(long_digest) << '\n';
    if (example::hex(short_digest) !=
        "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500") {
        return 1;
    }

    // Two functions: each size has its own initial value, so neither digest starts the other.
    bool const starts = std::equal(short_digest.begin(), short_digest.end(), long_digest.begin());
    std::cout << "streebog_256 starts streebog_512: " << (starts ? "yes" : "no") << '\n';
}

// end::example[]
