// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Skein-512 with its 64-byte digest (Skein 1.3) on backends::botan, the one backend that has it,
// named in the call: the digest of the empty message, checked against the one Botan's own test
// file (skein.vec) gives; then a digest of another size, refused.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/digest.hpp>

#include <array>
#include <cstdint>
#include <iostream>

int main() {
    namespace hash = webcpp::hash;
    using hash::backends::botan;

    std::array<std::uint8_t, 64> digest{};
    if (!hash::digest_of<hash::digests::skein_512, botan>(digest, {})) {
        return 1;
    }
    std::cout << "skein_512 " << example::hex(digest) << '\n';
    if (example::hex(digest) !=
        "bc5b4c50925519c290cc634277ae3d6257212395cba733bbad37a4af0fa06af4"
        "1fca7903d06564fea7a2d3730dbdb80c1f85562dfcc070334ea4d1d9e72cba7a") {
        return 1;
    }

    // The tag is Skein-512 with its 512-bit output: 32 bytes would be another function's digest,
    // Skein-512-256, which encodes its size in its configuration, not the first half of this one.
    std::array<std::uint8_t, 32> half{};
    std::cout << "32 bytes: "
              << hash::digest_of<hash::digests::skein_512, botan>(half, {}).error().message()
              << '\n';
}

// end::example[]
