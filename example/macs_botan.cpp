// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The MACs of backends::botan, each named in the call, since Botan is never a default: HMAC over
// Streebog-256 against RFC 7836's example (section 4.1.1), which no other backend has; KMAC128
// against NIST's KMAC sample #2 (SP 800-185's examples); HMAC-SHA-256 under a key of 10,000
// bytes, past Botan's own HMAC limit, the same tag as backends::hash2's; and a KMAC key of 193
// bytes, past Botan's KMAC limit, refused.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/mac.hpp>

#include <array>
#include <cstdint>
#include <iostream>
#include <vector>

int main() {
    namespace hash = webcpp::hash;
    namespace macs = hash::macs;
    using hash::backends::botan;

    // HMAC_GOSTR3411_2012_256 of RFC 7836.
    auto const gost_key =
        example::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    std::array<std::uint8_t, 32> gost{};
    if (!hash::mac<macs::hmac<hash::digests::streebog_256>, botan>(
            gost, gost_key, example::from_hex("0126bdb87800af214341456563780100"))) {
        return 1;
    }
    std::cout << "hmac streebog_256 " << example::hex(gost) << '\n';
    if (example::hex(gost) != "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9") {
        return 1;
    }

    // KMAC128 with a customisation string: NIST's sample #2.
    auto const key =
        example::from_hex("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
    auto const data = example::from_hex("00010203");
    std::array<std::uint8_t, 32> kmac{};
    if (!hash::mac<macs::kmac_128, botan>(
            kmac, key, data, {.customisation = example::bytes("My Tagged Application")})) {
        return 1;
    }
    std::cout << "kmac_128 " << example::hex(kmac) << '\n';

    // A key longer than Botan's HMAC takes is hashed first, as RFC 2104 says: the same tag.
    std::vector<std::uint8_t> const long_key(10000, 0x0b);
    std::array<std::uint8_t, 32> on_botan{};
    std::array<std::uint8_t, 32> on_hash2{};
    using hmac_sha256 = macs::hmac<hash::digests::sha2_256>;
    if (!hash::mac<hmac_sha256, botan>(on_botan, long_key, data) ||
        !hash::mac<hmac_sha256, hash::backends::hash2>(on_hash2, long_key, data)) {
        return 1;
    }
    std::cout << "10,000-byte key: " << (on_botan == on_hash2 ? "same" : "different") << '\n';

    // Botan's KMAC takes a key of at most 192 bytes, narrower than SP 800-185.
    std::vector<std::uint8_t> const kmac_key(193, 0x40);
    std::cout << "193-byte KMAC key: "
              << hash::mac<macs::kmac_128, botan>(kmac, kmac_key, data).error().message() << '\n';
    return on_botan == on_hash2 ? 0 : 1;
}

// end::example[]
