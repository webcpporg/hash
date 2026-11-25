// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The key derivations of backends::botan, each named in the call: HKDF over HMAC-SHA-256 against
// RFC 5869's first case; PBKDF2 over HMAC-SHA-1 against RFC 6070's second; KBKDF against RFC
// 8009's checksum key, the inputs of kbkdf.cpp; and KBKDF without L, which Botan's SP 800-108
// always writes, refused.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/kdf_standards.hpp>
#include <webcpp/hash/pbkdf2.hpp>

#include <array>
#include <cstdint>
#include <iostream>

int main() {
    namespace hash = webcpp::hash;
    using hash::backends::botan;

    // HKDF: RFC 5869, Test Case 1.
    auto const input_key_material =
        example::from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    auto const salt = example::from_hex("000102030405060708090a0b0c");
    auto const application_info = example::from_hex("f0f1f2f3f4f5f6f7f8f9");
    std::array<std::uint8_t, 42> output_key_material{};
    if (!hash::hkdf<hash::hmac_sha2_256, botan>(output_key_material, salt, input_key_material,
                                                application_info)) {
        return 1;
    }
    std::cout << "hkdf " << example::hex(output_key_material) << '\n';
    if (example::hex(output_key_material) !=
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865") {
        return 1;
    }

    // PBKDF2: RFC 6070, 2 iterations.
    std::array<std::uint8_t, 20> key{};
    if (!hash::pbkdf2<hash::hmac_sha1_160, botan>(key, example::bytes("password"),
                                                  example::bytes("salt"), 2)) {
        return 1;
    }
    std::cout << "pbkdf2 " << example::hex(key) << '\n';

    // KBKDF: RFC 8009's Kc, with SP 800-108's separator and L, as Botan writes them.
    auto const base_key = example::from_hex("3705d96080c17728a0e800eab6e0d23c");
    auto const label = example::from_hex("0000000299");
    std::array<std::uint8_t, 16> checksum_key{};
    if (!hash::kbkdf<hash::hmac_sha2_256, botan>(checksum_key, base_key, {.label = label})) {
        return 1;
    }
    std::cout << "kbkdf " << example::hex(checksum_key) << '\n';

    // Without L the fixed input is another one, which Botan's KBKDF cannot write.
    auto const refused = hash::kbkdf<hash::hmac_sha2_256, botan>(checksum_key, base_key,
                                                                 {.label = label, .length = false});
    std::cout << "kbkdf without L: " << refused.error().message() << '\n';
}

// end::example[]
