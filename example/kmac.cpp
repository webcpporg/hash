// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// KMAC128 with mac, on its default backend, XKCP, against NIST's KMAC sample #2 (the key 0x40 to
// 0x5F, the message 00 01 02 03, S = "My Tagged Application"); the receiver's check with
// webcpp::crypto::constant_time_equal; and KMACXOF128 of the same inputs, another tag, NIST's
// KMACXOF sample #2.

// tag::example[]
#include "hex.hpp"

#include <webcpp/crypto/constant_time_equal.hpp>
#include <webcpp/hash/mac.hpp>

#include <array>
#include <cstdint>
#include <iostream>

int main() {
    namespace hash = webcpp::hash;
    using webcpp::hash::macs::kmac_128;

    auto const key =
        example::from_hex("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
    auto const message = example::from_hex("00010203");
    auto const application = example::bytes("My Tagged Application");
    std::array<std::uint8_t, 32> tag{};
    if (!hash::mac<kmac_128>(tag, key, message, {.customisation = application})) {
        return 1;
    }
    std::cout << "kmac_128 " << example::hex(tag) << '\n';
    if (example::hex(tag) != "3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5") {
        return 1;
    }

    // The receiver computes the tag again and compares it in constant time, never with ==.
    std::array<std::uint8_t, 32> expected{};
    bool const genuine =
        hash::mac<kmac_128>(expected, key, message, {.customisation = application}).has_value() &&
        webcpp::crypto::constant_time_equal(expected, tag);
    std::cout << "genuine: " << (genuine ? "yes" : "no") << '\n';

    // KMACXOF128: the same inputs, another tag.
    std::array<std::uint8_t, 32> xof{};
    if (!hash::mac<kmac_128>(xof, key, message, {.customisation = application, .xof = true})) {
        return 1;
    }
    std::cout << "kmacxof_128 " << example::hex(xof) << '\n';
    if (example::hex(xof) != "31a44527b4ed9f5c6101d11de6d26f0620aa5c341def41299657fe9df1a3b16c") {
        return 1;
    }
    return genuine ? 0 : 1;
}

// end::example[]
