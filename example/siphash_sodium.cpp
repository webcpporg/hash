// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// SipHash through mac, on libsodium: SipHash-2-4 on backends::sodium gives backends::hash2's bytes
// (its default), and SipHash-2-4x, libsodium's 16-byte SipHash, runs on its default,
// backends::sodium. The key is fixed here so that the output can be checked; a program draws it
// from webcpp::crypto::random_device once per process (see siphash.cpp). The values agree with the
// SipHash reference implementation (github.com/veorq/SipHash), in 64-bit and 128-bit output.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/mac.hpp>

#include <array>
#include <cstdint>
#include <iostream>

int main() {
    namespace hash = webcpp::hash;
    namespace macs = hash::macs;

    auto const key = example::from_hex("000102030405060708090a0b0c0d0e0f");
    auto const message = example::bytes("user:alice");

    std::array<std::uint8_t, 8> on_sodium{};
    std::array<std::uint8_t, 8> on_hash2{};
    if (!hash::mac<macs::siphash_2_4, hash::backends::sodium>(on_sodium, key, message) ||
        !hash::mac<macs::siphash_2_4>(on_hash2, key, message)) {
        return 1;
    }
    std::cout << "siphash_2_4 " << example::hex(on_sodium) << '\n';
    std::cout << "the same on hash2: " << (on_sodium == on_hash2 ? "yes" : "no") << '\n';

    // SipHash-2-4x: 16 bytes, another value than SipHash-2-4's, not two of its tags side by side.
    std::array<std::uint8_t, 16> wide{};
    if (!hash::mac<macs::siphash_2_4x>(wide, key, message)) {
        return 1;
    }
    std::cout << "siphash_2_4x " << example::hex(wide) << '\n';

    // The key is 16 bytes, always.
    std::array<std::uint8_t, 8> const short_key{};
    std::cout << "8-byte key: "
              << hash::mac<macs::siphash_2_4x>(wide, short_key, message).error().message() << '\n';
    return on_sodium == on_hash2 ? 0 : 1;
}

// end::example[]
