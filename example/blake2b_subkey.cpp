// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A chat app's keys from one master key with blake2b_subkey, libsodium's crypto_kdf: the key that
// encrypts messages is subkey 1, the one that authenticates them subkey 2, both in the context
// "messages"; a libsodium program that calls crypto_kdf_derive_from_key with the same master key,
// ids and context derives the same bytes. The master key is fixed here so that the output can be
// checked; an app draws it from webcpp::crypto::random_device. The values agree with Python's
// hashlib.blake2b(b"", digest_size=n, key=master, salt=id.to_bytes(8, "little") + bytes(8),
// person=b"messages" + bytes(8)), the construction libsodium uses.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/blake2b_subkey.hpp>

#include <array>
#include <cstdint>
#include <iostream>

int main() {
    namespace hash = webcpp::hash;

    auto const master =
        example::from_hex("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
    auto const context = example::bytes("messages");  // exactly 8 bytes

    std::array<std::uint8_t, 32> encryption{};
    std::array<std::uint8_t, 32> authentication{};
    if (!hash::blake2b_subkey(encryption, master, 1, context) ||
        !hash::blake2b_subkey(authentication, master, 2, context)) {
        return 1;
    }
    std::cout << "subkey 1 " << example::hex(encryption) << '\n';
    std::cout << "subkey 2 " << example::hex(authentication) << '\n';

    // The length is part of the derivation: subkey 3 of 16 bytes is not the start of subkey 3 of
    // 32 bytes.
    std::array<std::uint8_t, 16> short_key{};
    std::array<std::uint8_t, 32> long_key{};
    if (!hash::blake2b_subkey(short_key, master, 3, context) ||
        !hash::blake2b_subkey(long_key, master, 3, context)) {
        return 1;
    }
    std::cout << "subkey 3, 16 bytes " << example::hex(short_key) << '\n';
    std::cout << "subkey 3, 32 bytes " << example::hex(long_key) << '\n';

    // The context is 8 bytes, never padded: a shorter one is refused.
    std::cout
        << "7-byte context: "
        << hash::blake2b_subkey(encryption, master, 1, example::bytes("message")).error().message()
        << '\n';
}

// end::example[]
