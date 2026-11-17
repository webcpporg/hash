// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Key separation: one master key, a different key for each purpose, so that a weakness in one
// use of a key does not open the others. This is what an application builds from webcpp::hash.
// Part (a) is HKDF-SHA-256 with a label per purpose. Part (b) is blake2b_subkey, libsodium's
// crypto_kdf: a subkey per id in an 8-byte context, the bytes a libsodium program derives with
// crypto_kdf_derive_from_key. All four keys agree with Python (hmac for HKDF;
// hashlib.blake2b(b"", digest_size=32, key=master, salt=id.to_bytes(8, "little") + bytes(8),
// person=b"vault v1" + bytes(8)) for the subkeys).

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/blake2b_subkey.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>

#include <array>
#include <cstdint>
#include <iostream>
#include <span>
#include <string_view>

namespace {

// The label names the purpose: a key derived for file encryption is unrelated to the one for
// authentication, though both come from the master key.
std::array<std::uint8_t, 32> from_label(std::span<std::uint8_t const> master,
                                        std::string_view label) {
    std::array<std::uint8_t, 32> key{};
    auto const done =
        webcpp::hash::hkdf<webcpp::hash::hmac_sha2_256>(key, {}, master, example::bytes(label));
    if (!done) {
        std::cerr << done.error().message() << '\n';
        key.fill(0);
    }
    return key;
}

// The id numbers the purpose, and the context, 8 bytes, names the application: the same id in
// another application's context gives an unrelated key.
std::array<std::uint8_t, 32> from_id(std::span<std::uint8_t const> master, std::uint64_t id) {
    std::array<std::uint8_t, 32> key{};
    auto const done = webcpp::hash::blake2b_subkey(key, master, id, example::bytes("vault v1"));
    if (!done) {
        std::cerr << done.error().message() << '\n';
    }
    return key;
}

}  // namespace

int main() {
    auto const master =
        example::from_hex("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");

    std::cout << "hkdf file-encryption "
              << example::hex(from_label(master, "vault v1 file-encryption")) << '\n';
    std::cout << "hkdf sync-authentication "
              << example::hex(from_label(master, "vault v1 sync-authentication")) << '\n';
    std::cout << "blake2b subkey 1 " << example::hex(from_id(master, 1)) << '\n';
    std::cout << "blake2b subkey 2 " << example::hex(from_id(master, 2)) << '\n';
}

// end::example[]
