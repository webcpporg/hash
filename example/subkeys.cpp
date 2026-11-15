// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Key separation: one master key, a different key for each purpose, so that a weakness in one
// use of a key does not open the others. This is what an application builds from webcpp::hash.
// Part (a) is HKDF-SHA-256 with a label per purpose. Part (b) is a keyed BLAKE2b-512 over the
// subkey's id and a context, cut to 32 bytes: it is NOT libsodium's crypto_kdf, which uses
// BLAKE2b's salt and personalisation parameters (a later increment of webcpp::hash); a program
// that must interoperate with libsodium waits for it. All four keys agree with Python (hmac for
// HKDF, hashlib.blake2b(key=...) for the keyed BLAKE2b).

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/algorithms.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
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

// The message is the subkey's id in 8 little-endian bytes, then an 8-byte context.
std::array<std::uint8_t, 32> from_id(std::span<std::uint8_t const> master, std::uint64_t id) {
    std::array<std::uint8_t, 16> message{};
    for (std::size_t i = 0; i < 8; ++i) {
        message[i] = static_cast<std::uint8_t>(id >> (8 * i));
    }
    std::string_view const context = "vault v1";
    std::ranges::copy(context, message.begin() + 8);

    webcpp::hash::blake2b_512 mac(master.data(), master.size());
    mac.update(message.data(), message.size());
    auto const full = mac.result();
    std::array<std::uint8_t, 32> key{};
    std::copy_n(full.begin(), key.size(), key.begin());
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
