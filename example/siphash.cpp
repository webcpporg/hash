// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// SipHash-2-4 as a hash table's keyed hash. Part one is the reference implementation's published
// vector (Aumasson and Bernstein, key 00..0f, message 00..0e, the 64-bit output
// 0xa129ca6149be45e5). Part two is HalfSipHash-2-4, the 32-bit variant Boost.Hash2 names
// siphash_32, with the 8-byte key 00..07: its value for the same 15-byte message is vectors_hsip32
// of github.com/veorq/SipHash (vectors.h, entry 15, bytes 74 fe 2b 97 read as a little-endian
// integer).

// tag::example[]
#include <webcpp/crypto/random_device.hpp>
#include <webcpp/hash/algorithms.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>
#include <unordered_set>

namespace {

// A hasher for a hash table of ids that arrive from the network, keyed with a secret.
struct peer_hasher {
    std::array<std::uint8_t, 16> key;

    std::size_t operator()(std::string const& id) const {
        webcpp::hash::siphash_64 h(key.data(), key.size());
        h.update(id.data(), id.size());
        return static_cast<std::size_t>(h.result());
    }
};

}  // namespace

int main() {
    std::array<std::uint8_t, 16> key{};
    std::array<std::uint8_t, 15> message{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>(i);
    }
    for (std::size_t i = 0; i < message.size(); ++i) {
        message[i] = static_cast<std::uint8_t>(i);
    }

    // The 64-bit hash takes a 16-byte key.
    webcpp::hash::siphash_64 wide(key.data(), key.size());
    wide.update(message.data(), message.size());
    std::uint64_t const wide_value = wide.result();

    // The 32-bit hash takes an 8-byte key: HalfSipHash, for the targets where 32-bit words are
    // the natural size.
    webcpp::hash::siphash_32 narrow(key.data(), 8);
    narrow.update(message.data(), message.size());
    std::uint32_t const narrow_value = narrow.result();

    std::cout << std::hex << std::setfill('0');
    std::cout << "siphash_64 " << std::setw(16) << wide_value << '\n';
    std::cout << "siphash_32 " << std::setw(8) << narrow_value << '\n';
    std::cout << std::dec;
    if (wide_value != 0xa129ca6149be45e5ULL || narrow_value != 0x972bfe74U) {
        return 1;
    }

    // The use. A table keyed by an unkeyed hash (FNV, xxHash) lets an attacker who chooses the
    // keys choose keys that all collide, and the table degrades to a list: hash flooding. A
    // random key, secret and different in every process, takes that choice away from the attacker.
    peer_hasher hasher{};
    auto const filled = webcpp::crypto::random_device{}.fill(hasher.key);
    if (!filled) {
        std::cerr << filled.error().message() << '\n';
        return 1;
    }
    std::unordered_set<std::string, peer_hasher> peers(8, hasher);
    peers.insert("peer-a");
    peers.insert("peer-b");
    peers.insert("peer-c");
    std::cout << "peers " << peers.size() << '\n';
}

// end::example[]
