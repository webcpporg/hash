// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Keyed BLAKE2b through mac on its default, backends::sodium (libsodium's keyed
// crypto_generichash_blake2b): a 32-byte tag under a 32-byte key, checked in constant time; a
// 16-byte tag, which is not the 32-byte one cut; and the empty key, refused. Each value agrees with
// Python's hashlib.blake2b(message, key=key, digest_size=n).

// tag::example[]
#include "hex.hpp"

#include <webcpp/crypto/constant_time_equal.hpp>
#include <webcpp/hash/mac.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>

int main() {
    namespace hash = webcpp::hash;
    using webcpp::hash::macs::blake2b_mac;

    // A 32-byte key, as webcpp::crypto::random_device gives it (fixed here, for the output).
    std::array<std::uint8_t, 32> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>(i);
    }
    auto const message = example::bytes("order:42,amount:10.00");

    // The default backend of macs::blake2b_mac is backends::sodium: link /third_party//sodium.
    std::array<std::uint8_t, 32> tag{};
    if (!hash::mac<blake2b_mac>(tag, key, message)) {
        return 1;
    }
    std::cout << "BLAKE2b-256 keyed " << example::hex(tag) << '\n';

    // The receiver computes the tag again and compares it in constant time.
    std::array<std::uint8_t, 32> again{};
    bool const genuine = hash::mac<blake2b_mac>(again, key, message) &&
                         webcpp::crypto::constant_time_equal(again, tag);
    std::cout << "genuine: " << (genuine ? "yes" : "no") << '\n';

    // The tag's size is a parameter of the hash: a 16-byte tag is not the 32-byte one cut.
    std::array<std::uint8_t, 16> short_tag{};
    if (!hash::mac<blake2b_mac>(short_tag, key, message)) {
        return 1;
    }
    std::cout << "BLAKE2b-128 keyed " << example::hex(short_tag) << '\n';

    // An empty key is the unkeyed hash, a digest (digests::blake2b), not a MAC.
    std::cout
        << "empty key: "
        << hash::mac<blake2b_mac>(tag, std::span<std::uint8_t const>{}, message).error().message()
        << '\n';
    return genuine ? 0 : 1;
}

// end::example[]
