// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// BLAKE2b-512 (RFC 7693) of "abc", checked against RFC 7693 appendix A, then BLAKE2b's keyed mode
// as a MAC. The keyed value is the RFC's key parameter at work; it agrees with Python's
// hashlib.blake2b(key=...).

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/algorithms.hpp>

#include <array>
#include <cstdint>
#include <iostream>
#include <string_view>

int main() {
    std::string_view const message = "abc";

    webcpp::hash::blake2b_512 plain;
    plain.update(message.data(), message.size());
    auto const digest = example::hex(plain.result());
    std::cout << "blake2b_512(abc) " << digest << '\n';

    if (digest !=
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
        "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923") {
        return 1;
    }

    // The key goes to the constructor, which is the RFC's key parameter: BLAKE2b mixes it in as
    // a first block of its own. Never prepend the key to the message yourself; that is a
    // different function, whose output matches no other implementation's keyed BLAKE2b.
    // Hash2's BLAKE2b has no salt or personalisation parameter: libsodium's crypto_generichash
    // has them, and a later increment of webcpp::hash.
    std::array<std::uint8_t, 32> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>(i);
    }
    webcpp::hash::blake2b_512 keyed(key.data(), key.size());
    keyed.update(message.data(), message.size());
    std::cout << "keyed " << example::hex(keyed.result()) << '\n';
}

// end::example[]
