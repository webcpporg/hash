// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Argon2id (RFC 9106) at libsodium's interactive costs (2 passes over 64 MiB, one lane), a
// 32-byte tag from a password and a fixed 16-byte salt. The tag agrees with an independent
// implementation: Node.js 26's crypto.argon2Sync('argon2id', ...) with the same parameters.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/error.hpp>

#include <array>
#include <cstdint>
#include <iostream>
#include <span>

int main() {
    // The salt is 16 random bytes per password in a real program, stored with the tag; it is
    // fixed here so that the output is the same on every run.
    auto const salt = example::from_hex("000102030405060708090a0b0c0d0e0f");

    std::array<std::uint8_t, 32> tag{};
    auto const done = webcpp::hash::argon2id(tag, example::bytes("correct horse battery staple"),
                                             salt, webcpp::hash::argon2id_interactive);
    if (!done) {
        std::cerr << done.error().message() << '\n';
        return 1;
    }
    std::cout << "argon2id " << example::hex(tag) << '\n';

    // A salt of another size is refused before any work, and the output stays as it was.
    auto const refused =
        webcpp::hash::argon2id(tag, example::bytes("correct horse battery staple"),
                               std::span(salt).first(15), webcpp::hash::argon2id_interactive);
    if (refused || refused.error() != webcpp::hash::error::invalid_salt_size) {
        return 1;
    }
    std::cout << "15-byte salt: " << refused.error().message() << '\n';
}

// end::example[]
