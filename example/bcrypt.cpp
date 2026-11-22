// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// bcrypt and bcrypt_pbkdf on backends::botan, their one backend, named in the call: the string of
// "U*U" under the salt "CCCCCCCCCCCCCCCCCCCCC." at cost 5, version 'a', checked against
// bcrypt-tester's (Openwall's) string; bcrypt_verify of the right and of a wrong password; a
// password of 73 bytes and one with a zero byte, refused rather than cut; and bcrypt_pbkdf of
// "password" and "salt" over 12 rounds against Go's bcrypt_pbkdf test, as OpenSSH's keys derive.
// A real program draws the salt from webcpp::crypto::random_device and takes a cost of 10 or more.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/bcrypt.hpp>

#include <array>
#include <cstdint>
#include <iostream>
#include <string_view>
#include <vector>

int main() {
    namespace hash = webcpp::hash;
    using hash::backends::botan;

    // The salt is the caller's: 16 bytes, here those "CCCCCCCCCCCCCCCCCCCCC." encodes.
    auto const salt = example::from_hex("10410410410410410410410410410410");
    std::array<char, hash::bcrypt_hash_size> stored{};
    if (!hash::bcrypt<botan>(stored, example::bytes("U*U"), salt, {.cost = 5, .version = 'a'})) {
        return 1;
    }
    std::string_view const text(stored.data(), stored.size());
    std::cout << "bcrypt " << text << '\n';
    if (text != "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW") {
        return 1;
    }

    // Verifying reads the cost and the salt from the string.
    auto const right = hash::bcrypt_verify<botan>(example::bytes("U*U"), text);
    auto const wrong = hash::bcrypt_verify<botan>(example::bytes("U*V"), text);
    if (!right || !wrong) {
        return 1;
    }
    std::cout << "U*U " << (*right ? "matches" : "does not match") << ", U*V "
              << (*wrong ? "matches" : "does not match") << '\n';

    // bcrypt reads 72 bytes, and OpenBSD's stops at a zero byte: both are refused, never cut.
    std::vector<std::uint8_t> const long_password(73, 'a');
    std::array<std::uint8_t, 3> const with_zero{'a', 0, 'b'};
    std::cout << "73 bytes: " << hash::bcrypt<botan>(stored, long_password, salt).error().message()
              << '\n';
    std::cout << "a zero byte: " << hash::bcrypt<botan>(stored, with_zero, salt).error().message()
              << '\n';

    // bcrypt_pbkdf, the key derivation of OpenSSH's encrypted private keys.
    std::array<std::uint8_t, 32> key{};
    if (!hash::bcrypt_pbkdf<botan>(key, example::bytes("password"), example::bytes("salt"), 12)) {
        return 1;
    }
    std::cout << "bcrypt_pbkdf " << example::hex(key) << '\n';
    return *right && !*wrong ? 0 : 1;
}

// end::example[]
