// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Argon2 and scrypt on backends::botan, named in the call: Argon2id with RFC 9106's section 5.3
// inputs (four lanes, a secret and associated data), the tag argon2_openssl.cpp checks; scrypt
// with RFC 7914's second case; and the costs past Botan's own limits, refused.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/scrypt.hpp>

#include <array>
#include <cstdint>
#include <iostream>

int main() {
    namespace hash = webcpp::hash;
    using hash::backends::botan;

    // RFC 9106, section 5.3: four lanes over 32 KiB, three passes, a secret and associated data.
    std::array<std::uint8_t, 32> password{};
    password.fill(0x01);
    std::array<std::uint8_t, 16> salt{};
    salt.fill(0x02);
    std::array<std::uint8_t, 8> pepper{};
    pepper.fill(0x03);
    std::array<std::uint8_t, 12> context{};
    context.fill(0x04);
    hash::argon2_parameters costs{
        .passes = 3,
        .memory_kibibytes = 32,
        .lanes = 4,
        .secret = pepper,
        .associated_data = context,
    };
    std::array<std::uint8_t, 32> tag{};
    if (!hash::argon2<hash::kdfs::argon2id, botan>(tag, password, salt, costs)) {
        return 1;
    }
    std::cout << "argon2id " << example::hex(tag) << '\n';

    // scrypt: RFC 7914, N 1,024, r 8, p 16.
    std::array<std::uint8_t, 64> key{};
    if (!hash::scrypt<botan>(key, example::bytes("password"), example::bytes("NaCl"),
                             {.cost = 1024, .block_size = 8, .parallelism = 16})) {
        return 1;
    }
    std::cout << "scrypt " << example::hex(key).substr(0, 32) << "...\n";

    // Botan's Argon2 takes at most 128 lanes, which RFC 9106 allows up to 2^24 - 1 of.
    costs.lanes = 129;
    costs.memory_kibibytes = 8 * 129;
    auto const lanes = hash::argon2<hash::kdfs::argon2id, botan>(tag, password, salt, costs);
    std::cout << "129 lanes: " << lanes.error().message() << '\n';
    // Botan's scrypt takes N up to 2^22.
    auto const large = hash::scrypt<botan>(key, example::bytes("password"), example::bytes("NaCl"),
                                           {.cost = 1U << 23U, .block_size = 2, .parallelism = 1});
    std::cout << "N 2^23: " << large.error().message() << '\n';
}

// end::example[]
