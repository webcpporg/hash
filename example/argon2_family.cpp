// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The family argon2 on its default backend, libsodium: Argon2id at OWASP's minimum for a login
// (2 passes over 19 MiB, one lane), the same tag as the function argon2id; Argon2i at libsodium's
// interactive costs for it (4 passes over 32 MiB); and four lanes, which RFC 9106 allows and
// libsodium does not take, refused before any work. Both tags agree with an independent
// implementation: Node.js 26's crypto.argon2Sync with the same parameters.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/error.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>

namespace hash = webcpp::hash;

int main() {
    // The salt is 16 random bytes per password in a real program, stored with the tag and the
    // costs; it is fixed here so that the output is the same on every run.
    auto const salt = example::from_hex("000102030405060708090a0b0c0d0e0f");
    auto const password = example::bytes("correct horse battery staple");

    // The family counts memory in KiB, as RFC 9106 does: 19,456 KiB are 19 MiB.
    hash::argon2_parameters const login{.passes = 2, .memory_kibibytes = 19456};
    std::array<std::uint8_t, 32> tag{};
    if (!hash::argon2<hash::kdfs::argon2id>(tag, password, salt, login)) {
        return 1;
    }
    std::cout << "argon2id " << example::hex(tag) << '\n';

    // The function argon2id counts bytes: the same costs give the same tag.
    std::array<std::uint8_t, 32> same{};
    if (!hash::argon2id(same, password, salt, {.passes = 2, .memory = std::size_t{19456} * 1024}) ||
        same != tag) {
        return 1;
    }

    // Argon2i, only to check tags a system already stored with it; libsodium takes 3 passes or
    // more.
    if (!hash::argon2<hash::kdfs::argon2i>(tag, password, salt,
                                           {.passes = 4, .memory_kibibytes = 32768})) {
        return 1;
    }
    std::cout << "argon2i  " << example::hex(tag) << '\n';

    // Four lanes are RFC 9106's, not libsodium's: refused before any work, the tag untouched.
    auto const refused = hash::argon2<hash::kdfs::argon2id>(
        tag, password, salt, {.passes = 2, .memory_kibibytes = 19456, .lanes = 4});
    if (refused || refused.error() != hash::error::unsupported_by_backend) {
        return 1;
    }
    std::cout << "4 lanes: " << refused.error().message() << '\n';
}

// end::example[]
