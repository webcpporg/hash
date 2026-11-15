// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// PBKDF2-HMAC-SHA-256 (RFC 8018), first the vector of RFC 7914 section 11 (P "passwd", S "salt",
// c 1, 64 bytes), checked against the RFC, then a key derived from a password at the iteration
// count OWASP's Password Storage Cheat Sheet gives for PBKDF2-HMAC-SHA-256, 600,000. The second
// value agrees with Python's hashlib.pbkdf2_hmac.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/pbkdf2.hpp>

#include <array>
#include <cstdint>
#include <iostream>

int main() {
    std::array<std::uint8_t, 64> vector{};
    auto done = webcpp::hash::pbkdf2<webcpp::hash::hmac_sha2_256>(vector, example::bytes("passwd"),
                                                                  example::bytes("salt"), 1);
    if (!done) {
        std::cerr << done.error().message() << '\n';
        return 1;
    }
    std::cout << "rfc7914 " << example::hex(vector) << '\n';
    if (example::hex(vector) !=
        "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783") {
        return 1;
    }

    // A key from a password. The iteration count is the cost an attacker pays for every guess:
    // too few, and a GPU tries billions of passwords a second. In a real program the salt is
    // 16 random bytes per user (webcpp::crypto::random_device), stored beside the result; it is
    // fixed here so that the output is the same on every run.
    auto const salt = example::from_hex("000102030405060708090a0b0c0d0e0f");
    std::array<std::uint8_t, 32> key{};
    done = webcpp::hash::pbkdf2<webcpp::hash::hmac_sha2_256>(
        key, example::bytes("correct horse battery staple"), salt, 600'000);
    if (!done) {
        std::cerr << done.error().message() << '\n';
        return 1;
    }
    std::cout << "600000 iterations " << example::hex(key) << '\n';
}

// end::example[]
