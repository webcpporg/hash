// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// HKDF (RFC 5869) over HMAC-SHA-256: test case 1 of appendix A, checked against the RFC's
// output keying material, then the way an application uses it. The two derived keys agree with an
// independent computation, Python's hmac module following RFC 5869.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>

#include <array>
#include <cstdint>
#include <iostream>

int main() {
    // RFC 5869, appendix A.1.
    auto const ikm = example::from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    auto const salt = example::from_hex("000102030405060708090a0b0c");
    auto const info = example::from_hex("f0f1f2f3f4f5f6f7f8f9");

    std::array<std::uint8_t, 42> okm{};
    auto done = webcpp::hash::hkdf<webcpp::hash::hmac_sha2_256>(okm, salt, ikm, info);
    if (!done) {
        std::cerr << done.error().message() << '\n';
        return 1;
    }
    std::cout << "okm " << example::hex(okm) << '\n';
    if (example::hex(okm) !=
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865") {
        return 1;
    }

    // The two steps of HKDF apart: extract turns the input into a uniform pseudorandom key, and
    // expand stretches it to the length asked, once per context. A program that needs several
    // keys from one secret extracts once and expands as many times as it needs.
    auto prk = webcpp::hash::hkdf_extract<webcpp::hash::hmac_sha2_256>(salt, ikm);
    if (!prk) {
        std::cerr << prk.error().message() << '\n';
        return 1;
    }
    std::array<std::uint8_t, 42> again{};
    done = webcpp::hash::hkdf_expand<webcpp::hash::hmac_sha2_256>(again, *prk, info);
    if (!done) {
        std::cerr << done.error().message() << '\n';
        return 1;
    }
    std::cout << "two steps " << (again == okm ? "same" : "different") << '\n';

    // The use: one shared secret, two keys. Each key has its own info, so that the encryption
    // key and the authentication key are independent: a key used for two purposes can let an
    // attack on one purpose break the other. The secret is already uniform (a key agreement's
    // output hashed, say), so an empty salt is fine.
    auto const secret =
        example::from_hex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    std::array<std::uint8_t, 32> encryption{};
    std::array<std::uint8_t, 32> authentication{};
    done = webcpp::hash::hkdf<webcpp::hash::hmac_sha2_256>(
        encryption, {}, secret, example::bytes("example chat v1 encryption"));
    if (!done) {
        std::cerr << done.error().message() << '\n';
        return 1;
    }
    done = webcpp::hash::hkdf<webcpp::hash::hmac_sha2_256>(
        authentication, {}, secret, example::bytes("example chat v1 authentication"));
    if (!done) {
        std::cerr << done.error().message() << '\n';
        return 1;
    }
    std::cout << "encryption key " << example::hex(encryption) << '\n';
    std::cout << "authentication key " << example::hex(authentication) << '\n';
}

// end::example[]
