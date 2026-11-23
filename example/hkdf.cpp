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
    auto const input_key_material =
        example::from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    auto const salt = example::from_hex("000102030405060708090a0b0c");
    auto const application_info = example::from_hex("f0f1f2f3f4f5f6f7f8f9");

    std::array<std::uint8_t, 42> output_key_material{};
    auto done = webcpp::hash::hkdf<webcpp::hash::hmac_sha2_256>(
        output_key_material, salt, input_key_material, application_info);
    if (!done) {
        std::cerr << done.error().message() << '\n';
        return 1;
    }
    std::cout << "okm " << example::hex(output_key_material) << '\n';
    if (example::hex(output_key_material) !=
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865") {
        return 1;
    }

    // The two steps of HKDF apart: extract turns the input into a uniform pseudorandom key, and
    // expand stretches it to the length asked, once per context. A program that needs several
    // keys from one secret extracts once and expands as many times as it needs.
    auto pseudorandom_key =
        webcpp::hash::hkdf_extract<webcpp::hash::hmac_sha2_256>(salt, input_key_material);
    if (!pseudorandom_key) {
        std::cerr << pseudorandom_key.error().message() << '\n';
        return 1;
    }
    std::array<std::uint8_t, 42> again{};
    done = webcpp::hash::hkdf_expand<webcpp::hash::hmac_sha2_256>(again, *pseudorandom_key,
                                                                  application_info);
    if (!done) {
        std::cerr << done.error().message() << '\n';
        return 1;
    }
    std::cout << "two steps " << (again == output_key_material ? "same" : "different") << '\n';

    // The use: one shared secret, two keys. Each key has its own application_info, so that the
    // encryption key and the authentication key are independent: a key used for two purposes can
    // let an attack on one purpose break the other. The secret is already uniform (a key
    // agreement's output hashed, say), so an empty salt is fine.
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
