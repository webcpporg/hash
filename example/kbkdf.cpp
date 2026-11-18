// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// KBKDF (NIST SP 800-108, counter mode over HMAC-SHA-256) on backends::openssl, as Kerberos's
// AES-SHA2 encryption types derive a checksum key from a base key: RFC 8009's KDF-HMAC-SHA2 is
// SP 800-108's default fixed input, Label || 0x00 || Context || L, with a 32-bit counter. The
// inputs and the key are RFC 8009's Appendix A (aes128-cts-hmac-sha256-128, Kc, usage 2).

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/kdf_standards.hpp>

#include <array>
#include <cstdint>
#include <iostream>

int main() {
    namespace hash = webcpp::hash;
    auto const base_key = example::from_hex("3705d96080c17728a0e800eab6e0d23c");
    // The key usage 2 in 4 bytes, then 0x99: the checksum key's label in RFC 8009.
    auto const label = example::from_hex("0000000299");

    std::array<std::uint8_t, 16> checksum_key{};
    auto const done = hash::kbkdf<hash::hmac_sha2_256, hash::backends::openssl>(
        checksum_key, base_key, {.label = label});
    if (!done) {
        std::cerr << done.error().message() << '\n';
        return 1;
    }
    std::cout << "Kc " << example::hex(checksum_key) << '\n';
    if (example::hex(checksum_key) != "b31a018a48f54776f403e9a396325dc3") {
        return 1;
    }
}

// end::example[]
