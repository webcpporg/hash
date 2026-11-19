// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The KDF of ANSI X9.63 over SHA-256 on backends::openssl, as ECIES (SEC 1, section 5.1) derives
// its encryption and MAC keys from an ECDH shared secret, here with the sender's ephemeral public
// key as the shared info. The inputs are the example's own (the public key's bytes are an
// illustration, not a point of a real exchange); the test kdf_standards_openssl checks x963kdf
// against OpenSSL's and NIST's vectors.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/kdf_standards.hpp>

#include <array>
#include <cstdint>
#include <iostream>
#include <span>

int main() {
    namespace hash = webcpp::hash;
    // Z, the ECDH result's x-coordinate, and the bytes of the sender's ephemeral public key.
    auto const shared_secret =
        example::from_hex("9e56d91d817135d372834283bf84269cfb316ea3da806a48f6daa7798cfe90c4");
    auto const ephemeral_public_key =
        example::from_hex("02d7c5f8f1c5bd2a0a83c0a5b84dbbc1bf1e3b0a8e7dc7cc5b2b8b1d3e8f7a6b5c");

    // 16 bytes of AES-128 key, then 32 bytes of HMAC-SHA-256 key: one derivation, cut in two.
    std::array<std::uint8_t, 48> keys{};
    auto const done = hash::x963kdf<hash::digests::sha2_256, hash::backends::openssl>(
        keys, shared_secret, ephemeral_public_key);
    if (!done) {
        std::cerr << done.error().message() << '\n';
        return 1;
    }
    std::cout << "encryption key " << example::hex(std::span(keys).first(16)) << '\n';
    std::cout << "mac key " << example::hex(std::span(keys).subspan(16)) << '\n';
}

// end::example[]
