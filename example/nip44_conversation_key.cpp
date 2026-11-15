// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The first step of Nostr's NIP-44 version 2 encryption: the conversation key is HKDF-Extract
// with the salt "nip44-v2" over the 32-byte x coordinate of the ECDH shared point. This is what a
// domain library such as webcpp::nostr would build from webcpp::hash's HKDF; webcpp::hash has no
// NIP-44 function. The shared x is that of 2G (one secret key is 1 and the other public key is
// 2G); the ECDH itself is webcpp::crypto's secp256k1 and is not shown. The key agrees with Python's
// hmac module (HKDF-Extract is HMAC-SHA-256 of the IKM under the salt).

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>

#include <iostream>

int main() {
    auto const shared_x =
        example::from_hex("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");

    // The key is the same for both parties of the conversation, whoever of them computes it.
    // NIP-44's later steps (expanding a key per message from a random nonce) are webcpp::nostr's.
    auto key = webcpp::hash::hkdf_extract<webcpp::hash::hmac_sha2_256>(example::bytes("nip44-v2"),
                                                                       shared_x);
    if (!key) {
        std::cerr << key.error().message() << '\n';
        return 1;
    }
    std::cout << "conversation_key " << example::hex(*key) << '\n';
}

// end::example[]
