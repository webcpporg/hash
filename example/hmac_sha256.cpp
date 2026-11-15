// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// HMAC-SHA-256 of RFC 4231 test case 2 (key "Jefe", data "what do ya want for nothing?"), and
// the receiver's check of a tag. The tag is RFC 4231's published value.

// tag::example[]
#include "hex.hpp"

#include <webcpp/crypto/equal.hpp>
#include <webcpp/hash/hmac.hpp>

#include <iostream>
#include <span>
#include <string_view>

namespace {

webcpp::hash::hmac_sha2_256::result_type tag_of(std::span<std::uint8_t const> key,
                                                std::string_view message) {
    webcpp::hash::hmac_sha2_256 mac(key.data(), key.size());
    mac.update(message.data(), message.size());
    return mac.result();
}

}  // namespace

int main() {
    auto const key = example::bytes("Jefe");
    std::string_view const message = "what do ya want for nothing?";

    // The sender computes the tag and sends it along with the message.
    auto const tag = tag_of(key, message);
    std::cout << "hmac_sha2_256 " << example::hex(tag) << '\n';
    if (example::hex(tag) != "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843") {
        return 1;
    }

    // The receiver computes the tag again from the message it got, and compares it with the one
    // it got. Never with ==: memcmp stops at the first different byte, so an attacker who
    // measures how long the answer takes learns how many leading bytes of a guess are right,
    // and guesses a valid tag one byte at a time. webcpp::crypto::equal reads every byte.
    bool const genuine = webcpp::crypto::equal(tag_of(key, message), tag);
    std::cout << "genuine: " << (genuine ? "yes" : "no") << '\n';

    // One byte of the message changed in transit: the tags differ.
    bool const forged = webcpp::crypto::equal(tag_of(key, "what do ya want for nothing!"), tag);
    std::cout << "tampered: " << (forged ? "accepted" : "refused") << '\n';
    if (!genuine || forged) {
        return 1;
    }
}

// end::example[]
