// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The MAC family: HMAC-SHA-256 with mac, in one call, against RFC 4231's test case 2; the
// receiver's check with webcpp::crypto::equal; and a tag cut to 16 bytes, RFC 4231's test case 5.

// tag::example[]
#include "hex.hpp"

#include <webcpp/crypto/equal.hpp>
#include <webcpp/hash/mac.hpp>

#include <array>
#include <cstdint>
#include <iostream>
#include <vector>

int main() {
    namespace hash = webcpp::hash;
    using hmac_sha256 = hash::macs::hmac<hash::digests::sha2_256>;

    auto const key = example::bytes("Jefe");
    auto const message = example::bytes("what do ya want for nothing?");
    std::array<std::uint8_t, 32> tag{};
    if (!hash::mac<hmac_sha256>(tag, key, message)) {
        return 1;
    }
    std::cout << "mac " << example::hex(tag) << '\n';
    if (example::hex(tag) != "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843") {
        return 1;
    }

    // The receiver computes the tag again and compares it in constant time, never with ==.
    std::array<std::uint8_t, 32> expected{};
    bool const genuine = hash::mac<hmac_sha256>(expected, key, message).has_value() &&
                         webcpp::crypto::equal(expected, tag);
    std::cout << "genuine: " << (genuine ? "yes" : "no") << '\n';

    // A tag cut to 16 bytes is the digest's first 16 (RFC 2104, section 5); shorter than 10 is
    // refused.
    std::vector<std::uint8_t> const key_5(20, 0x0c);
    std::array<std::uint8_t, 16> cut{};
    if (!hash::mac<hmac_sha256>(cut, key_5, example::bytes("Test With Truncation"))) {
        return 1;
    }
    std::cout << "cut to 16 " << example::hex(cut) << '\n';
    std::array<std::uint8_t, 8> too_short{};
    std::cout << "8-byte tag: " << hash::mac<hmac_sha256>(too_short, key, message).error().message()
              << '\n';
    return genuine ? 0 : 1;
}

// end::example[]
