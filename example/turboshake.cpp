// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// TurboSHAKE128 on libsodium, named in the call: RFC 9861's first vector (the empty message, 32
// bytes), the same function on a message, its first 32 bytes again inside a 64-byte output, a
// second function from another domain byte, the same id from a hasher fed in pieces, and a domain
// byte outside RFC 9861's range refused. Each value agrees with RFC 9861, section 5, or with an
// independent Python TurboSHAKE over Keccak-p[1600, 12].

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/digest.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <span>

int main() {
    namespace hash = webcpp::hash;
    using webcpp::hash::backends::sodium;
    using webcpp::hash::digests::turboshake_128;

    // RFC 9861, section 5: TurboSHAKE128 of the empty message, D = 0x1F, 32 bytes.
    std::array<std::uint8_t, 32> empty{};
    if (!hash::digest_of<turboshake_128, sodium>(empty, {})) {
        return 1;
    }
    std::cout << "RFC 9861 " << example::hex(empty) << '\n';
    if (example::hex(empty) != "1e415f1c5983aff2169217277d17bb538cd945a397ddec541f1ce41af2c1b74c") {
        return 1;
    }

    // An extendable output: as many bytes as the caller takes, the shorter a prefix of the longer.
    auto const message = example::bytes("hello, world");
    std::array<std::uint8_t, 32> id{};
    std::array<std::uint8_t, 64> longer{};
    if (!hash::digest_of<turboshake_128, sodium>(id, message) ||
        !hash::digest_of<turboshake_128, sodium>(longer, message)) {
        return 1;
    }
    std::cout << "32 bytes " << example::hex(id) << '\n';
    std::cout << "64 bytes start alike: "
              << (std::ranges::equal(std::span(longer).first(32), id) ? "yes" : "no") << '\n';

    // The domain byte (0x01 to 0x7F; 0x1F by default) makes another function from the same
    // permutation: an application gives each of its uses its own byte.
    std::array<std::uint8_t, 32> other{};
    if (!hash::digest_of<turboshake_128, sodium>(other, message, {.domain = 0x0B})) {
        return 1;
    }
    std::cout << "domain 0x0B " << example::hex(other) << '\n';

    // A hasher takes the domain byte when it starts.
    auto hashing = hash::hasher<turboshake_128, sodium>::make({.domain = 0x1F});
    if (!hashing || !hashing->update(example::bytes("hello, ")) ||
        !hashing->update(example::bytes("world"))) {
        return 1;
    }
    std::array<std::uint8_t, 32> pieces{};
    if (!hashing->finish(pieces)) {
        return 1;
    }
    std::cout << "hasher " << (pieces == id ? "same" : "different") << '\n';

    // A domain byte outside RFC 9861's range is refused before any work.
    auto const refused = hash::digest_of<turboshake_128, sodium>(id, message, {.domain = 0x80});
    std::cout << "domain 0x80: " << refused.error().message() << '\n';
}

// end::example[]
