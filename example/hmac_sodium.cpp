// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// HMAC on libsodium, named in the call: HMAC-SHA-256 under a 32-byte key, checked in constant time;
// libsodium's "HMAC-SHA-512-256" (crypto_auth_hmacsha512256), which is HMAC-SHA-512 cut to 32
// bytes; and HMAC over SHA-512/256, another function, on the default backend. Each value agrees
// with Python's hmac.new(key, message, ...).

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/mac.hpp>
#include <webcpp/secure/constant_time_equal.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>

int main() {
    namespace hash = webcpp::hash;
    namespace digests = webcpp::hash::digests;
    using webcpp::hash::backends::sodium;
    using webcpp::hash::macs::hmac;

    // A 32-byte key, as webcpp::crypto::random_device gives it (fixed here, for the output).
    std::array<std::uint8_t, 32> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>(i);
    }
    auto const message = example::bytes("hello, world");

    std::array<std::uint8_t, 32> tag{};
    if (!hash::mac<hmac<digests::sha2_256>, sodium>(tag, key, message)) {
        return 1;
    }
    std::cout << "HMAC-SHA-256 " << example::hex(tag) << '\n';

    // The receiver computes the tag again and compares it in constant time.
    std::array<std::uint8_t, 32> again{};
    bool const genuine = hash::mac<hmac<digests::sha2_256>, sodium>(again, key, message) &&
                         webcpp::secure::constant_time_equal(again, tag);
    std::cout << "genuine: " << (genuine ? "yes" : "no") << '\n';

    // libsodium's crypto_auth_hmacsha512256 is HMAC-SHA-512 cut to 32 bytes: the same tag, with a
    // 32-byte output.
    std::array<std::uint8_t, 32> cut{};
    if (!hash::mac<hmac<digests::sha2_512>, sodium>(cut, key, message)) {
        return 1;
    }
    std::cout << "HMAC-SHA-512 cut to 32 " << example::hex(cut) << '\n';

    // HMAC over SHA-512/256 is another function, which libsodium does not have.
    std::array<std::uint8_t, 32> over_512_256{};
    if (!hash::mac<hmac<digests::sha2_512_256>>(over_512_256, key, message)) {
        return 1;
    }
    std::cout << "HMAC over SHA-512/256 " << example::hex(over_512_256) << '\n';
    return genuine ? 0 : 1;
}

// end::example[]
