// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// BLAKE2b with its options on its default backend, libsodium: a chat app's 32-byte message id,
// personalised so that no other kind of hash the app makes can collide with it; the same id from a
// hasher fed in pieces; the id without the personalisation, another value; a 16-byte keyed tag;
// a personalisation of the wrong size refused. Each value agrees with Python's
// hashlib.blake2b(message, digest_size=..., person=..., key=...).

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/digest.hpp>

#include <array>
#include <cstdint>
#include <iostream>

int main() {
    namespace hash = webcpp::hash;
    using webcpp::hash::digests::blake2b;
    auto const message = example::bytes("hello, world");

    // The personalisation is 16 bytes, one per kind of hash an application makes; the output's
    // size is an option, since BLAKE2b-256 is not BLAKE2b-512 cut short.
    auto const message_ids = example::bytes("chatapp.msg.v001");
    hash::digest_options<blake2b> const id_options{
        .personalisation = message_ids,
        .output_size = 32,
    };
    std::array<std::uint8_t, 32> id{};
    if (!hash::digest_of<blake2b>(id, message, id_options)) {
        return 1;
    }
    std::cout << "message id " << example::hex(id) << '\n';
    if (example::hex(id) != "fa88bb46494debf0d96d9e2d15fb6ecc42d9ab6a1502e5900249db8274767960") {
        return 1;
    }

    // A hasher takes its options, the output's size among them, when it starts.
    auto hashing = hash::hasher<blake2b>::make(id_options);
    if (!hashing || !hashing->update(example::bytes("hello, ")) ||
        !hashing->update(example::bytes("world"))) {
        return 1;
    }
    std::array<std::uint8_t, 32> pieces{};
    if (!hashing->finish(pieces)) {
        return 1;
    }
    std::cout << "hasher " << (pieces == id ? "same" : "different") << '\n';

    // Without the personalisation: another function, another value.
    std::array<std::uint8_t, 32> plain{};
    if (!hash::digest_of<blake2b>(plain, message, {.output_size = 32})) {
        return 1;
    }
    std::cout << "unpersonalised " << example::hex(plain) << '\n';

    // A key makes BLAKE2b a MAC: here a 16-byte tag under a 32-byte key.
    std::array<std::uint8_t, 32> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>(i);
    }
    std::array<std::uint8_t, 16> tag{};
    if (!hash::digest_of<blake2b>(tag, message, {.key = key, .output_size = 16})) {
        return 1;
    }
    std::cout << "tag " << example::hex(tag) << '\n';

    // A personalisation is 16 bytes or none: a shorter one is refused before any work.
    auto const refused = hash::digest_of<blake2b>(
        id, message, {.personalisation = example::bytes("chatapp"), .output_size = 32});
    std::cout << "7-byte personalisation: " << refused.error().message() << '\n';
}

// end::example[]
