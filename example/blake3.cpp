// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// BLAKE3's four modes on the official test vectors' input: the plain hash, the keyed hash, the
// key derivation and the extendable output. Input, key and context are those of
// third_party/libs/blake3/test_vectors/test_vectors.json (input_len 1: the single byte 0), and
// the printed values are that file's, the first 32 bytes of each output (64 for the extension).

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/blake3.hpp>

#include <array>
#include <cstdint>
#include <iostream>
#include <string_view>

int main() {
    // The test vectors' input: bytes 0, 1, 2 ... 250, 0, 1 ... For one byte, a single zero.
    std::array<std::uint8_t, 1> const input{0};

    // BLAKE3's plain hash. result() gives its 32 bytes.
    webcpp::hash::blake3 plain;
    plain.update(input.data(), input.size());
    auto const digest = example::hex(plain.result());
    std::cout << "hash " << digest << '\n';

    // The keyed hash is a MAC: the key is exactly 32 bytes, and the type says so.
    auto const key = example::bytes("whats the Elvish word for friend").first<32>();
    auto keyed = webcpp::hash::blake3::keyed(key);
    keyed.update(input.data(), input.size());
    auto const tag = example::hex(keyed.result());
    std::cout << "keyed_hash " << tag << '\n';

    // The key derivation takes a context, a string that names the purpose of the derived key:
    // the same secret under two contexts gives two unrelated keys, which is the point.
    auto derive =
        webcpp::hash::blake3::derive_key("BLAKE3 2019-12-27 16:29:52 test vectors context");
    derive.update(input.data(), input.size());
    auto const derived = example::hex(derive.result());
    std::cout << "derive_key " << derived << '\n';

    // Extendable output: any number of bytes from any position, without changing the hash. The
    // first 32 are the digest above.
    std::array<std::uint8_t, 64> extended{};
    plain.squeeze(extended);
    auto const stream = example::hex(extended);
    std::cout << "extended " << stream << '\n';

    if (digest != "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213" ||
        tag != "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b" ||
        derived != "b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c" ||
        stream !=
            "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"
            "c3a6cb8bf623e20cdb535f8d1a5ffb86342d9c0b64aca3bce1d31f60adfa137b") {
        return 1;
    }
}

// end::example[]
