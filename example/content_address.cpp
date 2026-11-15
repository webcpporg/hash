// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A file-sharing application names a file by the BLAKE3 hash of its content: its id. This is
// what such an application builds on webcpp::hash's BLAKE3; webcpp::hash has no content-address
// function. The content is the 102,400 bytes of BLAKE3's test vectors (bytes i % 251), so the id
// is the hash of that case in third_party/libs/blake3/test_vectors/test_vectors.json.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/blake3.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <string>
#include <vector>

namespace {

// The id of a file: its BLAKE3 hash, fed in chunks as a program reads a file, so that a file
// of any size is hashed with the memory of one chunk.
std::string id_of(std::span<std::uint8_t const> content) {
    constexpr std::size_t chunk = std::size_t{64} * 1024;
    webcpp::hash::blake3 hash;
    for (std::size_t offset = 0; offset < content.size(); offset += chunk) {
        auto const piece = content.subspan(offset, std::min(chunk, content.size() - offset));
        hash.update(piece.data(), piece.size());
    }
    return example::hex(hash.result());
}

}  // namespace

int main() {
    std::vector<std::uint8_t> content(102400);
    for (std::size_t i = 0; i < content.size(); ++i) {
        content[i] = static_cast<std::uint8_t>(i % 251);
    }

    // The sender publishes the id; the content may come from anywhere.
    auto const id = id_of(content);
    std::cout << "id " << id << '\n';
    if (id != "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085") {
        return 1;
    }

    // A receiver recomputes the id of what it got. The id is public, not a secret, so an
    // ordinary comparison is right here. One flipped byte gives an unrelated id.
    std::cout << "intact " << (id_of(content) == id ? "yes" : "no") << '\n';
    content[5000] ^= 1U;
    std::cout << "corrupted " << (id_of(content) == id ? "undetected" : "detected") << '\n';
}

// end::example[]
