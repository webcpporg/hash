// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// RFC 9861's functions on their default backend, XKCP: KT128 of the RFC's ptn(17), checked against
// its section 5; KT128 of a 20,000-byte file with a customisation string, fed to a hasher in
// pieces of 4,096 bytes and equal to digest_of (the value also computed by an implementation of
// the RFC independent of XKCP); then TurboSHAKE128 of one message under two domain bytes, each
// checked against the RFC.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/digest.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <vector>

namespace hash = webcpp::hash;

int main() {
    // KT128 of RFC 9861's ptn(17), the bytes 00 to 10, with no customisation.
    std::vector<std::uint8_t> pattern(20000);
    for (std::size_t i = 0; i != pattern.size(); ++i) {
        pattern[i] = static_cast<std::uint8_t>(i % 251);
    }
    std::span<std::uint8_t const> const file(pattern);
    std::array<std::uint8_t, 32> digest{};
    if (!hash::digest_of<hash::digests::kt128>(digest, file.first(17))) {
        return 1;
    }
    std::cout << "kt128 " << example::hex(digest) << '\n';
    if (example::hex(digest) !=
        "6bf75fa2239198db4772e36478f8e19b0f371205f6a9a93a273f51df37122888") {
        return 1;
    }

    // A file read in pieces, with the application's customisation string, which the hasher
    // reads at finish: `label` lives until then.
    auto const label = example::bytes("webcpp example");
    auto hashing = hash::hasher<hash::digests::kt128>::make({.customisation = label});
    if (!hashing) {
        return 1;
    }
    for (std::size_t at = 0; at < file.size(); at += 4096) {
        if (!hashing->update(file.subspan(at, std::min<std::size_t>(4096, file.size() - at)))) {
            return 1;
        }
    }
    std::array<std::uint8_t, 32> pieces{};
    std::array<std::uint8_t, 32> once{};
    if (!hashing->finish(pieces) ||
        !hash::digest_of<hash::digests::kt128>(once, file, {.customisation = label})) {
        return 1;
    }
    std::cout << "kt128 of the file " << example::hex(pieces) << '\n';
    std::cout << "pieces and one call agree: " << (pieces == once ? "yes" : "no") << '\n';
    if (example::hex(pieces) !=
            "485b2905b93dacfa84cc6b94bef012cfd8aa9232aab119a0afae1073bd82c224" ||
        pieces != once) {
        return 1;
    }

    // tag::turboshake[]
    // TurboSHAKE128 of FF FF FF under two domain bytes: two unrelated functions.
    auto const message = example::from_hex("ffffff");
    std::array<std::uint8_t, 32> first{};
    std::array<std::uint8_t, 32> second{};
    if (!hash::digest_of<hash::digests::turboshake_128>(first, message, {.domain = 0x01}) ||
        !hash::digest_of<hash::digests::turboshake_128>(second, message, {.domain = 0x07})) {
        return 1;
    }
    std::cout << "turboshake_128 D=01 " << example::hex(first) << '\n';
    std::cout << "turboshake_128 D=07 " << example::hex(second) << '\n';
    // end::turboshake[]
    return example::hex(first) ==
                       "bf323f940494e88ee1c540fe660be8a0c93f43d15ec006998462fa994eed5dab" &&
                   example::hex(second) ==
                       "b658576001cad9b1e5f399a9f77723bba05458042d68206f7252682dba3663ed"
               ? 0
               : 1;
}

// end::example[]
