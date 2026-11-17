// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The digest family: SHA-256 of "abc" with digest_of in one call, checked against FIPS 180-4's
// Appendix B.1; the same digest with hasher, the message arriving in two pieces; the hasher
// refusing a second result; an output of the wrong size refused before any work; and SHAKE128 on
// backends::hash2, named in the call, which serves up to 32 bytes.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/digest.hpp>

#include <array>
#include <cstdint>
#include <iostream>

int main() {
    namespace hash = webcpp::hash;
    auto const message = example::bytes("abc");

    // One call: the tag names the algorithm, the default backend runs it (backends::hash2 here).
    std::array<std::uint8_t, 32> once{};
    if (!hash::digest_of<hash::digests::sha2_256>(once, message)) {
        return 1;
    }
    std::cout << "digest_of " << example::hex(once) << '\n';
    if (example::hex(once) != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") {
        return 1;
    }

    // Data that arrives in pieces (a file read in blocks, a stream) goes through a hasher.
    auto hashing = hash::hasher<hash::digests::sha2_256>::make();
    if (!hashing || !hashing->update(example::bytes("a")) ||
        !hashing->update(example::bytes("bc"))) {
        return 1;
    }
    std::array<std::uint8_t, 32> pieces{};
    if (!hashing->finish(pieces)) {
        return 1;
    }
    std::cout << "hasher " << (pieces == once ? "same" : "different") << '\n';

    // The result is final: a second finish is an error, not the hash of nothing more.
    auto const again = hashing->finish(pieces);
    std::cout << "second finish: " << again.error().message() << '\n';

    // A fixed-size digest takes its size alone: the output is refused before any work.
    std::array<std::uint8_t, 20> too_short{};
    auto const refused = hash::digest_of<hash::digests::sha2_256>(too_short, message);
    std::cout << "20-byte output: " << refused.error().message() << '\n';

    // A backend named in the call: Boost.Hash2's SHAKE128, any size up to one result.
    std::array<std::uint8_t, 16> shake{};
    if (!hash::digest_of<hash::digests::shake_128, hash::backends::hash2>(shake, message)) {
        return 1;
    }
    std::cout << "shake_128 " << example::hex(shake) << '\n';
}

// end::example[]
