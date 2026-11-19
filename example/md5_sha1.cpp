// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// BearSSL reached by name: TLS 1.0's MD5-SHA1 of "abc" on backends::bearssl, its one backend,
// which is MD5 of the data followed by SHA-1 of it (RFC 1321 A.5's and RFC 3174's printed digests
// of "abc"); the same 36 bytes from a hasher fed in two pieces; and SHA-256 on backends::bearssl,
// named in the call, giving the bytes of the default backend.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/digest.hpp>

#include <array>
#include <cstdint>
#include <iostream>

int main() {
    namespace hash = webcpp::hash;
    using hash::backends::bearssl;
    auto const message = example::bytes("abc");

    // MD5-SHA1 has no default backend: the call names BearSSL.
    std::array<std::uint8_t, 36> joined{};
    if (!hash::digest_of<hash::digests::md5_sha1, bearssl>(joined, message)) {
        return 1;
    }
    std::cout << "md5_sha1 " << example::hex(joined) << '\n';

    // It is the two digests side by side, which the default backend computes one by one.
    std::array<std::uint8_t, 16> md5{};
    std::array<std::uint8_t, 20> sha1{};
    if (!hash::digest_of<hash::digests::md5>(md5, message) ||
        !hash::digest_of<hash::digests::sha1>(sha1, message)) {
        return 1;
    }
    std::cout << "md5 then sha1 " << example::hex(md5) << example::hex(sha1) << '\n';
    if (example::hex(joined) !=
        "900150983cd24fb0d6963f7d28e17f72a9993e364706816aba3e25717850c26c9cd0d89d") {
        return 1;
    }

    // A handshake's messages arrive one by one: a hasher on BearSSL takes them in pieces.
    auto hashing = hash::hasher<hash::digests::md5_sha1, bearssl>::make();
    std::array<std::uint8_t, 36> pieces{};
    if (!hashing || !hashing->update(example::bytes("ab")) ||
        !hashing->update(example::bytes("c")) || !hashing->finish(pieces)) {
        return 1;
    }
    std::cout << "hasher " << (pieces == joined ? "same" : "different") << '\n';

    // Any digest BearSSL has is reached the same way, and gives the default backend's bytes.
    std::array<std::uint8_t, 32> by_name{};
    std::array<std::uint8_t, 32> by_default{};
    if (!hash::digest_of<hash::digests::sha2_256, bearssl>(by_name, message) ||
        !hash::digest_of<hash::digests::sha2_256>(by_default, message)) {
        return 1;
    }
    std::cout << "sha2_256 on bearssl " << (by_name == by_default ? "same" : "different") << '\n';
}

// end::example[]
