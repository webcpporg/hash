// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// SM3 of "abc" on backends::openssl, checked against GB/T 32905-2016's first example; the same
// digest with a hasher, the message arriving in two pieces; and Keccak-256 and MD5-SHA1 on the
// same backend, each named in the call, since backends::openssl is never a default.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/digest.hpp>

#include <array>
#include <cstdint>
#include <iostream>

int main() {
    namespace hash = webcpp::hash;
    using hash::backends::openssl;
    auto const message = example::bytes("abc");

    // SM3 has no default backend: the call names OpenSSL, which the Jamfile links.
    std::array<std::uint8_t, 32> once{};
    if (!hash::digest_of<hash::digests::sm3, openssl>(once, message)) {
        return 1;
    }
    std::cout << "sm3 " << example::hex(once) << '\n';
    if (example::hex(once) != "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0") {
        return 1;
    }

    // The same digest in pieces: the hasher owns OpenSSL's context until it finishes.
    auto hashing = hash::hasher<hash::digests::sm3, openssl>::make();
    std::array<std::uint8_t, 32> pieces{};
    if (!hashing || !hashing->update(example::bytes("a")) ||
        !hashing->update(example::bytes("bc")) || !hashing->finish(pieces)) {
        return 1;
    }
    std::cout << "hasher " << (pieces == once ? "same" : "different") << '\n';

    // Other digests of OpenSSL, each named: Keccak-256 (Ethereum's) and TLS 1.0's MD5-SHA1.
    std::array<std::uint8_t, 32> keccak{};
    std::array<std::uint8_t, 36> md5_sha1{};
    if (!hash::digest_of<hash::digests::keccak_256, openssl>(keccak, message) ||
        !hash::digest_of<hash::digests::md5_sha1, openssl>(md5_sha1, message)) {
        return 1;
    }
    std::cout << "keccak_256 " << example::hex(keccak) << '\n';
    std::cout << "md5_sha1 " << example::hex(md5_sha1) << '\n';
}

// end::example[]
