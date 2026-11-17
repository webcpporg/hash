// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// NIST SP 800-185's hashes on their default backend, XKCP: cSHAKE128 with a customisation string,
// TupleHash128 of a tuple of two strings fed one per update, and ParallelHash128 in blocks of 8
// bytes, each checked against NIST's samples #1; then TupleHash's point, two tuples whose
// concatenations are equal and whose digests are not.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/digest.hpp>

#include <array>
#include <cstdint>
#include <initializer_list>
#include <iostream>
#include <span>

namespace {

namespace hash = webcpp::hash;

// TupleHash128 of a tuple, one hasher update per element, into digest.
bool tuple_hash(std::initializer_list<std::span<std::uint8_t const>> elements,
                std::span<std::uint8_t> digest) {
    auto hashing = hash::hasher<hash::digests::tuplehash_128>::make();
    if (!hashing) {
        return false;
    }
    for (auto const element : elements) {
        if (!hashing->update(element)) {
            return false;
        }
    }
    return hashing->finish(digest).has_value();
}

}  // namespace

int main() {
    // cSHAKE128: SHAKE128 separated from every other use by the customisation string S.
    std::array<std::uint8_t, 32> cshake{};
    if (!hash::digest_of<hash::digests::cshake_128>(
            cshake, example::from_hex("00010203"),
            {.customisation = example::bytes("Email Signature")})) {
        return 1;
    }
    std::cout << "cshake_128 " << example::hex(cshake) << '\n';
    if (example::hex(cshake) !=
        "c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5") {
        return 1;
    }

    // TupleHash128 of (00 01 02, 10 11 12 13 14 15): each update is one element.
    auto const first = example::from_hex("000102");
    auto const second = example::from_hex("101112131415");
    std::array<std::uint8_t, 32> tuple{};
    if (!tuple_hash({first, second}, tuple)) {
        return 1;
    }
    std::cout << "tuplehash_128 " << example::hex(tuple) << '\n';
    if (example::hex(tuple) != "c5d8786c1afb9b82111ab34b65b2c0048fa64e6d48e263264ce1707d3ffc8ed1") {
        return 1;
    }

    // ParallelHash128 in blocks of 8 bytes, a block size the call states.
    std::array<std::uint8_t, 32> parallel{};
    if (!hash::digest_of<hash::digests::parallelhash_128>(
            parallel, example::from_hex("000102030405060710111213141516172021222324252627"),
            {.block_size = 8})) {
        return 1;
    }
    std::cout << "parallelhash_128 " << example::hex(parallel) << '\n';
    if (example::hex(parallel) !=
        "ba8dc1d1d979331d3f813603c67f72609ab5e44b94a0b8f9af46514454a2b4f5") {
        return 1;
    }

    // ("ab", "c") and ("a", "bc") concatenate to the same bytes and hash apart.
    std::array<std::uint8_t, 32> ab_c{};
    std::array<std::uint8_t, 32> a_bc{};
    if (!tuple_hash({example::bytes("ab"), example::bytes("c")}, ab_c) ||
        !tuple_hash({example::bytes("a"), example::bytes("bc")}, a_bc)) {
        return 1;
    }
    std::cout << "(ab, c) and (a, bc) differ: " << (ab_c != a_bc ? "yes" : "no") << '\n';
    return ab_c != a_bc ? 0 : 1;
}

// end::example[]
