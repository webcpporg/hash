// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// An Ethereum address, as a domain library such as webcpp::ethereum would compute it from
// webcpp::hash's Keccak-256: the last 20 bytes of the Keccak-256 of the 64-byte public key (x
// then y, without the 04 prefix of the uncompressed form), and EIP-55's mixed-case checksum.
// webcpp::hash itself has no address function. The key is the public key of secret key 1 (the
// generator), whose address is 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf; it agrees with a pure
// Python Keccak-256. Keccak-256 is not SHA3-256 (see keccak_256.cpp).

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/keccak.hpp>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <string>

namespace {

std::string keccak_hex(std::span<std::uint8_t const> data) {
    webcpp::hash::keccak_256 hash;
    hash.update(data.data(), data.size());
    return example::hex(hash.result());
}

// EIP-55: a letter of the address is upper case when the same position of the Keccak-256 of the
// lowercase address (as ASCII text, without 0x) is 8 or more. A wallet that finds a letter in
// the wrong case knows that a character was mistyped.
std::string checksummed(std::string const& lower) {
    std::string const digest = keccak_hex(example::bytes(lower));
    std::string out = "0x";
    for (std::size_t i = 0; i < lower.size(); ++i) {
        bool const letter = lower[i] >= 'a' && lower[i] <= 'f';
        bool const upper = digest[i] >= '8';
        out += letter && upper ? static_cast<char>(lower[i] - 'a' + 'A') : lower[i];
    }
    return out;
}

}  // namespace

int main() {
    auto const public_key = example::from_hex(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");

    // The last 20 of the 32 bytes: 40 hexadecimal digits from the 24th.
    auto const lower = keccak_hex(public_key).substr(24);
    std::cout << "address 0x" << lower << '\n';

    auto const mixed = checksummed(lower);
    std::cout << "checksummed " << mixed << '\n';
    if (mixed != "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf") {
        return 1;
    }
}

// end::example[]
