// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The one-step KDF of NIST SP 800-56C over SHA-256 on backends::openssl, as JOSE's ECDH-ES derives
// a content key from an ECDH shared secret (RFC 7518, section 4.6.2, its "Concat KDF"). The
// shared secret, the fixed info and the key are RFC 7518's Appendix C: A128GCM, from Alice to
// Bob, 128 bits.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/kdf_standards.hpp>

#include <array>
#include <cstdint>
#include <iostream>
#include <string_view>
#include <vector>

namespace {

// JOSE's fixed info: each field as its 4-byte big-endian length, then its bytes.
void append_field(std::vector<std::uint8_t>& info, std::string_view field) {
    auto const size = static_cast<std::uint32_t>(field.size());
    for (unsigned const shift : {24U, 16U, 8U, 0U}) {
        info.push_back(static_cast<std::uint8_t>(size >> shift));
    }
    info.insert(info.end(), field.begin(), field.end());
}

}  // namespace

int main() {
    namespace hash = webcpp::hash;
    // Z, the x-coordinate of the ECDH result on P-256.
    auto const shared_secret =
        example::from_hex("9e56d91d817135d372834283bf84269cfb316ea3da806a48f6daa7798cfe90c4");
    std::vector<std::uint8_t> fixed_info;
    append_field(fixed_info, "A128GCM");  // AlgorithmID
    append_field(fixed_info, "Alice");    // PartyUInfo
    append_field(fixed_info, "Bob");      // PartyVInfo
    // SuppPubInfo: the key's length, 128 bits.
    fixed_info.insert(fixed_info.end(), {0x00, 0x00, 0x00, 0x80});

    std::array<std::uint8_t, 16> content_key{};
    auto const done = hash::sskdf<hash::digests::sha2_256, hash::backends::openssl>(
        content_key, shared_secret, fixed_info);
    if (!done) {
        std::cerr << done.error().message() << '\n';
        return 1;
    }
    std::cout << "content key " << example::hex(content_key) << '\n';
    // RFC 7518's "VqqN6vgjbSBcIijNcacQGg", decoded from base64url.
    if (example::hex(content_key) != "56aa8deaf8236d205c2228cd71a7101a") {
        return 1;
    }
}

// end::example[]
