// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// HKDF over byte pieces: HPKE's LabeledExtract and LabeledExpand (RFC 9180, section 4), each one
// call whose input is its labeled parts, no buffer joined, then HPKE's key schedule in base mode,
// checked against RFC 9180's test vector A.1.1 (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
// AES-128-GCM). The three values agree with an independent computation, Python's hmac module
// following RFC 5869 and RFC 9180.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>

#include <array>
#include <cstdint>
#include <iostream>
#include <span>
#include <string_view>
#include <vector>

namespace {

namespace hash = webcpp::hash;

using bytes_view = std::span<std::uint8_t const>;

// RFC 9180's version label, "HPKE-v1".
constexpr std::array<std::uint8_t, 7> hpke_v1{'H', 'P', 'K', 'E', '-', 'v', '1'};

// The suite's identifier: "HPKE", then the KEM (0x0020, DHKEM(X25519, HKDF-SHA256)), the KDF
// (0x0001, HKDF-SHA256) and the AEAD (0x0001, AES-128-GCM), two bytes each.
constexpr std::array<std::uint8_t, 10> suite_id{'H', 'P', 'K', 'E', 0, 0x20, 0, 1, 0, 1};

// LabeledExtract(salt, label, ikm) = Extract(salt, "HPKE-v1" || suite_id || label || ikm): the
// braced list at the call is the input keying material's pieces.
auto labeled_extract(bytes_view salt, std::string_view label, bytes_view ikm) {
    return hash::hkdf_extract<hash::hmac_sha2_256>(salt,
                                                   {hpke_v1, suite_id, example::bytes(label), ikm});
}

// LabeledExpand(prk, label, info, L) = Expand(prk, I2OSP(L, 2) || "HPKE-v1" || suite_id || label
// || info, L), L the output's size.
auto labeled_expand(std::span<std::uint8_t> output, bytes_view pseudorandom_key,
                    std::string_view label, bytes_view info) {
    // I2OSP(L, 2): the size in two bytes, big-endian.
    std::array<std::uint8_t, 2> const length{
        static_cast<std::uint8_t>(output.size() >> 8U),
        static_cast<std::uint8_t>(output.size() & 0xffU),
    };
    return hash::hkdf_expand<hash::hmac_sha2_256>(
        output, pseudorandom_key, {length, hpke_v1, suite_id, example::bytes(label), info});
}

}  // namespace

int main() {
    // RFC 9180, A.1.1: the application's info and the KEM's shared secret; no PSK (base mode).
    auto const info = example::from_hex("4f6465206f6e2061204772656369616e2055726e");
    auto const shared_secret =
        example::from_hex("fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc");
    bytes_view const no_psk{};

    // KeySchedule: key_schedule_context = mode || psk_id_hash || info_hash.
    auto const psk_id_hash = labeled_extract({}, "psk_id_hash", no_psk);
    auto const info_hash = labeled_extract({}, "info_hash", info);
    auto const secret = labeled_extract(shared_secret, "secret", no_psk);
    if (!psk_id_hash || !info_hash || !secret) {
        std::cerr << "extract failed\n";
        return 1;
    }
    std::vector<std::uint8_t> context{0x00};  // mode_base
    context.insert(context.end(), psk_id_hash->begin(), psk_id_hash->end());
    context.insert(context.end(), info_hash->begin(), info_hash->end());

    std::array<std::uint8_t, 16> key{};
    std::array<std::uint8_t, 12> base_nonce{};
    std::array<std::uint8_t, 32> exporter_secret{};
    if (!labeled_expand(key, *secret, "key", context) ||
        !labeled_expand(base_nonce, *secret, "base_nonce", context) ||
        !labeled_expand(exporter_secret, *secret, "exp", context)) {
        std::cerr << "expand failed\n";
        return 1;
    }
    std::cout << "key " << example::hex(key) << '\n';
    std::cout << "base_nonce " << example::hex(base_nonce) << '\n';
    std::cout << "exporter_secret " << example::hex(exporter_secret) << '\n';
    if (example::hex(key) != "4531685d41d65f03dc48f6b8302c05b0" ||
        example::hex(base_nonce) != "56d890e5accaaf011cff4b7d" ||
        example::hex(exporter_secret) !=
            "45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8") {
        return 1;
    }

    // The pieces are read as if joined: the same extract over one buffer gives the same key.
    std::vector<std::uint8_t> joined(hpke_v1.begin(), hpke_v1.end());
    joined.insert(joined.end(), suite_id.begin(), suite_id.end());
    auto const label = example::bytes("secret");
    joined.insert(joined.end(), label.begin(), label.end());
    auto const from_joined = hash::hkdf_extract<hash::hmac_sha2_256>(shared_secret, joined);
    std::cout << "pieces and joined "
              << (from_joined && *from_joined == *secret ? "same" : "different") << '\n';
}

// end::example[]
