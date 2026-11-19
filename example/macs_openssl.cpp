// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The MACs of backends::openssl, each named in the call, since OpenSSL is never a default: KMAC128
// against NIST's KMAC sample #2 (SP 800-185's examples), its XOF form; HMAC-SM3 against
// GM/T 0042-2015's "Jefe" case; keyed BLAKE2b at 32 bytes (Python's hashlib.blake2b gives the same
// bytes); SipHash-2-4x of an empty message (OpenSSL's evpmac_siphash.txt); and a key OpenSSL's KMAC
// does not take.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/mac.hpp>

#include <array>
#include <cstdint>
#include <iostream>
#include <numeric>

int main() {
    namespace hash = webcpp::hash;
    namespace macs = hash::macs;
    using hash::backends::openssl;

    // KMAC128 with a customisation string: NIST's sample #2.
    auto const key =
        example::from_hex("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
    auto const data = example::from_hex("00010203");
    std::array<std::uint8_t, 32> kmac{};
    if (!hash::mac<macs::kmac_128, openssl>(
            kmac, key, data, {.customisation = example::bytes("My Tagged Application")})) {
        return 1;
    }
    std::cout << "kmac_128 " << example::hex(kmac) << '\n';
    if (example::hex(kmac) != "3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5") {
        return 1;
    }

    // The XOF form encodes no length: its 16 bytes are the start of its 32.
    std::array<std::uint8_t, 32> long_xof{};
    std::array<std::uint8_t, 16> short_xof{};
    if (!hash::mac<macs::kmac_128, openssl>(long_xof, key, data, {.xof = true}) ||
        !hash::mac<macs::kmac_128, openssl>(short_xof, key, data, {.xof = true})) {
        return 1;
    }
    bool const prefix = std::equal(short_xof.begin(), short_xof.end(), long_xof.begin());
    std::cout << "kmacxof_128 16 bytes are the start of 32: " << (prefix ? "yes" : "no") << '\n';

    // HMAC over SM3, which has no default backend.
    std::array<std::uint8_t, 32> hmac_sm3{};
    if (!hash::mac<macs::hmac<hash::digests::sm3>, openssl>(
            hmac_sm3, example::bytes("Jefe"), example::bytes("what do ya want for nothing?"))) {
        return 1;
    }
    std::cout << "hmac sm3 " << example::hex(hmac_sm3) << '\n';

    // Keyed BLAKE2b of 32 bytes, its size a parameter of the hash, not a cut.
    std::array<std::uint8_t, 32> blake2b_key{};
    std::iota(blake2b_key.begin(), blake2b_key.end(), std::uint8_t{0});
    std::array<std::uint8_t, 32> blake2b{};
    if (!hash::mac<macs::blake2b_mac, openssl>(blake2b, blake2b_key, example::bytes("abc"))) {
        return 1;
    }
    std::cout << "blake2b_mac " << example::hex(blake2b) << '\n';

    // SipHash-2-4 with a 16-byte tag.
    std::array<std::uint8_t, 16> siphash_key{};
    std::iota(siphash_key.begin(), siphash_key.end(), std::uint8_t{0});
    std::array<std::uint8_t, 16> siphash{};
    if (!hash::mac<macs::siphash_2_4x, openssl>(siphash, siphash_key, {})) {
        return 1;
    }
    std::cout << "siphash_2_4x " << example::hex(siphash) << '\n';

    // OpenSSL's KMAC takes a key of 4 to 512 bytes, narrower than SP 800-185.
    std::array<std::uint8_t, 3> const short_key{1, 2, 3};
    std::cout << "3-byte KMAC key: "
              << hash::mac<macs::kmac_128, openssl>(kmac, short_key, data).error().message()
              << '\n';
    return prefix ? 0 : 1;
}

// end::example[]
