// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The same HKDF, RFC 5869 appendix A.1, on each backend that has it, named as the second template
// argument: Boost.Hash2's own code, libsodium and BearSSL give the RFC's output keying material.
// The program also asks what each backend has, which is a property of the library behind it.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/pbkdf2.hpp>

#include <array>
#include <cstdint>
#include <iostream>
#include <string>

namespace {

// RFC 5869, appendix A.1, on the backend `Backend`.
template <class Backend>
std::string okm() {
    auto const input_key_material =
        example::from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    auto const salt = example::from_hex("000102030405060708090a0b0c");
    auto const application_info = example::from_hex("f0f1f2f3f4f5f6f7f8f9");
    std::array<std::uint8_t, 42> out{};
    auto const done = webcpp::hash::hkdf<webcpp::hash::hmac_sha2_256, Backend>(
        out, salt, input_key_material, application_info);
    return done ? example::hex(out) : done.error().message();
}

}  // namespace

int main() {
    auto const hash2 = okm<webcpp::hash::backends::hash2>();
    auto const sodium = okm<webcpp::hash::backends::sodium>();
    auto const bearssl = okm<webcpp::hash::backends::bearssl>();

    std::cout << "hash2 " << hash2 << '\n';
    std::cout << "sodium " << (sodium == hash2 ? "same" : sodium) << '\n';
    std::cout << "bearssl " << (bearssl == hash2 ? "same" : bearssl) << '\n';
    if (hash2 !=
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865") {
        return 1;
    }

    // A backend that does not have the function is a compile-time fact, not a runtime failure:
    // libsodium has no PBKDF2, and asking for it by name stops the build.
    using webcpp::hash::backend_has_v;
    using webcpp::hash::hmac_sha2_256;
    namespace kdfs = webcpp::hash::kdfs;
    std::cout << "sodium has pbkdf2: "
              << (backend_has_v<webcpp::hash::backends::sodium, kdfs::pbkdf2, hmac_sha2_256> ? "yes"
                                                                                             : "no")
              << '\n';
    std::cout << "bearssl has hkdf: "
              << (backend_has_v<webcpp::hash::backends::bearssl, kdfs::hkdf, hmac_sha2_256> ? "yes"
                                                                                            : "no")
              << '\n';
}

// end::example[]
