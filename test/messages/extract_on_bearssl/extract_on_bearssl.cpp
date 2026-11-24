// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The single-buffer hkdf_extract on backends::bearssl, whose br_hkdf_* keeps the PRK inside its
// context, stops with spec section 3.3's text, and with no other error, while hkdf_extract over
// pieces on BearSSL compiles (the change hkdf-pieces, scenario "BearSSL's Extract over pieces").

// clang-format off
// expected-error@webcpp/hash/backends/bearssl.hpp:* {{webcpp::hash: hkdf_extract and hkdf_expand are not in backends::bearssl, whose HKDF does both steps together: call hkdf, or name backends::hash2, backends::sodium, backends::openssl or backends::botan.}}
// clang-format on
#include <webcpp/hash/backends/bearssl.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 13> salt{};
    std::array<std::uint8_t, 22> ikm{};
    auto pieces =
        webcpp::hash::hkdf_extract<webcpp::hash::hmac_sha2_256, webcpp::hash::backends::bearssl>(
            salt, {ikm, ikm});
    auto single =
        webcpp::hash::hkdf_extract<webcpp::hash::hmac_sha2_256, webcpp::hash::backends::bearssl>(
            salt, ikm);
    return pieces && single ? 0 : 1;
}
