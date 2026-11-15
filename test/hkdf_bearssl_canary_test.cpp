// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// hkdf on backends::bearssl reads webcpp::hash's canary of BearSSL, optimised too: built with
// /third_party//bearssl it links and runs; with another commit's canary it does not link (spec
// section 5.4). Like keccak_canary_test.cpp it names nothing of the test support, which a
// link-fail program is built without.

#include <webcpp/hash/backends/bearssl.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>

#include <array>
#include <cstdint>

int main() {
    // RFC 5869's A.3: hmac_sha2_256, IKM 22 octets of 0x0b, no salt, no info; the OKM begins 8d a4.
    std::array<std::uint8_t, 42> okm{};
    std::array<std::uint8_t, 22> ikm{};
    ikm.fill(0x0b);
    auto const done =
        webcpp::hash::hkdf<webcpp::hash::hmac_sha2_256, webcpp::hash::backends::bearssl>(okm, {},
                                                                                         ikm, {});
    return done && okm[0] == 0x8d && okm[1] == 0xa4 ? 0 : 1;
}
