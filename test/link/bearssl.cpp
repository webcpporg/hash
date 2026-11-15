// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program that derives 42 bytes with HKDF on backends::bearssl. Without /third_party//bearssl in
// its link, or with another commit's canary (WEBCPP_HASH_BEARSSL_CANARY_COMMIT), it does not link:
// the canary its header reads,
//
//     webcpp_hash_bearssl_7bea48e_<configuration>__add_third_party_bearssl_to_your_link,
//
// whose configuration is noseeder on Windows and getentropy elsewhere, is undefined (spec
// section 5.4). It names nothing of the test support, which a link-fail program is built without.

#include <webcpp/hash/backends/bearssl.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 42> okm{};
    std::array<std::uint8_t, 22> const ikm{};
    auto const done =
        webcpp::hash::hkdf<webcpp::hash::hmac_sha2_256, webcpp::hash::backends::bearssl>(okm, {},
                                                                                         ikm, {});
    return done ? 0 : 1;
}
