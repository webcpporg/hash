// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program that derives 42 bytes with HKDF on backends::sodium. Without /third_party//sodium in
// its link, or with another commit's canary (WEBCPP_HASH_SODIUM_CANARY_COMMIT), it does not link:
// the canary its header reads,
//
//     webcpp_hash_sodium_77e1ce5_configured__add_third_party_sodium_to_your_link,
//
// on every target, is undefined (spec section 5.4). It names nothing of the test support, which a
// link-fail program is built without.

#include <webcpp/hash/backends/sodium.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 42> okm{};
    std::array<std::uint8_t, 22> const ikm{};
    auto const done =
        webcpp::hash::hkdf<webcpp::hash::hmac_sha2_256, webcpp::hash::backends::sodium>(okm, {},
                                                                                        ikm, {});
    return done ? 0 : 1;
}
