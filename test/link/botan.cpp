// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program that hashes "abc" with Whirlpool on backends::botan. Without /third_party//botan in
// its link (its headers and define taken from the library's usage requirements alone, <use>), or
// with another commit's canary (WEBCPP_HASH_BOTAN_CANARY_COMMIT), it does not link: the canary its
// header reads,
//
//     webcpp_hash_botan_01af88c_configured__add_third_party_botan_to_your_link,
//
// is undefined (spec section 5.4). It names nothing of the test support, which a link-fail
// program is built without.

#include <webcpp/hash/backends/botan.hpp>
#include <webcpp/hash/digest.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 3> const abc{0x61, 0x62, 0x63};
    std::array<std::uint8_t, 64> digest{};
    auto const done =
        webcpp::hash::digest_of<webcpp::hash::digests::whirlpool, webcpp::hash::backends::botan>(
            digest, abc);
    return done ? 0 : 1;
}
