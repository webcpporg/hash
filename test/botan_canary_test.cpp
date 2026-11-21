// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// backends::botan's read of its canary survives optimisation: test/Jamfile builds this program at
// full optimisation with /third_party//botan, which must link and run, and with another commit's
// canary (WEBCPP_HASH_BOTAN_CANARY_COMMIT), the program's one missing symbol, which must not link
// (spec section 5.4). Like keccak_canary_test.cpp it names nothing of the test support, which a
// link-fail program is built without.

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
    // The first byte of Whirlpool("abc"), 4e2448a4...
    return done && digest[0] == 0x4e ? 0 : 1;
}
