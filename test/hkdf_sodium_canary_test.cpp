// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// backends::sodium's HKDF reads libsodium's canary, which survives optimisation: this program
// links with /third_party//sodium and runs; built with another commit's canary it does not link.

#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 42> okm{};
    const std::array<std::uint8_t, 22> ikm{};
    const auto done =
        webcpp::hash::hkdf<webcpp::hash::hmac_sha2_256, webcpp::hash::backends::sodium>(okm, {},
                                                                                        ikm, {});
    return done.has_value() ? 0 : 1;
}
