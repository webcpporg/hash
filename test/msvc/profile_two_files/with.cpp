// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The translation unit of profile_two_files with the define (see main.cpp).

#define WEBCPP_HASH_PROFILE_SMALLEST
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>

#include <array>
#include <cstdint>

int with() {
    std::array<std::uint8_t, 32> output{};
    std::array<std::uint8_t, 4> const input{};
    return webcpp::hash::hkdf<webcpp::hash::hmac_sha2_256>(output, input, input, input) ? 0 : 1;
}
