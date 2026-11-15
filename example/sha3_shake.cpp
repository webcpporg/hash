// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// SHA3-256 and SHAKE128 (FIPS 202) of "abc". The values are those of an independent
// implementation, Python's hashlib (sha3_256 and shake_128), as FIPS 202 defines the functions.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/algorithms.hpp>

#include <cstddef>
#include <iostream>
#include <string_view>

int main() {
    std::string_view const message = "abc";

    webcpp::hash::sha3_256 fixed;
    fixed.update(message.data(), message.size());
    std::cout << "sha3_256 " << example::hex(fixed.result()) << '\n';

    // SHAKE128 has no digest size: its output goes on as long as the caller asks. Hash2's
    // result() returns one whole block of 168 bytes, and each further call continues the stream.
    webcpp::hash::shake_128 xof;
    xof.update(message.data(), message.size());
    auto const first = xof.result();
    auto const second = xof.result();

    // The length is the caller's security choice. SHAKE128 has a 128-bit security strength, so
    // 32 bytes are as strong as it gets; keeping 16 bytes would give only 64 bits against
    // collisions. Take what the protocol needs and no less.
    constexpr std::size_t taken = 32;
    std::cout << "shake_128 first block " << example::hex({first.data(), taken}) << '\n';
    std::cout << "shake_128 second block " << example::hex({second.data(), taken}) << '\n';
}

// end::example[]
