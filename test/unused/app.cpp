// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program that includes every header of webcpp::hash its libraries give it and calls none
// of their parts: it prints SHA-256 of "abc" (Boost.Hash2's). Built with a C library named and
// without it, the two programs are the same bytes (spec section 7.8).

#include <webcpp/hash.hpp>

// Botan's public headers include <chrono>, which under MSVC's C++20 brings the locale's
// time_get members into every object that includes it; their references to the C runtime
// change the order of the program's imports, not one byte of its code. Both programs include
// it, so that the two differ only by what a library adds.
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <string_view>

int main() {
    std::string_view const abc = "abc";
    webcpp::hash::sha2_256 hasher;
    hasher.update(abc.data(), abc.size());
    for (std::uint8_t const b : hasher.result()) {
        std::printf("%02x", static_cast<unsigned>(b));
    }
    std::printf("\n");
    return 0;
}
