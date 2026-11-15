// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program that includes every header of webcpp::hash its libraries give it and calls none
// of their parts: it prints SHA-256 of "abc" (Boost.Hash2's). Built with a C library named and
// without it, the two programs are the same bytes (spec section 7.8).

#include <webcpp/hash.hpp>

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
