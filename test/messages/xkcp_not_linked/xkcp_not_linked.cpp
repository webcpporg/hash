// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program that names keccak_256 and does not link XKCP stops with the instruction to add
// /third_party//xkcp (spec section 5.7, the first row).

// clang-format off
// expected-error@webcpp/hash/keccak.hpp:* {{webcpp::hash: keccak_256 needs XKCP. Add /third_party//xkcp to the program's Jamfile: exe app : app.cpp /webcpp/hash//hash /third_party//xkcp ;}}
// clang-format on
#include <webcpp/hash/keccak.hpp>

int main() {
    return 0;
}
