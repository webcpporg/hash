// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// scrypt (RFC 7914) with the parameters of the RFC's section 12 second vector (P "password",
// S "NaCl", N 1024, r 8, p 16, 64 bytes), checked against the RFC and against Python's
// hashlib.scrypt.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/scrypt.hpp>

#include <array>
#include <cstdint>
#include <iostream>

int main() {
    // N is the CPU and memory cost (a power of two), r the block size and p the parallelism: the
    // memory is 128 r N bytes, 1 MiB here. A real password hash uses a larger N.
    std::array<std::uint8_t, 64> key{};
    auto const done = webcpp::hash::scrypt(key, example::bytes("password"), example::bytes("NaCl"),
                                           {.n = 1024, .r = 8, .p = 16});
    if (!done) {
        std::cerr << done.error().message() << '\n';
        return 1;
    }
    std::cout << "scrypt " << example::hex(key) << '\n';
    if (example::hex(key) !=
        "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162"
        "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640") {
        return 1;
    }
}

// end::example[]
