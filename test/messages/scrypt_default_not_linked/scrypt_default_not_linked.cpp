// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// scrypt on its default backend, backends::sodium, in a program that does not link libsodium stops
// with the instruction to add /third_party//sodium (spec section 5.7, the third row).

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so the
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/hash/detail/engines.hpp:* {{webcpp::hash: backends::sodium, argon2id, scrypt and blake2b_subkey need libsodium. Add /third_party//sodium to the program's Jamfile: exe app : app.cpp /webcpp/hash//hash /third_party//sodium ;}}
// clang-format on
#include <webcpp/hash/scrypt.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 32> output{};
    std::array<std::uint8_t, 16> salt{};
    auto done = webcpp::hash::scrypt(output, {}, salt, webcpp::hash::scrypt_parameters{1024, 8, 1});
    return done ? 0 : 1;
}
