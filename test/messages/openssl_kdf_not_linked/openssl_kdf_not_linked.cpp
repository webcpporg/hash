// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// argon2id and scrypt on backends::openssl, named without openssl.hpp in a program that does not
// link /webcpp/hash//openssl, stop at their engines with the instruction to add it, as every
// function on backends::openssl does (spec 5.7, the fifth row).

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so the
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/hash/detail/engines.hpp:* {{webcpp::hash: backends::openssl needs OpenSSL. Add /webcpp/hash//openssl to the program's Jamfile (native, wasip2 and wasip3): exe app : app.cpp /webcpp/hash//hash /webcpp/hash//openssl ;}}
// expected-error@webcpp/hash/detail/engines.hpp:* {{webcpp::hash: backends::openssl needs OpenSSL. Add /webcpp/hash//openssl to the program's Jamfile (native, wasip2 and wasip3): exe app : app.cpp /webcpp/hash//hash /webcpp/hash//openssl ;}}
// clang-format on
#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/scrypt.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace hash = webcpp::hash;
    std::array<std::uint8_t, 32> output{};
    std::array<std::uint8_t, 16> salt{};
    auto const argon2id = hash::argon2id<hash::backends::openssl>(
        output, {}, salt, hash::argon2id_parameters{.passes = 2, .memory = 19456 * 1024});
    auto const scrypt = hash::scrypt<hash::backends::openssl>(output, {}, salt,
                                                              hash::scrypt_parameters{1024, 8, 1});
    return argon2id && scrypt ? 0 : 1;
}
