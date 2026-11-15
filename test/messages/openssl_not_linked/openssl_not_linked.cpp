// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program that names backends::openssl without linking /webcpp/hash//openssl stops with the
// instruction to add it (spec 5.7, the fifth row).

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so the
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/hash/backends/openssl.hpp:* {{webcpp::hash: backends::openssl needs OpenSSL. Add /webcpp/hash//openssl to the program's Jamfile (native, wasip2 and wasip3): exe app : app.cpp /webcpp/hash//hash /webcpp/hash//openssl ;}}
// clang-format on
#include <webcpp/hash/backends/openssl.hpp>

int main() {
    return 0;
}
