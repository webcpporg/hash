// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// scrypt on backends::sodium (libsodium): 32 bytes from the fixed password and salt at
// N = 16384, r = 8, p = 1, libsodium's interactive memory of 16 MiB (spec section 4.2).

#include "measure.hpp"

#include <webcpp/hash/scrypt.hpp>

#include <cstdint>
#include <span>

int main(int argc, char** argv) {
    namespace hash = webcpp::hash;
    namespace measure = webcpp::test::measure;
    return measure::run(argc, argv, 1, [] {
        return measure::derive([](std::span<std::uint8_t> output) {
            return hash::scrypt<hash::backends::sodium>(
                output, measure::first(measure::secret, 16), measure::first(measure::salt, 16),
                hash::scrypt_parameters{.n = 16384, .r = 8, .p = 1});
        });
    });
}
