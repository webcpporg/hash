// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// argon2id on backends::sodium (libsodium): 32 bytes from the fixed password and salt
// at libsodium's interactive costs, 2 passes over 64 MiB (spec section 4.2).

#include "measure.hpp"

#include <webcpp/hash/argon2.hpp>

#include <cstdint>
#include <span>

int main(int argc, char** argv) {
    namespace hash = webcpp::hash;
    namespace measure = webcpp::test::measure;
    return measure::run(argc, argv, 1, [] {
        return measure::derive([](std::span<std::uint8_t> output) {
            return hash::argon2id<hash::backends::sodium>(
                output, measure::first(measure::secret, 16), measure::first(measure::salt, 16),
                hash::argon2id_interactive);
        });
    });
}
