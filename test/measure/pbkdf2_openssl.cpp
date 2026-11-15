// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// pbkdf2 on backends::openssl (OpenSSL), over the hmac the build names: 32 bytes from
// the fixed password and salt at 100,000 iterations (spec section 4.2).

#include "measure.hpp"

#include <webcpp/hash/pbkdf2.hpp>

#include <cstdint>
#include <span>

int main(int argc, char** argv) {
    namespace hash = webcpp::hash;
    namespace measure = webcpp::test::measure;
    return measure::run(argc, argv, 1, [] {
        return measure::derive([](std::span<std::uint8_t> output) {
            return hash::pbkdf2<measure::hmac, hash::backends::openssl>(
                output, measure::first(measure::secret, 16), measure::first(measure::salt, 16),
                100000);
        });
    });
}
