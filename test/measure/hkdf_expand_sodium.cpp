// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// hkdf_expand on backends::sodium (libsodium), over the hmac the build names: 32
// bytes from a fixed digest-size PRK and info, 1,000 times per timed run (spec section 4.2).

#include "measure.hpp"

#include <webcpp/hash/hkdf.hpp>

#include <cstddef>
#include <cstdint>
#include <span>

int main(int argc, char** argv) {
    namespace hash = webcpp::hash;
    namespace measure = webcpp::test::measure;
    return measure::run(argc, argv, 1000, [] {
        constexpr std::size_t digest_size = measure::hmac::result_type().size();
        return measure::derive([](std::span<std::uint8_t> output) {
            return hash::hkdf_expand<measure::hmac, hash::backends::sodium>(
                output, measure::first(measure::prk, digest_size), measure::info);
        });
    });
}
