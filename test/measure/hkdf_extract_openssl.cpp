// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// hkdf_extract on backends::openssl (OpenSSL), over the hmac the build names: the
// pseudorandom key of the fixed IKM and salt, 1,000 times per timed run (spec section 4.2).

#include "measure.hpp"

#include <webcpp/hash/hkdf.hpp>

int main(int argc, char** argv) {
    namespace hash = webcpp::hash;
    namespace measure = webcpp::test::measure;
    return measure::run(argc, argv, 1000, [] {
        auto prk = hash::hkdf_extract<measure::hmac, hash::backends::openssl>(measure::salt,
                                                                              measure::secret);
        return prk.has_value() ? measure::result_of(*prk) : measure::result{};
    });
}
