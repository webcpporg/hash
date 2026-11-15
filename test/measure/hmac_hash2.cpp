// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// hmac on backends::hash2 (Boost.Hash2): hmac<sha2_256>, the template over a hash, keyed with the
// fixed key, of the 1 MiB message (spec section 4.2).

#include "measure.hpp"

#include <webcpp/hash/algorithms.hpp>
#include <webcpp/hash/hmac.hpp>

int main(int argc, char** argv) {
    namespace measure = webcpp::test::measure;
    return measure::run(argc, argv, 1, [] {
        return measure::mac_message<webcpp::hash::hmac<webcpp::hash::sha2_256>>();
    });
}
