// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// hmac_sha1_160 on backends::hash2 (Boost.Hash2): the MAC, keyed with the fixed key, of the 1 MiB
// message (spec section 4.2).

#include "measure.hpp"

#include <webcpp/hash/hmac.hpp>

int main(int argc, char** argv) {
    namespace measure = webcpp::test::measure;
    return measure::run(argc, argv, 1,
                        [] { return measure::mac_message<webcpp::hash::hmac_sha1_160>(); });
}
