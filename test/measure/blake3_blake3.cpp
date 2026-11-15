// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// blake3 on BLAKE3's C implementation: the hash of the 1 MiB message (spec section 4.2).

#include "measure.hpp"

#include <webcpp/hash/blake3.hpp>

int main(int argc, char** argv) {
    namespace hash = webcpp::hash;
    namespace measure = webcpp::test::measure;
    return measure::run(argc, argv, 1, [] { return measure::hash_message<hash::blake3>(); });
}
