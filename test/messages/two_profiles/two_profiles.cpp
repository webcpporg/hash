// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Two library profiles (spec 4.1) stop the build with an #error naming both defines.

// clang-format off
// expected-error@webcpp/hash/config.hpp:* {{webcpp::hash: WEBCPP_HASH_PROFILE_FASTEST and WEBCPP_HASH_PROFILE_SMALLEST are both defined. Keep one.}}
// clang-format on
#include <webcpp/hash/config.hpp>

int main() {
    return 0;
}
