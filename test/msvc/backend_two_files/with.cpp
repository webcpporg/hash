// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The translation unit of backend_two_files with the define (see main.cpp).

#define WEBCPP_HASH_XKCP_CANARY_CONFIGURATION unconfigured
#include <webcpp/hash/keccak.hpp>

int with() {
    webcpp::hash::keccak_256 hasher;
    hasher.update("abc", 3);
    return hasher.result()[0] == 0x4e ? 0 : 1;
}
