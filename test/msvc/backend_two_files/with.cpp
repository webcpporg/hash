// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The translation unit of backend_two_files under another configuration of XKCP (see
// main.cpp): it includes keccak.hpp and calls nothing of it.

#define WEBCPP_HASH_XKCP_CANARY_CONFIGURATION unconfigured
#include <webcpp/hash/keccak.hpp>

int with() {
    return 0;
}
