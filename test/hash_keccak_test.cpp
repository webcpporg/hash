// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// hash.hpp's branch for XKCP, which headers-alone, without the library, leaves out.

#include <webcpp/hash.hpp>

static_assert(webcpp::hash::keccak_256::block_size == 136);

int main() {
    return 0;
}
