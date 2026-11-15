// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// keccak_256's read of XKCP's canary survives optimisation: test/Jamfile builds this program at
// full optimisation with /third_party//xkcp, which must link and run, and with another commit's
// canary (WEBCPP_HASH_XKCP_CANARY_COMMIT), the program's one missing symbol, which must not link
// (spec section 5.4). Like webcpp::crypto's canary_read_test.cpp it names nothing of the test
// support, which a link-fail program is built without.

#include <webcpp/hash/keccak.hpp>

int main() {
    webcpp::hash::keccak_256 hasher;
    hasher.update("abc", 3);
    // The first byte of Keccak-256("abc"), 4e03657a...
    return hasher.result()[0] == 0x4e ? 0 : 1;
}
