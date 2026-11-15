// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program that hashes "abc" with Keccak-256. Without /third_party//xkcp in its link, or with
// another commit's canary (WEBCPP_HASH_XKCP_CANARY_COMMIT), it does not link: the canary its
// header reads,
//
//     webcpp_hash_xkcp_d20c8fc_generic64__add_third_party_xkcp_to_your_link,
//
// on every target, is undefined (spec section 5.4). It names nothing of the test support, which a
// link-fail program is built without.

#include <webcpp/hash/keccak.hpp>

int main() {
    webcpp::hash::keccak_256 hasher;
    hasher.update("abc", 3);
    return hasher.result()[0] == 0x4e ? 0 : 1;
}
