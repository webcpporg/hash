// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program that hashes "abc" with BLAKE3. Without /third_party//blake3 in its link, or with
// another commit's canary (WEBCPP_HASH_BLAKE3_CANARY_COMMIT), it does not link: the canary its
// header reads,
//
//     webcpp_hash_blake3_f3149ec_<configuration>__add_third_party_blake3_to_your_link,
//
// whose configuration is portable on WebAssembly, x86 on x86-64 and neon on arm64, is undefined
// (spec section 5.4). It names nothing of the test support, which a link-fail program is built
// without.

#include <webcpp/hash/blake3.hpp>

int main() {
    webcpp::hash::blake3 hasher;
    hasher.update("abc", 3);
    return hasher.result()[0] == 0x64 ? 0 : 1;
}
