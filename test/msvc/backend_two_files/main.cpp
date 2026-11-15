// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// keccak_256 in a program whose two translation units include keccak.hpp under two
// configurations of XKCP: MSVC's linker refuses the pair with LNK2038 on
// "webcpp_hash_backend_xkcp" (spec section 5.7), and with nothing else. This file calls
// keccak_256 with the configuration /third_party//xkcp builds, whose canary it defines, so the
// program links on any other linker; with.cpp only includes the header under another
// configuration, which emits its #pragma detect_mismatch and reads no canary.

#include <webcpp/hash/keccak.hpp>

int with();

int main() {
    webcpp::hash::keccak_256 hasher;
    hasher.update("abc", 3);
    return hasher.result()[0] == 0x4e && with() == 0 ? 0 : 1;
}
