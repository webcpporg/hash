// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// keccak_256 in two translation units, one of them with another configuration of XKCP:
// MSVC's linker refuses the pair with LNK2038 on "webcpp_hash_backend_xkcp" (spec section 5.7).
// This file is the one without the define; with.cpp has it.

#include <webcpp/hash/keccak.hpp>

int with();

int main() {
    return with() == 0 ? 0 : 1;
}
