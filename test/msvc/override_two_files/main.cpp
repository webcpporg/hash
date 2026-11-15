// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// hkdf in two translation units, one of them under WEBCPP_HASH_DEFAULT_BACKEND_HKDF_HASH2:
// MSVC's linker refuses the pair with LNK2038 on "webcpp_hash_default_backend_hkdf" (spec
// section 5.7). This file is the one without the define; with.cpp has it.

#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>

#include <array>
#include <cstdint>

int with();

int main() {
    return with() == 0 ? 0 : 1;
}
