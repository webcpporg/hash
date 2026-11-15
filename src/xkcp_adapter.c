/* Copyright (c) 2026 WebCpp.org
 *
 * Distributed under the Boost Software License, Version 1.0. (See
 * accompanying file LICENSE_1_0.txt or copy at
 * https://www.boost.org/LICENSE_1_0.txt)
 *
 * webcpp::hash's adapter over XKCP's Keccak-p[1600]: four functions of webcpp's own names, so
 * that no XKCP header, and with them XKCP's config.h, reaches a program's translation unit.
 * The state is the caller's 25 lanes of 64 bits, the layout of KeccakP1600_plain64_state.
 * offset + length never exceeds 200, the state's size: the callers are keccak_256's members,
 * which the unsigned int casts rely on. */
#include <stddef.h>
#include <stdint.h>

#include "KeccakP-1600-SnP.h"

void webcpp_hash_xkcp_initialize(uint64_t* state) {
    KeccakP1600_Initialize((KeccakP1600_plain64_state*)state);
}

void webcpp_hash_xkcp_add_bytes(uint64_t* state, const unsigned char* data, size_t offset,
                                size_t length) {
    KeccakP1600_AddBytes((KeccakP1600_plain64_state*)state, data, (unsigned int)offset,
                         (unsigned int)length);
}

void webcpp_hash_xkcp_permute(uint64_t* state) {
    KeccakP1600_Permute_24rounds((KeccakP1600_plain64_state*)state);
}

void webcpp_hash_xkcp_extract_bytes(const uint64_t* state, unsigned char* data, size_t offset,
                                    size_t length) {
    KeccakP1600_ExtractBytes((const KeccakP1600_plain64_state*)state, data, (unsigned int)offset,
                             (unsigned int)length);
}
