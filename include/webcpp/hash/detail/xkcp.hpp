// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The four functions of webcpp::hash's adapter over XKCP's Keccak-p[1600]
 (`libs/hash/src/xkcp_adapter.c`, compiled into `/third_party//xkcp`): no XKCP
 header reaches a program's translation unit. The state is 25 lanes of 64 bits,
 the layout of XKCP's `KeccakP1600_plain64_state`; every `offset + length` is at
 most 200, the state's size in bytes.
*/
#ifndef WEBCPP_HASH_DETAIL_XKCP_HPP
#define WEBCPP_HASH_DETAIL_XKCP_HPP

#include <webcpp/hash/config.hpp>

#include <cstddef>
#include <cstdint>

extern "C" {

/** Sets the 25 lanes at `state` to zero (XKCP's `KeccakP1600_Initialize`). @param state The state.
 */
void webcpp_hash_xkcp_initialize(std::uint64_t* state);

/**
 Adds, by exclusive or, the `length` bytes at `data` to the state's bytes from `offset`
 (XKCP's `KeccakP1600_AddBytes`).

 @param state The state.
 @param data The bytes.
 @param offset The first byte of the state they are added to.
 @param length Their number.
*/
void webcpp_hash_xkcp_add_bytes(std::uint64_t* state, unsigned char const* data, std::size_t offset,
                                std::size_t length);

/** Applies Keccak-f[1600], 24 rounds, to the state (XKCP's `KeccakP1600_Permute_24rounds`). @param
 * state The state. */
void webcpp_hash_xkcp_permute(std::uint64_t* state);

/**
 Copies the state's `length` bytes from `offset` to `data` (XKCP's `KeccakP1600_ExtractBytes`).

 @param state The state.
 @param data Where the bytes go.
 @param offset The first byte of the state copied.
 @param length Their number.
*/
void webcpp_hash_xkcp_extract_bytes(std::uint64_t const* state, unsigned char* data,
                                    std::size_t offset, std::size_t length);
}

#endif  // WEBCPP_HASH_DETAIL_XKCP_HPP
