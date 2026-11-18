/* Copyright (c) 2026 WebCpp.org
 *
 * Distributed under the Boost Software License, Version 1.0. (See
 * accompanying file LICENSE_1_0.txt or copy at
 * https://www.boost.org/LICENSE_1_0.txt)
 *
 * The storage of each XKCP instance kind, in 64-bit words, readable as C and C++: the one
 * source of the numbers that src/xkcp_adapter.c checks against XKCP's structures (C static
 * assertions) and that detail/xkcp.hpp allocates (std::array, with a C++ static assertion
 * that each array has exactly this many words). A pin of XKCP whose structure outgrows its
 * storage stops the adapter's build; raising the number here raises both sides at once.
 * Each size is the native maximum of XKCP's structure; on wasm32, where size_t is 4 bytes,
 * the structures are smaller. */
#ifndef WEBCPP_HASH_DETAIL_XKCP_STORAGE_H
#define WEBCPP_HASH_DETAIL_XKCP_STORAGE_H

/* KeccakWidth1600_SpongeInstance: 216 bytes. */
#define WEBCPP_HASH_XKCP_SPONGE_WORDS 27
/* Keccak_HashInstance: 224 bytes. */
#define WEBCPP_HASH_XKCP_KECCAK_HASH_WORDS 28
/* TurboSHAKE_Instance: 216 bytes. */
#define WEBCPP_HASH_XKCP_TURBOSHAKE_WORDS 27
/* KangarooTwelve_Instance: 464 bytes natively, 456 on wasm32. */
#define WEBCPP_HASH_XKCP_KANGAROOTWELVE_WORDS 58
/* cSHAKE_Instance: 240 bytes. */
#define WEBCPP_HASH_XKCP_CSHAKE_WORDS 30
/* KMAC_Instance: 248 bytes. */
#define WEBCPP_HASH_XKCP_KMAC_WORDS 31
/* TupleHash_Instance: 248 bytes. */
#define WEBCPP_HASH_XKCP_TUPLEHASH_WORDS 31
/* ParallelHash_Instance: 472 bytes natively, 456 on wasm32. */
#define WEBCPP_HASH_XKCP_PARALLELHASH_WORDS 59

#endif
