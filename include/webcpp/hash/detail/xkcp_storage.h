/* Copyright (c) 2026 WebCpp.org
 *
 * Distributed under the Boost Software License, Version 1.0. (See
 * accompanying file LICENSE_1_0.txt or copy at
 * https://www.boost.org/LICENSE_1_0.txt)
 *
 * The storage of each XKCP instance kind, in 64-bit words, readable as C and C++: the one
 * source of the numbers that src/xkcp_adapter.c checks against XKCP's structures (C static
 * assertions) and that detail/xkcp.hpp allocates (std::array, with C++ static assertions that
 * each array's size is exactly this many words, at their alignment). A pin of XKCP whose
 * structure outgrows its storage stops the adapter's build; raising the number here raises both
 * sides at once.
 * Each size is the native maximum of XKCP's structure; on wasm32, where size_t is 4 bytes,
 * the structures are smaller. */
#ifndef WEBCPP_HASH_DETAIL_XKCP_STORAGE_H
#define WEBCPP_HASH_DETAIL_XKCP_STORAGE_H

/* One enumeration, a constant expression in C and in C++ alike (a C++ template argument, a C
 * static assertion), and not a macro, so that no macro of a number reaches a program; in C++ it
 * is webcpp::hash::detail's, so that no name of it reaches a program's global namespace. The
 * last enumerator has no trailing comma, which C89 does not allow. */
#ifdef __cplusplus
namespace webcpp::hash::detail {
#endif
/** The number of 64-bit words of webcpp's storage for each XKCP instance kind. */
enum webcpp_hash_xkcp_storage_words {
    /** The words of a `KeccakWidth1600_SpongeInstance`: 216 bytes. */
    webcpp_hash_xkcp_sponge_words = 27,
    /** The words of a `Keccak_HashInstance`: 224 bytes. */
    webcpp_hash_xkcp_keccak_hash_words = 28,
    /** The words of a `TurboSHAKE_Instance`: 216 bytes. */
    webcpp_hash_xkcp_turboshake_words = 27,
    /** The words of a `KangarooTwelve_Instance`: 464 bytes natively, 456 on wasm32. */
    webcpp_hash_xkcp_kangarootwelve_words = 58,
    /** The words of a `cSHAKE_Instance`: 240 bytes. */
    webcpp_hash_xkcp_cshake_words = 30,
    /** The words of a `KMAC_Instance`: 248 bytes. */
    webcpp_hash_xkcp_kmac_words = 31,
    /** The words of a `TupleHash_Instance`: 248 bytes. */
    webcpp_hash_xkcp_tuplehash_words = 31,
    /** The words of a `ParallelHash_Instance`: 472 bytes natively, 456 on wasm32. */
    webcpp_hash_xkcp_parallelhash_words = 59 /* NOLINT(readability-trailing-comma): C89 has none */
};
#ifdef __cplusplus
} /* namespace webcpp::hash::detail */
#endif

#endif
