/* Copyright (c) 2026 WebCpp.org
 *
 * Distributed under the Boost Software License, Version 1.0. (See
 * accompanying file LICENSE_1_0.txt or copy at
 * https://www.boost.org/LICENSE_1_0.txt)
 *
 * The configuration XKCP's build generates as config.h, for the components webcpp::hash
 * compiles: Keccak-p[1600] in the plain-64bits implementation (XKCP's "generic64" profile),
 * and the high-level files over it that XKCP's lib/HighLevel.build names KeccakSponge,
 * TurboSHAKE, FIPS202, SP800-185 and KangarooTwelve, each with the define its fragment sets.
 * No XKCP_has_KeccakP1600times2, 4 or 8: generic64 has no parallel permutation, so
 * KangarooTwelve.c and SP800-185.inc take their serial loops and no times-N file is
 * compiled. It is on the include path of /third_party//xkcp and of XKCP's unit tests alone,
 * never of a program. */
#ifndef WEBCPP_HASH_XKCP_CONFIG_H
#define WEBCPP_HASH_XKCP_CONFIG_H
#define XKCP_has_KeccakP1600
#define XKCP_has_Sponge_Keccak
#define XKCP_has_TurboSHAKE
#define XKCP_has_FIPS202
#define XKCP_has_SP800_185
#define XKCP_has_KangarooTwelve

/* KangarooTwelve.c marks three locals __attribute__((unused)), which MSVC's compiler does
 * not know (clang-cl does): there the attribute is dropped, as it changes no code. */
#if defined(_MSC_VER) && !defined(__clang__) && !defined(__attribute__)
#define __attribute__(x)
#endif
#endif
