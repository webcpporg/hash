/* Copyright (c) 2026 WebCpp.org
 *
 * Distributed under the Boost Software License, Version 1.0. (See
 * accompanying file LICENSE_1_0.txt or copy at
 * https://www.boost.org/LICENSE_1_0.txt)
 *
 * The configuration XKCP's build generates as config.h, for the one component webcpp::hash
 * compiles: Keccak-p[1600] in the plain-64bits implementation (XKCP's "generic64" profile).
 * It is on the include path of /third_party//xkcp alone, never of a program. */
#ifndef WEBCPP_HASH_XKCP_CONFIG_H
#define WEBCPP_HASH_XKCP_CONFIG_H
#define XKCP_has_KeccakP1600
#endif
