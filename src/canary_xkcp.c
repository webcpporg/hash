/* Copyright (c) 2026 WebCpp.org
 *
 * Distributed under the Boost Software License, Version 1.0. (See
 * accompanying file LICENSE_1_0.txt or copy at
 * https://www.boost.org/LICENSE_1_0.txt)
 *
 * The canary of XKCP, compiled into /third_party//xkcp with its defines. Its configuration is
 * the profile of KeccakP-1600-opt64.c those defines make: generic64, every round unrolled and
 * no lane complementing (no KeccakP1600_plain64_unrolling, no
 * KeccakP1600_plain64_useLaneComplementing); unconfigured for any other build. */
#include <webcpp/hash/detail/canary.h>

#if !defined(KeccakP1600_plain64_unrolling) && !defined(KeccakP1600_plain64_useLaneComplementing)
#define WEBCPP_HASH_XKCP_BUILT generic64
#else
#define WEBCPP_HASH_XKCP_BUILT unconfigured
#endif

#if defined(_MSC_VER)
#pragma detect_mismatch(        \
    "webcpp_hash_backend_xkcp", \
    WEBCPP_HASH_DETAIL_MISMATCH_VALUE(xkcp, WEBCPP_HASH_XKCP_COMMIT, WEBCPP_HASH_XKCP_BUILT))
#endif

extern const char WEBCPP_HASH_DETAIL_CANARY(xkcp, WEBCPP_HASH_XKCP_COMMIT, WEBCPP_HASH_XKCP_BUILT);
const char WEBCPP_HASH_DETAIL_CANARY(xkcp, WEBCPP_HASH_XKCP_COMMIT, WEBCPP_HASH_XKCP_BUILT) = 0;
