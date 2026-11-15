/* Copyright (c) 2026 WebCpp.org
 *
 * Distributed under the Boost Software License, Version 1.0. (See
 * accompanying file LICENSE_1_0.txt or copy at
 * https://www.boost.org/LICENSE_1_0.txt)
 *
 * The canary of BLAKE3's C implementation, compiled into /third_party//blake3 with BLAKE3's
 * own defines. Its configuration is the code those defines leave to BLAKE3's dispatcher:
 * portable, the four BLAKE3_NO_* (WebAssembly, and any native target without SIMD files);
 * neon, BLAKE3_USE_NEON == 1 (arm64); x86, none of them on x86-64, where the four intrinsics
 * files are linked; and unconfigured for any other build, which no header expects. */
#include <webcpp/hash/detail/canary.h>

#if defined(BLAKE3_NO_SSE2) && defined(BLAKE3_NO_SSE41) && defined(BLAKE3_NO_AVX2) && \
    defined(BLAKE3_NO_AVX512) && !(defined(BLAKE3_USE_NEON) && BLAKE3_USE_NEON == 1)
#define WEBCPP_HASH_BLAKE3_BUILT portable
#elif defined(BLAKE3_USE_NEON) && BLAKE3_USE_NEON == 1 && !defined(BLAKE3_NO_SSE2) && \
    !defined(BLAKE3_NO_SSE41) && !defined(BLAKE3_NO_AVX2) && !defined(BLAKE3_NO_AVX512)
#define WEBCPP_HASH_BLAKE3_BUILT neon
#elif !defined(BLAKE3_NO_SSE2) && !defined(BLAKE3_NO_SSE41) && !defined(BLAKE3_NO_AVX2) && \
    !defined(BLAKE3_NO_AVX512) && !defined(BLAKE3_USE_NEON) &&                             \
    (defined(__x86_64__) || defined(_M_X64))
#define WEBCPP_HASH_BLAKE3_BUILT x86
#else
#define WEBCPP_HASH_BLAKE3_BUILT unconfigured
#endif

#if defined(_MSC_VER)
#pragma detect_mismatch("webcpp_hash_backend_blake3",                                        \
                        WEBCPP_HASH_DETAIL_MISMATCH_VALUE(blake3, WEBCPP_HASH_BLAKE3_COMMIT, \
                                                          WEBCPP_HASH_BLAKE3_BUILT))
#endif

extern const char WEBCPP_HASH_DETAIL_CANARY(blake3, WEBCPP_HASH_BLAKE3_COMMIT,
                                            WEBCPP_HASH_BLAKE3_BUILT);
const char WEBCPP_HASH_DETAIL_CANARY(blake3, WEBCPP_HASH_BLAKE3_COMMIT,
                                     WEBCPP_HASH_BLAKE3_BUILT) = 0;
