/* Copyright (c) 2026 WebCpp.org
 *
 * Distributed under the Boost Software License, Version 1.0. (See
 * accompanying file LICENSE_1_0.txt or copy at
 * https://www.boost.org/LICENSE_1_0.txt)
 *
 * webcpp::hash's canary of the backend BearSSL, compiled into /third_party//bearssl, beside
 * webcpp::crypto's, with BearSSL's own defines. Its configuration is decided as crypto's is:
 * getentropy, the one source, with RDRAND and /dev/urandom off; noseeder, every seeder off
 * (Windows); and unconfigured for any other build, which no header expects. */
#include <webcpp/hash/detail/canary.h>

#if defined(BR_USE_GETENTROPY) && BR_USE_GETENTROPY == 1 && defined(BR_RDRAND) && \
    BR_RDRAND == 0 && defined(BR_USE_URANDOM) && BR_USE_URANDOM == 0
#define WEBCPP_HASH_BEARSSL_BUILT getentropy
#elif defined(BR_USE_GETENTROPY) && BR_USE_GETENTROPY == 0 && defined(BR_RDRAND) && \
    BR_RDRAND == 0 && defined(BR_USE_URANDOM) && BR_USE_URANDOM == 0 &&             \
    defined(BR_USE_WIN32_RAND) && BR_USE_WIN32_RAND == 0
#define WEBCPP_HASH_BEARSSL_BUILT noseeder
#else
#define WEBCPP_HASH_BEARSSL_BUILT unconfigured
#endif

#if defined(_MSC_VER)
#pragma detect_mismatch("webcpp_hash_backend_bearssl",                                         \
                        WEBCPP_HASH_DETAIL_MISMATCH_VALUE(bearssl, WEBCPP_HASH_BEARSSL_COMMIT, \
                                                          WEBCPP_HASH_BEARSSL_BUILT))
#endif

extern const char WEBCPP_HASH_DETAIL_CANARY(bearssl, WEBCPP_HASH_BEARSSL_COMMIT,
                                            WEBCPP_HASH_BEARSSL_BUILT);
const char WEBCPP_HASH_DETAIL_CANARY(bearssl, WEBCPP_HASH_BEARSSL_COMMIT,
                                     WEBCPP_HASH_BEARSSL_BUILT) = 0;
