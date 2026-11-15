/* Copyright (c) 2026 WebCpp.org
 *
 * Distributed under the Boost Software License, Version 1.0. (See
 * accompanying file LICENSE_1_0.txt or copy at
 * https://www.boost.org/LICENSE_1_0.txt)
 *
 * The canary of the backend libsodium, compiled into /third_party//sodium with libsodium's
 * own defines. Its configuration is configured exactly when those defines are the ones
 * third_party/Jamfile derives from libsodium's configure: CONFIGURED, SODIUM_STATIC and
 * NATIVE_LITTLE_ENDIAN each 1, and libsodium's assembly off (no HAVE_AMD64_ASM), so that every
 * function is its C code; and unconfigured for any other build, which no header expects. */
#include <webcpp/hash/detail/canary.h>

#if defined(CONFIGURED) && CONFIGURED == 1 && defined(SODIUM_STATIC) && SODIUM_STATIC == 1 && \
    defined(NATIVE_LITTLE_ENDIAN) && NATIVE_LITTLE_ENDIAN == 1 && !defined(HAVE_AMD64_ASM)
#define WEBCPP_HASH_SODIUM_BUILT configured
#else
#define WEBCPP_HASH_SODIUM_BUILT unconfigured
#endif

#if defined(_MSC_VER)
#pragma detect_mismatch("webcpp_hash_backend_sodium",                                        \
                        WEBCPP_HASH_DETAIL_MISMATCH_VALUE(sodium, WEBCPP_HASH_SODIUM_COMMIT, \
                                                          WEBCPP_HASH_SODIUM_BUILT))
#endif

extern const char WEBCPP_HASH_DETAIL_CANARY(sodium, WEBCPP_HASH_SODIUM_COMMIT,
                                            WEBCPP_HASH_SODIUM_BUILT);
const char WEBCPP_HASH_DETAIL_CANARY(sodium, WEBCPP_HASH_SODIUM_COMMIT,
                                     WEBCPP_HASH_SODIUM_BUILT) = 0;
