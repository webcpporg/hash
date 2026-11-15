/* Copyright (c) 2026 WebCpp.org
 *
 * Distributed under the Boost Software License, Version 1.0. (See
 * accompanying file LICENSE_1_0.txt or copy at
 * https://www.boost.org/LICENSE_1_0.txt)
 *
 * The link-time canaries of webcpp::hash's backends, readable as C and C++. A backend's
 * header reads its canary inside every function that calls the C library, and webcpp's
 * src/canary_<name>.c, which /third_party//<name> compiles with the library's own flags,
 * defines it, so that a program linked without that library, or with one of another
 * commit or configuration, fails to link with the canary's name:
 *
 *     webcpp_hash_<name>_<commit7>_<configuration>__add_third_party_<name>_to_your_link
 *
 * On MSVC the same three facts also reach the linker as #pragma detect_mismatch. */
#ifndef WEBCPP_HASH_DETAIL_CANARY_H
#define WEBCPP_HASH_DETAIL_CANARY_H

/* The commit each library is pinned at, its first seven hex digits, which the CI compares
 * with `git -C third_party/libs/<name> rev-parse --short=7 HEAD`. A test of the canary
 * gives another through WEBCPP_HASH_<NAME>_CANARY_COMMIT. A library's pin,
 * WEBCPP_HASH_<NAME>_COMMIT behind that seam, is added with the library's target. */
#ifdef WEBCPP_HASH_XKCP_CANARY_COMMIT
#define WEBCPP_HASH_XKCP_COMMIT WEBCPP_HASH_XKCP_CANARY_COMMIT
#else
#define WEBCPP_HASH_XKCP_COMMIT d20c8fc
#endif

#ifdef WEBCPP_HASH_SODIUM_CANARY_COMMIT
#define WEBCPP_HASH_SODIUM_COMMIT WEBCPP_HASH_SODIUM_CANARY_COMMIT
#else
#define WEBCPP_HASH_SODIUM_COMMIT 77e1ce5
#endif

#ifdef WEBCPP_HASH_BLAKE3_CANARY_COMMIT
#define WEBCPP_HASH_BLAKE3_COMMIT WEBCPP_HASH_BLAKE3_CANARY_COMMIT
#else
#define WEBCPP_HASH_BLAKE3_COMMIT f3149ec
#endif

#ifdef WEBCPP_HASH_BEARSSL_CANARY_COMMIT
#define WEBCPP_HASH_BEARSSL_COMMIT WEBCPP_HASH_BEARSSL_CANARY_COMMIT
#else
#define WEBCPP_HASH_BEARSSL_COMMIT 7bea48e
#endif

#define WEBCPP_HASH_DETAIL_CANARY_I(name, commit, configuration) \
    webcpp_hash_##name##_##commit##_##configuration##__add_third_party_##name##_to_your_link
#define WEBCPP_HASH_DETAIL_CANARY(name, commit, configuration) \
    WEBCPP_HASH_DETAIL_CANARY_I(name, commit, configuration)
#define WEBCPP_HASH_DETAIL_STRING_I(x) #x
#define WEBCPP_HASH_DETAIL_STRING(x) WEBCPP_HASH_DETAIL_STRING_I(x)
#define WEBCPP_HASH_DETAIL_MISMATCH_VALUE(name, commit, configuration) \
    #name "-" WEBCPP_HASH_DETAIL_STRING(commit) "-" WEBCPP_HASH_DETAIL_STRING(configuration)

#endif
