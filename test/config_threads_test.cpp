// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// <webcpp/hash/config.hpp> defines WEBCPP_HASH_HAS_THREADS natively (every native build has
// Boost.Config's BOOST_HAS_THREADS, threading=single included) and on Emscripten built with
// -pthread, never on wasip2 or wasip3 (whose cooperative threads do not run in parallel), and never
// when the developer defines WEBCPP_HASH_NO_THREADS (spec 11.5, ruling R70). test/Jamfile builds
// this file as the build asks (config_single), with threading=multi (config_threads, natively and
// on Emscripten, which b2 then builds with -pthread; config_threads_wasip3, the cooperative
// sysroot), and with WEBCPP_HASH_NO_THREADS (config_no_threads). WEBCPP_TEST_HASH_MULTI tells this
// file that the build asked for threading=multi.

#include <webcpp/hash/config.hpp>

#ifdef WEBCPP_HASH_NO_THREADS
#define WEBCPP_TEST_HASH_EXPECT_THREADS 0
#elif defined(WEBCPP_TARGET_NATIVE)
#define WEBCPP_TEST_HASH_EXPECT_THREADS 1
#elif defined(WEBCPP_TARGET_EMSCRIPTEN) && defined(WEBCPP_TEST_HASH_MULTI)
#define WEBCPP_TEST_HASH_EXPECT_THREADS 1
#else
#define WEBCPP_TEST_HASH_EXPECT_THREADS 0
#endif

#if WEBCPP_TEST_HASH_EXPECT_THREADS && !defined(WEBCPP_HASH_HAS_THREADS)
#error "WEBCPP_HASH_HAS_THREADS is not defined in a build that has threads"
#endif
#if !WEBCPP_TEST_HASH_EXPECT_THREADS && defined(WEBCPP_HASH_HAS_THREADS)
#error \
    "WEBCPP_HASH_HAS_THREADS is defined in a build without threads, or with WEBCPP_HASH_NO_THREADS"
#endif

int main() {
    return 0;
}
