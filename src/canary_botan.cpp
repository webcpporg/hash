// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)
//
// webcpp::hash's canary of the backend Botan, compiled into /third_party//botan with Botan's own
// properties and its configured build.h. Its configuration is configured exactly when build.h is
// that of Botan 3.14.1 with every module hash's tags need (BOTAN_HAS_* of tools/botan/modules.txt's
// hashes, XOFs, MACs and key derivations) and no random generator of the system's
// (BOTAN_HAS_SYSTEM_RNG, BOTAN_HAS_AUTO_SEEDING_RNG: hash draws no random bytes from Botan, design
// D43); and unconfigured for any other build, which no header expects.
#include <webcpp/hash/detail/canary.h>

#include <botan/build.h>  // third_party/libs/botan, configured by /third_party//botan

#if defined(BOTAN_VERSION_MAJOR) && BOTAN_VERSION_MAJOR == 3 && defined(BOTAN_VERSION_MINOR) && \
    BOTAN_VERSION_MINOR == 14 && defined(BOTAN_VERSION_PATCH) && BOTAN_VERSION_PATCH == 1 &&    \
    defined(BOTAN_HAS_MD5) && defined(BOTAN_HAS_SHA1) && defined(BOTAN_HAS_SHA2_32) &&          \
    defined(BOTAN_HAS_SHA2_64) && defined(BOTAN_HAS_SHA3) && defined(BOTAN_HAS_SHAKE) &&        \
    defined(BOTAN_HAS_SHAKE_XOF) && defined(BOTAN_HAS_KECCAK) && defined(BOTAN_HAS_BLAKE2B) &&  \
    defined(BOTAN_HAS_BLAKE2S) && defined(BOTAN_HAS_BLAKE2BMAC) &&                              \
    defined(BOTAN_HAS_RIPEMD_160) && defined(BOTAN_HAS_SM3) && defined(BOTAN_HAS_STREEBOG) &&   \
    defined(BOTAN_HAS_WHIRLPOOL) && defined(BOTAN_HAS_SKEIN_512) && defined(BOTAN_HAS_HMAC) &&  \
    defined(BOTAN_HAS_KMAC) && defined(BOTAN_HAS_SIPHASH) && defined(BOTAN_HAS_HKDF) &&         \
    defined(BOTAN_HAS_PBKDF2) && defined(BOTAN_HAS_SCRYPT) && defined(BOTAN_HAS_ARGON2) &&      \
    defined(BOTAN_HAS_BCRYPT) && defined(BOTAN_HAS_PBKDF_BCRYPT) &&                             \
    defined(BOTAN_HAS_SP800_108) && defined(BOTAN_HAS_SP800_56A) && defined(BOTAN_HAS_KDF2) &&  \
    !defined(BOTAN_HAS_SYSTEM_RNG) && !defined(BOTAN_HAS_AUTO_SEEDING_RNG)
#define WEBCPP_HASH_BOTAN_BUILT configured
#else
#define WEBCPP_HASH_BOTAN_BUILT unconfigured
#endif

#ifdef _MSC_VER
#pragma detect_mismatch(         \
    "webcpp_hash_backend_botan", \
    WEBCPP_HASH_DETAIL_MISMATCH_VALUE(botan, WEBCPP_HASH_BOTAN_COMMIT, WEBCPP_HASH_BOTAN_BUILT))
#endif

// The canary, constant, with C's linkage, as backends/botan.hpp declares it: constinit there, so
// constinit here too, on the initialising declaration, as the standard asks.
extern "C" constinit const char WEBCPP_HASH_DETAIL_CANARY(botan, WEBCPP_HASH_BOTAN_COMMIT,
                                                          WEBCPP_HASH_BOTAN_BUILT);
extern "C" constinit const char WEBCPP_HASH_DETAIL_CANARY(botan, WEBCPP_HASH_BOTAN_COMMIT,
                                                          WEBCPP_HASH_BOTAN_BUILT) = 0;
