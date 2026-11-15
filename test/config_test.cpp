// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// <webcpp/hash/config.hpp> defines WEBCPP_HASH_NO_EXCEPTIONS exactly when
// webcpp has no exceptions, keeps the developer's own definition in a build that
// has them, defines WEBCPP_HASH_WEBASSEMBLY exactly on wasip2, wasip3 and
// Emscripten, and declares the tags of the backends and of the key derivation
// functions. test/Jamfile builds this file as the build asks; without exceptions;
// with WEBCPP_NO_EXCEPTIONS defined as a developer defines it for every webcpp
// library, which WEBCPP_TEST_HASH_ALL_OFF tells this file; and with the macro
// itself defined on the command line, which WEBCPP_TEST_HASH_DEVELOPER_DEFINED
// tells this file.

#include <webcpp/hash/config.hpp>

// webcpp's configuration, which config.hpp includes, has said whether webcpp
// has exceptions and which target the program is for.
#ifndef WEBCPP_CONFIG_HPP
#error "config.hpp does not include <webcpp/config.hpp>"
#endif

#ifdef WEBCPP_TEST_HASH_ALL_OFF
#ifndef WEBCPP_HASH_NO_EXCEPTIONS
#error "WEBCPP_NO_EXCEPTIONS does not define WEBCPP_HASH_NO_EXCEPTIONS"
#endif
#elif defined(WEBCPP_TEST_HASH_DEVELOPER_DEFINED)
#ifndef WEBCPP_HASH_NO_EXCEPTIONS
#error "config.hpp drops WEBCPP_HASH_NO_EXCEPTIONS, which the developer defined"
#endif
#elif defined(WEBCPP_HAS_EXCEPTIONS) == defined(WEBCPP_HASH_NO_EXCEPTIONS)
#error "WEBCPP_HASH_NO_EXCEPTIONS is not defined exactly when webcpp has no exceptions"
#endif

#if defined(WEBCPP_TARGET_NATIVE) == defined(WEBCPP_HASH_WEBASSEMBLY)
#error "WEBCPP_HASH_WEBASSEMBLY is not defined exactly on WebAssembly"
#endif

// The tags are declared, incomplete until their headers define them.
template <class T>
constexpr bool declared = sizeof(T*) != 0;
static_assert(declared<webcpp::hash::backends::hash2> && declared<webcpp::hash::backends::sodium> &&
              declared<webcpp::hash::backends::bearssl> &&
              declared<webcpp::hash::backends::openssl> && declared<webcpp::hash::kdfs::hkdf> &&
              declared<webcpp::hash::kdfs::pbkdf2> && declared<webcpp::hash::kdfs::hkdf_extract> &&
              declared<webcpp::hash::kdfs::hkdf_expand> && declared<webcpp::hash::kdfs::argon2id> &&
              declared<webcpp::hash::kdfs::scrypt>);

int main() {
    return 0;
}
