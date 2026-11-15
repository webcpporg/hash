// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

#ifndef WEBCPP_HASH_SRC_OPENSSL_ON_EMSCRIPTEN_HPP
#define WEBCPP_HASH_SRC_OPENSSL_ON_EMSCRIPTEN_HPP

// Forced into every source, C and C++, when an Emscripten program names /webcpp/hash//openssl:
// its message is the first refusal of config.hpp (spec sections 2.2 and 5.6).
#if defined(__EMSCRIPTEN__)
#error \
    "webcpp::hash: OpenSSL is not built for Emscripten. In the program's Jamfile, remove /webcpp/hash//openssl: hkdf and pbkdf2 then run on backends::hash2."
#endif
#endif  // WEBCPP_HASH_SRC_OPENSSL_ON_EMSCRIPTEN_HPP
