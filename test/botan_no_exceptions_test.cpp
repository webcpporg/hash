// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Under WEBCPP_HASH_NO_EXCEPTIONS backends/botan.hpp declares nothing (ruling P4): compiled with
// /third_party//botan linked (exceptions on, which the library needs) and the developer's
// WEBCPP_HASH_NO_EXCEPTIONS, the header includes no Botan header and backends::botan has no
// cell, so that a call on it stops with the text "needs exceptions" (test/messages/
// botan_without_exceptions).

#include <webcpp/hash/backends/botan.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/hash/mac.hpp>

#ifndef WEBCPP_HASH_NO_EXCEPTIONS
#error "the test's Jamfile defines WEBCPP_HASH_NO_EXCEPTIONS"
#endif
#ifndef WEBCPP_HASH_HAS_BOTAN
#error "the test's Jamfile links /third_party//botan, which defines WEBCPP_HASH_HAS_BOTAN"
#endif
#ifdef WEBCPP_HASH_BACKENDS_BOTAN_HPP
#ifdef WEBCPP_HASH_DETAIL_BOTAN_CANARY
#error "backends/botan.hpp declared its canary without exceptions"
#endif
#endif

namespace hash = webcpp::hash;

static_assert(!hash::backend_has_v<hash::backends::botan, hash::digests::sha2_256, void>);
static_assert(!hash::backend_has_v<hash::backends::botan, hash::digests::whirlpool, void>);
static_assert(
    !hash::backend_has_v<hash::backends::botan, hash::macs::hmac<hash::digests::sha2_256>, void>);
static_assert(hash::detail::missing_library_v<hash::backends::botan>);

int main() {
    return 0;
}
