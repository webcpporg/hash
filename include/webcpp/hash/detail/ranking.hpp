// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Provisional: until tools/hash/measure.py generates this file from webcpp's measurements (spec
// section 4.2), it encodes increment 1's rule. Natively OpenSSL leads by throughput, so that a
// program that links it keeps OpenSSL's HKDF and PBKDF2 by default, and backends::hash2 leads by
// size; on WebAssembly backends::hash2 leads both orders.

#ifndef WEBCPP_HASH_DETAIL_RANKING_HPP
#define WEBCPP_HASH_DETAIL_RANKING_HPP

#include <webcpp/hash/config.hpp>

namespace webcpp::hash::detail {

/**
 An ordered list of backends, the first preferred.

 @tparam B The backends, tags of `backends`.
*/
template <class... B>
struct backend_list {};

/**
 The backends of the portable profile, in its order: those present on every target (spec 4.1).
 `backends::xkcp` and `backends::blake3` join it, after hash2, when a later increment declares
 them.
*/
using portable_order = backend_list<backends::hash2, backends::sodium, backends::bearssl>;

#ifdef WEBCPP_TARGET_WASIP2

/** The orders of an algorithm's backends on this target, as on the native target. */
template <class Algorithm, class Hmac>
struct ranking {
    /** The smallest program first. */
    using by_size =
        backend_list<backends::hash2, backends::sodium, backends::bearssl, backends::openssl>;
    /** The fastest first. */
    using by_throughput =
        backend_list<backends::hash2, backends::sodium, backends::bearssl, backends::openssl>;
};

#elif defined(WEBCPP_TARGET_WASIP3)

/** The orders of an algorithm's backends on this target, as on the native target. */
template <class Algorithm, class Hmac>
struct ranking {
    /** The smallest program first. */
    using by_size =
        backend_list<backends::hash2, backends::sodium, backends::bearssl, backends::openssl>;
    /** The fastest first. */
    using by_throughput =
        backend_list<backends::hash2, backends::sodium, backends::bearssl, backends::openssl>;
};

#elif defined(WEBCPP_TARGET_EMSCRIPTEN)

/** The orders of an algorithm's backends on this target, as on the native target. */
template <class Algorithm, class Hmac>
struct ranking {
    /** The smallest program first. */
    using by_size =
        backend_list<backends::hash2, backends::sodium, backends::bearssl, backends::openssl>;
    /** The fastest first. */
    using by_throughput =
        backend_list<backends::hash2, backends::sodium, backends::bearssl, backends::openssl>;
};

#else  // native

/**
 The measured orders of the backends of an algorithm on this target (spec 4.2): `by_size`, the
 smallest program first, and `by_throughput`, the fastest first.

 @tparam Algorithm The algorithm's tag, as `kdfs::hkdf`. @tparam Hmac The hmac of a key
 derivation.
*/
template <class Algorithm, class Hmac>
struct ranking {
    /** The smallest program first. */
    using by_size =
        backend_list<backends::hash2, backends::sodium, backends::bearssl, backends::openssl>;
    /** The fastest first. */
    using by_throughput =
        backend_list<backends::openssl, backends::hash2, backends::sodium, backends::bearssl>;
};

#endif

}  // namespace webcpp::hash::detail

#endif  // WEBCPP_HASH_DETAIL_RANKING_HPP
