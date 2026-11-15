// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The backends each agreement test must compare, written out from spec section 3.2's table and the
// Jamfile's links (sodium and BearSSL everywhere, OpenSSL on every target but Emscripten), and not
// read from the traits the test also uses to pick them: a library lost from a Jamfile line, or a
// trait that goes false, then fails the test instead of shrinking the comparison.

#ifndef WEBCPP_TEST_HASH_SUPPORT_AGREEMENT_EXPECT_HPP
#define WEBCPP_TEST_HASH_SUPPORT_AGREEMENT_EXPECT_HPP

#include <webcpp/hash/hmac.hpp>

#include <string>
#include <type_traits>

namespace webcpp::test {

namespace expect_detail {

template <class Hmac, class... Hmacs>
inline constexpr bool one_of = (std::is_same_v<Hmac, Hmacs> || ...);

namespace h = webcpp::hash;

// libsodium's HKDF: SHA-256 and SHA-512.
template <class Hmac>
inline constexpr bool sodium_hkdf = one_of<Hmac, h::hmac_sha2_256, h::hmac_sha2_512>;

// BearSSL's hkdf: MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512.
template <class Hmac>
inline constexpr bool bearssl_hkdf =
    one_of<Hmac, h::hmac_md5_128, h::hmac_sha1_160, h::hmac_sha2_224, h::hmac_sha2_256,
           h::hmac_sha2_384, h::hmac_sha2_512>;

// OpenSSL's HKDF and PBKDF2: every hmac but RIPEMD-128, where webcpp builds OpenSSL.
template <class Hmac>
inline constexpr bool openssl_has =
#ifdef WEBCPP_TARGET_EMSCRIPTEN
    false;
#else
    !std::is_same_v<Hmac, h::hmac_ripemd_128>;
#endif

}  // namespace expect_detail

// The names, in the tests' order, of the backends that compare HKDF over Hmac on this target.
template <class Hmac>
std::string expected_hkdf_backends() {
    std::string names = "hash2";
    if (expect_detail::sodium_hkdf<Hmac>) {
        names += ",sodium";
    }
    if (expect_detail::bearssl_hkdf<Hmac>) {
        names += ",bearssl";
    }
    if (expect_detail::openssl_has<Hmac>) {
        names += ",openssl";
    }
    return names;
}

// The same for PBKDF2: hash2, and OpenSSL where webcpp builds it (on Emscripten, hash2 alone).
template <class Hmac>
std::string expected_pbkdf2_backends() {
    std::string names = "hash2";
    if (expect_detail::openssl_has<Hmac>) {
        names += ",openssl";
    }
    return names;
}

}  // namespace webcpp::test

#endif  // WEBCPP_TEST_HASH_SUPPORT_AGREEMENT_EXPECT_HPP
