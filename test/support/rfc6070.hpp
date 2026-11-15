// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// PBKDF2's published cases: RFC 6070's six (HMAC-SHA-1) and RFC 7914 section 11's two
// (HMAC-SHA-256), the password and salt as the RFCs spell them in ASCII ("\0" a NUL octet), the
// derived key a hex string. Checked twice: parsed from the RFCs' text, and recomputed by Python's
// hashlib.pbkdf2_hmac (all but RFC 6070's case 4, which its own test checks); the stream's report
// records both.

#ifndef WEBCPP_TEST_HASH_SUPPORT_RFC6070_HPP
#define WEBCPP_TEST_HASH_SUPPORT_RFC6070_HPP

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace webcpp::test {

// One PBKDF2 case.
struct pbkdf2_case {
    std::string_view hash;  // "sha1" or "sha256"
    std::string_view password;
    std::string_view salt;
    std::uint64_t iterations;  // c
    std::size_t length;        // dkLen
    std::string_view derived_key;
};

// RFC 6070, section 2, the first case.
inline constexpr pbkdf2_case rfc6070_1{
    "sha1", "password", "salt", 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6"};

// RFC 6070, section 2, the second case.
inline constexpr pbkdf2_case rfc6070_2{
    "sha1", "password", "salt", 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"};

// RFC 6070, section 2, the third case.
inline constexpr pbkdf2_case rfc6070_3{
    "sha1", "password", "salt", 4096, 20, "4b007901b765489abead49d926f721d065a429c1"};

// RFC 6070, section 2, the fourth case: 16,777,216 iterations (pbkdf2_rfc6070_long_test.cpp).
inline constexpr pbkdf2_case rfc6070_4{
    "sha1", "password", "salt", 16777216, 20, "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984"};

// RFC 6070, section 2, the fifth case.
inline constexpr pbkdf2_case rfc6070_5{"sha1",
                                       "passwordPASSWORDpassword",
                                       "saltSALTsaltSALTsaltSALTsaltSALTsalt",
                                       4096,
                                       25,
                                       "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"};

// RFC 6070, section 2, the sixth case: a NUL octet inside the password and the salt.
inline constexpr pbkdf2_case rfc6070_6{
    "sha1", std::string_view("pass\0word", 9), std::string_view("sa\0lt", 5), 4096,
    16,     "56fa6aa75548099dcc37d7f03425e0c3"};

// RFC 7914, section 11, the first case.
inline constexpr pbkdf2_case rfc7914_1{
    "sha256",
    "passwd",
    "salt",
    1,
    64,
    "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
    "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"};

// RFC 7914, section 11, the second case.
inline constexpr pbkdf2_case rfc7914_2{
    "sha256",
    "Password",
    "NaCl",
    80000,
    64,
    "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
    "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"};

}  // namespace webcpp::test

#endif  // WEBCPP_TEST_HASH_SUPPORT_RFC6070_HPP
