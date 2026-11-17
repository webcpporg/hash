// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// RFC 2202's seven test cases of HMAC-MD5 (section 2) and HMAC-SHA-1 (section 3), each field a hex
// string as the RFC prints it, joined; the text inputs written in hex. Checked twice: against the
// RFC's text, and recomputed by Python's hmac (the stream's report records both). Case 5 is
// checked as the RFC's "digest-96", the HMAC truncated to 12 octets.

#ifndef WEBCPP_TEST_HASH_SUPPORT_RFC2202_HPP
#define WEBCPP_TEST_HASH_SUPPORT_RFC2202_HPP

#include <array>
#include <cstddef>
#include <string_view>

namespace webcpp::test {

// One case of RFC 2202: the key, the data, the tag's octets and the tag.
struct rfc2202_case {
    std::string_view key;
    std::string_view data;
    std::size_t length;
    std::string_view mac;
};

// RFC 2202, section 2: HMAC-MD5's test cases 1 to 7.
inline constexpr std::array<rfc2202_case, 7> rfc2202_md5_cases{
    {
        // test_case 1.
        {
            .key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            .data = "4869205468657265",
            .length = 16,
            .mac = "9294727a3638bb1c13f48ef8158bfc9d",
        },
        // test_case 2.
        {
            .key = "4a656665",
            .data = "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
            .length = 16,
            .mac = "750c783e6ab0b503eaa86e310a5db738",
        },
        // test_case 3.
        {
            .key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            .data = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                    "dddddddddddddddddddddddddddddddddddd",
            .length = 16,
            .mac = "56be34521d144c88dbb8c733f0e8b3f6",
        },
        // test_case 4.
        {
            .key = "0102030405060708090a0b0c0d0e0f10111213141516171819",
            .data = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
                    "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            .length = 16,
            .mac = "697eaf0aca3a3aea3a75164746ffaa79",
        },
        // test_case 5.
        {
            .key = "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            .data = "546573742057697468205472756e636174696f6e",
            .length = 12,
            .mac = "56461ef2342edc00f9bab995",
        },
        // test_case 6.
        {
            .key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            .data = "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a"
                    "65204b6579202d2048617368204b6579204669727374",
            .length = 16,
            .mac = "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd",
        },
        // test_case 7.
        {
            .key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            .data = "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a"
                    "65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d"
                    "53697a652044617461",
            .length = 16,
            .mac = "6f630fad67cda0ee1fb1f562db3aa53e",
        },
    },
};

// RFC 2202, section 3: HMAC-SHA-1's test cases 1 to 7.
inline constexpr std::array<rfc2202_case, 7> rfc2202_sha1_cases{
    {
        // test_case 1.
        {
            .key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            .data = "4869205468657265",
            .length = 20,
            .mac = "b617318655057264e28bc0b6fb378c8ef146be00",
        },
        // test_case 2.
        {
            .key = "4a656665",
            .data = "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
            .length = 20,
            .mac = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
        },
        // test_case 3.
        {
            .key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            .data = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                    "dddddddddddddddddddddddddddddddddddd",
            .length = 20,
            .mac = "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
        },
        // test_case 4.
        {
            .key = "0102030405060708090a0b0c0d0e0f10111213141516171819",
            .data = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
                    "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            .length = 20,
            .mac = "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
        },
        // test_case 5.
        {
            .key = "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            .data = "546573742057697468205472756e636174696f6e",
            .length = 12,
            .mac = "4c1a03424b55e07fe7f27be1",
        },
        // test_case 6.
        {
            .key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            .data = "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a"
                    "65204b6579202d2048617368204b6579204669727374",
            .length = 20,
            .mac = "aa4ae5e15272d00e95705637ce8a3b55ed402112",
        },
        // test_case 7.
        {
            .key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            .data = "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a"
                    "65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d"
                    "53697a652044617461",
            .length = 20,
            .mac = "e8e99d0f45237d786d6bbaa7965c7808bbff1a91",
        },
    },
};

}  // namespace webcpp::test

#endif  // WEBCPP_TEST_HASH_SUPPORT_RFC2202_HPP
