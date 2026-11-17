// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// RFC 4231's seven HMAC test cases (section 4), the key, the data and the HMAC-SHA-256 and
// HMAC-SHA-512 tags, each a hex string as the RFC prints it, joined; test case 5's tags are cut to
// 128 bits, as the RFC prints them. Checked twice: parsed from the RFC's text, and recomputed by
// Python's hmac (the stream's report records both).

#ifndef WEBCPP_TEST_HASH_SUPPORT_RFC4231_HPP
#define WEBCPP_TEST_HASH_SUPPORT_RFC4231_HPP

#include <array>
#include <string_view>

namespace webcpp::test {

// One test case of RFC 4231, section 4.
struct rfc4231_case {
    unsigned number;
    std::string_view key;
    std::string_view data;
    std::string_view sha2_256;
    std::string_view sha2_512;
};

// The test cases 1 to 7 (sections 4.2 to 4.8).
inline constexpr std::array<rfc4231_case, 7> rfc4231 = std::to_array<rfc4231_case>({
    // RFC 4231, section 4.2: test case 1.
    {
        .number = 1,
        .key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        .data = "4869205468657265",
        .sha2_256 = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        .sha2_512 = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
                    "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
    },
    // RFC 4231, section 4.3: test case 2.
    {
        .number = 2,
        .key = "4a656665",
        .data = "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
        .sha2_256 = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        .sha2_512 = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
                    "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
    },
    // RFC 4231, section 4.4: test case 3.
    {
        .number = 3,
        .key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        .data = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                "dddddddddddddddddddddddddddddddddddd",
        .sha2_256 = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        .sha2_512 = "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39"
                    "bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
    },
    // RFC 4231, section 4.5: test case 4.
    {
        .number = 4,
        .key = "0102030405060708090a0b0c0d0e0f10111213141516171819",
        .data = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
                "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        .sha2_256 = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
        .sha2_512 = "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db"
                    "a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
    },
    // RFC 4231, section 4.6: test case 5.
    {
        .number = 5,
        .key = "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
        .data = "546573742057697468205472756e636174696f6e",
        .sha2_256 = "a3b6167473100ee06e0c796c2955552b",
        .sha2_512 = "415fad6271580a531d4179bc891d87a6",
    },
    // RFC 4231, section 4.7: test case 6.
    {
        .number = 6,
        .key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
               "aaaaaa",
        .data = "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a"
                "65204b6579202d2048617368204b6579204669727374",
        .sha2_256 = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        .sha2_512 = "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352"
                    "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
    },
    // RFC 4231, section 4.8: test case 7.
    {
        .number = 7,
        .key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
               "aaaaaa",
        .data = "5468697320697320612074657374207573696e672061206c6172676572207468"
                "616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074"
                "68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565"
                "647320746f20626520686173686564206265666f7265206265696e6720757365"
                "642062792074686520484d414320616c676f726974686d2e",
        .sha2_256 = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
        .sha2_512 = "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944"
                    "b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
    },
});

}  // namespace webcpp::test

#endif  // WEBCPP_TEST_HASH_SUPPORT_RFC4231_HPP
