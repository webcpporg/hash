// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// RFC 5869's seven test cases (appendix A), each field a hex string as the RFC prints it, joined.
// Checked twice: parsed from the RFC's text, and recomputed by Python's hmac (the stream's
// report records both). A.7's salt is "not provided", which an empty salt means (RFC 5869,
// section 2.2: HashLen zeros).

#ifndef WEBCPP_TEST_HASH_SUPPORT_RFC5869_HPP
#define WEBCPP_TEST_HASH_SUPPORT_RFC5869_HPP

#include <cstddef>
#include <string_view>

namespace webcpp::test {

// One case of RFC 5869's appendix A.
struct rfc5869_case {
    std::string_view hash;  // "sha256" or "sha1"
    std::string_view ikm;
    std::string_view salt;
    std::string_view info;
    std::size_t length;  // L, the output's octets
    std::string_view prk;
    std::string_view okm;
};

// RFC 5869, A.1: basic test case with SHA-256.
inline constexpr rfc5869_case a1{"sha256",
                                 "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                                 "000102030405060708090a0b0c",
                                 "f0f1f2f3f4f5f6f7f8f9",
                                 42,
                                 "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                                 "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                                 "34007208d5b887185865"};

// RFC 5869, A.2: test with SHA-256 and longer inputs/outputs.
inline constexpr rfc5869_case a2{"sha256",
                                 "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                                 "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                                 "404142434445464748494a4b4c4d4e4f",
                                 "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
                                 "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
                                 "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                                 "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                                 "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                                 "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                                 82,
                                 "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
                                 "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
                                 "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
                                 "cc30c58179ec3e87c14c01d5c1f3434f1d87"};

// RFC 5869, A.3: test with SHA-256 and zero-length salt/info.
inline constexpr rfc5869_case a3{"sha256",
                                 "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                                 "",
                                 "",
                                 42,
                                 "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
                                 "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
                                 "9d201395faa4b61a96c8"};

// RFC 5869, A.4: basic test case with SHA-1.
inline constexpr rfc5869_case a4{"sha1",
                                 "0b0b0b0b0b0b0b0b0b0b0b",
                                 "000102030405060708090a0b0c",
                                 "f0f1f2f3f4f5f6f7f8f9",
                                 42,
                                 "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243",
                                 "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2"
                                 "c22e422478d305f3f896"};

// RFC 5869, A.5: test with SHA-1 and longer inputs/outputs.
inline constexpr rfc5869_case a5{"sha1",
                                 "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                                 "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                                 "404142434445464748494a4b4c4d4e4f",
                                 "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
                                 "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
                                 "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                                 "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                                 "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                                 "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                                 82,
                                 "8adae09a2a307059478d309b26c4115a224cfaf6",
                                 "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe"
                                 "8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e"
                                 "927336d0441f4c4300e2cff0d0900b52d3b4"};

// RFC 5869, A.6: test with SHA-1 and zero-length salt/info.
inline constexpr rfc5869_case a6{"sha1",
                                 "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                                 "",
                                 "",
                                 42,
                                 "da8c8a73c7fa77288ec6f5e7c297786aa0d32d01",
                                 "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0"
                                 "ea00033de03984d34918"};

// RFC 5869, A.7: test with SHA-1, salt not provided (defaults to HashLen zero octets), zero-length
// info.
inline constexpr rfc5869_case a7{"sha1",
                                 "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
                                 "",
                                 "",
                                 42,
                                 "2adccada18779e7c2077ad2eb19d3f3e731385dd",
                                 "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5"
                                 "673a081d70cce7acfc48"};

}  // namespace webcpp::test

#endif  // WEBCPP_TEST_HASH_SUPPORT_RFC5869_HPP
