// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// RFC 7914, section 12: scrypt's four test vectors, copied from the RFC's text. The password and
// salt are ASCII; the output is 64 bytes.

#ifndef WEBCPP_TEST_HASH_SUPPORT_RFC7914_HPP
#define WEBCPP_TEST_HASH_SUPPORT_RFC7914_HPP

#include <array>
#include <cstdint>
#include <span>
#include <string_view>

namespace webcpp::test {

struct rfc7914_case {
    std::string_view password;
    std::string_view salt;
    std::uint64_t n;
    std::uint32_t r;
    std::uint32_t p;
    std::string_view output;
};

// The first three, cheap enough for every target (the third takes 16 MiB).
inline constexpr std::array rfc7914_cases{
    rfc7914_case{
        .password = "",
        .salt = "",
        .n = 16,
        .r = 1,
        .p = 1,
        .output = "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
                  "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
    },
    rfc7914_case{
        .password = "password",
        .salt = "NaCl",
        .n = 1024,
        .r = 8,
        .p = 16,
        .output = "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162"
                  "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
    },
    rfc7914_case{
        .password = "pleaseletmein",
        .salt = "SodiumChloride",
        .n = 16384,
        .r = 8,
        .p = 1,
        .output = "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2"
                  "d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887",
    },
};

// An ASCII text's bytes, as scrypt takes them: the span points at the text, never null.
inline std::span<std::uint8_t const> bytes_of(std::string_view text) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): ASCII characters as bytes
    return {reinterpret_cast<std::uint8_t const*>(text.data()), text.size()};
}

// The fourth: N = 1,048,576 and r = 8, 1 GiB of memory.
inline constexpr rfc7914_case rfc7914_large{
    .password = "pleaseletmein",
    .salt = "SodiumChloride",
    .n = 1048576,
    .r = 8,
    .p = 1,
    .output =
        "2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa47"
        "8e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4",
};

}  // namespace webcpp::test

#endif  // WEBCPP_TEST_HASH_SUPPORT_RFC7914_HPP
