// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// RFC 9861's TurboSHAKE test vectors (section 5), each as the RFC prints it, its hex joined: the
// message is ptn(n), the pattern 00 01 .. FA repeated and cut to n bytes, or the bytes written;
// the output, of `length` bytes, is compared from byte `offset` on (the RFC prints the last 32
// bytes of its 10,032-byte outputs). Checked twice: parsed from the RFC's text, and recomputed by
// an independent Python TurboSHAKE over Keccak-p[1600, 12] (the stream's report records both).
// KangarooTwelve's vectors of the same section are increment 3's.

#ifndef WEBCPP_TEST_HASH_SUPPORT_RFC9861_TURBOSHAKE_HPP
#define WEBCPP_TEST_HASH_SUPPORT_RFC9861_TURBOSHAKE_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace webcpp::test {

// One TurboSHAKE vector of RFC 9861, section 5.
struct rfc9861_turboshake_case {
    unsigned variant;            // 128 or 256
    bool pattern;                // the message is ptn(pattern_length)
    std::size_t pattern_length;  // n of ptn(n)
    std::string_view message;    // the message's hex, when it is not a pattern
    std::uint8_t domain;         // D
    std::size_t length;          // the output's bytes
    std::size_t offset;          // the first byte of the output the RFC prints
    std::string_view expected;   // the bytes printed, from offset on
};

// ptn(n)'s byte at index i: the pattern 00 01 .. FA, 251 bytes, repeated.
constexpr std::uint8_t rfc9861_pattern_byte(std::size_t index) {
    return static_cast<std::uint8_t>(index % 251);
}

// The vectors, in the RFC's order.
inline constexpr std::array<rfc9861_turboshake_case, 31> rfc9861_turboshake =
    std::to_array<rfc9861_turboshake_case>({
        // TurboSHAKE128(M=the empty message, D=1F, 32).
        {
            .variant = 128,
            .pattern = false,
            .pattern_length = 0,
            .message = "",
            .domain = 0x1F,
            .length = 32,
            .offset = 0,
            .expected = "1e415f1c5983aff2169217277d17bb538cd945a397ddec541f1ce41af2c1b74c",
        },
        // TurboSHAKE128(M=the empty message, D=1F, 64).
        {
            .variant = 128,
            .pattern = false,
            .pattern_length = 0,
            .message = "",
            .domain = 0x1F,
            .length = 64,
            .offset = 0,
            .expected = "1e415f1c5983aff2169217277d17bb538cd945a397ddec541f1ce41af2c1b74c"
                        "3e8ccae2a4dae56c84a04c2385c03c15e8193bdf58737363321691c05462c8df",
        },
        // TurboSHAKE128(M=the empty message, D=1F, 10032), the last 32 bytes.
        {
            .variant = 128,
            .pattern = false,
            .pattern_length = 0,
            .message = "",
            .domain = 0x1F,
            .length = 10032,
            .offset = 10000,
            .expected = "a3b9b0385900ce761f22aed548e754da10a5242d62e8c658e3f3a923a7555607",
        },
        // TurboSHAKE128(M=ptn(17**0), D=1F, 32).
        {
            .variant = 128,
            .pattern = true,
            .pattern_length = 1,
            .message = "",
            .domain = 0x1F,
            .length = 32,
            .offset = 0,
            .expected = "55cedd6f60af7bb29a4042ae832ef3f58db7299f893ebb9247247d856958daa9",
        },
        // TurboSHAKE128(M=ptn(17**1), D=1F, 32).
        {
            .variant = 128,
            .pattern = true,
            .pattern_length = 17,
            .message = "",
            .domain = 0x1F,
            .length = 32,
            .offset = 0,
            .expected = "9c97d036a3bac819db70ede0ca554ec6e4c2a1a4ffbfd9ec269ca6a111161233",
        },
        // TurboSHAKE128(M=ptn(17**2), D=1F, 32).
        {
            .variant = 128,
            .pattern = true,
            .pattern_length = 289,
            .message = "",
            .domain = 0x1F,
            .length = 32,
            .offset = 0,
            .expected = "96c77c279e0126f7fc07c9b07f5cdae1e0be60bdbe10620040e75d7223a624d2",
        },
        // TurboSHAKE128(M=ptn(17**3), D=1F, 32).
        {
            .variant = 128,
            .pattern = true,
            .pattern_length = 4913,
            .message = "",
            .domain = 0x1F,
            .length = 32,
            .offset = 0,
            .expected = "d4976eb56bcf118520582b709f73e1d6853e001fdaf80e1b13e0d0599d5fb372",
        },
        // TurboSHAKE128(M=ptn(17**4), D=1F, 32).
        {
            .variant = 128,
            .pattern = true,
            .pattern_length = 83521,
            .message = "",
            .domain = 0x1F,
            .length = 32,
            .offset = 0,
            .expected = "da67c7039e98bf530cf7a37830c6664e14cbab7f540f58403b1b82951318ee5c",
        },
        // TurboSHAKE128(M=ptn(17**5), D=1F, 32).
        {
            .variant = 128,
            .pattern = true,
            .pattern_length = 1419857,
            .message = "",
            .domain = 0x1F,
            .length = 32,
            .offset = 0,
            .expected = "b97a906fbf83ef7c812517abf3b2d0aea0c4f60318ce11cf103925127f59eecd",
        },
        // TurboSHAKE128(M=ptn(17**6), D=1F, 32).
        {
            .variant = 128,
            .pattern = true,
            .pattern_length = 24137569,
            .message = "",
            .domain = 0x1F,
            .length = 32,
            .offset = 0,
            .expected = "35cd494adeded2f25239af09a7b8ef0c4d1ca4fe2d1ac370fa63216fe7b4c2b1",
        },
        // TurboSHAKE128(M=FF FF FF, D=01, 32).
        {
            .variant = 128,
            .pattern = false,
            .pattern_length = 0,
            .message = "ffffff",
            .domain = 0x01,
            .length = 32,
            .offset = 0,
            .expected = "bf323f940494e88ee1c540fe660be8a0c93f43d15ec006998462fa994eed5dab",
        },
        // TurboSHAKE128(M=FF, D=06, 32).
        {
            .variant = 128,
            .pattern = false,
            .pattern_length = 0,
            .message = "ff",
            .domain = 0x06,
            .length = 32,
            .offset = 0,
            .expected = "8ec9c66465ed0d4a6c35d13506718d687a25cb05c74cca1e42501abd83874a67",
        },
        // TurboSHAKE128(M=FF FF FF, D=07, 32).
        {
            .variant = 128,
            .pattern = false,
            .pattern_length = 0,
            .message = "ffffff",
            .domain = 0x07,
            .length = 32,
            .offset = 0,
            .expected = "b658576001cad9b1e5f399a9f77723bba05458042d68206f7252682dba3663ed",
        },
        // TurboSHAKE128(M=FF FF FF FF FF FF FF, D=0B, 32).
        {
            .variant = 128,
            .pattern = false,
            .pattern_length = 0,
            .message = "ffffffffffffff",
            .domain = 0x0B,
            .length = 32,
            .offset = 0,
            .expected = "8deeaa1aec47ccee569f659c21dfa8e112db3cee37b18178b2acd805b799cc37",
        },
        // TurboSHAKE128(M=FF, D=30, 32).
        {
            .variant = 128,
            .pattern = false,
            .pattern_length = 0,
            .message = "ff",
            .domain = 0x30,
            .length = 32,
            .offset = 0,
            .expected = "553122e2135e363c3292bed2c6421fa232bab03daa07c7d6636603286506325b",
        },
        // TurboSHAKE128(M=FF FF FF, D=7F, 32).
        {
            .variant = 128,
            .pattern = false,
            .pattern_length = 0,
            .message = "ffffff",
            .domain = 0x7F,
            .length = 32,
            .offset = 0,
            .expected = "16274cc656d44cefd422395d0f9053bda6d28e122aba15c765e5ad0e6eaf26f9",
        },
        // TurboSHAKE256(M=the empty message, D=1F, 64).
        {
            .variant = 256,
            .pattern = false,
            .pattern_length = 0,
            .message = "",
            .domain = 0x1F,
            .length = 64,
            .offset = 0,
            .expected = "367a329dafea871c7802ec67f905ae13c57695dc2c6663c61035f59a18f8e7db"
                        "11edc0e12e91ea60eb6b32df06dd7f002fbafabb6e13ec1cc20d995547600db0",
        },
        // TurboSHAKE256(M=the empty message, D=1F, 10032), the last 32 bytes.
        {
            .variant = 256,
            .pattern = false,
            .pattern_length = 0,
            .message = "",
            .domain = 0x1F,
            .length = 10032,
            .offset = 10000,
            .expected = "abefa11630c661269249742685ec082f207265dccf2f43534e9c61ba0c9d1d75",
        },
        // TurboSHAKE256(M=ptn(17**0), D=1F, 64).
        {
            .variant = 256,
            .pattern = true,
            .pattern_length = 1,
            .message = "",
            .domain = 0x1F,
            .length = 64,
            .offset = 0,
            .expected = "3e1712f928f8eaf1054632b2aa0a246ed8b0c378728f60bc970410155c28820e"
                        "90cc90d8a3006aa2372c5c5ea176b0682bf22bae7467ac94f74d43d39b0482e2",
        },
        // TurboSHAKE256(M=ptn(17**1), D=1F, 64).
        {
            .variant = 256,
            .pattern = true,
            .pattern_length = 17,
            .message = "",
            .domain = 0x1F,
            .length = 64,
            .offset = 0,
            .expected = "b3bab0300e6a191fbe6137939835923578794ea54843f5011090fa2f3780a9e5"
                        "cb22c59d78b40a0fbff9e672c0fbe0970bd2c845091c6044d687054da5d8e9c7",
        },
        // TurboSHAKE256(M=ptn(17**2), D=1F, 64).
        {
            .variant = 256,
            .pattern = true,
            .pattern_length = 289,
            .message = "",
            .domain = 0x1F,
            .length = 64,
            .offset = 0,
            .expected = "66b810db8e90780424c0847372fdc95710882fde31c6df75beb9d4cd9305cfca"
                        "e35e7b83e8b7e6eb4b78605880116316fe2c078a09b94ad7b8213c0a738b65c0",
        },
        // TurboSHAKE256(M=ptn(17**3), D=1F, 64).
        {
            .variant = 256,
            .pattern = true,
            .pattern_length = 4913,
            .message = "",
            .domain = 0x1F,
            .length = 64,
            .offset = 0,
            .expected = "c74ebc919a5b3b0dd1228185ba02d29ef442d69d3d4276a93efe0bf9a16a7dc0"
                        "cd4eabadab8cd7a5edd96695f5d360abe09e2c6511a3ec397da3b76b9e1674fb",
        },
        // TurboSHAKE256(M=ptn(17**4), D=1F, 64).
        {
            .variant = 256,
            .pattern = true,
            .pattern_length = 83521,
            .message = "",
            .domain = 0x1F,
            .length = 64,
            .offset = 0,
            .expected = "02cc3a8897e6f4f6ccb6fd46631b1f5207b66c6de9c7b55b2d1a23134a170afd"
                        "ac234eaba9a77cff88c1f020b73724618c5687b362c430b248cd38647f848a1d",
        },
        // TurboSHAKE256(M=ptn(17**5), D=1F, 64).
        {
            .variant = 256,
            .pattern = true,
            .pattern_length = 1419857,
            .message = "",
            .domain = 0x1F,
            .length = 64,
            .offset = 0,
            .expected = "add53b06543e584b5823f626996aee50fe45ed15f20243a7165485acb4aa76b4"
                        "ffda75cedf6d8cdc95c332bd56f4b986b58bb17d1778bfc1b1a97545cdf4ec9f",
        },
        // TurboSHAKE256(M=ptn(17**6), D=1F, 64).
        {
            .variant = 256,
            .pattern = true,
            .pattern_length = 24137569,
            .message = "",
            .domain = 0x1F,
            .length = 64,
            .offset = 0,
            .expected = "9e11bc59c24e73993c1484ec66358ef71db74aefd84e123f7800ba9c4853e02c"
                        "fe701d9e6bb765a304f0dc34a4ee3ba82c410f0da70e86bfbd90ea877c2d6104",
        },
        // TurboSHAKE256(M=FF FF FF, D=01, 64).
        {
            .variant = 256,
            .pattern = false,
            .pattern_length = 0,
            .message = "ffffff",
            .domain = 0x01,
            .length = 64,
            .offset = 0,
            .expected = "d21c6fbbf587fa2282f29aea620175fb0257413af78a0b1b2a87419ce031d933"
                        "ae7a4d383327a8a17641a34f8a1d1003ad7da6b72dba84bb62fef28f62f12424",
        },
        // TurboSHAKE256(M=FF, D=06, 64).
        {
            .variant = 256,
            .pattern = false,
            .pattern_length = 0,
            .message = "ff",
            .domain = 0x06,
            .length = 64,
            .offset = 0,
            .expected = "738d7b4e37d18b7f22ad1b5313e357e3dd7d07056a26a303c433fa3533455280"
                        "f4f5a7d4f700efb437fe6d281405e07be32a0a972e22e63adc1b090daefe004b",
        },
        // TurboSHAKE256(M=FF FF FF, D=07, 64).
        {
            .variant = 256,
            .pattern = false,
            .pattern_length = 0,
            .message = "ffffff",
            .domain = 0x07,
            .length = 64,
            .offset = 0,
            .expected = "18b3b5b7061c2e67c1753a00e6ad7ed7ba1c906cf93efb7092eaf27fbeebb755"
                        "ae6e292493c110e48d260028492b8e09b5500612b8f2578985ded5357d00ec67",
        },
        // TurboSHAKE256(M=FF FF FF FF FF FF FF, D=0B, 64).
        {
            .variant = 256,
            .pattern = false,
            .pattern_length = 0,
            .message = "ffffffffffffff",
            .domain = 0x0B,
            .length = 64,
            .offset = 0,
            .expected = "bb36764951ec97e9d85f7ee9a67a7718fc005cf42556be79ce12c0bde50e5736"
                        "d6632b0d0dfb202d1bbb8ffe3dd74cb00834fa756cb03471bab13a1e2c16b3c0",
        },
        // TurboSHAKE256(M=FF, D=30, 64).
        {
            .variant = 256,
            .pattern = false,
            .pattern_length = 0,
            .message = "ff",
            .domain = 0x30,
            .length = 64,
            .offset = 0,
            .expected = "f3fe12873d34bcbb2e608779d6b70e7f86bec7e90bf113cbd4fdd0c4e2f4625e"
                        "148dd7ee1a52776cf77f240514d9ccfc3b5ddab8ee255e39ee389072962c111a",
        },
        // TurboSHAKE256(M=FF FF FF, D=7F, 64).
        {
            .variant = 256,
            .pattern = false,
            .pattern_length = 0,
            .message = "ffffff",
            .domain = 0x7F,
            .length = 64,
            .offset = 0,
            .expected = "abe569c1f77ec340f02705e7d37c9ab7e155516e4a6a150021d70b6fac0bb40c"
                        "069f9a9828a0d575cd99f9bae435ab1acf7ed9110ba97ce0388d074bac768776",
        },
    });

}  // namespace webcpp::test

#endif  // WEBCPP_TEST_HASH_SUPPORT_RFC9861_TURBOSHAKE_HPP
