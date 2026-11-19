// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// RFC 9861's KangarooTwelve test vectors (section 5), each as the RFC prints it, its hex joined:
// the message is ptn(n), the pattern 00 01 .. FA repeated and cut to n bytes, or the bytes written;
// the customisation string C is ptn(n) (the empty string for n = 0); the output, of `length`
// bytes, is compared from byte `offset` on (the RFC prints the last bytes of its 10,032- and
// 10,064-byte outputs). Checked twice when written here: parsed from the RFC's text, and
// recomputed by an independent Python KT128 and KT256 over Keccak-p[1600, 12], written from the
// RFC's text, which also reproduces its 31 TurboSHAKE vectors (support/rfc9861_turboshake.hpp).

#ifndef WEBCPP_TEST_HASH_SUPPORT_RFC9861_KANGAROOTWELVE_HPP
#define WEBCPP_TEST_HASH_SUPPORT_RFC9861_KANGAROOTWELVE_HPP

#include <array>
#include <cstddef>
#include <string_view>

namespace webcpp::test {

// One KangarooTwelve vector of RFC 9861, section 5.
struct rfc9861_kangarootwelve_case {
    unsigned variant;                  // 128 or 256
    bool pattern;                      // the message is ptn(pattern_length)
    std::size_t pattern_length;        // n of the message's ptn(n)
    std::string_view message;          // the message's hex, when it is not a pattern
    std::size_t customisation_length;  // n of C's ptn(n), 0 for the empty string
    std::size_t length;                // the output's bytes
    std::size_t offset;                // the first byte of the output the RFC prints
    std::string_view expected;         // the bytes printed, from offset on
};

// The vectors, in the RFC's order: 18 of KT128, 18 of KT256.
inline constexpr std::array<rfc9861_kangarootwelve_case, 36> rfc9861_kangarootwelve =
    std::to_array<rfc9861_kangarootwelve_case>({
        // KT128(M=the empty message, C=the empty string, 32).
        {
            .variant = 128,
            .pattern = false,
            .pattern_length = 0,
            .message = "",
            .customisation_length = 0,
            .length = 32,
            .offset = 0,
            .expected = "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5",
        },
        // KT128(M=the empty message, C=the empty string, 64).
        {
            .variant = 128,
            .pattern = false,
            .pattern_length = 0,
            .message = "",
            .customisation_length = 0,
            .length = 64,
            .offset = 0,
            .expected = "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5"
                        "4269c056b8c82e48276038b6d292966cc07a3d4645272e31ff38508139eb0a71",
        },
        // KT128(M=the empty message, C=the empty string, 10032), the last 32 bytes.
        {
            .variant = 128,
            .pattern = false,
            .pattern_length = 0,
            .message = "",
            .customisation_length = 0,
            .length = 10032,
            .offset = 10000,
            .expected = "e8dc563642f7228c84684c898405d3a834799158c079b12880277a1d28e2ff6d",
        },
        // KT128(M=ptn(1), C=the empty string, 32).
        {
            .variant = 128,
            .pattern = true,
            .pattern_length = 1,
            .message = "",
            .customisation_length = 0,
            .length = 32,
            .offset = 0,
            .expected = "2bda92450e8b147f8a7cb629e784a058efca7cf7d8218e02d345dfaa65244a1f",
        },
        // KT128(M=ptn(17), C=the empty string, 32).
        {
            .variant = 128,
            .pattern = true,
            .pattern_length = 17,
            .message = "",
            .customisation_length = 0,
            .length = 32,
            .offset = 0,
            .expected = "6bf75fa2239198db4772e36478f8e19b0f371205f6a9a93a273f51df37122888",
        },
        // KT128(M=ptn(17**2), C=the empty string, 32).
        {
            .variant = 128,
            .pattern = true,
            .pattern_length = 289,
            .message = "",
            .customisation_length = 0,
            .length = 32,
            .offset = 0,
            .expected = "0c315ebcdedbf61426de7dcf8fb725d1e74675d7f5327a5067f367b108ecb67c",
        },
        // KT128(M=ptn(17**3), C=the empty string, 32).
        {
            .variant = 128,
            .pattern = true,
            .pattern_length = 4913,
            .message = "",
            .customisation_length = 0,
            .length = 32,
            .offset = 0,
            .expected = "cb552e2ec77d9910701d578b457ddf772c12e322e4ee7fe417f92c758f0d59d0",
        },
        // KT128(M=ptn(17**4), C=the empty string, 32).
        {
            .variant = 128,
            .pattern = true,
            .pattern_length = 83521,
            .message = "",
            .customisation_length = 0,
            .length = 32,
            .offset = 0,
            .expected = "8701045e22205345ff4dda05555cbb5c3af1a771c2b89baef37db43d9998b9fe",
        },
        // KT128(M=ptn(17**5), C=the empty string, 32).
        {
            .variant = 128,
            .pattern = true,
            .pattern_length = 1419857,
            .message = "",
            .customisation_length = 0,
            .length = 32,
            .offset = 0,
            .expected = "844d610933b1b9963cbdeb5ae3b6b05cc7cbd67ceedf883eb678a0a8e0371682",
        },
        // KT128(M=ptn(17**6), C=the empty string, 32).
        {
            .variant = 128,
            .pattern = true,
            .pattern_length = 24137569,
            .message = "",
            .customisation_length = 0,
            .length = 32,
            .offset = 0,
            .expected = "3c390782a8a4e89fa6367f72feaaf13255c8d95878481d3cd8ce85f58e880af8",
        },
        // KT128(M=the empty message, C=ptn(1), 32).
        {
            .variant = 128,
            .pattern = false,
            .pattern_length = 0,
            .message = "",
            .customisation_length = 1,
            .length = 32,
            .offset = 0,
            .expected = "fab658db63e94a246188bf7af69a133045f46ee984c56e3c3328caaf1aa1a583",
        },
        // KT128(M=FF, C=ptn(41), 32).
        {
            .variant = 128,
            .pattern = false,
            .pattern_length = 0,
            .message = "ff",
            .customisation_length = 41,
            .length = 32,
            .offset = 0,
            .expected = "d848c5068ced736f4462159b9867fd4c20b808acc3d5bc48e0b06ba0a3762ec4",
        },
        // KT128(M=FF FF FF, C=ptn(41**2), 32).
        {
            .variant = 128,
            .pattern = false,
            .pattern_length = 0,
            .message = "ffffff",
            .customisation_length = 1681,
            .length = 32,
            .offset = 0,
            .expected = "c389e5009ae57120854c2e8c64670ac01358cf4c1baf89447a724234dc7ced74",
        },
        // KT128(M=FF FF FF FF FF FF FF, C=ptn(41**3), 32).
        {
            .variant = 128,
            .pattern = false,
            .pattern_length = 0,
            .message = "ffffffffffffff",
            .customisation_length = 68921,
            .length = 32,
            .offset = 0,
            .expected = "75d2f86a2e644566726b4fbcfc5657b9dbcf070c7b0dca06450ab291d7443bcf",
        },
        // KT128(M=ptn(8191), C=the empty string, 32).
        {
            .variant = 128,
            .pattern = true,
            .pattern_length = 8191,
            .message = "",
            .customisation_length = 0,
            .length = 32,
            .offset = 0,
            .expected = "1b577636f723643e990cc7d6a659837436fd6a103626600eb8301cd1dbe553d6",
        },
        // KT128(M=ptn(8192), C=the empty string, 32).
        {
            .variant = 128,
            .pattern = true,
            .pattern_length = 8192,
            .message = "",
            .customisation_length = 0,
            .length = 32,
            .offset = 0,
            .expected = "48f256f6772f9edfb6a8b661ec92dc93b95ebd05a08a17b39ae3490870c926c3",
        },
        // KT128(M=ptn(8192), C=ptn(8189), 32).
        {
            .variant = 128,
            .pattern = true,
            .pattern_length = 8192,
            .message = "",
            .customisation_length = 8189,
            .length = 32,
            .offset = 0,
            .expected = "3ed12f70fb05ddb58689510ab3e4d23c6c6033849aa01e1d8c220a297fedcd0b",
        },
        // KT128(M=ptn(8192), C=ptn(8190), 32).
        {
            .variant = 128,
            .pattern = true,
            .pattern_length = 8192,
            .message = "",
            .customisation_length = 8190,
            .length = 32,
            .offset = 0,
            .expected = "6a7c1b6a5cd0d8c9ca943a4a216cc64604559a2ea45f78570a15253d67ba00ae",
        },
        // KT256(M=the empty message, C=the empty string, 64).
        {
            .variant = 256,
            .pattern = false,
            .pattern_length = 0,
            .message = "",
            .customisation_length = 0,
            .length = 64,
            .offset = 0,
            .expected = "b23d2e9cea9f4904e02bec06817fc10ce38ce8e93ef4c89e6537076af8646404"
                        "e3e8b68107b8833a5d30490aa33482353fd4adc7148ecb782855003aaebde4a9",
        },
        // KT256(M=the empty message, C=the empty string, 128).
        {
            .variant = 256,
            .pattern = false,
            .pattern_length = 0,
            .message = "",
            .customisation_length = 0,
            .length = 128,
            .offset = 0,
            .expected = "b23d2e9cea9f4904e02bec06817fc10ce38ce8e93ef4c89e6537076af8646404"
                        "e3e8b68107b8833a5d30490aa33482353fd4adc7148ecb782855003aaebde4a9"
                        "b0925319d8ea1e121a609821ec19efea89e6d08daee1662b69c840289f188ba8"
                        "60f55760b61f82114c030c97e5178449608ccd2cd2d919fc7829ff69931ac4d0",
        },
        // KT256(M=the empty message, C=the empty string, 10064), the last 64 bytes.
        {
            .variant = 256,
            .pattern = false,
            .pattern_length = 0,
            .message = "",
            .customisation_length = 0,
            .length = 10064,
            .offset = 10000,
            .expected = "ad4a1d718cf950506709a4c33396139b4449041fc79a05d68da35f1e453522e0"
                        "56c64fe94958e7085f2964888259b9932752f3ccd855288efee5fcbb8b563069",
        },
        // KT256(M=ptn(1), C=the empty string, 64).
        {
            .variant = 256,
            .pattern = true,
            .pattern_length = 1,
            .message = "",
            .customisation_length = 0,
            .length = 64,
            .offset = 0,
            .expected = "0d005a194085360217128cf17f91e1f71314efa5564539d444912e3437efa17f"
                        "82db6f6ffe76e781eaa068bce01f2bbf81eacb983d7230f2fb02834a21b1ddd0",
        },
        // KT256(M=ptn(17), C=the empty string, 64).
        {
            .variant = 256,
            .pattern = true,
            .pattern_length = 17,
            .message = "",
            .customisation_length = 0,
            .length = 64,
            .offset = 0,
            .expected = "1ba3c02b1fc514474f06c8979978a9056c8483f4a1b63d0dccefe3a28a2f323e"
                        "1cdcca40ebf006ac76ef0397152346837b1277d3e7faa9c9653b19075098527b",
        },
        // KT256(M=ptn(17**2), C=the empty string, 64).
        {
            .variant = 256,
            .pattern = true,
            .pattern_length = 289,
            .message = "",
            .customisation_length = 0,
            .length = 64,
            .offset = 0,
            .expected = "de8ccbc63e0f133ebb4416814d4c66f691bbf8b6a61ec0a7700f836b086cb029"
                        "d54f12ac7159472c72db118c35b4e6aa213c6562caaa9dcc518959e69b10f3ba",
        },
        // KT256(M=ptn(17**3), C=the empty string, 64).
        {
            .variant = 256,
            .pattern = true,
            .pattern_length = 4913,
            .message = "",
            .customisation_length = 0,
            .length = 64,
            .offset = 0,
            .expected = "647efb49fe9d717500171b41e7f11bd491544443209997ce1c2530d15eb1ffbb"
                        "598935ef954528ffc152b1e4d731ee2683680674365cd191d562bae753b84aa5",
        },
        // KT256(M=ptn(17**4), C=the empty string, 64).
        {
            .variant = 256,
            .pattern = true,
            .pattern_length = 83521,
            .message = "",
            .customisation_length = 0,
            .length = 64,
            .offset = 0,
            .expected = "b06275d284cd1cf205bcbe57dccd3ec1ff6686e3ed15776383e1f2fa3c6ac8f0"
                        "8bf8a162829db1a44b2a43ff83dd89c3cf1ceb61ede659766d5ccf817a62ba8d",
        },
        // KT256(M=ptn(17**5), C=the empty string, 64).
        {
            .variant = 256,
            .pattern = true,
            .pattern_length = 1419857,
            .message = "",
            .customisation_length = 0,
            .length = 64,
            .offset = 0,
            .expected = "9473831d76a4c7bf77ace45b59f1458b1673d64bcd877a7c66b2664aa6dd149e"
                        "60eab71b5c2bab858c074ded81ddce2b4022b5215935c0d4d19bf511aeeb0772",
        },
        // KT256(M=ptn(17**6), C=the empty string, 64).
        {
            .variant = 256,
            .pattern = true,
            .pattern_length = 24137569,
            .message = "",
            .customisation_length = 0,
            .length = 64,
            .offset = 0,
            .expected = "0652b740d78c5e1f7c8dcc1777097382768b7ff38f9a7a20f29f413bb1b3045b"
                        "31a5578f568f911e09cf44746da84224a5266e96a4a535e871324e4f9c7004da",
        },
        // KT256(M=the empty message, C=ptn(1), 64).
        {
            .variant = 256,
            .pattern = false,
            .pattern_length = 0,
            .message = "",
            .customisation_length = 1,
            .length = 64,
            .offset = 0,
            .expected = "9280f5cc39b54a5a594ec63de0bb99371e4609d44bf845c2f5b8c316d72b1598"
                        "11f748f23e3fabbe5c3226ec96c62186df2d33e9df74c5069ceecbb4dd10eff6",
        },
        // KT256(M=FF, C=ptn(41), 64).
        {
            .variant = 256,
            .pattern = false,
            .pattern_length = 0,
            .message = "ff",
            .customisation_length = 41,
            .length = 64,
            .offset = 0,
            .expected = "47ef96dd616f200937aa7847e34ec2feae8087e3761dc0f8c1a154f51dc9ccf8"
                        "45d7adbce57ff64b639722c6a1672e3bf5372d87e00aff89be97240756998853",
        },
        // KT256(M=FF FF FF, C=ptn(41**2), 64).
        {
            .variant = 256,
            .pattern = false,
            .pattern_length = 0,
            .message = "ffffff",
            .customisation_length = 1681,
            .length = 64,
            .offset = 0,
            .expected = "3b48667a5051c5966c53c5d42b95de451e05584e7806e2fb765eda959074172c"
                        "b438a9e91dde337c98e9c41bed94c4e0aef431d0b64ef2324f7932caa6f54969",
        },
        // KT256(M=FF FF FF FF FF FF FF, C=ptn(41**3), 64).
        {
            .variant = 256,
            .pattern = false,
            .pattern_length = 0,
            .message = "ffffffffffffff",
            .customisation_length = 68921,
            .length = 64,
            .offset = 0,
            .expected = "e0911cc00025e1540831e266d94add9b98712142b80d2629e643aac4efaf5a3a"
                        "30a88cbf4ac2a91a2432743054fbcc9897670e86ba8cec2fc2ace9c966369724",
        },
        // KT256(M=ptn(8191), C=the empty string, 64).
        {
            .variant = 256,
            .pattern = true,
            .pattern_length = 8191,
            .message = "",
            .customisation_length = 0,
            .length = 64,
            .offset = 0,
            .expected = "3081434d93a4108d8d8a3305b89682cebedc7ca4ea8a3ce869fbb73cbe4a58ee"
                        "f6f24de38ffc170514c70e7ab2d01f03812616e863d769afb3753193ba045b20",
        },
        // KT256(M=ptn(8192), C=the empty string, 64).
        {
            .variant = 256,
            .pattern = true,
            .pattern_length = 8192,
            .message = "",
            .customisation_length = 0,
            .length = 64,
            .offset = 0,
            .expected = "c6ee8e2ad3200c018ac87aaa031cdac22121b412d07dc6e0dccbb53423747e9a"
                        "1c18834d99df596cf0cf4b8dfafb7bf02d139d0c9035725adc1a01b7230a41fa",
        },
        // KT256(M=ptn(8192), C=ptn(8189), 64).
        {
            .variant = 256,
            .pattern = true,
            .pattern_length = 8192,
            .message = "",
            .customisation_length = 8189,
            .length = 64,
            .offset = 0,
            .expected = "74e47879f10a9c5d11bd2da7e194fe57e86378bf3c3f7448eff3c576a0f18c5c"
                        "aae0999979512090a7f348af4260d4de3c37f1ecaf8d2c2c96c1d16c64b12496",
        },
        // KT256(M=ptn(8192), C=ptn(8190), 64).
        {
            .variant = 256,
            .pattern = true,
            .pattern_length = 8192,
            .message = "",
            .customisation_length = 8190,
            .length = 64,
            .offset = 0,
            .expected = "f4b5908b929ffe01e0f79ec2f21243d41a396b2e7303a6af1d6399cd6c7a0a2d"
                        "d7c4f607e8277f9c9b1cb4ab9ddc59d4b92d1fc7558441f1832c3279a4241b8b",
        },
    });

}  // namespace webcpp::test

#endif  // WEBCPP_TEST_HASH_SUPPORT_RFC9861_KANGAROOTWELVE_HPP
