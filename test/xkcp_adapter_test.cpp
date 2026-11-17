// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The adapter's functions over XKCP's high-level interfaces (detail/xkcp.hpp), each through
// all its phases, in webcpp's storage, against published values: input cut in pieces, output
// squeezed in pieces, the XOF forms, null pointers with no bytes, XKCP's refusals passed on, and
// the adapter's own refusal of a length whose bits a size_t does not hold, made before any byte
// is read. Its C declarations are checked by these calls agreeing with the values: C linkage
// does not check them.
//
// Sources: FIPS 202's SHA3-256 and SHAKE128 of "abc" (Python's hashlib); NIST's SP 800-185
// samples (csrc.nist.gov, "Examples with Intermediate Values": cSHAKE_samples.pdf,
// KMAC_samples.pdf, KMACXOF_samples.pdf, TupleHash_samples.pdf, ParallelHash_samples.pdf,
// ParallelHashXOF_samples.pdf), also in XKCP's tests/UnitTests/testSP800-185.c; RFC 9861,
// section 5, for TurboSHAKE and KangarooTwelve (the KT128 ones also in XKCP's
// tests/TestVectors/KangarooTwelve.txt). Every value was recomputed by a second implementation
// written from FIPS 202, SP 800-185 and RFC 9861.

#include <webcpp/hash/detail/xkcp.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace {

namespace detail = webcpp::hash::detail;
using webcpp::test::from_hex;
using webcpp::test::to_hex;

static_assert(alignof(detail::xkcp_sponge_storage) == alignof(std::uint64_t));
static_assert(alignof(detail::xkcp_parallelhash_storage) == alignof(std::uint64_t));

// The most bytes whose length in bits a size_t holds: the adapter refuses more at once.
constexpr std::size_t bit_chunk = SIZE_MAX / 8;

std::vector<std::uint8_t> bytes_of(std::string_view text) {
    return {text.begin(), text.end()};
}

// The bytes 0, 1, ..., n - 1 from first on, modulo 256.
std::vector<std::uint8_t> counting(std::size_t n, std::uint8_t first = 0) {
    std::vector<std::uint8_t> bytes(n);
    for (std::size_t i = 0; i < n; ++i) {
        bytes[i] = static_cast<std::uint8_t>(first + i);
    }
    return bytes;
}

// RFC 9861's ptn(n): n bytes of the pattern 0x00 to 0xFA, repeated.
std::vector<std::uint8_t> ptn(std::size_t n) {
    std::vector<std::uint8_t> bytes(n);
    for (std::size_t i = 0; i < n; ++i) {
        bytes[i] = static_cast<std::uint8_t>(i % 251);
    }
    return bytes;
}

// NIST's SP 800-185 samples' inputs: KMAC's key 0x40 to 0x5F, and messages of 4 and 200 bytes.
std::vector<std::uint8_t> nist_kmac_key() {
    return counting(32, 0x40);
}

std::vector<std::uint8_t> nist_message_4() {
    return counting(4);
}

std::vector<std::uint8_t> nist_message_200() {
    return counting(200);
}

// ParallelHash's samples' 24 bytes.
std::vector<std::uint8_t> nist_parallel_message() {
    return from_hex("000102030405060710111213141516172021222324252627");
}

void check_sponge() {
    // SHA3-256("abc") through the sponge: rate 1088, capacity 512, suffix 0x06.
    detail::xkcp_sponge_storage storage{};
    auto const abc = bytes_of("abc");
    std::array<std::uint8_t, 32> output{};
    BOOST_TEST_EQ(webcpp_hash_xkcp_sponge_initialize(storage.data(), 1088, 512), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_sponge_update(storage.data(), abc.data(), 1), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_sponge_update(storage.data(), nullptr, 0), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_sponge_update(storage.data(), abc.data() + 1, 2), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_sponge_final(storage.data(), 0x06), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_sponge_squeeze(storage.data(), output.data(), 10), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_sponge_squeeze(storage.data(), output.data() + 10, 22), 0);
    BOOST_TEST_EQ(to_hex(output),
                  "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    // XKCP's refusals: a rate and capacity that are not 1600 bits, a suffix of 0, absorbing
    // once squeezing.
    BOOST_TEST_NE(webcpp_hash_xkcp_sponge_update(storage.data(), abc.data(), 3), 0);
    BOOST_TEST_NE(webcpp_hash_xkcp_sponge_initialize(storage.data(), 1088, 256), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_sponge_initialize(storage.data(), 1088, 512), 0);
    BOOST_TEST_NE(webcpp_hash_xkcp_sponge_final(storage.data(), 0), 0);
}

void check_keccak_hash() {
    detail::xkcp_keccak_hash_storage storage{};
    auto const abc = bytes_of("abc");
    // SHA3-256: a fixed output of 32 bytes written by final.
    std::array<std::uint8_t, 32> digest{};
    BOOST_TEST_EQ(webcpp_hash_xkcp_keccak_hash_initialize(storage.data(), 1088, 512, 32, 0x06), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_keccak_hash_update(storage.data(), abc.data(), 2), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_keccak_hash_update(storage.data(), abc.data() + 2, 1), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_keccak_hash_final(storage.data(), digest.data()), 0);
    BOOST_TEST_EQ(to_hex(digest),
                  "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    BOOST_TEST_NE(webcpp_hash_xkcp_keccak_hash_update(storage.data(), abc.data(), 3), 0);
    // Keccak-256 of nothing: suffix 0x01, no update, a null input of no bytes.
    BOOST_TEST_EQ(webcpp_hash_xkcp_keccak_hash_initialize(storage.data(), 1088, 512, 32, 0x01), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_keccak_hash_update(storage.data(), nullptr, 0), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_keccak_hash_final(storage.data(), digest.data()), 0);
    BOOST_TEST_EQ(to_hex(digest),
                  "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    // SHAKE128: no fixed output, 40 bytes squeezed in two pieces.
    std::array<std::uint8_t, 40> squeezed{};
    BOOST_TEST_EQ(webcpp_hash_xkcp_keccak_hash_initialize(storage.data(), 1344, 256, 0, 0x1F), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_keccak_hash_update(storage.data(), abc.data(), 3), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_keccak_hash_final(storage.data(), nullptr), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_keccak_hash_squeeze(storage.data(), squeezed.data(), 13), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_keccak_hash_squeeze(storage.data(), squeezed.data() + 13, 27),
                  0);
    BOOST_TEST_EQ(to_hex(squeezed),
                  "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"
                  "44c50af32acd3f2c");
    // A suffix of 0 is XKCP's refusal; an output whose bits an unsigned int does not hold is
    // the adapter's.
    BOOST_TEST_NE(webcpp_hash_xkcp_keccak_hash_initialize(storage.data(), 1088, 512, 32, 0), 0);
    BOOST_TEST_NE(webcpp_hash_xkcp_keccak_hash_initialize(storage.data(), 1088, 512,
                                                          (UINT_MAX / 8) + 1, 0x06),
                  0);
}

void check_turboshake() {
    detail::xkcp_turboshake_storage storage{};
    // TurboSHAKE128(M=empty, D=0x1F, 32) and TurboSHAKE256(M=empty, D=0x1F, 64), RFC 9861.
    std::array<std::uint8_t, 32> output128{};
    BOOST_TEST_EQ(webcpp_hash_xkcp_turboshake_initialize(storage.data(), 256), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_turboshake_update(storage.data(), nullptr, 0), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_turboshake_final(storage.data(), 0x1F), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_turboshake_squeeze(storage.data(), output128.data(), 32), 0);
    BOOST_TEST_EQ(to_hex(output128),
                  "1e415f1c5983aff2169217277d17bb538cd945a397ddec541f1ce41af2c1b74c");
    std::array<std::uint8_t, 64> output256{};
    BOOST_TEST_EQ(webcpp_hash_xkcp_turboshake_initialize(storage.data(), 512), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_turboshake_final(storage.data(), 0x1F), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_turboshake_squeeze(storage.data(), output256.data(), 1), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_turboshake_squeeze(storage.data(), output256.data() + 1, 63), 0);
    BOOST_TEST_EQ(to_hex(output256),
                  "367a329dafea871c7802ec67f905ae13c57695dc2c6663c61035f59a18f8e7db"
                  "11edc0e12e91ea60eb6b32df06dd7f002fbafabb6e13ec1cc20d995547600db0");
    // TurboSHAKE128(M=0xFF 0xFF 0xFF, D=0x01, 32), RFC 9861, absorbed in two pieces.
    std::array<std::uint8_t, 3> const ffs{0xFF, 0xFF, 0xFF};
    BOOST_TEST_EQ(webcpp_hash_xkcp_turboshake_initialize(storage.data(), 256), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_turboshake_update(storage.data(), ffs.data(), 1), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_turboshake_update(storage.data(), ffs.data() + 1, 2), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_turboshake_final(storage.data(), 0x01), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_turboshake_squeeze(storage.data(), output128.data(), 32), 0);
    BOOST_TEST_EQ(to_hex(output128),
                  "bf323f940494e88ee1c540fe660be8a0c93f43d15ec006998462fa994eed5dab");
    // XKCP's refusals: a capacity over 512 bits, a domain byte of 0, absorbing after it.
    BOOST_TEST_NE(webcpp_hash_xkcp_turboshake_initialize(storage.data(), 520), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_turboshake_initialize(storage.data(), 256), 0);
    BOOST_TEST_NE(webcpp_hash_xkcp_turboshake_final(storage.data(), 0), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_turboshake_final(storage.data(), 0x1F), 0);
    BOOST_TEST_NE(webcpp_hash_xkcp_turboshake_update(storage.data(), ffs.data(), 3), 0);
}

void check_kangarootwelve() {
    detail::xkcp_kangarootwelve_storage storage{};
    // KT128(M=empty, C=empty, 32), RFC 9861: a fixed output written by final, null pointers.
    std::array<std::uint8_t, 32> output128{};
    BOOST_TEST_EQ(webcpp_hash_xkcp_kangarootwelve_initialize(storage.data(), 128, 32), 0);
    BOOST_TEST_EQ(
        webcpp_hash_xkcp_kangarootwelve_final(storage.data(), output128.data(), nullptr, 0), 0);
    BOOST_TEST_EQ(to_hex(output128),
                  "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5");
    // KT128(M=ptn(17^4 bytes), C=empty, 32), RFC 9861: past one chunk of 8192 bytes, so the
    // tree's leaves, absorbed in pieces across the chunks' bounds.
    auto const message = ptn(83521);
    std::size_t at = 0;
    BOOST_TEST_EQ(webcpp_hash_xkcp_kangarootwelve_initialize(storage.data(), 128, 32), 0);
    for (std::size_t const piece :
         {std::size_t{1}, std::size_t{8191}, std::size_t{8193}, std::size_t{30000}}) {
        BOOST_TEST_EQ(
            webcpp_hash_xkcp_kangarootwelve_update(storage.data(), message.data() + at, piece), 0);
        at += piece;
    }
    BOOST_TEST_EQ(webcpp_hash_xkcp_kangarootwelve_update(storage.data(), message.data() + at,
                                                         message.size() - at),
                  0);
    BOOST_TEST_EQ(
        webcpp_hash_xkcp_kangarootwelve_final(storage.data(), output128.data(), nullptr, 0), 0);
    BOOST_TEST_EQ(to_hex(output128),
                  "8701045e22205345ff4dda05555cbb5c3af1a771c2b89baef37db43d9998b9fe");
    // KT128(M=0xFF 0xFF 0xFF, C=ptn(41^2 bytes), 32), RFC 9861: the customisation at final,
    // the output squeezed.
    std::array<std::uint8_t, 3> const ffs{0xFF, 0xFF, 0xFF};
    auto const customisation = ptn(1681);
    BOOST_TEST_EQ(webcpp_hash_xkcp_kangarootwelve_initialize(storage.data(), 128, 0), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_kangarootwelve_update(storage.data(), ffs.data(), ffs.size()),
                  0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_kangarootwelve_final(storage.data(), nullptr,
                                                        customisation.data(), customisation.size()),
                  0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_kangarootwelve_squeeze(storage.data(), output128.data(), 32), 0);
    BOOST_TEST_EQ(to_hex(output128),
                  "c389e5009ae57120854c2e8c64670ac01358cf4c1baf89447a724234dc7ced74");
    // KT256(M=empty, C=empty, 64) and KT256(M=ptn(17^2 bytes), C=empty, 64), RFC 9861.
    std::array<std::uint8_t, 64> output256{};
    BOOST_TEST_EQ(webcpp_hash_xkcp_kangarootwelve_initialize(storage.data(), 256, 64), 0);
    BOOST_TEST_EQ(
        webcpp_hash_xkcp_kangarootwelve_final(storage.data(), output256.data(), nullptr, 0), 0);
    BOOST_TEST_EQ(to_hex(output256),
                  "b23d2e9cea9f4904e02bec06817fc10ce38ce8e93ef4c89e6537076af8646404"
                  "e3e8b68107b8833a5d30490aa33482353fd4adc7148ecb782855003aaebde4a9");
    auto const short_message = ptn(289);
    BOOST_TEST_EQ(webcpp_hash_xkcp_kangarootwelve_initialize(storage.data(), 256, 64), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_kangarootwelve_update(storage.data(), short_message.data(),
                                                         short_message.size()),
                  0);
    BOOST_TEST_EQ(
        webcpp_hash_xkcp_kangarootwelve_final(storage.data(), output256.data(), nullptr, 0), 0);
    BOOST_TEST_EQ(to_hex(output256),
                  "de8ccbc63e0f133ebb4416814d4c66f691bbf8b6a61ec0a7700f836b086cb029"
                  "d54f12ac7159472c72db118c35b4e6aa213c6562caaa9dcc518959e69b10f3ba");
    // XKCP's refusals: another security level, absorbing after final.
    BOOST_TEST_NE(webcpp_hash_xkcp_kangarootwelve_initialize(storage.data(), 192, 32), 0);
    BOOST_TEST_NE(webcpp_hash_xkcp_kangarootwelve_update(storage.data(), ffs.data(), 3), 0);
}

void check_cshake() {
    auto const message_4 = nist_message_4();
    auto const message_200 = nist_message_200();
    detail::xkcp_cshake_storage storage{};
    auto const email = bytes_of("Email Signature");
    // cSHAKE128 sample #1: X = 00010203, N empty, S = "Email Signature", 32 bytes.
    std::array<std::uint8_t, 32> output128{};
    BOOST_TEST_EQ(webcpp_hash_xkcp_cshake128_initialize(storage.data(), 32, nullptr, 0,
                                                        email.data(), email.size()),
                  0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_cshake128_update(storage.data(), message_4.data(), 1), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_cshake128_update(storage.data(), message_4.data() + 1, 3), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_cshake128_final(storage.data(), output128.data()), 0);
    BOOST_TEST_EQ(to_hex(output128),
                  "c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5");
    BOOST_TEST_NE(webcpp_hash_xkcp_cshake128_update(storage.data(), message_4.data(), 4), 0);
    // cSHAKE256 sample #4: X = 00 to C7, N empty, S = "Email Signature", 64 bytes squeezed.
    std::array<std::uint8_t, 64> output256{};
    BOOST_TEST_EQ(webcpp_hash_xkcp_cshake256_initialize(storage.data(), 0, nullptr, 0, email.data(),
                                                        email.size()),
                  0);
    BOOST_TEST_EQ(
        webcpp_hash_xkcp_cshake256_update(storage.data(), message_200.data(), message_200.size()),
        0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_cshake256_final(storage.data(), nullptr), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_cshake256_squeeze(storage.data(), output256.data(), 64), 0);
    BOOST_TEST_EQ(to_hex(output256),
                  "07dc27b11e51fbac75bc7b3c1d983e8b4b85fb1defaf218912ac86430273091727f42b17ed1df63e"
                  "8ec118f04b23633c1dfb1574c8fb55cb45da8e25afb092bb");
    // The adapter's refusals, before any byte is read: lengths whose bits a size_t does not
    // hold. The pointer is to one byte, which XKCP would read past.
    std::uint8_t const one = 0;
    BOOST_TEST_NE(webcpp_hash_xkcp_cshake128_initialize(storage.data(), bit_chunk + 1, nullptr, 0,
                                                        nullptr, 0),
                  0);
    BOOST_TEST_NE(
        webcpp_hash_xkcp_cshake128_initialize(storage.data(), 32, &one, bit_chunk + 1, nullptr, 0),
        0);
    BOOST_TEST_NE(
        webcpp_hash_xkcp_cshake256_initialize(storage.data(), 32, nullptr, 0, &one, bit_chunk + 1),
        0);
}

void check_kmac() {
    auto const key = nist_kmac_key();
    auto const message_4 = nist_message_4();
    auto const message_200 = nist_message_200();
    detail::xkcp_kmac_storage storage{};
    // KMAC128 sample #1: K = 40 to 5F, X = 00010203, S empty, 32 bytes.
    std::array<std::uint8_t, 32> output128{};
    BOOST_TEST_EQ(
        webcpp_hash_xkcp_kmac128_initialize(storage.data(), key.data(), key.size(), 32, nullptr, 0),
        0);
    BOOST_TEST_EQ(
        webcpp_hash_xkcp_kmac128_update(storage.data(), message_4.data(), message_4.size()), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_kmac128_final(storage.data(), output128.data()), 0);
    BOOST_TEST_EQ(to_hex(output128),
                  "e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e");
    // KMACXOF128 sample #1: the same inputs, the XOF form, squeezed in two pieces.
    BOOST_TEST_EQ(
        webcpp_hash_xkcp_kmac128_initialize(storage.data(), key.data(), key.size(), 0, nullptr, 0),
        0);
    BOOST_TEST_EQ(
        webcpp_hash_xkcp_kmac128_update(storage.data(), message_4.data(), message_4.size()), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_kmac128_final(storage.data(), nullptr), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_kmac128_squeeze(storage.data(), output128.data(), 5), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_kmac128_squeeze(storage.data(), output128.data() + 5, 27), 0);
    BOOST_TEST_EQ(to_hex(output128),
                  "cd83740bbd92ccc8cf032b1481a0f4460e7ca9dd12b08a0c4031178bacd6ec35");
    // KMAC256 sample #6: K = 40 to 5F, X = 00 to C7, S = "My Tagged Application", 64 bytes.
    auto const tagged = bytes_of("My Tagged Application");
    std::array<std::uint8_t, 64> output256{};
    BOOST_TEST_EQ(webcpp_hash_xkcp_kmac256_initialize(storage.data(), key.data(), key.size(), 64,
                                                      tagged.data(), tagged.size()),
                  0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_kmac256_update(storage.data(), message_200.data(), 100), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_kmac256_update(storage.data(), message_200.data() + 100, 100),
                  0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_kmac256_final(storage.data(), output256.data()), 0);
    BOOST_TEST_EQ(to_hex(output256),
                  "b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d9"
                  "70fbacfde50033aea585f1a2708510c32d07880801bd182898fe476876fc8965");
    // The adapter's refusals: a key, an output or a customisation too long for its bits.
    std::uint8_t const one = 0;
    BOOST_TEST_NE(
        webcpp_hash_xkcp_kmac128_initialize(storage.data(), &one, bit_chunk + 1, 32, nullptr, 0),
        0);
    BOOST_TEST_NE(
        webcpp_hash_xkcp_kmac128_initialize(storage.data(), nullptr, 0, bit_chunk + 1, nullptr, 0),
        0);
    BOOST_TEST_NE(
        webcpp_hash_xkcp_kmac256_initialize(storage.data(), nullptr, 0, 32, &one, bit_chunk + 1),
        0);
}

void check_tuplehash() {
    detail::xkcp_tuplehash_storage storage{};
    auto const first = counting(3);
    auto const second = counting(6, 0x10);
    auto const third = counting(9, 0x20);
    // TupleHash128 sample #1: (000102, 101112131415), S empty, 32 bytes.
    std::array<std::uint8_t, 32> output128{};
    BOOST_TEST_EQ(webcpp_hash_xkcp_tuplehash128_initialize(storage.data(), 32, nullptr, 0), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_tuplehash128_update(storage.data(), first.data(), first.size()),
                  0);
    BOOST_TEST_EQ(
        webcpp_hash_xkcp_tuplehash128_update(storage.data(), second.data(), second.size()), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_tuplehash128_final(storage.data(), output128.data()), 0);
    BOOST_TEST_EQ(to_hex(output128),
                  "c5d8786c1afb9b82111ab34b65b2c0048fa64e6d48e263264ce1707d3ffc8ed1");
    // Each update is one element: the same bytes as one element hash otherwise.
    std::array<std::uint8_t, 32> joined{};
    auto const both = from_hex("000102101112131415");
    BOOST_TEST_EQ(webcpp_hash_xkcp_tuplehash128_initialize(storage.data(), 32, nullptr, 0), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_tuplehash128_update(storage.data(), both.data(), both.size()),
                  0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_tuplehash128_final(storage.data(), joined.data()), 0);
    BOOST_TEST_NE(to_hex(joined), to_hex(output128));
    // TupleHash256 sample #6: three elements, S = "My Tuple App", 64 bytes.
    auto const app = bytes_of("My Tuple App");
    std::array<std::uint8_t, 64> output256{};
    BOOST_TEST_EQ(
        webcpp_hash_xkcp_tuplehash256_initialize(storage.data(), 64, app.data(), app.size()), 0);
    for (auto const* element : {&first, &second, &third}) {
        BOOST_TEST_EQ(
            webcpp_hash_xkcp_tuplehash256_update(storage.data(), element->data(), element->size()),
            0);
    }
    BOOST_TEST_EQ(webcpp_hash_xkcp_tuplehash256_final(storage.data(), output256.data()), 0);
    BOOST_TEST_EQ(to_hex(output256),
                  "45000be63f9b6bfd89f54717670f69a9bc763591a4f05c50d68891a744bcc6e7"
                  "d6d5b5e82c018da999ed35b0bb49c9678e526abd8e85c13ed254021db9e790ce");
    // The adapter's refusals: an element, an output or a customisation too long for its bits.
    std::uint8_t const one = 0;
    BOOST_TEST_EQ(webcpp_hash_xkcp_tuplehash128_initialize(storage.data(), 32, nullptr, 0), 0);
    BOOST_TEST_NE(webcpp_hash_xkcp_tuplehash128_update(storage.data(), &one, bit_chunk + 1), 0);
    BOOST_TEST_NE(
        webcpp_hash_xkcp_tuplehash128_initialize(storage.data(), bit_chunk + 1, nullptr, 0), 0);
    BOOST_TEST_NE(webcpp_hash_xkcp_tuplehash256_initialize(storage.data(), 64, &one, bit_chunk + 1),
                  0);
}

void check_parallelhash() {
    auto const message = nist_parallel_message();
    detail::xkcp_parallelhash_storage storage{};
    // ParallelHash128 sample #1: the 24 bytes, B = 8, S empty, 32 bytes, absorbed across the
    // blocks' bounds.
    std::array<std::uint8_t, 32> output128{};
    BOOST_TEST_EQ(webcpp_hash_xkcp_parallelhash128_initialize(storage.data(), 8, 32, nullptr, 0),
                  0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_parallelhash128_update(storage.data(), message.data(), 5), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_parallelhash128_update(storage.data(), message.data() + 5, 19),
                  0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_parallelhash128_final(storage.data(), output128.data()), 0);
    BOOST_TEST_EQ(to_hex(output128),
                  "ba8dc1d1d979331d3f813603c67f72609ab5e44b94a0b8f9af46514454a2b4f5");
    // ParallelHashXOF128 sample #1: the same inputs, the XOF form.
    BOOST_TEST_EQ(webcpp_hash_xkcp_parallelhash128_initialize(storage.data(), 8, 0, nullptr, 0), 0);
    BOOST_TEST_EQ(
        webcpp_hash_xkcp_parallelhash128_update(storage.data(), message.data(), message.size()), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_parallelhash128_final(storage.data(), nullptr), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_parallelhash128_squeeze(storage.data(), output128.data(), 32),
                  0);
    BOOST_TEST_EQ(to_hex(output128),
                  "fe47d661e49ffe5b7d999922c062356750caf552985b8e8ce6667f2727c3c8d3");
    // ParallelHash256 sample #5: B = 8, S = "Parallel Data", 64 bytes.
    auto const data = bytes_of("Parallel Data");
    std::array<std::uint8_t, 64> output256{};
    BOOST_TEST_EQ(webcpp_hash_xkcp_parallelhash256_initialize(storage.data(), 8, 64, data.data(),
                                                              data.size()),
                  0);
    BOOST_TEST_EQ(
        webcpp_hash_xkcp_parallelhash256_update(storage.data(), message.data(), message.size()), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_parallelhash256_final(storage.data(), output256.data()), 0);
    BOOST_TEST_EQ(to_hex(output256),
                  "cdf15289b54f6212b4bc270528b49526006dd9b54e2b6add1ef6900dda3963bb"
                  "33a72491f236969ca8afaea29c682d47a393c065b38e29fae651a2091c833110");
    // XKCP's refusals of a block size that is not a power of two of at least 8 bytes (the lane's
    // size): 0, 4 (below 8) and 12 (not a power of two), on both functions; 16 is taken.
    for (std::size_t const block_size : {std::size_t{0}, std::size_t{4}, std::size_t{12}}) {
        BOOST_TEST_NE(
            webcpp_hash_xkcp_parallelhash128_initialize(storage.data(), block_size, 32, nullptr, 0),
            0);
        BOOST_TEST_NE(
            webcpp_hash_xkcp_parallelhash256_initialize(storage.data(), block_size, 64, nullptr, 0),
            0);
    }
    BOOST_TEST_EQ(webcpp_hash_xkcp_parallelhash128_initialize(storage.data(), 16, 32, nullptr, 0),
                  0);
    // The adapter's refusals of an output or a customisation too long for its bits.
    std::uint8_t const one = 0;
    BOOST_TEST_NE(
        webcpp_hash_xkcp_parallelhash128_initialize(storage.data(), 8, bit_chunk + 1, nullptr, 0),
        0);
    BOOST_TEST_NE(
        webcpp_hash_xkcp_parallelhash256_initialize(storage.data(), 8, 64, &one, bit_chunk + 1), 0);
}

// TupleHash's and ParallelHash's final with the output length L given at the end, as a
// hasher knows it, in place of initialize's: started with 0, each gives NIST's samples of the
// fixed form for L and of the XOF form for 0. Refused: twice, after final, and an L too long
// for its bits.
void check_final_length() {
    auto const first = counting(3);
    auto const second = counting(6, 0x10);
    auto const third = counting(9, 0x20);
    auto const app = bytes_of("My Tuple App");
    detail::xkcp_tuplehash_storage tuple{};
    // TupleHash128 sample #1, then TupleHashXOF128 sample #1.
    std::array<std::uint8_t, 32> output128{};
    for (std::size_t const length : {std::size_t{32}, std::size_t{0}}) {
        BOOST_TEST_EQ(webcpp_hash_xkcp_tuplehash128_initialize(tuple.data(), 0, nullptr, 0), 0);
        BOOST_TEST_EQ(
            webcpp_hash_xkcp_tuplehash128_update(tuple.data(), first.data(), first.size()), 0);
        BOOST_TEST_EQ(
            webcpp_hash_xkcp_tuplehash128_update(tuple.data(), second.data(), second.size()), 0);
        BOOST_TEST_EQ(webcpp_hash_xkcp_tuplehash128_final_length(
                          tuple.data(), length == 0 ? nullptr : output128.data(), length),
                      0);
        if (length == 0) {
            BOOST_TEST_EQ(webcpp_hash_xkcp_tuplehash128_squeeze(tuple.data(), output128.data(),
                                                                output128.size()),
                          0);
        }
        BOOST_TEST_EQ(to_hex(output128),
                      length == 0
                          ? "2f103cd7c32320353495c68de1a8129245c6325f6f2a3d608d92179c96e68488"
                          : "c5d8786c1afb9b82111ab34b65b2c0048fa64e6d48e263264ce1707d3ffc8ed1");
    }
    // TupleHash256 sample #6, three elements, S = "My Tuple App"; final_length twice refused.
    std::array<std::uint8_t, 64> output256{};
    BOOST_TEST_EQ(webcpp_hash_xkcp_tuplehash256_initialize(tuple.data(), 0, app.data(), app.size()),
                  0);
    for (auto const* element : {&first, &second, &third}) {
        BOOST_TEST_EQ(
            webcpp_hash_xkcp_tuplehash256_update(tuple.data(), element->data(), element->size()),
            0);
    }
    BOOST_TEST_EQ(webcpp_hash_xkcp_tuplehash256_final_length(tuple.data(), output256.data(), 64),
                  0);
    BOOST_TEST_EQ(to_hex(output256),
                  "45000be63f9b6bfd89f54717670f69a9bc763591a4f05c50d68891a744bcc6e7"
                  "d6d5b5e82c018da999ed35b0bb49c9678e526abd8e85c13ed254021db9e790ce");
    BOOST_TEST_NE(webcpp_hash_xkcp_tuplehash256_final_length(tuple.data(), output256.data(), 64),
                  0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_tuplehash128_initialize(tuple.data(), 0, nullptr, 0), 0);
    BOOST_TEST_NE(webcpp_hash_xkcp_tuplehash128_final_length(tuple.data(), nullptr, bit_chunk + 1),
                  0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_tuplehash128_final(tuple.data(), nullptr), 0);
    BOOST_TEST_NE(webcpp_hash_xkcp_tuplehash128_final_length(tuple.data(), output128.data(), 32),
                  0);

    auto const message = nist_parallel_message();
    detail::xkcp_parallelhash_storage parallel{};
    // ParallelHash128 sample #1, then ParallelHashXOF128 sample #1.
    for (std::size_t const length : {std::size_t{32}, std::size_t{0}}) {
        BOOST_TEST_EQ(
            webcpp_hash_xkcp_parallelhash128_initialize(parallel.data(), 8, 0, nullptr, 0), 0);
        BOOST_TEST_EQ(webcpp_hash_xkcp_parallelhash128_update(parallel.data(), message.data(),
                                                              message.size()),
                      0);
        BOOST_TEST_EQ(webcpp_hash_xkcp_parallelhash128_final_length(
                          parallel.data(), length == 0 ? nullptr : output128.data(), length),
                      0);
        if (length == 0) {
            BOOST_TEST_EQ(
                webcpp_hash_xkcp_parallelhash128_squeeze(parallel.data(), output128.data(), 32), 0);
        }
        BOOST_TEST_EQ(to_hex(output128),
                      length == 0
                          ? "fe47d661e49ffe5b7d999922c062356750caf552985b8e8ce6667f2727c3c8d3"
                          : "ba8dc1d1d979331d3f813603c67f72609ab5e44b94a0b8f9af46514454a2b4f5");
    }
    // ParallelHash256 sample #5: B = 8, S = "Parallel Data", 64 bytes; final_length twice
    // refused.
    auto const data = bytes_of("Parallel Data");
    BOOST_TEST_EQ(webcpp_hash_xkcp_parallelhash256_initialize(parallel.data(), 8, 0, data.data(),
                                                              data.size()),
                  0);
    BOOST_TEST_EQ(
        webcpp_hash_xkcp_parallelhash256_update(parallel.data(), message.data(), message.size()),
        0);
    BOOST_TEST_EQ(
        webcpp_hash_xkcp_parallelhash256_final_length(parallel.data(), output256.data(), 64), 0);
    BOOST_TEST_EQ(to_hex(output256),
                  "cdf15289b54f6212b4bc270528b49526006dd9b54e2b6add1ef6900dda3963bb"
                  "33a72491f236969ca8afaea29c682d47a393c065b38e29fae651a2091c833110");
    BOOST_TEST_NE(
        webcpp_hash_xkcp_parallelhash256_final_length(parallel.data(), output256.data(), 64), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_parallelhash128_initialize(parallel.data(), 8, 0, nullptr, 0),
                  0);
    BOOST_TEST_NE(
        webcpp_hash_xkcp_parallelhash128_final_length(parallel.data(), nullptr, bit_chunk + 1), 0);
    BOOST_TEST_EQ(webcpp_hash_xkcp_parallelhash128_final(parallel.data(), nullptr), 0);
    BOOST_TEST_NE(
        webcpp_hash_xkcp_parallelhash128_final_length(parallel.data(), output128.data(), 32), 0);

    // At other lengths, against XKCP's own path, L given to initialize: 1 and 200 bytes, both
    // functions, so that the deferred L has an oracle beside NIST's 32 and 64 bytes.
    for (std::size_t const length : {std::size_t{1}, std::size_t{200}}) {
        std::vector<std::uint8_t> early(length);
        std::vector<std::uint8_t> late(length);
        BOOST_TEST_EQ(
            webcpp_hash_xkcp_tuplehash256_initialize(tuple.data(), length, app.data(), app.size()),
            0);
        BOOST_TEST_EQ(
            webcpp_hash_xkcp_tuplehash256_update(tuple.data(), first.data(), first.size()), 0);
        BOOST_TEST_EQ(webcpp_hash_xkcp_tuplehash256_final(tuple.data(), early.data()), 0);
        BOOST_TEST_EQ(
            webcpp_hash_xkcp_tuplehash256_initialize(tuple.data(), 0, app.data(), app.size()), 0);
        BOOST_TEST_EQ(
            webcpp_hash_xkcp_tuplehash256_update(tuple.data(), first.data(), first.size()), 0);
        BOOST_TEST_EQ(webcpp_hash_xkcp_tuplehash256_final_length(tuple.data(), late.data(), length),
                      0);
        BOOST_TEST(early == late);

        BOOST_TEST_EQ(webcpp_hash_xkcp_parallelhash128_initialize(parallel.data(), 8, length,
                                                                  data.data(), data.size()),
                      0);
        BOOST_TEST_EQ(webcpp_hash_xkcp_parallelhash128_update(parallel.data(), message.data(),
                                                              message.size()),
                      0);
        BOOST_TEST_EQ(webcpp_hash_xkcp_parallelhash128_final(parallel.data(), early.data()), 0);
        BOOST_TEST_EQ(webcpp_hash_xkcp_parallelhash128_initialize(parallel.data(), 8, 0,
                                                                  data.data(), data.size()),
                      0);
        BOOST_TEST_EQ(webcpp_hash_xkcp_parallelhash128_update(parallel.data(), message.data(),
                                                              message.size()),
                      0);
        BOOST_TEST_EQ(
            webcpp_hash_xkcp_parallelhash128_final_length(parallel.data(), late.data(), length), 0);
        BOOST_TEST(early == late);
    }
}

// The phases' refusals the Doc Comments state, on the kinds that track their phase: squeezing
// before final, and final twice. Each starts in the XOF form, where squeeze follows final.
template <class Storage, class Initialize, class Final, class Squeeze>
void check_phases(char const* kind, Initialize initialize, Final final_phase, Squeeze squeeze) {
    int const errors_before = boost::detail::test_errors();
    Storage storage{};
    std::array<std::uint8_t, 8> output{};
    BOOST_TEST_EQ(initialize(storage.data()), 0);
    BOOST_TEST_NE(squeeze(storage.data(), output.data(), output.size()), 0);
    BOOST_TEST_EQ(final_phase(storage.data()), 0);
    BOOST_TEST_NE(final_phase(storage.data()), 0);
    BOOST_TEST_EQ(squeeze(storage.data(), output.data(), output.size()), 0);
    if (boost::detail::test_errors() != errors_before) {
        BOOST_ERROR(kind);
    }
}

void check_phase_refusals() {
    check_phases<detail::xkcp_kangarootwelve_storage>(
        "kangarootwelve",
        [](std::uint64_t* s) { return webcpp_hash_xkcp_kangarootwelve_initialize(s, 128, 0); },
        [](std::uint64_t* s) {
            return webcpp_hash_xkcp_kangarootwelve_final(s, nullptr, nullptr, 0);
        },
        webcpp_hash_xkcp_kangarootwelve_squeeze);
    check_phases<detail::xkcp_cshake_storage>(
        "cshake128",
        [](std::uint64_t* s) {
            return webcpp_hash_xkcp_cshake128_initialize(s, 0, nullptr, 0, nullptr, 0);
        },
        [](std::uint64_t* s) { return webcpp_hash_xkcp_cshake128_final(s, nullptr); },
        webcpp_hash_xkcp_cshake128_squeeze);
    check_phases<detail::xkcp_kmac_storage>(
        "kmac256",
        [](std::uint64_t* s) {
            return webcpp_hash_xkcp_kmac256_initialize(s, nullptr, 0, 0, nullptr, 0);
        },
        [](std::uint64_t* s) { return webcpp_hash_xkcp_kmac256_final(s, nullptr); },
        webcpp_hash_xkcp_kmac256_squeeze);
    check_phases<detail::xkcp_tuplehash_storage>(
        "tuplehash128",
        [](std::uint64_t* s) { return webcpp_hash_xkcp_tuplehash128_initialize(s, 0, nullptr, 0); },
        [](std::uint64_t* s) { return webcpp_hash_xkcp_tuplehash128_final(s, nullptr); },
        webcpp_hash_xkcp_tuplehash128_squeeze);
    check_phases<detail::xkcp_parallelhash_storage>(
        "parallelhash256",
        [](std::uint64_t* s) {
            return webcpp_hash_xkcp_parallelhash256_initialize(s, 8, 0, nullptr, 0);
        },
        [](std::uint64_t* s) { return webcpp_hash_xkcp_parallelhash256_final(s, nullptr); },
        webcpp_hash_xkcp_parallelhash256_squeeze);
    check_phases<detail::xkcp_tuplehash_storage>(
        "tuplehash256 final_length",
        [](std::uint64_t* s) { return webcpp_hash_xkcp_tuplehash256_initialize(s, 0, nullptr, 0); },
        [](std::uint64_t* s) { return webcpp_hash_xkcp_tuplehash256_final_length(s, nullptr, 0); },
        webcpp_hash_xkcp_tuplehash256_squeeze);
    check_phases<detail::xkcp_parallelhash_storage>(
        "parallelhash128 final_length",
        [](std::uint64_t* s) {
            return webcpp_hash_xkcp_parallelhash128_initialize(s, 8, 0, nullptr, 0);
        },
        [](std::uint64_t* s) {
            return webcpp_hash_xkcp_parallelhash128_final_length(s, nullptr, 0);
        },
        webcpp_hash_xkcp_parallelhash128_squeeze);
}

}  // namespace

int main() {
    check_sponge();
    check_keccak_hash();
    check_turboshake();
    check_kangarootwelve();
    check_cshake();
    check_kmac();
    check_tuplehash();
    check_parallelhash();
    check_final_length();
    check_phase_refusals();
    return webcpp::test::exit_status(boost::report_errors());
}
