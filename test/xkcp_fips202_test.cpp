// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The Keccak family's hashes on backends::xkcp, through digest_of and hasher: Keccak-224 to
// Keccak-512, SHA3-224 to SHA3-512, SHAKE128 and SHAKE256.
//
// - Keccak-n of the empty message and of "abc": the Keccak team's values (the Len = 0 entries of
//   their SHA-3 competition KAT files ShortMsgKAT_224.txt to ShortMsgKAT_512.txt; "abc" as
//   upstream_keccak_test.cpp states its source), and Boost.Hash2's keccak_base<0x01, 2n, n>, the
//   class under its SHA-3 types with Keccak's padding byte, on deterministic random inputs.
// - SHA3-n and SHAKE against XKCP's own ShortMsgKAT_SHA3-*.txt and ShortMsgKAT_SHAKE*.txt
//   (/third_party//xkcp_vectors), each entry whose length is whole bytes (256 of the 2048 of each
//   file, counted, so that a parser that reads nothing fails), and against Boost.Hash2's sha3_n
//   and shake_n on random inputs; SHAKE past one rate block, where Boost.Hash2's result() returns
//   the stream's next block on each call.
//
// Each value is taken in one call and in pieces of every split of the input in three.

#include <webcpp/hash/backends/xkcp.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/test/exit_status.hpp>

#include "require.hpp"
#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/sha3.hpp>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

namespace hash = webcpp::hash;
namespace digests = webcpp::hash::digests;
namespace test = webcpp::test;
using webcpp::hash::backends::xkcp;
using bytes = std::vector<std::uint8_t>;

// The whole file at path; one that cannot be opened ends the test, by name.
std::string read_text(std::string const& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cerr << "cannot open test data: " << path << '\n';
        std::abort();
    }
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

// Deterministic bytes from a 64-bit xorshift: the same "random" inputs on every target.
bytes random_bytes(std::size_t size, std::uint64_t seed) {
    bytes out(size);
    std::uint64_t x = seed | 1U;
    for (auto& b : out) {
        x ^= x << 13U;
        x ^= x >> 7U;
        x ^= x << 17U;
        b = static_cast<std::uint8_t>(x >> 56U);
    }
    return out;
}

// The lengths every agreement covers: around each rate of the family (72, 104, 136, 144 and 168
// bytes) and past two blocks of the widest.
std::vector<std::size_t> const& lengths() {
    static std::vector<std::size_t> const all{
        0, 1, 3, 71, 72, 73, 103, 104, 105, 135, 136, 137, 143, 144, 145, 167, 168, 169, 400, 1000,
    };
    return all;
}

// The output of Digest on xkcp over input, of `size` bytes, in one call.
template <class Digest>
bytes once(std::span<std::uint8_t const> input, std::size_t size) {
    bytes output(size);
    test::require(BOOST_TEST((hash::digest_of<Digest, xkcp>(output, input).has_value())));
    return output;
}

// The same through a hasher, the input in three pieces cut at first and second.
template <class Digest>
bytes in_pieces(std::span<std::uint8_t const> input, std::size_t first, std::size_t second,
                std::size_t size) {
    auto hashing = hash::hasher<Digest, xkcp>::make();
    test::require(BOOST_TEST(hashing.has_value()));
    BOOST_TEST(hashing->update(input.first(first)).has_value());
    BOOST_TEST(hashing->update(input.subspan(first, second - first)).has_value());
    BOOST_TEST(hashing->update(input.subspan(second)).has_value());
    bytes output(size);
    BOOST_TEST(hashing->finish(output).has_value());
    return output;
}

// Digest on xkcp against expected, in one call and in pieces at a few splits.
template <class Digest>
void expect(std::span<std::uint8_t const> input, bytes const& expected, std::string const& what) {
    if (!BOOST_TEST(once<Digest>(input, expected.size()) == expected)) {
        std::cerr << "  digest_of: " << what << '\n';
    }
    std::size_t const n = input.size();
    for (auto const& [first, second] : {
             std::pair{std::size_t{0}, n},
             std::pair{n / 3, 2 * n / 3},
             std::pair{n / 2, n / 2},
             std::pair{n, n},
         }) {
        if (!BOOST_TEST(in_pieces<Digest>(input, first, second, expected.size()) == expected)) {
            std::cerr << "  hasher split at " << first << ", " << second << ": " << what << '\n';
        }
    }
}

// A Boost.Hash2 algorithm's results over input, concatenated and cut to size bytes: one result
// for a fixed-size digest, the stream's successive blocks for SHAKE.
template <class Hash>
bytes hash2_of(std::span<std::uint8_t const> input, std::size_t size) {
    Hash hashed;
    hashed.update(input.data(), input.size());
    bytes out;
    while (out.size() < size) {
        auto const result = hashed.result();
        out.insert(out.end(), result.begin(), result.end());
    }
    out.resize(size);
    return out;
}

// Digest on xkcp against the Boost.Hash2 algorithm Hash, of size bytes, over every length.
template <class Digest, class Hash>
void agree_with_hash2(std::string_view name, std::size_t size) {
    std::uint64_t seed = 0x9E3779B97F4A7C15U;
    for (std::size_t const length : lengths()) {
        auto const input = random_bytes(length, seed++);
        expect<Digest>(input, hash2_of<Hash>(input, size),
                       std::string(name) + " over " + std::to_string(length) + " bytes, " +
                           std::to_string(size) + " out");
    }
}

// The Keccak team's digests of "" and "abc", then Boost.Hash2's keccak_base with Keccak's
// padding byte 0x01, capacity 2n and digest n bits.
void check_keccak() {
    namespace h2d = boost::hash2::detail;
    bytes const empty;
    bytes const abc{0x61, 0x62, 0x63};
    auto const v = [](std::string_view hex) { return test::from_hex(hex); };

    expect<digests::keccak_224>(
        empty, v("f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd"), "keccak_224()");
    expect<digests::keccak_224>(abc, v("c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8"),
                                "keccak_224(abc)");
    expect<digests::keccak_256>(
        empty, v("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
        "keccak_256()");
    expect<digests::keccak_256>(
        abc, v("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
        "keccak_256(abc)");
    expect<digests::keccak_384>(empty,
                                v("2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b"
                                  "2dd2b21362337441ac12b515911957ff"),
                                "keccak_384()");
    expect<digests::keccak_384>(abc,
                                v("f7df1165f033337be098e7d288ad6a2f74409d7a60b49c36642218de161b1f99"
                                  "f8c681e4afaf31a34db29fb763e3c28e"),
                                "keccak_384(abc)");
    expect<digests::keccak_512>(
        empty,
        v("0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304"
          "c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e"),
        "keccak_512()");
    expect<digests::keccak_512>(
        abc,
        v("18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5"
          "d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96"),
        "keccak_512(abc)");

    agree_with_hash2<digests::keccak_224, h2d::keccak_base<0x01, 2 * 224, 224>>("keccak_224", 28);
    agree_with_hash2<digests::keccak_256, h2d::keccak_base<0x01, 2 * 256, 256>>("keccak_256", 32);
    agree_with_hash2<digests::keccak_384, h2d::keccak_base<0x01, 2 * 384, 384>>("keccak_384", 48);
    agree_with_hash2<digests::keccak_512, h2d::keccak_base<0x01, 2 * 512, 512>>("keccak_512", 64);
}

// One whole-byte entry of a KAT file: the message and the expected output.
struct kat_entry {
    bytes message;
    bytes expected;
};

// The entries of XKCP's ShortMsgKAT file whose Len is a multiple of 8: "Len = ", "Msg = " (00
// for the empty message) and `output_field` (MD or Squeezed), in that order.
std::vector<kat_entry> read_kat(std::string const& file, std::string_view output_field) {
    std::istringstream text(read_text(std::string(WEBCPP_TEST_XKCP_VECTORS) + "/" + file));
    std::vector<kat_entry> entries;
    std::size_t bits = 0;
    bytes message;
    std::string line;
    std::string const output_prefix = std::string(output_field) + " = ";
    while (std::getline(text, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line.starts_with("Len = ")) {
            bits = std::stoul(line.substr(6));
        } else if (line.starts_with("Msg = ")) {
            message = test::from_hex(line.substr(6));
            message.resize(bits / 8);
        } else if (line.starts_with(output_prefix) && bits % 8 == 0) {
            entries.push_back({
                .message = message,
                .expected = test::from_hex(line.substr(output_prefix.size())),
            });
        }
    }
    return entries;
}

// Every whole-byte entry of a KAT file through Digest on xkcp; the file at the pin holds 256.
template <class Digest>
void check_kat(std::string const& file, std::string_view output_field) {
    auto const entries = read_kat(file, output_field);
    BOOST_TEST_EQ(entries.size(), std::size_t{256});
    for (auto const& entry : entries) {
        expect<Digest>(entry.message, entry.expected,
                       file + " Len = " + std::to_string(entry.message.size() * 8));
    }
}

void check_sha3() {
    namespace h2 = boost::hash2;
    check_kat<digests::sha3_224>("ShortMsgKAT_SHA3-224.txt", "MD");
    check_kat<digests::sha3_256>("ShortMsgKAT_SHA3-256.txt", "MD");
    check_kat<digests::sha3_384>("ShortMsgKAT_SHA3-384.txt", "MD");
    check_kat<digests::sha3_512>("ShortMsgKAT_SHA3-512.txt", "MD");
    agree_with_hash2<digests::sha3_224, h2::sha3_224>("sha3_224", 28);
    agree_with_hash2<digests::sha3_256, h2::sha3_256>("sha3_256", 32);
    agree_with_hash2<digests::sha3_384, h2::sha3_384>("sha3_384", 48);
    agree_with_hash2<digests::sha3_512, h2::sha3_512>("sha3_512", 64);
}

// SHAKE: the KAT files' 512 squeezed bytes; Boost.Hash2's stream at 1 byte, within its first
// block, at the block (168 and 136 bytes), one past it, and over three blocks.
void check_shake() {
    namespace h2 = boost::hash2;
    check_kat<digests::shake_128>("ShortMsgKAT_SHAKE128.txt", "Squeezed");
    check_kat<digests::shake_256>("ShortMsgKAT_SHAKE256.txt", "Squeezed");
    for (std::size_t const size : {1U, 32U, 167U, 168U, 169U, 505U}) {
        agree_with_hash2<digests::shake_128, h2::shake_128>("shake_128", size);
    }
    for (std::size_t const size : {1U, 64U, 135U, 136U, 137U, 409U}) {
        agree_with_hash2<digests::shake_256, h2::shake_256>("shake_256", size);
    }
}

}  // namespace

int main() {
    check_keccak();
    check_sha3();
    check_shake();
    return webcpp::test::exit_status(boost::report_errors());
}
