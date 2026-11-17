// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The digests of backends::openssl (spec 2.15): OpenSSL 3.5.9's default provider through
// EVP_MD_fetch, EVP_DigestInit_ex2, EVP_DigestUpdate, EVP_DigestFinal_ex and EVP_DigestFinalXOF,
// each tag through digest_of and through a hasher fed in random pieces (empty ones included):
// - MD5, SHA-1, the six SHA-2, the four SHA-3, RIPEMD-160, BLAKE2s-256 and MD5-SHA1 (MD5 then
//   SHA-1) against Boost.Hash2 on random inputs;
// - Keccak-224 to Keccak-512 against Boost.Hash2's Keccak (its keccak_base with the padding
//   byte 0x01) and the published digests of "", 0xCC and "abc"; Keccak-256 also against
//   backends::xkcp;
// - SHAKE128 and SHAKE256 at random output sizes (and one of 10,000 bytes) against Boost.Hash2's
//   stream, its results one rate block after another;
// - BLAKE2b unkeyed at every output size from 1 to 64 against backends::sodium, at 64 against
//   Boost.Hash2's blake2b_512; a key, a salt or a personalisation is unsupported_by_backend;
// - SM3 against GB/T 32905-2016's two examples ("abc" and "abcd" sixteen times);
// - the hasher's EVP_MD_CTX freed by finish, by the destructor, and by a move, counted through
//   CRYPTO_set_mem_functions; backends::openssl never a default (design D34).

#include <webcpp/hash/backends/openssl.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/test/exit_status.hpp>

#include "require.hpp"
#include "support/hex.hpp"
#include "support/random_cases.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/blake2.hpp>
#include <boost/hash2/md5.hpp>
#include <boost/hash2/ripemd.hpp>
#include <boost/hash2/sha1.hpp>
#include <boost/hash2/sha2.hpp>
#include <boost/hash2/sha3.hpp>

#include <openssl/crypto.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <span>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace {

namespace hash = webcpp::hash;
namespace digests = webcpp::hash::digests;
namespace test = webcpp::test;
using hash::backends::openssl;

// OpenSSL's blocks alive: each allocation through OpenSSL's allocator adds one, each free of a
// block takes one away, so that a hasher's context freed or not shows in the count.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): OpenSSL's live blocks
std::size_t openssl_live = 0;

void* counting_malloc(std::size_t size, char const* /*file*/, int /*line*/) {
    void* const block = std::malloc(size);
    if (block != nullptr) {
        ++openssl_live;
    }
    return block;
}

void* counting_realloc(void* block, std::size_t size, char const* /*file*/, int /*line*/) {
    // OpenSSL's CRYPTO_realloc sends a null block to malloc and a zero size to free: here the
    // block exists and stays one.
    return std::realloc(block, size);
}

void counting_free(void* block, char const* /*file*/, int /*line*/) {
    if (block != nullptr) {
        --openssl_live;
    }
    std::free(block);
}

// The number of random cases of each digest (the first one empty).
constexpr std::size_t cases = 200;

// A random input of case `index`: the first empty, then up to 300 bytes, every 16th up to 3,000.
std::vector<std::uint8_t> next_input(test::random_source& rnd, std::size_t index) {
    if (index == 0) {
        return {};
    }
    std::size_t const longest = index % 16 == 0 ? 3000 : 300;
    return rnd.bytes(rnd.between(0, longest));
}

// The hasher of `Tag` on OpenSSL over `input` fed in random pieces (empty ones included), into
// `output`.
template <class Tag>
bool hash_in_pieces(test::random_source& rnd, std::span<std::uint8_t const> input,
                    std::span<std::uint8_t> output, hash::digest_options<Tag> const& options = {}) {
    auto made = hash::hasher<Tag, openssl>::make(options);
    if (!made) {
        return false;
    }
    std::size_t offset = 0;
    do {
        std::size_t const piece = std::min(rnd.between(0, 200), input.size() - offset);
        if (!made->update(input.subspan(offset, piece))) {
            return false;
        }
        offset += piece;
    } while (offset < input.size());
    return made->finish(output).has_value();
}

// The bytes of a Boost.Hash2 algorithm's result over `input`.
template <class Hash>
std::vector<std::uint8_t> hash2_of(std::span<std::uint8_t const> input) {
    Hash hashed;
    hashed.update(input.data(), input.size());
    auto const result = hashed.result();
    return {result.begin(), result.end()};
}

// MD5-SHA1's oracle: MD5's 16 bytes, then SHA-1's 20, of the same input.
std::vector<std::uint8_t> md5_sha1_of(std::span<std::uint8_t const> input) {
    auto both = hash2_of<boost::hash2::md5_128>(input);
    auto const second = hash2_of<boost::hash2::sha1_160>(input);
    both.insert(both.end(), second.begin(), second.end());
    return both;
}

// Boost.Hash2's Keccak with the original padding (byte 0x01), of `Bits` output bits.
template <std::size_t Bits>
using keccak_oracle = boost::hash2::detail::keccak_base<0x01, 2 * Bits, Bits>;

// A fixed-size digest on OpenSSL, through digest_of and a hasher, against `reference`, which gives
// the expected bytes of an input.
template <class Tag, class Reference>
void agree_fixed(std::string_view name, std::size_t size, Reference reference) {
    test::random_source rnd(test::agreement_seed);
    for (std::size_t index = 0; index < cases; ++index) {
        auto const input = next_input(rnd, index);
        std::vector<std::uint8_t> const expected = reference(input);
        std::vector<std::uint8_t> once(size, 0x55);
        std::vector<std::uint8_t> pieces(size, 0x55);
        bool const ran_once = hash::digest_of<Tag, openssl>(once, input).has_value();
        bool const ran_pieces = hash_in_pieces<Tag>(rnd, input, pieces);
        if (!BOOST_TEST(ran_once && ran_pieces && expected.size() == size && once == expected &&
                        pieces == expected)) {
            std::cerr << "  " << name << ", case " << index << " (" << input.size()
                      << " bytes), seed " << test::agreement_seed << '\n';
            return;
        }
    }
}

// A digest's printed value of an input, through digest_of and a hasher fed one byte at a time.
template <class Tag>
void printed(std::string_view name, std::span<std::uint8_t const> input, std::string_view hex) {
    std::vector<std::uint8_t> once(hex.size() / 2);
    std::vector<std::uint8_t> pieces(hex.size() / 2);
    bool const ran_once = hash::digest_of<Tag, openssl>(once, input).has_value();
    auto made = hash::hasher<Tag, openssl>::make();
    bool ran_pieces = made.has_value();
    for (std::size_t i = 0; ran_pieces && i < input.size(); ++i) {
        ran_pieces = made->update(input.subspan(i, 1)).has_value();
    }
    ran_pieces = ran_pieces && made->finish(pieces).has_value();
    if (!BOOST_TEST(ran_once && ran_pieces && test::to_hex(once) == hex &&
                    test::to_hex(pieces) == hex)) {
        std::cerr << "  " << name << " of " << test::to_hex(input) << '\n';
    }
}

std::span<std::uint8_t const> text(std::string_view chars) {
    return {reinterpret_cast<std::uint8_t const*>(chars.data()), chars.size()};
}

void check_fixed() {
    namespace h2 = boost::hash2;
    agree_fixed<digests::md5>("md5", 16, hash2_of<h2::md5_128>);
    agree_fixed<digests::sha1>("sha1", 20, hash2_of<h2::sha1_160>);
    agree_fixed<digests::sha2_224>("sha2_224", 28, hash2_of<h2::sha2_224>);
    agree_fixed<digests::sha2_256>("sha2_256", 32, hash2_of<h2::sha2_256>);
    agree_fixed<digests::sha2_384>("sha2_384", 48, hash2_of<h2::sha2_384>);
    agree_fixed<digests::sha2_512>("sha2_512", 64, hash2_of<h2::sha2_512>);
    agree_fixed<digests::sha2_512_224>("sha2_512_224", 28, hash2_of<h2::sha2_512_224>);
    agree_fixed<digests::sha2_512_256>("sha2_512_256", 32, hash2_of<h2::sha2_512_256>);
    agree_fixed<digests::sha3_224>("sha3_224", 28, hash2_of<h2::sha3_224>);
    agree_fixed<digests::sha3_256>("sha3_256", 32, hash2_of<h2::sha3_256>);
    agree_fixed<digests::sha3_384>("sha3_384", 48, hash2_of<h2::sha3_384>);
    agree_fixed<digests::sha3_512>("sha3_512", 64, hash2_of<h2::sha3_512>);
    agree_fixed<digests::ripemd_160>("ripemd_160", 20, hash2_of<h2::ripemd_160>);
    agree_fixed<digests::blake2s_256>("blake2s_256", 32, hash2_of<h2::blake2s_256>);
    agree_fixed<digests::md5_sha1>("md5_sha1", 36, md5_sha1_of);
    agree_fixed<digests::keccak_224>("keccak_224", 28, hash2_of<keccak_oracle<224>>);
    agree_fixed<digests::keccak_256>("keccak_256", 32, hash2_of<keccak_oracle<256>>);
    agree_fixed<digests::keccak_384>("keccak_384", 48, hash2_of<keccak_oracle<384>>);
    agree_fixed<digests::keccak_512>("keccak_512", 64, hash2_of<keccak_oracle<512>>);
}

// Keccak's published digests of "", 0xCC and "abc" (the values of Task 5's keccak_256 tests and
// of the Boost.Hash2 proposal's, test/upstream_keccak_test.cpp), and Keccak-256 against
// backends::xkcp on the random inputs.
void check_keccak() {
    std::array<std::uint8_t, 1> const cc{0xCC};
    printed<digests::keccak_224>("keccak_224", {},
                                 "f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd");
    printed<digests::keccak_224>("keccak_224", cc,
                                 "a9cab59eb40a10b246290f2d6086e32e3689faf1d26b470c899f2802");
    printed<digests::keccak_224>("keccak_224", text("abc"),
                                 "c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8");
    printed<digests::keccak_256>(
        "keccak_256", {}, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    printed<digests::keccak_256>(
        "keccak_256", cc, "eead6dbfc7340a56caedc044696a168870549a6a7f6f56961e84a54bd9970b8a");
    printed<digests::keccak_256>(
        "keccak_256", text("abc"),
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
    printed<digests::keccak_384>("keccak_384", {},
                                 "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b"
                                 "2dd2b21362337441ac12b515911957ff");
    printed<digests::keccak_384>("keccak_384", cc,
                                 "1b84e62a46e5a201861754af5dc95c4a1a69caf4a796ae405680161e29572641"
                                 "f5fa1e8641d7958336ee7b11c58f73e9");
    printed<digests::keccak_384>("keccak_384", text("abc"),
                                 "f7df1165f033337be098e7d288ad6a2f74409d7a60b49c36642218de161b1f99"
                                 "f8c681e4afaf31a34db29fb763e3c28e");
    printed<digests::keccak_512>(
        "keccak_512", {},
        "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304"
        "c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e");
    printed<digests::keccak_512>(
        "keccak_512", cc,
        "8630c13cbd066ea74bbe7fe468fec1dee10edc1254fb4c1b7c5fd69b646e4416"
        "0b8ce01d05a0908ca790dfb080f4b513bc3b6225ece7a810371441a5ac666eb9");
    printed<digests::keccak_512>(
        "keccak_512", text("abc"),
        "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5"
        "d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96");

    agree_fixed<digests::keccak_256>(
        "keccak_256 against backends::xkcp", 32, [](std::span<std::uint8_t const> input) {
            std::vector<std::uint8_t> out(32);
            test::require(
                BOOST_TEST((hash::digest_of<digests::keccak_256, hash::backends::xkcp>(out, input)
                                .has_value())));
            return out;
        });
}

// The first `size` bytes of Boost.Hash2's SHAKE over `input`: its results, one rate block after
// another, are the extendable output.
template <class Shake>
std::vector<std::uint8_t> shake_stream(std::span<std::uint8_t const> input, std::size_t size) {
    Shake hashed;
    hashed.update(input.data(), input.size());
    std::vector<std::uint8_t> out;
    while (out.size() < size) {
        auto const block = hashed.result();
        out.insert(out.end(), block.begin(), block.end());
    }
    out.resize(size);
    return out;
}

// SHAKE on OpenSSL at random output sizes from 1 to 700 bytes, and at 10,000, against Boost.Hash2.
template <class Tag, class Shake>
void agree_shake(std::string_view name) {
    test::random_source rnd(test::agreement_seed);
    for (std::size_t index = 0; index < cases; ++index) {
        auto const input = next_input(rnd, index);
        std::size_t const size = index + 1 == cases ? 10000 : rnd.between(1, 700);
        auto const expected = shake_stream<Shake>(input, size);
        std::vector<std::uint8_t> once(size);
        std::vector<std::uint8_t> pieces(size);
        bool const ran_once = hash::digest_of<Tag, openssl>(once, input).has_value();
        bool const ran_pieces = hash_in_pieces<Tag>(rnd, input, pieces);
        if (!BOOST_TEST(ran_once && ran_pieces && once == expected && pieces == expected)) {
            std::cerr << "  " << name << ", case " << index << ", " << size << " bytes\n";
            return;
        }
    }
    // An empty output is the family's refusal, before OpenSSL.
    std::array<std::uint8_t, 1> one{};
    auto const refused = hash::digest_of<Tag, openssl>(std::span(one).first(0), {});
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::invalid_output_size);
}

// BLAKE2b unkeyed at every output size from 1 to 64 against libsodium, at 64 against Boost.Hash2;
// the options OpenSSL's BLAKE2B-512 does not take are unsupported_by_backend, the output untouched.
void check_blake2b() {
    test::random_source rnd(test::agreement_seed);
    for (std::size_t index = 0; index < cases; ++index) {
        auto const input = next_input(rnd, index);
        std::size_t const size = index < 64 ? index + 1 : rnd.between(1, 64);
        hash::digest_options<digests::blake2b> const options{.output_size = size};
        std::vector<std::uint8_t> expected(size);
        test::require(BOOST_TEST(
            (hash::digest_of<digests::blake2b, hash::backends::sodium>(expected, input, options)
                 .has_value())));
        std::vector<std::uint8_t> once(size);
        std::vector<std::uint8_t> pieces(size);
        bool const ran_once =
            hash::digest_of<digests::blake2b, openssl>(once, input, options).has_value();
        bool const ran_pieces = hash_in_pieces<digests::blake2b>(rnd, input, pieces, options);
        bool const hash2_agrees =
            size != 64 || expected == hash2_of<boost::hash2::blake2b_512>(input);
        if (!BOOST_TEST(ran_once && ran_pieces && once == expected && pieces == expected &&
                        hash2_agrees)) {
            std::cerr << "  blake2b, case " << index << ", " << size << " bytes\n";
            return;
        }
    }

    std::array<std::uint8_t, 16> const sixteen{1, 2, 3};
    std::array<hash::digest_options<digests::blake2b>, 3> const refused_options{
        {
            {.key = sixteen},
            {.salt = sixteen},
            {.personalisation = sixteen},
        },
    };
    for (auto const& options : refused_options) {
        std::array<std::uint8_t, 64> output{};
        output.fill(0x55);
        auto const refused = hash::digest_of<digests::blake2b, openssl>(output, {}, options);
        BOOST_TEST(refused.has_error() && refused.error() == hash::error::unsupported_by_backend);
        BOOST_TEST(std::ranges::all_of(output, [](std::uint8_t b) { return b == 0x55; }));
        auto const made = hash::hasher<digests::blake2b, openssl>::make(options);
        BOOST_TEST(made.has_error() && made.error() == hash::error::unsupported_by_backend);
    }
}

// SM3, GB/T 32905-2016, appendix A: "abc", and "abcd" sixteen times (64 bytes); a hasher in random
// pieces gives digest_of's result on the random inputs.
void check_sm3() {
    printed<digests::sm3>("sm3", text("abc"),
                          "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
    printed<digests::sm3>("sm3",
                          text("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"),
                          "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732");
    agree_fixed<digests::sm3>(
        "sm3, digest_of against the hasher", 32, [](std::span<std::uint8_t const> input) {
            std::vector<std::uint8_t> out(32);
            test::require(
                BOOST_TEST((hash::digest_of<digests::sm3, openssl>(out, input).has_value())));
            return out;
        });
}

// The family's guard on a fixed size: the output untouched, nothing allocated.
void check_guards() {
    std::array<std::uint8_t, 31> short_output{};
    short_output.fill(0x55);
    auto const refused = hash::digest_of<digests::sha2_256, openssl>(short_output, {});
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::invalid_output_size);
    BOOST_TEST(std::ranges::all_of(short_output, [](std::uint8_t b) { return b == 0x55; }));
}

// A hasher owns an EVP_MD_CTX from make on: finish frees it, the destructor frees it unfinished,
// a move hands it over and an assignment over a hash in progress frees the one it replaces. After
// a first call has made OpenSSL's lasting objects (the provider, its method store), every block
// a call allocates is freed by its end.
void check_contexts() {
    std::array<std::uint8_t, 32> output{};
    test::require(
        BOOST_TEST((hash::digest_of<digests::sha2_256, openssl>(output, text("abc")).has_value())));
    std::size_t const before = openssl_live;

    test::require(
        BOOST_TEST((hash::digest_of<digests::sha2_256, openssl>(output, text("abc")).has_value())));
    BOOST_TEST_EQ(openssl_live, before);

    {
        auto made = hash::hasher<digests::sha2_256, openssl>::make();
        test::require(BOOST_TEST((made.has_value())));
        BOOST_TEST_GT(openssl_live, before);
        test::require(BOOST_TEST((made->update(text("abc")).has_value())));
        test::require(BOOST_TEST((made->finish(output).has_value())));
        BOOST_TEST_EQ(openssl_live, before);
    }
    {
        auto made = hash::hasher<digests::sha2_256, openssl>::make();
        test::require(BOOST_TEST((made.has_value())));
        test::require(BOOST_TEST((made->update(text("ab")).has_value())));
    }
    BOOST_TEST_EQ(openssl_live, before);
    {
        auto first = hash::hasher<digests::sha2_256, openssl>::make();
        test::require(BOOST_TEST((first.has_value())));
        test::require(BOOST_TEST((first->update(text("ab")).has_value())));
        std::size_t const one = openssl_live;
        auto second = std::move(*first);
        BOOST_TEST_EQ(openssl_live, one);
        BOOST_TEST(first->update(text("c")).error() == hash::error::invalid_state);
        auto third = hash::hasher<digests::sha2_256, openssl>::make();
        test::require(BOOST_TEST((third.has_value())));
        *third = std::move(second);
        BOOST_TEST_EQ(openssl_live, one);
        test::require(BOOST_TEST((third->update(text("c")).has_value())));
        test::require(BOOST_TEST((third->finish(output).has_value())));
        BOOST_TEST_EQ(test::to_hex(output),
                      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
    BOOST_TEST_EQ(openssl_live, before);
}

// backends::openssl has each of these tags, and is the default of none (design D34): a call
// reaches it only by naming it.
template <class... Tag>
constexpr bool in_openssl_by_name() {
    return ((hash::backend_has_v<openssl, Tag, void> &&
             !std::is_same_v<hash::default_backend<Tag>, openssl>) &&
            ...);
}

static_assert(in_openssl_by_name<
              digests::md5, digests::sha1, digests::sha2_224, digests::sha2_256, digests::sha2_384,
              digests::sha2_512, digests::sha2_512_224, digests::sha2_512_256, digests::sha3_224,
              digests::sha3_256, digests::sha3_384, digests::sha3_512, digests::shake_128,
              digests::shake_256, digests::keccak_224, digests::keccak_256, digests::keccak_384,
              digests::keccak_512, digests::blake2b, digests::blake2s_256, digests::ripemd_160,
              digests::md5_sha1, digests::sm3>());
// MD5-SHA1 and SM3 have no backend of D34's order: the call names one.
static_assert(std::is_same_v<hash::default_backend<digests::md5_sha1>, hash::detail::no_default>);
static_assert(std::is_same_v<hash::default_backend<digests::sm3>, hash::detail::no_default>);
// The legacy provider's Whirlpool is not loaded (doc/capabilities.json says why).
static_assert(!hash::backend_has_v<openssl, digests::whirlpool, void>);

}  // namespace

int main() {
    // Before anything: OpenSSL allocates through the test's functions from here on.
    test::require(BOOST_TEST(
        (CRYPTO_set_mem_functions(&counting_malloc, &counting_realloc, &counting_free) == 1)));
    check_contexts();
    check_fixed();
    check_keccak();
    agree_shake<digests::shake_128, boost::hash2::shake_128>("shake_128");
    agree_shake<digests::shake_256, boost::hash2::shake_256>("shake_256");
    check_blake2b();
    check_sm3();
    check_guards();
    return webcpp::test::exit_status(boost::report_errors());
}
