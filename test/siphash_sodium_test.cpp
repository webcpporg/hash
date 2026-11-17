// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// macs::siphash_2_4 and macs::siphash_2_4x on backends::sodium, libsodium's
// crypto_shorthash_siphash24 and crypto_shorthash_siphashx24, through mac, against published
// vectors read at run time from their pinned files (ruling R5): SipHash-2-4 against the 64
// reference vectors of the SipHash paper (Aumasson and Bernstein, appendix A: the key 00..0f over
// the inputs of 0 to 63 bytes, empty, 00, 00 01, ...), which libsodium's test/default/shorthash.exp
// prints and which backends::hash2 and Boost.Hash2's siphash_64 also give (agreement with Hash2);
// SipHash-2-4 with a 16-byte tag against libsodium's test/default/siphashx24.exp, the same key and
// inputs. Then backends::sodium against backends::hash2 on longer inputs, and the family's guards
// on backends::sodium.

#include <webcpp/hash/algorithms.hpp>
#include <webcpp/hash/backends/sodium.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/test/exit_status.hpp>

#include "require.hpp"
#include "support/data_file.hpp"
#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace {

namespace hash = webcpp::hash;
namespace test = webcpp::test;
namespace macs = webcpp::hash::macs;
namespace backends = webcpp::hash::backends;

// SipHash-2-4 keeps backends::hash2, the first backend of the order, as its default; SipHash-2-4x
// is libsodium's alone.
static_assert(std::is_same_v<hash::default_backend<macs::siphash_2_4>, backends::hash2>);
static_assert(std::is_same_v<hash::default_backend<macs::siphash_2_4x>, backends::sodium>);
static_assert(hash::backend_has_v<backends::sodium, macs::siphash_2_4, void>);
static_assert(hash::backend_has_v<backends::sodium, macs::siphash_2_4x, void>);

// The number of vectors in each file: the inputs of 0 to 63 bytes.
constexpr std::size_t vector_count = 64;

bool failed_with(boost::system::result<void> const& outcome, hash::error expected) {
    return outcome.has_error() && outcome.error() == expected;
}

// Whether every byte is `value`.
bool all_of(std::span<std::uint8_t const> bytes, std::uint8_t value) {
    return std::ranges::all_of(bytes, [value](std::uint8_t byte) { return byte == value; });
}

// The vectors' key, 00 01 ... 0f, and their inputs, 00 01 ... 3e: input i is the first i bytes.
std::array<std::uint8_t, 16> counting_key() {
    std::array<std::uint8_t, 16> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>(i);
    }
    return key;
}

std::array<std::uint8_t, vector_count> counting_input() {
    std::array<std::uint8_t, vector_count> input{};
    for (std::size_t i = 0; i < input.size(); ++i) {
        input[i] = static_cast<std::uint8_t>(i);
    }
    return input;
}

// The tag of `input` under `key` by Boost.Hash2's siphash_64, written little-endian, as the
// SipHash paper's reference implementation writes its 64-bit result.
std::array<std::uint8_t, 8> hash2_siphash(std::span<std::uint8_t const> key,
                                          std::span<std::uint8_t const> input) {
    hash::siphash_64 keyed(key.data(), key.size());
    keyed.update(input.data(), input.size());
    std::uint64_t value = keyed.result();
    std::array<std::uint8_t, 8> tag{};
    for (auto& byte : tag) {
        byte = static_cast<std::uint8_t>(value & 0xffU);
        value >>= 8U;
    }
    return tag;
}

// SipHash-2-4 against shorthash.exp, the paper's 64 vectors: on backends::sodium, on
// backends::hash2 (the default) and by Boost.Hash2's siphash_64.
void check_siphash_2_4() {
    auto const lines = test::read_lines(WEBCPP_TEST_SODIUM_VECTORS "/shorthash.exp");
    test::require(BOOST_TEST_EQ(lines.size(), vector_count));
    // The SipHash paper, appendix A, vectors_sip64[0]: the tag of the empty input.
    BOOST_TEST_EQ(lines.front(), "310e0edd47db6f72");
    auto const key = counting_key();
    auto const input = counting_input();
    for (std::size_t i = 0; i < vector_count; ++i) {
        auto const message = std::span(input).first(i);
        std::array<std::uint8_t, 8> on_sodium{};
        std::array<std::uint8_t, 8> on_hash2{};
        bool const computed =
            hash::mac<macs::siphash_2_4, backends::sodium>(on_sodium, key, message).has_value() &&
            hash::mac<macs::siphash_2_4>(on_hash2, key, message).has_value();
        if (!BOOST_TEST(computed) || !BOOST_TEST_EQ(test::to_hex(on_sodium), lines[i]) ||
            !BOOST_TEST_EQ(test::to_hex(on_hash2), lines[i]) ||
            !BOOST_TEST_EQ(test::to_hex(hash2_siphash(key, message)), lines[i])) {
            std::cerr << "  siphash_2_4, input of " << i << " bytes\n";
        }
    }
}

// SipHash-2-4x against siphashx24.exp: on backends::sodium named, and on the default.
void check_siphash_2_4x() {
    auto const lines = test::read_lines(WEBCPP_TEST_SODIUM_VECTORS "/siphashx24.exp");
    test::require(BOOST_TEST_EQ(lines.size(), vector_count));
    auto const key = counting_key();
    auto const input = counting_input();
    for (std::size_t i = 0; i < vector_count; ++i) {
        auto const message = std::span(input).first(i);
        std::array<std::uint8_t, 16> named{};
        std::array<std::uint8_t, 16> by_default{};
        bool const computed =
            hash::mac<macs::siphash_2_4x, backends::sodium>(named, key, message).has_value() &&
            hash::mac<macs::siphash_2_4x>(by_default, key, message).has_value();
        if (!BOOST_TEST(computed) || !BOOST_TEST_EQ(test::to_hex(named), lines[i]) ||
            !BOOST_TEST_EQ(test::to_hex(by_default), lines[i])) {
            std::cerr << "  siphash_2_4x, input of " << i << " bytes\n";
        }
    }
}

// backends::sodium and backends::hash2 give one SipHash-2-4 over inputs of 64 to 1,024 bytes, each
// length's bytes and key a function of the length.
void check_agreement() {
    for (std::size_t length = vector_count; length <= 1024; length += 37) {
        std::vector<std::uint8_t> message(length);
        std::array<std::uint8_t, 16> key{};
        for (std::size_t i = 0; i < message.size(); ++i) {
            message[i] = static_cast<std::uint8_t>(((i * 131U) + length) & 0xffU);
        }
        for (std::size_t i = 0; i < key.size(); ++i) {
            key[i] = static_cast<std::uint8_t>(((i * 29U) + (length * 7U)) & 0xffU);
        }
        std::array<std::uint8_t, 8> on_sodium{};
        std::array<std::uint8_t, 8> on_hash2{};
        bool const computed =
            hash::mac<macs::siphash_2_4, backends::sodium>(on_sodium, key, message).has_value() &&
            hash::mac<macs::siphash_2_4, backends::hash2>(on_hash2, key, message).has_value();
        if (!BOOST_TEST(computed) || !BOOST_TEST(on_sodium == on_hash2)) {
            std::cerr << "  agreement, input of " << length << " bytes\n";
        }
    }
}

// The family's guards on backends::sodium, before any work: a tag of another size is
// invalid_output_size, a key of another size invalid_key_size, the output as it was.
template <class Mac, std::size_t TagSize>
void check_guards(std::string_view name) {
    std::array<std::uint8_t, 3> const message{0x61, 0x62, 0x63};
    std::array<std::uint8_t, 17> const any_key{};
    auto const refuses = [&](std::size_t tag_size, std::size_t key_size, hash::error expected) {
        std::vector<std::uint8_t> tag(tag_size, 0x5A);
        bool const refused = failed_with(
            hash::mac<Mac, backends::sodium>(tag, std::span(any_key).first(key_size), message),
            expected);
        if (!BOOST_TEST(refused) || !BOOST_TEST(all_of(tag, 0x5A))) {
            std::cerr << "  " << name << ": a tag of " << tag_size << " bytes, a key of "
                      << key_size << '\n';
        }
    };
    refuses(0, 16, hash::error::invalid_output_size);
    refuses(TagSize - 1, 16, hash::error::invalid_output_size);
    refuses(TagSize + 1, 16, hash::error::invalid_output_size);
    refuses(TagSize, 0, hash::error::invalid_key_size);
    refuses(TagSize, 15, hash::error::invalid_key_size);
    refuses(TagSize, 17, hash::error::invalid_key_size);
}

}  // namespace

int main() {
    check_siphash_2_4();
    check_siphash_2_4x();
    check_agreement();
    check_guards<macs::siphash_2_4, 8>("siphash_2_4");
    check_guards<macs::siphash_2_4x, 16>("siphash_2_4x");
    return webcpp::test::exit_status(boost::report_errors());
}
