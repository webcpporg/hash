// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// blake2b_subkey on backends::sodium, libsodium's crypto_kdf_blake2b_derive_from_key, against
// libsodium's test/default/kdf.exp read at run time from the pinned submodule (ruling R5): the
// master key 00..1f and the context "KDF test", ten 64-byte subkeys of ids 0 to 9, then one subkey
// per length of 0 to 65 bytes, of the id equal to its length, where the lengths outside 16 to 64
// fail (here invalid_output_size, the output as it was). Then the construction itself, keyed
// BLAKE2b with the id in the salt and the context in the personalisation, through digest_of; ids
// past 32 bits against Python's hashlib; and the guards (ruling R22).

#include <webcpp/hash/backends/sodium.hpp>
#include <webcpp/hash/blake2b_subkey.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/test/exit_status.hpp>

#include "require.hpp"
#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
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
#include <type_traits>
#include <vector>

namespace {

namespace hash = webcpp::hash;
namespace test = webcpp::test;
namespace kdfs = webcpp::hash::kdfs;
namespace digests = webcpp::hash::digests;
namespace backends = webcpp::hash::backends;

static_assert(std::is_same_v<hash::default_backend<kdfs::blake2b_subkey>, backends::sodium>);
static_assert(hash::backend_has_v<backends::sodium, kdfs::blake2b_subkey, void>);
static_assert(!hash::backend_has_v<backends::hash2, kdfs::blake2b_subkey, void>);

// kdf.exp: 10 subkeys of 64 bytes, 66 lengths, then the test's own last line.
constexpr std::size_t fixed_count = 10;
constexpr std::size_t length_count = 66;
constexpr std::size_t line_count = fixed_count + length_count + 1;

// The whole file at path; one that cannot be opened ends the test, by name.
std::string read_text(std::string const& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cerr << "cannot open test data: " << path << '\n';
        std::abort();
    }
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

// The file's lines, without a trailing carriage return.
std::vector<std::string> read_lines(std::string const& path) {
    std::istringstream text(read_text(path));
    std::vector<std::string> lines;
    for (std::string line; std::getline(text, line);) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        lines.push_back(line);
    }
    return lines;
}

bool failed_with(boost::system::result<void> const& outcome, hash::error expected) {
    return outcome.has_error() && outcome.error() == expected;
}

// Whether every byte is `value`.
bool all_of(std::span<std::uint8_t const> bytes, std::uint8_t value) {
    return std::ranges::all_of(bytes, [value](std::uint8_t byte) { return byte == value; });
}

// kdf.exp's master key, 00 01 ... 1f.
std::array<std::uint8_t, 32> counting_master_key() {
    std::array<std::uint8_t, 32> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>(i);
    }
    return key;
}

// The bytes of an ASCII text.
std::vector<std::uint8_t> bytes_of(std::string_view text) {
    return {text.begin(), text.end()};
}

// Every line of kdf.exp: on the default backend and on backends::sodium named.
void check_kdf_exp() {
    auto const lines = read_lines(WEBCPP_TEST_SODIUM_VECTORS "/kdf.exp");
    test::require(BOOST_TEST_EQ(lines.size(), line_count));
    BOOST_TEST_EQ(lines.back(), "tv_kdf: ok");
    auto const master = counting_master_key();
    auto const context = bytes_of("KDF test");

    for (std::uint64_t id = 0; id < fixed_count; ++id) {
        std::array<std::uint8_t, 64> by_default{};
        std::array<std::uint8_t, 64> named{};
        bool const derived =
            hash::blake2b_subkey(by_default, master, id, context).has_value() &&
            hash::blake2b_subkey<backends::sodium>(named, master, id, context).has_value();
        auto const& expected = lines[static_cast<std::size_t>(id)];
        if (!BOOST_TEST(derived) || !BOOST_TEST_EQ(test::to_hex(by_default), expected) ||
            !BOOST_TEST_EQ(test::to_hex(named), expected)) {
            std::cerr << "  kdf.exp, subkey id " << id << '\n';
        }
    }

    for (std::size_t length = 0; length < length_count; ++length) {
        auto const& expected = lines[fixed_count + length];
        std::vector<std::uint8_t> subkey(length, 0x5A);
        auto const derived = hash::blake2b_subkey(subkey, master, length, context);
        bool const fine =
            expected.starts_with("Failure")
                ? failed_with(derived, hash::error::invalid_output_size) && all_of(subkey, 0x5A)
                : derived.has_value() && test::to_hex(subkey) == expected;
        if (!BOOST_TEST(fine)) {
            std::cerr << "  kdf.exp, length " << length << ": " << expected << '\n';
        }
    }
}

// The subkey is BLAKE2b of the empty message under the master key, of the subkey's length, with
// the id in 8 little-endian bytes then 8 zero bytes as the salt, and the context then 8 zero bytes
// as the personalisation: digest_of on backends::sodium gives the same bytes.
void check_construction() {
    auto const master = counting_master_key();
    auto const context = bytes_of("vault v1");
    constexpr std::array<std::uint64_t, 4> ids{0, 1, 0x0102030405060708, 0xffffffffffffffff};
    for (std::uint64_t const id : ids) {
        std::array<std::uint8_t, 16> salt{};
        for (std::size_t i = 0; i < 8; ++i) {
            salt[i] = static_cast<std::uint8_t>((id >> (8U * i)) & 0xffU);
        }
        std::array<std::uint8_t, 16> personalisation{};
        std::ranges::copy(context, personalisation.begin());
        for (std::size_t const length : {16U, 32U, 64U}) {
            std::vector<std::uint8_t> subkey(length);
            std::vector<std::uint8_t> digest(length);
            bool const computed = hash::blake2b_subkey(subkey, master, id, context).has_value() &&
                                  hash::digest_of<digests::blake2b, backends::sodium>(
                                      digest, {},
                                      {
                                          .key = master,
                                          .salt = salt,
                                          .personalisation = personalisation,
                                          .output_size = length,
                                      })
                                      .has_value();
            if (!BOOST_TEST(computed) || !BOOST_TEST(subkey == digest)) {
                std::cerr << "  construction, id " << id << ", length " << length << '\n';
            }
        }
    }
}

// Ids past 32 bits, whose high bytes kdf.exp never sets, against Python 3's
// hashlib.blake2b(b"", digest_size=n, key=master, salt=id.to_bytes(8, "little") + bytes(8),
// person=b"KDF test" + bytes(8)).
void check_wide_ids() {
    auto const master = counting_master_key();
    auto const context = bytes_of("KDF test");
    std::array<std::uint8_t, 32> highest{};
    BOOST_TEST(hash::blake2b_subkey(highest, master, 0xffffffffffffffff, context).has_value());
    BOOST_TEST_EQ(test::to_hex(highest),
                  "500c3043b2b9177ec843ecbe9f98f92d8c11fbbd10a225ab844548de89c21d55");
    std::array<std::uint8_t, 16> ordered{};
    BOOST_TEST(hash::blake2b_subkey(ordered, master, 0x0102030405060708, context).has_value());
    BOOST_TEST_EQ(test::to_hex(ordered), "167de6a9b8ce775405a525366f9f3ba4");
}

// The guards, before any work and in this order: the subkey of 16 to 64 bytes
// (invalid_output_size), the master key of 32 bytes (invalid_key_size), the context of 8 bytes
// (invalid_parameters); the output as it was.
void check_guards() {
    std::array<std::uint8_t, 33> const key_bytes{};
    std::array<std::uint8_t, 9> const context_bytes{};
    auto const refuses = [&](std::size_t output_size, std::size_t key_size,
                             std::size_t context_size, hash::error expected) {
        std::vector<std::uint8_t> subkey(output_size, 0x5A);
        bool const refused =
            failed_with(hash::blake2b_subkey(subkey, std::span(key_bytes).first(key_size), 7,
                                             std::span(context_bytes).first(context_size)),
                        expected);
        if (!BOOST_TEST(refused) || !BOOST_TEST(all_of(subkey, 0x5A))) {
            std::cerr << "  guard: output " << output_size << ", key " << key_size << ", context "
                      << context_size << '\n';
        }
    };
    for (std::size_t const output_size : {0U, 1U, 15U, 65U, 128U}) {
        refuses(output_size, 32, 8, hash::error::invalid_output_size);
    }
    for (std::size_t const key_size : {0U, 16U, 31U, 33U}) {
        refuses(32, key_size, 8, hash::error::invalid_key_size);
    }
    for (std::size_t const context_size : {0U, 7U, 9U}) {
        refuses(32, 32, context_size, hash::error::invalid_parameters);
    }
    refuses(15, 31, 7, hash::error::invalid_output_size);
    refuses(32, 31, 7, hash::error::invalid_key_size);

    // The edges the guards accept.
    for (std::size_t const output_size : {16U, 64U}) {
        std::vector<std::uint8_t> subkey(output_size);
        BOOST_TEST(hash::blake2b_subkey(subkey, std::span(key_bytes).first(32), 7,
                                        std::span(context_bytes).first(8))
                       .has_value());
    }
}

}  // namespace

int main() {
    check_kdf_exp();
    check_construction();
    check_wide_ids();
    check_guards();
    return webcpp::test::exit_status(boost::report_errors());
}
