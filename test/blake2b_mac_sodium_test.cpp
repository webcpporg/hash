// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// macs::blake2b_mac on backends::sodium, its default, libsodium's keyed
// crypto_generichash_blake2b_*, through mac (ruling R95): every case of BLAKE2's
// testvectors/blake2b-kat.txt read at run time from its pinned file (ruling R5), on
// backends::sodium named and on the default; Boost.Hash2's keyed blake2b_512 on random keys and
// inputs at the 64-byte tag (agreement with Hash2, which has no cell of the tag), and
// digests::blake2b keyed on backends::sodium at every tag size; every key and tag size of RFC
// 7693, those under libsodium's advisory 16-byte minimums included; the family's guards; and the
// wipe of libsodium's state after each call, reported through the seam
// WEBCPP_HASH_DETAIL_TEST_WIPE_RECORD. The agreement with backends::openssl on random cases is
// agreement_families_test's.

#include <webcpp/hash/algorithms.hpp>
#include <webcpp/hash/backends/sodium.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/test/exit_status.hpp>

#include "require.hpp"
#include "support/data_file.hpp"
#include "support/hex.hpp"
#include "support/random_cases.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/system/result.hpp>

#include <sodium/crypto_generichash_blake2b.h>  // third_party/libs/libsodium

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#ifndef WEBCPP_HASH_DETAIL_TEST_WIPE_RECORD
#error "blake2b_mac_sodium_test is built with WEBCPP_HASH_DETAIL_TEST_WIPE_RECORD (test/Jamfile)"
#endif

namespace {

namespace hash = webcpp::hash;
namespace test = webcpp::test;
namespace macs = webcpp::hash::macs;
namespace digests = webcpp::hash::digests;
namespace backends = webcpp::hash::backends;

using bytes = std::vector<std::uint8_t>;

// libsodium is the first backend of the order that has keyed BLAKE2b whole: its default.
static_assert(std::is_same_v<hash::default_backend<macs::blake2b_mac>, backends::sodium>);
static_assert(hash::backend_has_v<backends::sodium, macs::blake2b_mac, void>);

// The wipes since the last clear: the sizes of the first 16, how many in all, and how many found
// a byte not zero.
struct record {
    std::array<std::size_t, 16> sizes{};
    std::size_t count = 0;
    std::size_t not_zero = 0;

    // How many of the recorded wipes were of `size` bytes.
    [[nodiscard]] std::size_t of_size(std::size_t size) const {
        auto const recorded = std::span(sizes).first(std::min(count, sizes.size()));
        return static_cast<std::size_t>(std::ranges::count(recorded, size));
    }
};

// The seam's record, which detail::wipe reaches through a function of this test.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the seam's record
record wipes;

bool failed_with(boost::system::result<void> const& outcome, hash::error expected) {
    return outcome.has_error() && outcome.error() == expected;
}

// Whether every byte is `value`.
bool all_of(std::span<std::uint8_t const> bytes, std::uint8_t value) {
    return std::ranges::all_of(bytes, [value](std::uint8_t byte) { return byte == value; });
}

// The tag of `input` under `key` on backends::sodium named, with the wipes of the call checked:
// one of libsodium's state, every byte zero, and nothing else.
bool sodium_tag(std::span<std::uint8_t> tag, std::span<std::uint8_t const> key,
                std::span<std::uint8_t const> input) {
    wipes = {};
    bool const computed =
        hash::mac<macs::blake2b_mac, backends::sodium>(tag, key, input).has_value();
    BOOST_TEST_EQ(wipes.count, 1U);
    BOOST_TEST_EQ(wipes.of_size(sizeof(crypto_generichash_blake2b_state)), 1U);
    BOOST_TEST_EQ(wipes.not_zero, 0U);
    return computed;
}

// The value after "<name>:\t" on a line of blake2b-kat.txt; a line of another form ends the test.
std::string kat_value(std::string const& line, std::string_view name) {
    std::string const prefix = std::string(name) + ":\t";
    if (!line.starts_with(prefix)) {
        std::cerr << "blake2b-kat.txt: expected " << name << ", read: " << line << '\n';
        std::abort();
    }
    return line.substr(prefix.size());
}

// Every case of blake2b-kat.txt, stanzas of "in:", "key:" and "hash:" lines (a 64-byte key, inputs
// of 0 to 255 bytes, a 64-byte tag): on backends::sodium named, and on the default, which reaches
// it.
void check_keyed_kat() {
    auto const lines = test::read_lines(WEBCPP_TEST_BLAKE2_VECTORS "/blake2b-kat.txt");
    std::size_t run = 0;
    for (std::size_t index = 0; index + 2 < lines.size(); ++index) {
        if (!lines[index].starts_with("in:")) {
            continue;
        }
        auto const input = test::from_hex(kat_value(lines[index], "in"));
        auto const key = test::from_hex(kat_value(lines[index + 1], "key"));
        auto const expected = kat_value(lines[index + 2], "hash");
        test::require(BOOST_TEST_EQ(key.size(), 64U));
        bytes named(64, 0x5A);
        bytes by_default(64, 0x5A);
        bool const computed = sodium_tag(named, key, input) &&
                              hash::mac<macs::blake2b_mac>(by_default, key, input).has_value();
        if (!BOOST_TEST(computed) || !BOOST_TEST_EQ(test::to_hex(named), expected) ||
            !BOOST_TEST_EQ(test::to_hex(by_default), expected)) {
            std::cerr << "  blake2b-kat.txt, input of " << input.size() << " bytes\n";
        }
        index += 2;
        ++run;
    }
    BOOST_TEST_EQ(run, 256U);
}

// The number of random cases.
constexpr std::size_t cases = 500;

// A random input of case `index`: the first empty, then up to 300 bytes, every 16th up to 3,000.
bytes next_input(test::random_source& rnd, std::size_t index) {
    if (index == 0) {
        return {};
    }
    std::size_t const longest = index % 16 == 0 ? 3000 : 300;
    return rnd.bytes(rnd.between(0, longest));
}

// Random keys of 1 to 64 bytes and inputs: the 64-byte tag against Boost.Hash2's keyed
// blake2b_512, and every tag size from 1 to 64 bytes against digests::blake2b keyed on
// backends::sodium (the length a parameter of the hash, never a cut).
void agree() {
    test::random_source rnd(test::agreement_seed);
    for (std::size_t index = 0; index < cases; ++index) {
        auto const key = rnd.bytes(rnd.between(1, 64));
        auto const input = next_input(rnd, index);

        bytes whole(64);
        hash::blake2b_512 reference(key.data(), key.size());
        reference.update(input.data(), input.size());
        auto const expected_whole = reference.result();
        if (!BOOST_TEST(sodium_tag(whole, key, input)) ||
            !BOOST_TEST(std::ranges::equal(whole, expected_whole))) {
            std::cerr << "  blake2b_512, case " << index << ", key " << key.size() << '\n';
        }

        std::size_t const tag_size = 1 + (index % 64);
        bytes tag(tag_size);
        bytes expected(tag_size);
        bool const oracle = hash::digest_of<digests::blake2b, backends::sodium>(
                                expected, input, {.key = key, .output_size = tag_size})
                                .has_value();
        if (!BOOST_TEST(sodium_tag(tag, key, input) && oracle) ||
            !BOOST_TEST_EQ(test::to_hex(tag), test::to_hex(expected))) {
            std::cerr << "  digests::blake2b, case " << index << ", key " << key.size() << ", tag "
                      << tag_size << '\n';
        }
    }
}

// Every key and tag size RFC 7693 gives keyed BLAKE2b, 1 to 64 bytes each, served whole:
// libsodium's crypto_generichash_blake2b_BYTES_MIN and _KEYBYTES_MIN, 16, are advice its functions
// do not check, so a tag or a key under 16 bytes is computed, never unsupported_by_backend.
void check_sizes() {
    std::array<std::uint8_t, 3> const input{0x61, 0x62, 0x63};
    bytes const key(64, 0x07);
    for (std::size_t key_size = 1; key_size <= 64; ++key_size) {
        for (std::size_t tag_size = 1; tag_size <= 64; tag_size += key_size < 16 ? 1 : 21) {
            auto const chosen_key = std::span(key).first(key_size);
            bytes tag(tag_size, 0x5A);
            bytes expected(tag_size);
            bool const oracle = hash::digest_of<digests::blake2b, backends::sodium>(
                                    expected, input, {.key = chosen_key, .output_size = tag_size})
                                    .has_value();
            if (!BOOST_TEST(sodium_tag(tag, chosen_key, input) && oracle) ||
                !BOOST_TEST(tag == expected)) {
                std::cerr << "  key " << key_size << ", tag " << tag_size << '\n';
            }
        }
    }
}

// The family's guards (RFC 7693's sizes), before any work and without a wipe: a tag of 0 or 65
// bytes is invalid_output_size, a key of 0 or 65 bytes invalid_key_size, the output as it was; the
// same on the default.
void check_guards() {
    std::array<std::uint8_t, 3> const message{0x61, 0x62, 0x63};
    bytes const any_key(65, 0x0b);
    auto const refuses = [&](std::size_t tag_size, std::size_t key_size, hash::error expected) {
        bytes tag(tag_size, 0x5A);
        auto const key = std::span(any_key).first(key_size);
        wipes = {};
        bool const refused =
            failed_with(hash::mac<macs::blake2b_mac, backends::sodium>(tag, key, message),
                        expected) &&
            failed_with(hash::mac<macs::blake2b_mac>(tag, key, message), expected);
        if (!BOOST_TEST(refused) || !BOOST_TEST(all_of(tag, 0x5A)) ||
            !BOOST_TEST_EQ(wipes.count, 0U)) {
            std::cerr << "  a tag of " << tag_size << " bytes, a key of " << key_size << '\n';
        }
    };
    refuses(0, 32, hash::error::invalid_output_size);
    refuses(65, 32, hash::error::invalid_output_size);
    refuses(32, 0, hash::error::invalid_key_size);
    refuses(32, 65, hash::error::invalid_key_size);
}

}  // namespace

void webcpp::hash::detail::test::wipe_record(void const* wiped_data,
                                             std::size_t byte_count) noexcept {
    auto const* const wiped = static_cast<unsigned char const*>(wiped_data);
    if (!std::all_of(wiped, wiped + byte_count, [](unsigned char byte) { return byte == 0; })) {
        ++wipes.not_zero;
    }
    if (wipes.count < wipes.sizes.size()) {
        wipes.sizes[wipes.count] = byte_count;
    }
    ++wipes.count;
}

int main() {
    check_keyed_kat();
    agree();
    check_sizes();
    check_guards();
    return webcpp::test::exit_status(boost::report_errors());
}
