// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// digests::blake2b on backends::sodium, libsodium's crypto_generichash_blake2b_*, with its key,
// salt, personalisation and output size (RFC 7693), through digest_of and hasher, against
// published vectors read at run time from their pinned files (ruling R5): every keyed case of
// BLAKE2's testvectors/blake2b-kat.txt (a 64-byte key, inputs of 0 to 255 bytes, 64-byte outputs);
// every unkeyed BLAKE2b case of testvectors/blake2-kat.json, which Boost.Hash2's blake2b_512 and
// backends::hash2 also compute; every case of libsodium's test/default/generichash3.exp that the
// family can express (salt and personalisation, keys and outputs of 1 to 64 bytes). Then outputs of
// 16 and 32 bytes against Python's hashlib, and the family's guards (ruling R21).

#include <webcpp/hash/algorithms.hpp>
#include <webcpp/hash/backends/sodium.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/test/exit_status.hpp>

#include "require.hpp"
#include "support/data_file.hpp"
#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/json.hpp>
#include <boost/system/error_code.hpp>

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

namespace {

namespace hash = webcpp::hash;
namespace json = boost::json;
namespace test = webcpp::test;
namespace digests = webcpp::hash::digests;
namespace backends = webcpp::hash::backends;

using options = hash::digest_options<digests::blake2b>;

static_assert(std::is_same_v<hash::default_backend<digests::blake2b>, backends::sodium>);

bool failed_with(boost::system::result<void> const& outcome, hash::error expected) {
    return outcome.has_error() && outcome.error() == expected;
}

// Whether every byte is `value`.
bool all_of(std::span<std::uint8_t const> bytes, std::uint8_t value) {
    return std::ranges::all_of(bytes, [value](std::uint8_t byte) { return byte == value; });
}

// BLAKE2b of `input` under `chosen`, by digest_of on the default backend, then by a hasher fed in
// two pieces: each must give `expected` (hex). `label` names the case on a failure.
void expect_blake2b(std::span<std::uint8_t const> input, options const& chosen,
                    std::string_view expected, std::string_view label) {
    std::vector<std::uint8_t> once(chosen.output_size, 0x5A);
    auto const hashed = hash::digest_of<digests::blake2b>(once, input, chosen);
    if (!BOOST_TEST(hashed.has_value()) || !BOOST_TEST_EQ(test::to_hex(once), expected)) {
        std::cerr << "  digest_of, " << label << '\n';
    }

    std::vector<std::uint8_t> pieces(chosen.output_size, 0x5A);
    auto hashing = hash::hasher<digests::blake2b, backends::sodium>::make(chosen);
    test::require(BOOST_TEST(hashing.has_value()));
    auto const half = input.size() / 2;
    bool const fed = hashing->update(input.first(half)).has_value() &&
                     hashing->update(input.subspan(half)).has_value() &&
                     hashing->finish(pieces).has_value();
    if (!BOOST_TEST(fed) || !BOOST_TEST_EQ(test::to_hex(pieces), expected)) {
        std::cerr << "  hasher, " << label << '\n';
    }
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

// Every case of blake2b-kat.txt, stanzas of "in:", "key:" and "hash:" lines: the key is 64 bytes,
// the input 0 to 255 bytes, the output 64 bytes.
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
        expect_blake2b(input, {.key = key}, expected,
                       "blake2b-kat.txt, input of " + std::to_string(input.size()) + " bytes");
        index += 2;
        ++run;
    }
    BOOST_TEST_EQ(run, 256U);
}

// Every unkeyed BLAKE2b case of blake2-kat.json (inputs of 0 to 255 bytes, 64-byte outputs): on
// backends::sodium, and the same on backends::hash2 and Boost.Hash2's blake2b_512.
void check_unkeyed_kat() {
    auto const text = test::read_text(WEBCPP_TEST_BLAKE2_VECTORS "/blake2-kat.json");
    boost::system::error_code ec;
    auto const doc = json::parse(text, ec);
    test::require(BOOST_TEST(!ec));
    std::size_t run = 0;
    for (auto const& entry : doc.as_array()) {
        auto const& vector = entry.as_object();
        if (vector.at("hash").as_string() != "blake2b" || !vector.at("key").as_string().empty()) {
            continue;
        }
        auto const input = test::from_hex(vector.at("in").as_string());
        std::string_view const expected = vector.at("out").as_string();
        std::string const label =
            "blake2-kat.json, input of " + std::to_string(input.size()) + " bytes";
        options const unkeyed;
        expect_blake2b(input, unkeyed, expected, label);

        std::array<std::uint8_t, 64> on_hash2{};
        BOOST_TEST(
            (hash::digest_of<digests::blake2b, backends::hash2>(on_hash2, input).has_value()));
        hash::blake2b_512 reference;
        reference.update(input.data(), input.size());
        if (!BOOST_TEST_EQ(test::to_hex(on_hash2), expected) ||
            !BOOST_TEST_EQ(test::to_hex(reference.result()), expected)) {
            std::cerr << "  backends::hash2 or blake2b_512, " << label << '\n';
        }
        ++run;
    }
    BOOST_TEST_EQ(run, 256U);
}

// generichash3.c's salt and personalisation, 16 ASCII bytes each.
std::vector<std::uint8_t> ascii(std::string_view text) {
    return {text.begin(), text.end()};
}

// libsodium's generichash3 test (test/default/generichash3.c at the pin), whose outputs are the
// lines of generichash3.exp, in its order. Its key is bytes 0 to 63; its input bytes 0 to 63.
void check_generichash3() {
    auto const lines = test::read_lines(WEBCPP_TEST_SODIUM_VECTORS "/generichash3.exp");
    test::require(BOOST_TEST_EQ(lines.size(), 75U));
    auto const salt = ascii("5b6b41ed9b343fe0");
    auto const personal = ascii("5126fb2a37400d2a");
    std::vector<std::uint8_t> key(64);
    std::vector<std::uint8_t> input(64);
    for (std::size_t index = 0; index < 64; ++index) {
        key[index] = static_cast<std::uint8_t>(index);
        input[index] = static_cast<std::uint8_t>(index);
    }
    auto const all = std::span<std::uint8_t const>(input);
    auto const whole_key = std::span<std::uint8_t const>(key);

    // Lines 1 to 64: the case i has a key of i + 1 bytes, an output of i + 1 bytes, the input's
    // first i bytes, the salt and the personalisation.
    for (std::size_t index = 0; index < 64; ++index) {
        expect_blake2b(all.first(index),
                       {
                           .key = whole_key.first(index + 1),
                           .salt = salt,
                           .personalisation = personal,
                           .output_size = index + 1,
                       },
                       lines[index], "generichash3.exp line " + std::to_string(index + 1));
    }

    // Lines 65 to 73: a 64-byte output of the whole input. Line 66 is a null key of length 1,
    // which libsodium reads as no key. The cases of lines 70 to 73 are libsodium's one-shot
    // function, the same hash.
    struct line_case {
        std::size_t line;
        std::span<std::uint8_t const> key;
        bool salted;
        bool personalised;
    };

    auto const cases = std::to_array<line_case>({
        {.line = 65, .key = {}, .salted = true, .personalised = true},
        {.line = 66, .key = {}, .salted = true, .personalised = true},
        {.line = 67, .key = whole_key, .salted = false, .personalised = true},
        {.line = 68, .key = whole_key, .salted = true, .personalised = false},
        {.line = 69, .key = {}, .salted = true, .personalised = true},
        {.line = 70, .key = {}, .salted = true, .personalised = true},
        {.line = 71, .key = whole_key, .salted = true, .personalised = true},
        {.line = 72, .key = whole_key, .salted = false, .personalised = true},
        {.line = 73, .key = whole_key, .salted = true, .personalised = false},
    });
    for (auto const& each : cases) {
        options const chosen{
            .key = each.key,
            .salt =
                each.salted ? std::span<std::uint8_t const>(salt) : std::span<std::uint8_t const>(),
            .personalisation = each.personalised ? std::span<std::uint8_t const>(personal)
                                                 : std::span<std::uint8_t const>(),
        };
        expect_blake2b(all, chosen, lines[each.line - 1],
                       "generichash3.exp line " + std::to_string(each.line));
    }
    // Lines 74 and 75 are a state started for 32 bytes and finished with 64, which libsodium's
    // final permits and the family refuses: a result of another length than the one the hash was
    // started for is no BLAKE2b output. Not run.
}

// Outputs of 16 and 32 bytes, unkeyed: Python 3.15.2's hashlib.blake2b(message, digest_size=n),
// and with every option, hashlib.blake2b(b"abc", digest_size=32, key=bytes(range(32)),
// salt=b"5b6b41ed9b343fe0", person=b"5126fb2a37400d2a").
void check_lengths() {
    std::vector<std::uint8_t> const empty;
    auto const abc = ascii("abc");
    expect_blake2b(empty, {.output_size = 16}, "cae66941d9efbd404e4d88758ea67670", "16, empty");
    expect_blake2b(abc, {.output_size = 16}, "cf4ab791c62b8d2b2109c90275287816", "16, abc");
    expect_blake2b(empty, {.output_size = 32},
                   "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8", "32, empty");
    expect_blake2b(abc, {.output_size = 32},
                   "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319", "32, abc");

    std::vector<std::uint8_t> key(32);
    for (std::size_t index = 0; index < key.size(); ++index) {
        key[index] = static_cast<std::uint8_t>(index);
    }
    auto const salt = ascii("5b6b41ed9b343fe0");
    auto const personal = ascii("5126fb2a37400d2a");
    expect_blake2b(abc, {.key = key, .salt = salt, .personalisation = personal, .output_size = 32},
                   "e84505945bf67aa4f0c3ebfb7120e4e40fc80808685e7a2dfc729997ec686371",
                   "32, abc, every option");

    // A 32-byte BLAKE2b is not the 64-byte one cut: the length is a parameter of the hash.
    std::array<std::uint8_t, 64> whole{};
    BOOST_TEST((hash::digest_of<digests::blake2b>(whole, abc).has_value()));
    BOOST_TEST_NE(test::to_hex(std::span(whole).first(32)),
                  "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319");
}

// The family's guards (RFC 7693, ruling R21), the same on every backend, before any work: the
// output size 1 to 64 and the output of that size (invalid_output_size), the key 0 to 64 bytes
// (invalid_key_size), the salt empty or 16 bytes (invalid_salt_size), the personalisation empty or
// 16 bytes (invalid_parameters). A refusal leaves the output as it was.
template <class Backend>
void check_guards() {
    std::vector<std::uint8_t> const input{0x61, 0x62, 0x63};
    std::vector<std::uint8_t> const long_key(65, 0x01);
    std::vector<std::uint8_t> const any(64, 0x02);
    auto const refuses = [&](options const& chosen, std::size_t output_size, hash::error expected,
                             std::string_view label) {
        std::vector<std::uint8_t> output(output_size, 0x5A);
        auto const refused = hash::digest_of<digests::blake2b, Backend>(output, input, chosen);
        if (!BOOST_TEST(failed_with(refused, expected)) || !BOOST_TEST(all_of(output, 0x5A))) {
            std::cerr << "  digest_of guard: " << label << '\n';
        }
    };
    refuses({.output_size = 0}, 0, hash::error::invalid_output_size, "output size 0");
    refuses({.output_size = 65}, 65, hash::error::invalid_output_size, "output size 65");
    refuses({}, 32, hash::error::invalid_output_size, "32 bytes for the default 64");
    refuses({.output_size = 32}, 64, hash::error::invalid_output_size, "64 bytes for 32");
    refuses({.key = long_key}, 64, hash::error::invalid_key_size, "key of 65 bytes");
    for (std::size_t const size : {1U, 8U, 15U, 17U, 64U}) {
        refuses({.salt = std::span(any).first(size)}, 64, hash::error::invalid_salt_size,
                "salt of " + std::to_string(size) + " bytes");
        refuses({.personalisation = std::span(any).first(size)}, 64,
                hash::error::invalid_parameters,
                "personalisation of " + std::to_string(size) + " bytes");
    }

    auto const make_refuses = [](options const& chosen, hash::error expected) {
        auto const made = hash::hasher<digests::blake2b, Backend>::make(chosen);
        return made.has_error() && made.error() == expected;
    };
    BOOST_TEST(make_refuses({.output_size = 0}, hash::error::invalid_output_size));
    BOOST_TEST(make_refuses({.output_size = 65}, hash::error::invalid_output_size));
    BOOST_TEST(make_refuses({.key = long_key}, hash::error::invalid_key_size));
    BOOST_TEST(make_refuses({.salt = std::span(any).first(8)}, hash::error::invalid_salt_size));
    BOOST_TEST(make_refuses({.personalisation = std::span(any).first(8)},
                            hash::error::invalid_parameters));

    // A hasher made for 32 bytes refuses another size at finish, the output untouched, and still
    // gives its result.
    if constexpr (std::is_same_v<Backend, backends::sodium>) {
        auto hashing = hash::hasher<digests::blake2b, Backend>::make({.output_size = 32});
        test::require(BOOST_TEST(hashing.has_value()));
        std::vector<std::uint8_t> wrong(64, 0x5A);
        BOOST_TEST(failed_with(hashing->finish(wrong), hash::error::invalid_output_size));
        BOOST_TEST(all_of(wrong, 0x5A));
        std::array<std::uint8_t, 32> right{};
        BOOST_TEST(hashing->finish(right).has_value());
    }
}

// The edges the family accepts on backends::sodium: a key and an output of 1 byte and of 64.
void check_edges() {
    std::vector<std::uint8_t> const input{0x61, 0x62, 0x63};
    std::vector<std::uint8_t> const key(64, 0x07);
    for (std::size_t const key_size : {1U, 64U}) {
        for (std::size_t const output_size : {1U, 64U}) {
            std::vector<std::uint8_t> output(output_size);
            options const chosen{.key = std::span(key).first(key_size), .output_size = output_size};
            BOOST_TEST((hash::digest_of<digests::blake2b, backends::sodium>(output, input, chosen)
                            .has_value()));
        }
    }
}

}  // namespace

int main() {
    check_keyed_kat();
    check_unkeyed_kat();
    check_generichash3();
    check_lengths();
    check_guards<backends::sodium>();
    check_guards<backends::hash2>();
    check_edges();
    return webcpp::test::exit_status(boost::report_errors());
}
