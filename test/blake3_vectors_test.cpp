// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// blake3 against BLAKE3's official vectors, test_vectors/test_vectors.json at the pin: for each
// case, its input (the bytes i % 251 for each i below input_len), hashed plain, keyed with the
// file's key and derived under its context string; each output, squeezed to the expected length
// and taken as successive results, equals the file's.

#include <webcpp/hash/blake3.hpp>
#include <webcpp/test/exit_status.hpp>

#include "require.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/digest.hpp>
#include <boost/json.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

namespace json = boost::json;
using webcpp::hash::blake3;

// The whole file at path; one that cannot be opened ends the test, by name.
std::string read_text(std::string const& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cerr << "cannot open test data: " << path << '\n';
        std::abort();
    }
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

std::string to_hex(std::span<std::uint8_t const> bytes) {
    static constexpr std::string_view digits = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (std::uint8_t const b : bytes) {
        out += digits[b / 16];
        out += digits[b % 16];
    }
    return out;
}

// The output of hasher, which has absorbed a case's input, against expected, the file's hex:
// squeezed to its length, and as results of 32 bytes concatenated and cut to it.
void check_output(blake3 hasher, std::string_view expected, std::string const& what) {
    std::vector<std::uint8_t> squeezed(expected.size() / 2);
    hasher.squeeze(squeezed);
    if (!BOOST_TEST_EQ(to_hex(squeezed), expected)) {
        std::cerr << "  squeezed: " << what << '\n';
    }
    std::vector<std::uint8_t> results;
    while (results.size() < squeezed.size()) {
        auto const result = hasher.result();
        results.insert(results.end(), result.begin(), result.end());
    }
    results.resize(squeezed.size());
    if (!BOOST_TEST_EQ(to_hex(results), expected)) {
        std::cerr << "  results: " << what << '\n';
    }
}

}  // namespace

int main() {
    auto const text = read_text(WEBCPP_TEST_BLAKE3_VECTORS "/test_vectors.json");
    boost::system::error_code ec;
    auto const doc = json::parse(text, ec);
    webcpp::test::require(BOOST_TEST(!ec));

    std::string_view const key_text = doc.at("key").as_string();
    webcpp::test::require(BOOST_TEST_EQ(key_text.size(), std::size_t{32}));
    std::array<std::uint8_t, 32> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>(key_text[i]);
    }
    std::string_view const context = doc.at("context_string").as_string();

    int cases = 0;
    for (auto const& c : doc.at("cases").as_array()) {
        auto const length = static_cast<std::size_t>(c.at("input_len").as_int64());
        std::vector<std::uint8_t> input(length);
        for (std::size_t i = 0; i < length; ++i) {
            input[i] = static_cast<std::uint8_t>(i % 251);
        }
        std::string const at = " of input_len " + std::to_string(length);

        blake3 plain;
        plain.update(input.data(), input.size());
        check_output(plain, c.at("hash").as_string(), "hash" + at);

        auto keyed = blake3::keyed(key);
        keyed.update(input.data(), input.size());
        check_output(keyed, c.at("keyed_hash").as_string(), "keyed_hash" + at);

        auto derived = blake3::derive_key(context);
        derived.update(input.data(), input.size());
        check_output(derived, c.at("derive_key").as_string(), "derive_key" + at);
        ++cases;
    }
    // The file at the pin holds 35 cases.
    BOOST_TEST_EQ(cases, 35);
    return webcpp::test::exit_status(boost::report_errors());
}
