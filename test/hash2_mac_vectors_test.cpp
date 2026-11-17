// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// mac's SipHash-2-4 and keyed BLAKE2s on backends::hash2 (ruling R82) against published vectors,
// read at run time from their pinned files (ruling R5): every case of Wycheproof's
// testvectors_v1/siphash_2_4_test.json (all valid, a 16-byte key and an 8-byte tag), and the keyed
// BLAKE2s cases of OpenSSL's test/recipes/30-test_evp_data/evpmac_blake.txt that the hash2 cell
// takes: a 32-byte tag with neither salt nor personalisation (the others are counted, not run).

#include <webcpp/hash/mac.hpp>
#include <webcpp/test/exit_status.hpp>

#include "require.hpp"
#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/json.hpp>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

namespace hash = webcpp::hash;
namespace json = boost::json;
namespace test = webcpp::test;

// The whole file at path; one that cannot be opened ends the test, by name.
std::string read_text(std::string const& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cerr << "cannot open test data: " << path << '\n';
        std::abort();
    }
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

// Wycheproof's SipHash-2-4 cases, each on mac's default, backends::hash2.
void check_siphash() {
    auto const text = read_text(WEBCPP_TEST_WYCHEPROOF "/testvectors_v1/siphash_2_4_test.json");
    boost::system::error_code ec;
    auto const doc = json::parse(text, ec);
    test::require(BOOST_TEST(!ec));
    std::size_t run = 0;
    for (auto const& group : doc.at("testGroups").as_array()) {
        for (auto const& entry : group.at("tests").as_array()) {
            auto const& vector = entry.as_object();
            test::require(BOOST_TEST_EQ(vector.at("result").as_string(), "valid"));
            auto const key = test::from_hex(vector.at("key").as_string());
            auto const message = test::from_hex(vector.at("msg").as_string());
            auto const& expected = vector.at("tag").as_string();
            std::vector<std::uint8_t> tag(expected.size() / 2);
            BOOST_TEST(hash::mac<hash::macs::siphash_2_4>(tag, key, message).has_value());
            if (!BOOST_TEST_EQ(test::to_hex(tag), expected)) {
                std::cerr << "  siphash_2_4, tcId " << vector.at("tcId").as_int64() << '\n';
            }
            ++run;
        }
    }
    BOOST_TEST_EQ(run, static_cast<std::size_t>(doc.at("numberOfTests").as_int64()));
}

// The bytes of an OpenSSL test file's value: hex, or a quoted string's characters.
std::vector<std::uint8_t> value_bytes(std::string const& value) {
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
        return {value.begin() + 1, value.end() - 1};
    }
    return test::from_hex(value);
}

// The keyed BLAKE2s cases of evpmac_blake.txt, each a stanza of "Name = value" lines that starts
// with "MAC = BLAKE2SMAC" and ends at a blank line.
void check_blake2s_mac() {
    std::istringstream lines(read_text(WEBCPP_TEST_OPENSSL_EVP_DATA "/evpmac_blake.txt"));
    std::vector<std::map<std::string, std::string>> stanzas(1);
    for (std::string line; std::getline(lines, line);) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line.empty()) {
            stanzas.emplace_back();
            continue;
        }
        auto const separator = line.find(" = ");
        if (line.front() == '#' || separator == std::string::npos) {
            continue;
        }
        stanzas.back()[line.substr(0, separator)] = line.substr(separator + 3);
    }

    std::size_t run = 0;
    std::size_t skipped = 0;
    for (auto const& stanza : stanzas) {
        auto const mac = stanza.find("MAC");
        if (mac == stanza.end() || mac->second != "BLAKE2SMAC") {
            continue;
        }
        bool const whole_tag = !stanza.contains("OutputSize") || stanza.at("OutputSize") == "32";
        if (!whole_tag || stanza.contains("Ctrl") || stanza.contains("Salt") ||
            stanza.contains("Custom") || stanza.contains("Result") || !stanza.contains("Output")) {
            ++skipped;
            continue;
        }
        auto const key = value_bytes(stanza.at("Key"));
        auto const input = value_bytes(stanza.contains("Input") ? stanza.at("Input") : "");
        std::vector<std::uint8_t> tag(32);
        BOOST_TEST(hash::mac<hash::macs::blake2s_mac>(tag, key, input).has_value());
        if (!BOOST_TEST_EQ(test::to_hex(tag), test::to_hex(test::from_hex(stanza.at("Output"))))) {
            std::cerr << "  blake2s_mac, key " << key.size() << ", input " << input.size() << '\n';
        }
        ++run;
    }
    // At OpenSSL 3.5.9's pin: 12 cases the hash2 cell takes, 8 with a salt, a personalisation, a
    // shorter tag or an expected failure.
    BOOST_TEST_EQ(run, 12U);
    BOOST_TEST_EQ(skipped, 8U);
}

}  // namespace

int main() {
    check_siphash();
    check_blake2s_mac();
    return webcpp::test::exit_status(boost::report_errors());
}
