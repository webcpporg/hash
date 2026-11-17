// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// digest_of and hasher over SHAKE128 and SHAKE256 on backends::hash2, a whole extendable output,
// against the SHAKE cases of OpenSSL's test/recipes/30-test_evp_data/evpmd_sha.txt, read at run
// time from the pinned file: FIPS 202's examples among them (the empty message and 200 bytes of
// 0xA3, each squeezed to 512 bytes, past several blocks of 168 and 136 bytes), and NIST's
// shorter cases. Each output is also taken through hasher, the message fed in two pieces.

#include <webcpp/hash/digest.hpp>
#include <webcpp/test/exit_status.hpp>

#include "require.hpp"
#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

namespace hash = webcpp::hash;
namespace digests = webcpp::hash::digests;
namespace backends = webcpp::hash::backends;
namespace test = webcpp::test;

using stanza = std::map<std::string, std::string>;

// The whole file at path; one that cannot be opened ends the test, by name.
std::string read_text(std::string const& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cerr << "cannot open test data: " << path << '\n';
        std::abort();
    }
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

// The stanzas of an OpenSSL test file: "Name = value" lines up to a blank line.
std::vector<stanza> stanzas_of(std::string const& text) {
    std::istringstream lines(text);
    std::vector<stanza> stanzas(1);
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
    return stanzas;
}

// The bytes of a value: hex, or a quoted string's characters.
std::vector<std::uint8_t> value_bytes(std::string const& value) {
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
        return {value.begin() + 1, value.end() - 1};
    }
    return test::from_hex(value);
}

// A stanza's message: its Input, repeated Count times when it has one.
std::vector<std::uint8_t> message_of(stanza const& entry) {
    auto const input = value_bytes(entry.at("Input"));
    auto const count = entry.contains("Count") ? std::stoul(entry.at("Count")) : 1UL;
    std::vector<std::uint8_t> message;
    for (unsigned long index = 0; index < count; ++index) {
        message.insert(message.end(), input.begin(), input.end());
    }
    return message;
}

// One case on Digest: digest_of, then hasher with the message in two pieces.
template <class Digest>
void check_case(stanza const& entry, std::string_view name) {
    auto const message = message_of(entry);
    auto const expected = test::to_hex(test::from_hex(entry.at("Output")));
    std::vector<std::uint8_t> output(expected.size() / 2);
    BOOST_TEST((hash::digest_of<Digest, backends::hash2>(output, message).has_value()));
    if (!BOOST_TEST_EQ(test::to_hex(output), expected)) {
        std::cerr << "  digest_of " << name << ", input " << message.size() << ", output "
                  << output.size() << '\n';
    }
    auto hashing = hash::hasher<Digest, backends::hash2>::make();
    test::require(BOOST_TEST(hashing.has_value()));
    std::span<std::uint8_t const> const whole(message);
    BOOST_TEST(hashing->update(whole.first(whole.size() / 2)).has_value());
    BOOST_TEST(hashing->update(whole.subspan(whole.size() / 2)).has_value());
    std::vector<std::uint8_t> pieces(output.size());
    BOOST_TEST(hashing->finish(pieces).has_value());
    if (!BOOST_TEST_EQ(test::to_hex(pieces), expected)) {
        std::cerr << "  hasher " << name << ", input " << message.size() << '\n';
    }
}

}  // namespace

int main() {
    std::size_t run = 0;
    std::size_t past_a_block = 0;
    for (auto const& entry : stanzas_of(read_text(WEBCPP_TEST_OPENSSL_EVP_DATA "/evpmd_sha.txt"))) {
        auto const digest = entry.find("Digest");
        if (digest == entry.end()) {
            continue;
        }
        std::size_t const size = entry.at("Output").size() / 2;
        if (digest->second == "SHAKE128") {
            check_case<digests::shake_128>(entry, "shake_128");
            past_a_block += size > 168 ? 1U : 0U;
            ++run;
        } else if (digest->second == "SHAKE256") {
            check_case<digests::shake_256>(entry, "shake_256");
            past_a_block += size > 136 ? 1U : 0U;
            ++run;
        }
    }
    // At OpenSSL 3.5.9's pin: 12 SHAKE cases, 6 of them past one block of the stream.
    BOOST_TEST_EQ(run, 12U);
    BOOST_TEST_EQ(past_a_block, 6U);
    return webcpp::test::exit_status(boost::report_errors());
}
