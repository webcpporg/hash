// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// OpenSSL's EVP test files (test/recipes/30-test_evp_data at the pin, read at run time through
// /third_party//openssl_evp_data): their stanzas of "Name = value" lines, the values of their
// Ctrl lines, and the counts a test asserts of a file. The one reader of these files for every
// test of backends::openssl, and of backends::botan's that read them (on Emscripten too, where no
// OpenSSL is built: the files are data, and the version a failure names is then the pin's).

#ifndef WEBCPP_TEST_HASH_SUPPORT_EVP_STANZAS_HPP
#define WEBCPP_TEST_HASH_SUPPORT_EVP_STANZAS_HPP

#include "hex.hpp"

#include <boost/core/lightweight_test.hpp>

#ifdef WEBCPP_HASH_HAS_OPENSSL
#include <openssl/opensslv.h>  // through /webcpp/hash//openssl
#endif

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace webcpp::test::evp {

// The OpenSSL whose test files these are: the linked one's version, or, in a program that links no
// OpenSSL, the files' pin (third_party/libs/openssl).
#ifdef WEBCPP_HASH_HAS_OPENSSL
inline constexpr char const* evp_data_version = OPENSSL_VERSION_STR;
#else
inline constexpr char const* evp_data_version = "the pinned checkout";
#endif

// The whole file at path; one that cannot be opened ends the test, by name.
inline std::string read_text(std::string const& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cerr << "cannot open test data: " << path << '\n';
        std::abort();
    }
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

// The file's lines, without a trailing carriage return.
inline std::vector<std::string> read_lines(std::string const& path) {
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

// One stanza: its "Name = value" lines in order (a name may repeat, as Ctrl.hexinfo does).
using stanza = std::vector<std::pair<std::string, std::string>>;

// The stanzas of the file at path, each ending at a blank line; comments and lines of another
// form are left out.
inline std::vector<stanza> read_stanzas(std::string const& path) {
    std::vector<stanza> stanzas(1);
    for (auto const& line : read_lines(path)) {
        if (line.empty()) {
            stanzas.emplace_back();
            continue;
        }
        auto const separator = line.find(" = ");
        if (line.front() == '#' || separator == std::string::npos) {
            continue;
        }
        stanzas.back().emplace_back(line.substr(0, separator), line.substr(separator + 3));
    }
    return stanzas;
}

// The value of the stanza's first line named `name`, or none.
inline std::optional<std::string> value_of(stanza const& lines, std::string_view name) {
    for (auto const& [key, value] : lines) {
        if (key == name) {
            return value;
        }
    }
    return std::nullopt;
}

// The values of every line named `name`, in order.
inline std::vector<std::string> values_of(stanza const& lines, std::string_view name) {
    std::vector<std::string> values;
    for (auto const& [key, value] : lines) {
        if (key == name) {
            values.push_back(value);
        }
    }
    return values;
}

// The bytes of a line's value: a quoted string's characters, else hex ("Key = 000102").
inline std::vector<std::uint8_t> value_bytes(std::string const& value) {
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
        return {value.begin() + 1, value.end() - 1};
    }
    return from_hex(value);
}

// The value after a Ctrl's "name:" prefix: "digest:SHA256" gives "SHA256".
inline std::string ctrl_value(std::string const& value) {
    return value.substr(value.find(':') + 1);
}

// A Ctrl's bytes: "hexkey:0ef9" is hex, "key:abc" the characters.
inline std::vector<std::uint8_t> ctrl_bytes(std::string const& value) {
    std::string const text = ctrl_value(value);
    if (value.starts_with("hex")) {
        return from_hex(text);
    }
    return {text.begin(), text.end()};
}

// The bytes of every line named `name`, concatenated, as OpenSSL joins repeated info Ctrls.
inline std::vector<std::uint8_t> joined_bytes(stanza const& lines, std::string_view name) {
    std::vector<std::uint8_t> joined;
    for (auto const& [key, value] : lines) {
        if (key == name) {
            auto const part = ctrl_bytes(value);
            joined.insert(joined.end(), part.begin(), part.end());
        }
    }
    return joined;
}

// Whether a count of a file's stanzas is the one the test states for the pinned file; when it is
// not, the failure names the file, what was counted and OpenSSL's version, so that whoever moves
// the pin knows which comment and count to update.
inline bool count_is(std::string_view file, std::string_view counted_kind, std::size_t counted,
                     std::size_t stated) {
    if (BOOST_TEST_EQ(counted, stated)) {
        return true;
    }
    std::cerr << "  " << file << ": " << counted << " " << counted_kind << " where the test states "
              << stated << " for OpenSSL " << evp_data_version
              << "'s file; a new pin changes the file: recount it and update the test\n";
    return false;
}

}  // namespace webcpp::test::evp

#endif  // WEBCPP_TEST_HASH_SUPPORT_EVP_STANZAS_HPP
