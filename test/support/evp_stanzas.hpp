// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// OpenSSL's EVP test files (test/recipes/30-test_evp_data at the pin, read at run time through
// /third_party//openssl_evp_data): their stanzas of "Name = value" lines, and the values of their
// Ctrl lines.

#ifndef WEBCPP_TEST_HASH_SUPPORT_EVP_STANZAS_HPP
#define WEBCPP_TEST_HASH_SUPPORT_EVP_STANZAS_HPP

#include "hex.hpp"

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

// The whole file at path; one that cannot be opened ends the test, by name.
inline std::string read_text(std::string const& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cerr << "cannot open test data: " << path << '\n';
        std::abort();
    }
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

// One stanza: its "Name = value" lines in order (a name may repeat, as Ctrl.hexinfo does).
using stanza = std::vector<std::pair<std::string, std::string>>;

// The stanzas of the file at path, each ending at a blank line; comments and lines of another
// form are left out.
inline std::vector<stanza> read_stanzas(std::string const& path) {
    std::istringstream text(read_text(path));
    std::vector<stanza> stanzas(1);
    for (std::string line; std::getline(text, line);) {
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

}  // namespace webcpp::test::evp

#endif  // WEBCPP_TEST_HASH_SUPPORT_EVP_STANZAS_HPP
