// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The test data webcpp does not own, read at run time from the pinned upstream file (libsodium's
// .exp files, BLAKE2's vectors) through a test-data target, never copied.

#ifndef WEBCPP_TEST_HASH_SUPPORT_DATA_FILE_HPP
#define WEBCPP_TEST_HASH_SUPPORT_DATA_FILE_HPP

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

namespace webcpp::test {

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

}  // namespace webcpp::test

#endif  // WEBCPP_TEST_HASH_SUPPORT_DATA_FILE_HPP
