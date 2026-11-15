// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The driver of BLAKE3's own test program (blake3_main.c), doing what BLAKE3's c/test.py does
// with c/blake3: for every case of test_vectors.json, the input i % 251 for each i below
// input_len, and the program run with no argument, with --keyed <hex of the key> and with
// --derive-key <context>, each also with --length of the whole expected output; every line it
// prints (one per subset of the CPU features it tests, under BLAKE3_TESTING) must equal the
// file's. A run's standard input and output are this file's buffers, through the renames of
// blake3_main.c.
//
// Built with WEBCPP_TEST_BLAKE3_CORRUPTED, one expected line is changed, and the program passes
// only when that line, and no other, is reported: the comparison is shown to catch a difference.

#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/json.hpp>

#include <algorithm>
#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

extern "C" {
int webcpp_blake3_main(int argc, char** argv);
std::size_t webcpp_blake3_fread(void* buffer, std::size_t size, std::size_t count,
                                std::FILE* stream);
int webcpp_blake3_printf(char const* format, ...);
int webcpp_blake3_fprintf(std::FILE* stream, char const* format, ...);
}

namespace {

namespace json = boost::json;

// The buffers of the run in progress: what main.c reads from standard input, and what it
// writes to standard output and to standard error.
struct run_io {
    std::span<unsigned char const> input;
    std::size_t read = 0;
    std::string output;
    std::string errors;
};

// main.c's I/O reaches the run through this, one run at a time: the renamed C functions have no
// other way to reach it.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
run_io current;

void append(std::string& to, char const* format, std::va_list arguments) {
    std::va_list copy{};
    va_copy(copy, arguments);
    int const size = std::vsnprintf(nullptr, 0, format, copy);
    va_end(copy);
    if (size <= 0) {
        return;
    }
    std::vector<char> text(static_cast<std::size_t>(size) + 1);
    static_cast<void>(std::vsnprintf(text.data(), text.size(), format, arguments));
    to.append(text.data(), static_cast<std::size_t>(size));
}

}  // namespace

extern "C" std::size_t webcpp_blake3_fread(void* buffer, std::size_t size, std::size_t count,
                                           std::FILE* /*stream*/) {
    std::size_t const wanted = size * count;
    std::size_t const left = current.input.size() - current.read;
    std::size_t const n = std::min(wanted, left) / (size == 0 ? 1 : size) * size;
    std::copy_n(current.input.begin() + static_cast<std::ptrdiff_t>(current.read), n,
                static_cast<unsigned char*>(buffer));
    current.read += n;
    return size == 0 ? 0 : n / size;
}

extern "C" int webcpp_blake3_printf(char const* format, ...) {
    std::va_list arguments{};
    va_start(arguments, format);
    append(current.output, format, arguments);
    va_end(arguments);
    return 0;
}

extern "C" int webcpp_blake3_fprintf(std::FILE* /*stream*/, char const* format, ...) {
    std::va_list arguments{};
    va_start(arguments, format);
    append(current.errors, format, arguments);
    va_end(arguments);
    return 0;
}

namespace {

std::string read_text(std::string const& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cerr << "cannot open test data: " << path << '\n';
        std::abort();
    }
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

std::string to_hex(std::string_view text) {
    static constexpr std::string_view digits = "0123456789abcdef";
    std::string out;
    for (char const c : text) {
        auto const b = static_cast<unsigned char>(c);
        out += digits[b / 16];
        out += digits[b % 16];
    }
    return out;
}

// One run: its name as c/test.py's messages give it, its arguments, its input and the line
// every line it prints must equal.
struct run {
    std::string name;
    std::vector<std::string> arguments;
    std::vector<unsigned char> const* input;
    std::string expected;
};

// Runs main.c once and returns the lines it printed that are not expected, each with the run's
// name; a run that fails, or prints nothing, is one such line.
std::vector<std::string> differences(run const& r) {
    current = run_io{.input = *r.input};
    std::vector<std::string> words{"blake3"};
    words.insert(words.end(), r.arguments.begin(), r.arguments.end());
    std::vector<char*> argv;
    argv.reserve(words.size() + 1);
    for (auto& word : words) {
        argv.push_back(word.data());
    }
    argv.push_back(nullptr);
    int const status = webcpp_blake3_main(static_cast<int>(words.size()), argv.data());
    std::vector<std::string> found;
    if (status != 0) {
        found.push_back(r.name + ": exited " + std::to_string(status) + ": " + current.errors);
        return found;
    }
    std::istringstream lines(current.output);
    std::string line;
    int printed = 0;
    while (lines >> line) {
        ++printed;
        if (line != r.expected) {
            found.push_back(r.name + ": " + r.expected + " != " + line);
        }
    }
    if (printed == 0) {
        found.push_back(r.name + ": printed nothing");
    }
    return found;
}

}  // namespace

int main() {
    auto const text = read_text(WEBCPP_TEST_BLAKE3_VECTORS "/test_vectors.json");
    boost::system::error_code ec;
    auto const doc = json::parse(text, ec);
    if (!BOOST_TEST(!ec)) {
        return webcpp::test::exit_status(boost::report_errors());
    }
    std::string const key = to_hex(doc.at("key").as_string());
    std::string const context(doc.at("context_string").as_string());

    auto const& cases = doc.at("cases").as_array();
    std::vector<std::vector<unsigned char>> inputs;
    inputs.reserve(cases.size());
    std::vector<run> runs;
    runs.reserve(6 * cases.size());
    for (auto const& c : cases) {
        auto const length = static_cast<std::size_t>(c.at("input_len").as_int64());
        auto& input = inputs.emplace_back(length);
        for (std::size_t i = 0; i < length; ++i) {
            input[i] = static_cast<unsigned char>(i % 251);
        }

        struct mode {
            char const* field;
            std::vector<std::string> arguments;
        };

        for (auto const& [field, arguments] : {
                 mode{.field = "hash", .arguments = {}},
                 mode{.field = "keyed_hash", .arguments = {"--keyed", key}},
                 mode{.field = "derive_key", .arguments = {"--derive-key", context}},
             }) {
            std::string const expected(c.at(field).as_string());
            std::string const at = "(" + std::to_string(length) + ")";
            runs.push_back({
                .name = std::string(field) + at,
                .arguments = arguments,
                .input = &input,
                .expected = expected.substr(0, 64),
            });
            auto extended = arguments;
            extended.emplace_back("--length");
            extended.push_back(std::to_string(expected.size() / 2));
            runs.push_back({
                .name = std::string(field) + "_xof" + at,
                .arguments = extended,
                .input = &input,
                .expected = expected,
            });
        }
    }

#ifdef WEBCPP_TEST_BLAKE3_CORRUPTED
    // The extended keyed hash of the case of 1,024 bytes, its last digit changed.
    auto const corrupted = std::ranges::find(runs, std::string("keyed_hash_xof(1024)"), &run::name);
    if (!BOOST_TEST(corrupted != runs.end())) {
        return webcpp::test::exit_status(boost::report_errors());
    }
    std::string const original = corrupted->expected;
    corrupted->expected.back() = corrupted->expected.back() == '0' ? '1' : '0';
    // The one form a mismatch takes: never "exited N" or "printed nothing", which a broken run
    // would give instead.
    std::string const mismatch = corrupted->name + ": " + corrupted->expected + " != " + original;
#endif

    std::vector<std::string> found;
    for (auto const& r : runs) {
        auto const more = differences(r);
        found.insert(found.end(), more.begin(), more.end());
    }
    for (auto const& difference : found) {
        std::cout << difference << '\n';
    }

#ifdef WEBCPP_TEST_BLAKE3_CORRUPTED
    // Every line of the corrupted run is reported as that mismatch (one line per subset of CPU
    // features), and nothing else is.
    BOOST_TEST(!found.empty());
    for (auto const& difference : found) {
        BOOST_TEST_EQ(difference, mismatch);
    }
#else
    BOOST_TEST_EQ(runs.size(), std::size_t{6 * 35});
    if (BOOST_TEST(found.empty())) {
        std::cout << "blake3 c suite: " << cases.size() << " cases ok\n";
    }
#endif
    return webcpp::test::exit_status(boost::report_errors());
}
