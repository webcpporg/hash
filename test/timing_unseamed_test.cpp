// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// webcpp::secure::timing_guard in a program's build, without the seam: its constructor takes a bool
// and no std::source_location, on every target, so that no guarded function's name or header's path
// can reach a program. Built with WEBCPP_TEST_TIMING_READ_SELF (natively, at release), the program
// reads its own executable and finds neither the name of mac, which it calls over HMAC-SHA-256 on
// backends::hash2, nor the path of mac.hpp, where mac is declared. A copy of
// libs/crypto/test/timing_unseamed_test.cpp over hash's mac.

#include <webcpp/hash/algorithms.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/secure/timing_guard.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <source_location>
#include <type_traits>

#ifdef WEBCPP_TEST_TIMING_READ_SELF
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>
#endif

namespace {

namespace hash = webcpp::hash;

static_assert(!std::is_constructible_v<webcpp::secure::timing_guard, bool, std::source_location>,
              "without the seam, timing_guard takes no source_location");
static_assert(!std::is_constructible_v<webcpp::secure::timing_guard, std::source_location>,
              "without the seam, timing_guard takes no source_location");
static_assert(std::is_nothrow_constructible_v<webcpp::secure::timing_guard, bool>,
              "without the seam, timing_guard is constructed from a bool, and never throws");
static_assert(std::is_nothrow_default_constructible_v<webcpp::secure::timing_guard>,
              "without the seam, timing_guard is constructed from nothing, and never throws");

// mac over HMAC-SHA-256 on backends::hash2 runs and answers as it does with the seam. The call is
// outside BOOST_TEST, whose message would put the call's text, mac's name among it, in the program.
void mac_runs() {
    std::array<std::uint8_t, 4> const key{1, 2, 3, 4};
    std::array<std::uint8_t, 4> const input{5, 6, 7, 8};
    std::array<std::uint8_t, 32> tag{};
    auto const computed =
        hash::mac<hash::macs::hmac<hash::digests::sha2_256>, hash::backends::hash2>(tag, key,
                                                                                    input);
    BOOST_TEST(computed.has_value());
}

#ifdef WEBCPP_TEST_TIMING_READ_SELF
/**
 * The texts this program must not hold, kept in it with their last character changed, so that
 * the program's own constants are not what the search finds. Each is read through a volatile
 * pointer, which keeps it in the program whole: a search for a constant could otherwise compile
 * to comparisons with no copy of the text.
 */
constexpr std::string_view masked_name_text = "webcpp::hash::mac#";
constexpr std::string_view masked_path_text = "mac.hp#";

/**
 * A text of the program's, read where the compiler cannot see it.
 *
 * @param text A text of the program.
 * @return The same text, as the program holds it.
 */
std::string_view kept(std::string_view text) {
    char const* volatile const at = text.data();
    return {at, text.size()};
}

/**
 * A text this program must not hold, from its masked copy: the last character is restored at run
 * time, from a volatile the compiler cannot read ahead.
 *
 * @param masked The text, its last character replaced.
 * @param last The text's real last character.
 * @return The text.
 */
std::string unmasked(std::string_view masked, char last) {
    char volatile const restored = last;
    std::string text(masked);
    text.back() = restored;
    return text;
}

/**
 * Whether the bytes hold the text.
 *
 * @param bytes A file's bytes.
 * @param text The text.
 * @return Whether the text is somewhere in them.
 */
bool holds(std::vector<char> const& bytes, std::string_view text) {
    return !std::ranges::search(bytes, text).empty();
}

// The executable holds the masked texts, which shows the search reads it whole, and neither
// mac's name, as clang, GCC and MSVC begin function_name(), nor its header's path.
void executable_holds_no_location(char const* executable) {
    std::ifstream file(executable, std::ios::binary);
    if (!BOOST_TEST(file.is_open())) {
        return;
    }
    std::vector<char> const bytes{std::istreambuf_iterator<char>(file),
                                  std::istreambuf_iterator<char>()};
    std::string_view const masked_name = kept(masked_name_text);
    std::string_view const masked_path = kept(masked_path_text);
    BOOST_TEST(holds(bytes, masked_name));
    BOOST_TEST(holds(bytes, masked_path));
    BOOST_TEST(!holds(bytes, unmasked(masked_name, '(')));
    BOOST_TEST(!holds(bytes, unmasked(masked_path, 'p')));
}
#endif

}  // namespace

// NOLINTNEXTLINE(misc-const-correctness): main's arguments have the type the standard gives them
int main([[maybe_unused]] int argc, [[maybe_unused]] char** argv) {
    mac_runs();
#ifdef WEBCPP_TEST_TIMING_READ_SELF
    if (BOOST_TEST(argc > 0)) {
        executable_holds_no_location(argv[0]);
    }
#endif
    return webcpp::test::exit_status(boost::report_errors());
}
