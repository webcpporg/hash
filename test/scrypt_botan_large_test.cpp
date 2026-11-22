// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// scrypt on backends::botan, RFC 7914's fourth case (N = 1,048,576, r = 8, p = 1, 1 GiB), natively
// and on Emscripten, where /third_party//botan links with -sALLOW_MEMORY_GROWTH=1 (Task 40b).

#include <webcpp/hash/scrypt.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/rfc7914.hpp"

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstdint>
#include <string>

int main() {
    namespace hash = webcpp::hash;
    namespace test = webcpp::test;
    auto const& c = test::rfc7914_large;
    std::array<std::uint8_t, 64> output{};
    BOOST_TEST(hash::scrypt<hash::backends::botan>(output, test::bytes_of(c.password),
                                                   test::bytes_of(c.salt),
                                                   {.n = c.n, .r = c.r, .p = c.p})
                   .has_value());
    BOOST_TEST_EQ(test::to_hex(output), std::string(c.output));
    return webcpp::test::exit_status(boost::report_errors());
}
