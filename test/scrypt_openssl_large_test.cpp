// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// scrypt on backends::openssl past OpenSSL's own memory limit: RFC 7914's fourth case (N =
// 1,048,576, r = 8, p = 1, 1 GiB), and r = 9 at the same N, 1.125 GiB, past the 1,025 MiB that
// OpenSSL's maxmem_bytes allows by default, against backends::sodium.

#include <webcpp/hash/backends/openssl.hpp>
#include <webcpp/hash/scrypt.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/rfc7914.hpp"

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstdint>
#include <string>

namespace {

namespace hash = webcpp::hash;
namespace test = webcpp::test;
using hash::backends::openssl;
using hash::backends::sodium;

void check_rfc7914_large() {
    auto const& c = test::rfc7914_large;
    std::array<std::uint8_t, 64> output{};
    BOOST_TEST(hash::scrypt<openssl>(output, test::bytes_of(c.password), test::bytes_of(c.salt),
                                     {.cost = c.n, .block_size = c.r, .parallelism = c.p})
                   .has_value());
    BOOST_TEST_EQ(test::to_hex(output), std::string(c.output));
}

void check_past_default_limit() {
    auto const& c = test::rfc7914_large;
    hash::scrypt_parameters const costs{.cost = c.n, .block_size = 9, .parallelism = 1};
    std::array<std::uint8_t, 64> expected{};
    std::array<std::uint8_t, 64> output{};
    BOOST_TEST(
        hash::scrypt<sodium>(expected, test::bytes_of(c.password), test::bytes_of(c.salt), costs)
            .has_value());
    BOOST_TEST(
        hash::scrypt<openssl>(output, test::bytes_of(c.password), test::bytes_of(c.salt), costs)
            .has_value());
    BOOST_TEST_EQ(test::to_hex(output), test::to_hex(expected));
}

}  // namespace

int main() {
    check_rfc7914_large();
    check_past_default_limit();
    return webcpp::test::exit_status(boost::report_errors());
}
