// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// RFC 7914's fourth case alone: N = 1,048,576, r = 8, p = 1, which takes 1 GiB. The program
// prints scrypt's time, which the stream's report records per target.

#include <webcpp/hash/scrypt.hpp>

#include <boost/core/lightweight_test.hpp>

#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/rfc7914.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <string_view>

namespace {

void test_large() {
    auto const& c = webcpp::test::rfc7914_large;
    std::array<std::uint8_t, 64> output{};
    auto const start = std::chrono::steady_clock::now();
    auto const done =
        webcpp::hash::scrypt(output, webcpp::test::bytes_of(c.password),
                             webcpp::test::bytes_of(c.salt), {.n = c.n, .r = c.r, .p = c.p});
    auto const elapsed = std::chrono::steady_clock::now() - start;
    if (!BOOST_TEST(done.has_value())) {
        auto const message = done.error().message();
        std::printf("scrypt_rfc7914_large: %s\n", message.c_str());
        return;
    }
    std::printf("scrypt_rfc7914_large: %lld ms\n",
                static_cast<long long>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()));
    BOOST_TEST_EQ(webcpp::test::to_hex(output), std::string(c.output));
}

}  // namespace

int main() {
    test_large();
    return webcpp::test::exit_status(boost::report_errors());
}
