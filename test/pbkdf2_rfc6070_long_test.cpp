// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// PBKDF2 on backends::hash2: RFC 6070's fourth case, 16,777,216 iterations of HMAC-SHA-1, on every
// target (its time on each is in the stream's report).

#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/pbkdf2.hpp>

#include <boost/core/lightweight_test.hpp>

#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/rfc6070.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace hash = webcpp::hash;

int main() {
    const auto& c = webcpp::test::rfc6070_4;
    std::vector<std::uint8_t> derived(c.length);
    const auto done = hash::pbkdf2<hash::hmac_sha1_160, hash::backends::hash2>(
        derived, {reinterpret_cast<std::uint8_t const*>(c.password.data()), c.password.size()},
        {reinterpret_cast<std::uint8_t const*>(c.salt.data()), c.salt.size()}, c.iterations);
    BOOST_TEST(done.has_value());
    BOOST_TEST_EQ(webcpp::test::to_hex(derived), std::string(c.derived_key));
    return webcpp::test::exit_status(boost::report_errors());
}
