// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// PBKDF2 on backends::hash2: RFC 6070's cases 1, 2, 3, 5 and 6 (HMAC-SHA-1) and RFC 7914 section
// 11's two (HMAC-SHA-256); case 4, of 16,777,216 iterations, is pbkdf2_rfc6070_long_test.cpp.

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
#include <type_traits>
#include <vector>

namespace hash = webcpp::hash;
using webcpp::test::pbkdf2_case;
using webcpp::test::to_hex;

namespace {

std::span<std::uint8_t const> bytes_of(std::string_view text) {
    return {reinterpret_cast<std::uint8_t const*>(text.data()), text.size()};
}

template <class Hmac, class Backend = hash::backends::hash2>
void check(const pbkdf2_case& c) {
    std::vector<std::uint8_t> derived(c.length);
    const auto done =
        hash::pbkdf2<Hmac, Backend>(derived, bytes_of(c.password), bytes_of(c.salt), c.iterations);
    BOOST_TEST(done.has_value());
    BOOST_TEST_EQ(to_hex(derived), std::string(c.derived_key));
}

}  // namespace

int main() {
    check<hash::hmac_sha1_160>(webcpp::test::rfc6070_1);
    check<hash::hmac_sha1_160>(webcpp::test::rfc6070_2);
    check<hash::hmac_sha1_160>(webcpp::test::rfc6070_3);
    check<hash::hmac_sha1_160>(webcpp::test::rfc6070_5);
    check<hash::hmac_sha1_160>(webcpp::test::rfc6070_6);
    check<hash::hmac_sha2_256>(webcpp::test::rfc7914_1);
    check<hash::hmac_sha2_256>(webcpp::test::rfc7914_2);

    // The default backend of a program that links no other backend is backends::hash2.
    static_assert(std::is_same_v<hash::default_kdf_backend<hash::hmac_sha2_256, hash::kdfs::pbkdf2>,
                                 hash::backends::hash2>);
    std::vector<std::uint8_t> derived(webcpp::test::rfc7914_1.length);
    const auto done = hash::pbkdf2<hash::hmac_sha2_256>(
        derived, bytes_of(webcpp::test::rfc7914_1.password), bytes_of(webcpp::test::rfc7914_1.salt),
        webcpp::test::rfc7914_1.iterations);
    BOOST_TEST(done.has_value());
    BOOST_TEST_EQ(to_hex(derived), std::string(webcpp::test::rfc7914_1.derived_key));

    return webcpp::test::exit_status(boost::report_errors());
}
