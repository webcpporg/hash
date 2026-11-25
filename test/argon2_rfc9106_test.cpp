// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// RFC 9106, section 5.3: the Argon2id case, with four lanes, a secret and associated data, which
// argon2id does not take, through libsodium's private core argon2_ctx: the Argon2 that
// backends::sodium calls is RFC 9106's.

#include <boost/core/lightweight_test.hpp>

#include <webcpp/test/exit_status.hpp>

#include "support/argon2_reference.hpp"
#include "support/hex.hpp"

#include <array>
#include <cstdint>
#include <string>

using webcpp::test::to_hex;

namespace {

void test_section_5_3() {
    std::array<std::uint8_t, 32> password{};
    password.fill(0x01);
    std::array<std::uint8_t, 16> salt{};
    salt.fill(0x02);
    std::array<std::uint8_t, 8> secret{};
    secret.fill(0x03);
    std::array<std::uint8_t, 12> associated_data{};
    associated_data.fill(0x04);
    std::array<std::uint8_t, 32> tag{};

    int const code = webcpp::test::argon2_reference(tag, {
                                                             .password = password,
                                                             .salt = salt,
                                                             .secret = secret,
                                                             .associated_data = associated_data,
                                                             .passes = 3,
                                                             .memory_kibibytes = 32,
                                                             .lanes = 4,
                                                         });
    BOOST_TEST_EQ(code, ARGON2_OK);
    // RFC 9106, section 5.3, "Tag".
    BOOST_TEST_EQ(to_hex(tag),
                  std::string("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"));
}

}  // namespace

int main() {
    test_section_5_3();
    return webcpp::test::exit_status(boost::report_errors());
}
