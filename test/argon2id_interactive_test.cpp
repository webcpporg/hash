// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// argon2id with libsodium's interactive costs, 2 passes over 64 MiB, against libsodium's core
// argon2_ctx with one lane: the preset runs on every target. The program prints argon2id's time,
// which the stream's report records per target.

#include <webcpp/hash/argon2.hpp>

#include <boost/core/lightweight_test.hpp>

#include <webcpp/test/exit_status.hpp>

#include "support/argon2_reference.hpp"
#include "support/hex.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>

namespace hash = webcpp::hash;
using webcpp::test::to_hex;

namespace {

void test_interactive() {
    std::array<std::uint8_t, 13> const password{
        'c', 'o', 'r', 'r', 'e', 'c', 't',  // "correct"
        ' ', 'h', 'o', 'r', 's', 'e',
    };
    std::array<std::uint8_t, hash::argon2id_salt_size> salt{};
    salt.fill(0x5a);

    std::array<std::uint8_t, 32> tag{};
    auto const start = std::chrono::steady_clock::now();
    auto const done = hash::argon2id(tag, password, salt, hash::argon2id_interactive);
    auto const elapsed = std::chrono::steady_clock::now() - start;
    BOOST_TEST(done.has_value());
    std::printf("argon2id_interactive: %lld ms\n",
                static_cast<long long>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()));

    std::array<std::uint8_t, 32> expected{};
    int const code = webcpp::test::argon2_reference(
        expected, {
                      .password = password,
                      .salt = salt,
                      .secret = {},
                      .associated_data = {},
                      .passes = static_cast<std::uint32_t>(hash::argon2id_interactive.passes),
                      .memory_kibibytes =
                          static_cast<std::uint32_t>(hash::argon2id_interactive.memory / 1024),
                      .lanes = 1,
                  });
    BOOST_TEST_EQ(code, ARGON2_OK);
    BOOST_TEST_EQ(to_hex(tag), to_hex(expected));
}

}  // namespace

int main() {
    test_interactive();
    return webcpp::test::exit_status(boost::report_errors());
}
