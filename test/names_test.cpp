// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The spelled-out names compile (design D7): designated initializers of every renamed field, and
// the renamed constant.

#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/scrypt.hpp>

#include <boost/core/lightweight_test.hpp>

#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <string_view>

namespace hash = webcpp::hash;
using webcpp::test::to_hex;

static_assert(hash::hkdf_max_application_info_size == 32768);

namespace {

std::span<std::uint8_t const> bytes(std::string_view text) {
    return {reinterpret_cast<std::uint8_t const*>(text.data()), text.size()};
}

}  // namespace

int main() {
    std::array<std::uint8_t, 64> output{};
    auto const password = bytes("password");
    auto const salt = bytes("NaCl");
    // RFC 7914, section 12, the second vector: N = 1024, r = 8, p = 16.
    auto const done =
        hash::scrypt(output, password, salt, {.cost = 1024, .block_size = 8, .parallelism = 16});
    BOOST_TEST(done.has_value());
    BOOST_TEST_EQ(to_hex(output),
                  "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162"
                  "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640");
    hash::argon2_parameters const parameters{.passes = 3, .memory_kibibytes = 32, .lanes = 4};
    BOOST_TEST_EQ(parameters.memory_kibibytes, 32U);
    return webcpp::test::exit_status(boost::report_errors());
}
