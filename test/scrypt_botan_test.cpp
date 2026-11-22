// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// scrypt on backends::botan (Botan 3.14.1's "Scrypt"), in part: RFC 7914 section 12's first three
// cases, the first also with a password and a salt that are empty spans whose data() is null;
// backends::sodium's scrypt on random passwords, salts, costs and output sizes, and on passwords
// longer than Botan's HMAC-SHA-256 takes (8,192 bytes), hashed first; Botan's bounds, an r of 257,
// a p of 1,025, an N of 2^23 and more than 8 GiB and 2 MiB of memory (2 GiB on wasm32), answering
// unsupported_by_backend before any work, the output untouched; backends::botan never a default
// (design D34). The RFC's fourth case, 1 GiB, is scrypt_botan_large's.

#include <webcpp/hash/error.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/hash/scrypt.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/random_cases.hpp"
#include "support/rfc7914.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

namespace {

namespace hash = webcpp::hash;
namespace kdfs = webcpp::hash::kdfs;
namespace test = webcpp::test;
using hash::backends::botan;
using hash::backends::sodium;
using bytes = std::vector<std::uint8_t>;

constexpr std::uint8_t untouched = 0x5A;

void check_rfc7914() {
    for (auto const& c : test::rfc7914_cases) {
        std::array<std::uint8_t, 64> output{};
        auto const done =
            hash::scrypt<botan>(output, test::bytes_of(c.password), test::bytes_of(c.salt),
                                {.n = c.n, .r = c.r, .p = c.p});
        BOOST_TEST(done.has_value());
        BOOST_TEST_EQ(test::to_hex(output), std::string(c.output));
    }
    // The first case again, with spans whose data() is null.
    auto const& first = test::rfc7914_cases.front();
    std::array<std::uint8_t, 64> output{};
    std::span<std::uint8_t const> const nothing{};
    BOOST_TEST(
        hash::scrypt<botan>(output, nothing, nothing, {.n = first.n, .r = first.r, .p = first.p})
            .has_value());
    BOOST_TEST_EQ(test::to_hex(output), std::string(first.output));
}

// backends::sodium against backends::botan: passwords and salts of 0 to 64 bytes (and, one case in
// five, a password of 8,192 to 10,000 bytes), N of 2 to 1,024, r of 1 to 8, p of 1 to 4, outputs
// of 1 to 100 bytes.
void agree_with_sodium() {
    test::random_source rnd(test::agreement_seed);
    constexpr std::size_t cases = 30;
    for (std::size_t index = 0; index < cases; ++index) {
        auto const password =
            rnd.bytes(index % 5 == 4 ? rnd.between(8192, 10000) : rnd.between(0, 64));
        auto const salt = rnd.bytes(rnd.between(0, 64));
        hash::scrypt_parameters const costs{
            .n = std::uint64_t{1} << rnd.between(1, 10),
            .r = static_cast<std::uint32_t>(rnd.between(1, 8)),
            .p = static_cast<std::uint32_t>(rnd.between(1, 4)),
        };
        std::size_t const output_size = rnd.between(1, 100);
        bytes expected(output_size);
        bytes output(output_size);
        bool const both = hash::scrypt<sodium>(expected, password, salt, costs).has_value() &&
                          hash::scrypt<botan>(output, password, salt, costs).has_value();
        if (!BOOST_TEST(both) || !BOOST_TEST_EQ(test::to_hex(output), test::to_hex(expected))) {
            std::cerr << "  case " << index << ": password " << password.size() << ", N " << costs.n
                      << ", r " << costs.r << ", p " << costs.p << ", output " << output_size
                      << '\n';
        }
    }
}

bool refused(hash::scrypt_parameters const& costs) {
    std::array<std::uint8_t, 32> output{};
    output.fill(untouched);
    auto const outcome = hash::scrypt<botan>(output, {}, {}, costs);
    bool const untouched_output =
        std::ranges::all_of(output, [](std::uint8_t byte) { return byte == untouched; });
    if (!BOOST_TEST(outcome.has_error() &&
                    outcome.error() == hash::error::unsupported_by_backend) ||
        !BOOST_TEST(untouched_output)) {
        std::cerr << "  not refused: N " << costs.n << ", r " << costs.r << ", p " << costs.p
                  << '\n';
        return false;
    }
    return true;
}

// Botan's bounds (scrypt.cpp): N of at most 2^22, r 256, p 1,024, 128 r (N + p) bytes of at most
// 8 GiB and 2 MiB (2 GiB and 2 MiB on wasm32): past them unsupported_by_backend, before any work;
// at them, computed (r 256 and p 1,024 at N 2, a few MiB).
void check_limits() {
    using engine = hash::detail::scrypt_engine<botan>;
    static_assert(engine::limits.served_n == std::uint64_t{1} << 22U);
    static_assert(engine::limits.served_r == 256);
    static_assert(engine::limits.served_p == 1024);
    refused({.n = 2, .r = 257, .p = 1});
    refused({.n = 2, .r = 1, .p = 1025});
    refused({.n = std::uint64_t{1} << 23U, .r = 2, .p = 1});
    // Refused for its memory alone: N 2^22 and r 32 natively, 16 GiB; on wasm32, where the spec's
    // guard already refuses what does not fit a size_t (invalid_parameters), N 2^22 and r 5,
    // 2.5 GiB.
    refused({.n = std::uint64_t{1} << 22U, .r = sizeof(std::size_t) == 8 ? 32U : 5U, .p = 1});
    std::array<std::uint8_t, 16> output{};
    BOOST_TEST(hash::scrypt<botan>(output, {}, {}, {.n = 2, .r = 256, .p = 1}).has_value());
    BOOST_TEST(hash::scrypt<botan>(output, {}, {}, {.n = 2, .r = 1, .p = 1024}).has_value());
}

static_assert(hash::backend_has_v<botan, kdfs::scrypt, void>);
// backends::botan is never a default (design D34): scrypt's is libsodium.
static_assert(std::is_same_v<hash::default_backend<kdfs::scrypt>, sodium>);

}  // namespace

int main() {
    check_rfc7914();
    agree_with_sodium();
    check_limits();
    return webcpp::test::exit_status(boost::report_errors());
}
