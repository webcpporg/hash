// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// scrypt on backends::openssl (OpenSSL 3.5.9's EVP_KDF "SCRYPT", its memory limit maxmem_bytes
// lifted): RFC 7914's first three cases, the first also with a password and a salt that are empty
// spans whose data() is null; backends::sodium's scrypt on random passwords, salts, costs and
// output sizes; OpenSSL's narrower limit on r p (its PBKDF2 takes 128 r p bytes as an int),
// refused before any work; on wasm32, costs past OpenSSL's own memory sizing answered
// not_enough_memory; backends::openssl never a default (design D34). The RFC's fourth case,
// 1 GiB, is scrypt_openssl_large's.

#include <webcpp/hash/backends/openssl.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/hash/scrypt.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/random_cases.hpp"
#include "support/rfc7914.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/system/errc.hpp>
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
using hash::backends::openssl;
using hash::backends::sodium;
using bytes = std::vector<std::uint8_t>;

constexpr std::uint8_t untouched = 0x5A;

void check_rfc7914() {
    for (auto const& c : test::rfc7914_cases) {
        std::array<std::uint8_t, 64> output{};
        auto const done =
            hash::scrypt<openssl>(output, test::bytes_of(c.password), test::bytes_of(c.salt),
                                  {.cost = c.n, .block_size = c.r, .parallelism = c.p});
        BOOST_TEST(done.has_value());
        BOOST_TEST_EQ(test::to_hex(output), std::string(c.output));
    }
    // The first case again, with spans whose data() is null.
    auto const& first = test::rfc7914_cases.front();
    std::array<std::uint8_t, 64> output{};
    std::span<std::uint8_t const> const nothing{};
    BOOST_TEST(
        hash::scrypt<openssl>(output, nothing, nothing,
                              {.cost = first.n, .block_size = first.r, .parallelism = first.p})
            .has_value());
    BOOST_TEST_EQ(test::to_hex(output), std::string(first.output));
}

// backends::sodium against backends::openssl: passwords and salts of 0 to 64 bytes, N of 2 to
// 1,024, r of 1 to 8, p of 1 to 4, outputs of 1 to 100 bytes.
void agree_with_sodium() {
    test::random_source rnd(test::agreement_seed);
    constexpr std::size_t cases = 30;
    for (std::size_t index = 0; index < cases; ++index) {
        auto const password = rnd.bytes(rnd.between(0, 64));
        auto const salt = rnd.bytes(rnd.between(0, 64));
        hash::scrypt_parameters const costs{
            .cost = std::uint64_t{1} << rnd.between(1, 10),
            .block_size = static_cast<std::uint32_t>(rnd.between(1, 8)),
            .parallelism = static_cast<std::uint32_t>(rnd.between(1, 4)),
        };
        std::size_t const output_size = rnd.between(1, 100);
        bytes expected(output_size);
        bytes output(output_size);
        bool const both = hash::scrypt<sodium>(expected, password, salt, costs).has_value() &&
                          hash::scrypt<openssl>(output, password, salt, costs).has_value();
        if (!BOOST_TEST(both) || !BOOST_TEST_EQ(test::to_hex(output), test::to_hex(expected))) {
            std::cerr << "  case " << index << ": N " << costs.cost << ", r " << costs.block_size
                      << ", p " << costs.parallelism << ", output " << output_size << '\n';
        }
    }
}

// OpenSSL takes 128 r p bytes as an int, so r p of 2^24 and more is refused with
// invalid_parameters, as libsodium's N above 2^32 - 1 is, before any work; RFC 7914 allows
// r p below 2^30.
void check_limits() {
    using engine = hash::detail::scrypt_engine<openssl>;
    static_assert(engine::limits.rp == (std::uint64_t{1} << 24U) - 1);
    static_assert(engine::limits.n == hash::detail::no_limit);
    std::array<std::uint8_t, 32> output{};
    output.fill(untouched);
    auto const refused = hash::scrypt<openssl>(
        output, {}, {}, {.cost = 2, .block_size = 1, .parallelism = std::uint32_t{1} << 24U});
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::invalid_parameters);
    BOOST_TEST(std::ranges::all_of(output, [](std::uint8_t byte) { return byte == untouched; }));
    // The same r p on backends::sodium passes the guards: only the RFC's bound is libsodium's.
    static_assert(hash::detail::scrypt_engine<sodium>::limits.rp == hash::detail::no_limit);
}

// On wasm32, costs whose 128 r (N + p) bytes fit a size_t pass the spec's guard while OpenSSL's
// 128 r (N + p + 2) do not: r 2, N 2^23, p 2^23 - 1 (r p below 2^24, N + p = 2^24 - 1). OpenSSL
// refuses them with "memory limit exceeded" before it allocates: not_enough_memory, the output
// zeroed. Natively no such costs pass the guards (r p below 2^24 bounds them far lower).
void check_memory_limit_exceeded() {
    if constexpr (sizeof(std::size_t) == 4) {
        std::array<std::uint8_t, 32> output{};
        output.fill(untouched);
        auto const refused = hash::scrypt<openssl>(
            output, {}, {},
            {.cost = std::uint64_t{1} << 23U, .block_size = 2, .parallelism = (1U << 23U) - 1});
        BOOST_TEST(refused.has_error() &&
                   refused.error() == boost::system::errc::make_error_code(
                                          boost::system::errc::not_enough_memory));
        BOOST_TEST(std::ranges::all_of(output, [](std::uint8_t byte) { return byte == 0; }));
    }
}

static_assert(hash::backend_has_v<openssl, kdfs::scrypt, void>);
// backends::openssl is never a default (design D34): scrypt's is libsodium.
static_assert(std::is_same_v<hash::default_backend<kdfs::scrypt>, sodium>);

}  // namespace

int main() {
    check_rfc7914();
    agree_with_sodium();
    check_limits();
    check_memory_limit_exceeded();
    return webcpp::test::exit_status(boost::report_errors());
}
