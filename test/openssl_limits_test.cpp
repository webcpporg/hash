// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// backends::openssl's limits (ruling R24): OpenSSL 3.5.9 holds PBKDF2's output and salt lengths
// and HMAC's key length (PBKDF2's password, HKDF-Extract's salt, HKDF-Expand's PRK) in an int, so
// the public functions refuse more than INT_MAX bytes of them before OpenSSL is called, after the
// spec's own guards, the output untouched. Each long span is INT_MAX + 1 bytes over a buffer of a
// few: the guard refuses it before anything reads or writes it, so OpenSSL's behaviour beyond its
// limit is never exercised. Native only (the Jamfile), as the guard test of PBKDF2's output.

#include <webcpp/hash/backends/openssl.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/pbkdf2.hpp>

#include <boost/core/lightweight_test.hpp>

#include <webcpp/test/exit_status.hpp>

#include <algorithm>
#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <span>

namespace {

namespace hash = webcpp::hash;
using hmac = hash::hmac_sha2_256;
using hash::backends::openssl;

constexpr std::uint8_t untouched = 0x55;
constexpr std::size_t past = static_cast<std::size_t>(INT_MAX) + 1;

using limits = hash::detail::backend_limits<openssl>;
static_assert(limits::pbkdf2_output == INT_MAX && limits::pbkdf2_password == INT_MAX &&
              limits::pbkdf2_salt == INT_MAX && limits::hkdf_salt == INT_MAX &&
              limits::hkdf_prk == INT_MAX);
static_assert(limits::hkdf_ikm == hash::detail::no_limit &&
              limits::hkdf_info == hash::detail::no_limit &&
              limits::hkdf_output == hash::detail::no_limit);
// backends::hash2 has no limit of its own.
static_assert(hash::detail::backend_limits<hash::backends::hash2>::pbkdf2_output ==
              hash::detail::no_limit);

bool is_untouched(std::span<std::uint8_t const> bytes) {
    return std::ranges::all_of(bytes, [](std::uint8_t b) { return b == untouched; });
}

void pbkdf2_limits(std::span<std::uint8_t const> few) {
    std::array<std::uint8_t, 32> output{};
    output.fill(untouched);
    const std::span<std::uint8_t const> long_input(few.data(), past);

    auto refused =
        hash::pbkdf2<hmac, openssl>(std::span<std::uint8_t>(output.data(), past), few, few, 1);
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::invalid_output_size);
    refused = hash::pbkdf2<hmac, openssl>(output, long_input, few, 1);
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::input_too_long);
    refused = hash::pbkdf2<hmac, openssl>(output, few, long_input, 1);
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::input_too_long);
    BOOST_TEST(is_untouched(output));

    // The spec's own guards come first.
    refused =
        hash::pbkdf2<hmac, openssl>(std::span<std::uint8_t>(output.data(), 0), long_input, few, 1);
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::invalid_output_size);
    refused = hash::pbkdf2<hmac, openssl>(output, few, long_input, 0);
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::invalid_iterations);
    BOOST_TEST(is_untouched(output));

    // Within the limits, OpenSSL derives.
    BOOST_TEST((hash::pbkdf2<hmac, openssl>(output, few, few, 1).has_value()));
    BOOST_TEST(!is_untouched(output));
}

void hkdf_limits(std::span<std::uint8_t const> few) {
    std::array<std::uint8_t, 42> output{};
    output.fill(untouched);
    const std::span<std::uint8_t const> long_input(few.data(), past);

    const auto prk = hash::hkdf_extract<hmac, openssl>(long_input, few);
    BOOST_TEST(prk.has_error() && prk.error() == hash::error::input_too_long);
    auto refused = hash::hkdf<hmac, openssl>(output, long_input, few, few);
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::input_too_long);
    BOOST_TEST(is_untouched(output));

    // The spec's own guards come first: the output, then (expand) the PRK's exact size.
    refused =
        hash::hkdf<hmac, openssl>(std::span<std::uint8_t>(output.data(), 0), long_input, few, few);
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::invalid_output_size);
    refused = hash::hkdf_expand<hmac, openssl>(output, long_input, few);
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::invalid_key_size);
    BOOST_TEST(is_untouched(output));
}

}  // namespace

int main() {
    std::array<std::uint8_t, 32> const few{1, 2, 3, 4};
    pbkdf2_limits(few);
    hkdf_limits(few);
    return webcpp::test::exit_status(boost::report_errors());
}
