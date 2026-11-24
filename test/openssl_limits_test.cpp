// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// backends::openssl's limits: OpenSSL 3.5.9 holds PBKDF2's output and salt lengths
// and HMAC's key length (PBKDF2's password, HKDF-Extract's salt, HKDF-Expand's PRK) in an int, so
// the public functions refuse more than INT_MAX bytes of them before OpenSSL is called, after the
// spec's own guards, the output untouched; HKDF over pieces refuses the salt alike. Each long span
// is INT_MAX + 1 bytes over a buffer of a few: the guard refuses it before anything reads or writes
// it, so OpenSSL's behaviour beyond its limit is never exercised. Native only (the Jamfile), as the
// guard test of PBKDF2's output. mac's HMAC on OpenSSL refuses a key of more than INT_MAX bytes
// alike, with unsupported_by_backend (the engine's narrower limit, ruling R41), after the family's
// guards. scrypt on OpenSSL passes its password, its salt and its output to PBKDF2, whose lengths
// are ints: the same INT_MAX bytes. kbkdf's HMAC key alike (unsupported_by_backend); sskdf and
// x963kdf take at most 2^30 bytes of secret, info and output on OpenSSL (unsupported_by_backend),
// after the standards' own bounds on the output (2^32 - 1 blocks), on L (32 bits) and on what the
// digest hashes (2^61 - 1 bytes for SHA-256), which only spans this long reach.

#include <webcpp/hash/backends/openssl.hpp>
#include <webcpp/hash/byte_pieces.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/kdf_standards.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/hash/pbkdf2.hpp>
#include <webcpp/hash/scrypt.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/system/result.hpp>

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
              limits::hkdf_pseudorandom_key == INT_MAX);
static_assert(limits::scrypt_password == INT_MAX && limits::scrypt_salt == INT_MAX &&
              limits::scrypt_output == INT_MAX);
// Argon2's lengths are OpenSSL's uint32_t, RFC 9106's own bound, which argon2id's guards keep.
static_assert(limits::argon2id_password == 0xffffffffU && limits::argon2id_salt == 0xffffffffU &&
              limits::argon2id_output == 0xffffffffU);
static_assert(limits::hkdf_input_key_material == hash::detail::no_limit &&
              limits::hkdf_application_info == hash::detail::no_limit &&
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

    // Over pieces, the salt is HMAC's key alike: input_too_long, after the output's size; the
    // pieces themselves have no limit.
    const auto pieces_prk = hash::hkdf_extract<hmac, openssl>(long_input, {few, few});
    BOOST_TEST(pieces_prk.has_error() && pieces_prk.error() == hash::error::input_too_long);
    refused = hash::hkdf<hmac, openssl>(output, long_input, {few, few}, {few, few});
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::input_too_long);
    refused = hash::hkdf<hmac, openssl>(std::span<std::uint8_t>(output.data(), 0), long_input,
                                        {few, few}, {few, few});
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::invalid_output_size);
    refused = hash::hkdf_expand<hmac, openssl>(output, long_input, {few, few});
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::invalid_key_size);
    BOOST_TEST(is_untouched(output));
    // Within the limit, OpenSSL derives over pieces.
    BOOST_TEST((hash::hkdf<hmac, openssl>(output, few, {few, few}, {few, few}).has_value()));
    BOOST_TEST(!is_untouched(output));
}

void mac_limits(std::span<std::uint8_t const> few) {
    using hmac_tag = hash::macs::hmac<hash::digests::sha2_256>;
    std::array<std::uint8_t, 32> output{};
    output.fill(untouched);
    const std::span<std::uint8_t const> long_key(few.data(), past);

    auto refused = hash::mac<hmac_tag, openssl>(output, long_key, few);
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::unsupported_by_backend);
    BOOST_TEST(is_untouched(output));

    // The family's guard comes first: a tag under 10 bytes.
    refused =
        hash::mac<hmac_tag, openssl>(std::span<std::uint8_t>(output.data(), 9), long_key, few);
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::invalid_output_size);
    BOOST_TEST(is_untouched(output));

    // Within the limit, OpenSSL computes.
    BOOST_TEST((hash::mac<hmac_tag, openssl>(output, few, few).has_value()));
    BOOST_TEST(!is_untouched(output));
}

void scrypt_limits(std::span<std::uint8_t const> few) {
    std::array<std::uint8_t, 32> output{};
    output.fill(untouched);
    const std::span<std::uint8_t const> long_input(few.data(), past);
    constexpr hash::scrypt_parameters cheap{.cost = 16, .block_size = 1, .parallelism = 1};

    auto refused =
        hash::scrypt<openssl>(std::span<std::uint8_t>(output.data(), past), few, few, cheap);
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::invalid_output_size);
    refused = hash::scrypt<openssl>(output, long_input, few, cheap);
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::input_too_long);
    refused = hash::scrypt<openssl>(output, few, long_input, cheap);
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::input_too_long);
    BOOST_TEST(is_untouched(output));

    // The spec's own guards come first: N not a power of two.
    refused = hash::scrypt<openssl>(output, long_input, few,
                                    {.cost = 15, .block_size = 1, .parallelism = 1});
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::invalid_parameters);
    BOOST_TEST(is_untouched(output));

    // Within the limits, OpenSSL derives.
    BOOST_TEST((hash::scrypt<openssl>(output, few, few, cheap).has_value()));
    BOOST_TEST(!is_untouched(output));
}

bool refused_with(boost::system::result<void> const& outcome, hash::error expected) {
    return outcome.has_error() && outcome.error() == expected;
}

void kbkdf_limits(std::span<std::uint8_t const> few) {
    std::array<std::uint8_t, 32> output{};
    output.fill(untouched);
    const std::span<std::uint8_t const> long_key(few.data(), past);
    BOOST_TEST(refused_with(hash::kbkdf<hmac, openssl>(output, long_key),
                            hash::error::unsupported_by_backend));
    // L in bits fits 32 bits: 2^29 - 1 bytes; without L, 2^24 - 1 blocks bound r = 24.
    BOOST_TEST(refused_with(hash::kbkdf<hmac, openssl>(
                                std::span<std::uint8_t>(output.data(), std::size_t{1} << 29U), few),
                            hash::error::invalid_output_size));
    const std::size_t past_r24 = (((std::size_t{1} << 24U) - 1) * 32) + 1;
    BOOST_TEST(
        refused_with(hash::kbkdf<hmac, openssl>(std::span<std::uint8_t>(output.data(), past_r24),
                                                few, {.counter_bits = 24, .length = false}),
                     hash::error::invalid_output_size));
    // The standard's guards come first: a counter of 12 bits, before the empty key.
    BOOST_TEST(refused_with(hash::kbkdf<hmac, openssl>(output, {}, {.counter_bits = 12}),
                            hash::error::invalid_parameters));
    BOOST_TEST(is_untouched(output));
}

template <bool Sskdf, class Digest>
boost::system::result<void> digest_kdf(std::span<std::uint8_t> output,
                                       std::span<std::uint8_t const> secret,
                                       std::span<std::uint8_t const> info) {
    if constexpr (Sskdf) {
        return hash::sskdf<Digest, openssl>(output, secret, info);
    } else {
        return hash::x963kdf<Digest, openssl>(output, secret, info);
    }
}

template <bool Sskdf>
void digest_kdf_limits(std::span<std::uint8_t const> few) {
    std::array<std::uint8_t, 32> output{};
    output.fill(untouched);
    const std::size_t openssl_max = std::size_t{1} << 30U;
    const std::span<std::uint8_t const> long_input(few.data(), openssl_max + 1);
    const std::span<std::uint8_t> long_output(output.data(), openssl_max + 1);
    auto const call = digest_kdf<Sskdf, hash::digests::sha2_256>;
    BOOST_TEST(refused_with(call(output, long_input, few), hash::error::unsupported_by_backend));
    BOOST_TEST(refused_with(call(output, few, long_input), hash::error::unsupported_by_backend));
    BOOST_TEST(refused_with(call(long_output, few, few), hash::error::unsupported_by_backend));

    // SP 800-56C: at most 2^32 - 1 blocks; X9.63: fewer bytes than 2^32 - 1 blocks.
    const std::size_t blocks = std::size_t{0xffffffffU} * 32;
    std::span<std::uint8_t> const at_most(output.data(), blocks);
    std::span<std::uint8_t> const past_most(output.data(), blocks + 1);
    BOOST_TEST(refused_with(call(past_most, few, few), hash::error::invalid_output_size));
    BOOST_TEST(refused_with(call(at_most, few, few), Sskdf ? hash::error::unsupported_by_backend
                                                           : hash::error::invalid_output_size));

    // SHA-256 hashes at most 2^61 - 1 bytes: the counter, the secret and the info together.
    const std::size_t hashed = (std::size_t{1} << 61U) - 1 - 4;
    BOOST_TEST(refused_with(call(output, std::span<std::uint8_t const>(few.data(), hashed + 1), {}),
                            hash::error::input_too_long));
    BOOST_TEST(refused_with(call(output, std::span<std::uint8_t const>(few.data(), hashed), few),
                            hash::error::input_too_long));
    BOOST_TEST(refused_with(call(output, std::span<std::uint8_t const>(few.data(), hashed), {}),
                            hash::error::unsupported_by_backend));
    // SHA-384 has no such bound a size_t reaches: OpenSSL's 2^30 refuses.
    BOOST_TEST(refused_with(digest_kdf<Sskdf, hash::digests::sha2_384>(
                                output, std::span<std::uint8_t const>(few.data(), hashed + 1), {}),
                            hash::error::unsupported_by_backend));
    BOOST_TEST(is_untouched(output));

    // Within the limits, OpenSSL derives.
    BOOST_TEST(call(output, few, few).has_value());
    BOOST_TEST(!is_untouched(output));
}

}  // namespace

int main() {
    std::array<std::uint8_t, 32> const few{1, 2, 3, 4};
    pbkdf2_limits(few);
    hkdf_limits(few);
    mac_limits(few);
    scrypt_limits(few);
    kbkdf_limits(few);
    digest_kdf_limits<true>(few);
    digest_kdf_limits<false>(few);
    return webcpp::test::exit_status(boost::report_errors());
}
