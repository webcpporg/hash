// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// libsodium's extendable-output functions on backends::sodium, crypto_xof_shake128,
// crypto_xof_shake256, crypto_xof_turboshake128 and crypto_xof_turboshake256, through digest_of
// and hasher: TurboSHAKE128 and TurboSHAKE256 against RFC 9861's vectors (section 5, every domain
// byte it prints, the 10,032-byte outputs and the messages of up to 17^6 bytes); SHAKE128 and
// SHAKE256 against FIPS 202's examples (4,096 bits of output); SHAKE against Boost.Hash2's
// shake_128 and shake_256 on random inputs, past one rate block (Hash2's result() gives the stream
// block after block), and against backends::hash2 within its 32 and 64 bytes; then TurboSHAKE's
// domain byte, the family's guard (ruling R25), before any engine. The agreement with XKCP comes
// with increment 3 (ruling R6).

#include <webcpp/hash/backends/sodium.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/test/exit_status.hpp>

#include "require.hpp"
#include "support/fips202_shake.hpp"
#include "support/hex.hpp"
#include "support/random_cases.hpp"
#include "support/rfc9861_turboshake.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/sha3.hpp>
#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <string_view>
#include <vector>

namespace {

namespace hash = webcpp::hash;
namespace test = webcpp::test;
namespace digests = webcpp::hash::digests;
namespace backends = webcpp::hash::backends;

static_assert(hash::backend_has_v<backends::sodium, digests::shake_128, void>);
static_assert(hash::backend_has_v<backends::sodium, digests::shake_256, void>);
static_assert(hash::backend_has_v<backends::sodium, digests::turboshake_128, void>);
static_assert(hash::backend_has_v<backends::sodium, digests::turboshake_256, void>);

// TurboSHAKE's domain byte is the family's guard, the same on every backend (ruling R25).
static_assert(hash::digest_options<digests::turboshake_128>{}.domain == 0x1F);
static_assert(hash::digest_options<digests::turboshake_256>{}.domain == 0x1F);

bool failed_with(boost::system::result<void> const& outcome, hash::error expected) {
    return outcome.has_error() && outcome.error() == expected;
}

// Whether every byte is `value`.
bool all_of(std::span<std::uint8_t const> bytes, std::uint8_t value) {
    return std::ranges::all_of(bytes, [value](std::uint8_t byte) { return byte == value; });
}

// The bytes fed to a hasher at a time for a pattern: a multiple of the pattern's 251 bytes, so
// that every chunk starts the pattern over.
constexpr std::size_t pattern_chunk = std::size_t{251} * 16;

// The longest pattern also hashed at once by digest_of: 17^4 bytes; the two longer ones, 1.4 MB
// and 24 MB, go through a hasher alone, a chunk at a time.
constexpr std::size_t whole_pattern_limit = 83521;

// ptn(n) of RFC 9861, section 5.
std::vector<std::uint8_t> pattern(std::size_t length) {
    std::vector<std::uint8_t> bytes(length);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = test::rfc9861_pattern_byte(i);
    }
    return bytes;
}

// The output of a hasher on backends::sodium fed ptn(length) a chunk at a time.
template <class Digest>
std::vector<std::uint8_t> hash_pattern_in_chunks(std::size_t length, std::size_t output_size,
                                                 hash::digest_options<Digest> const& options) {
    auto const chunk = pattern(pattern_chunk);
    auto hashing = hash::hasher<Digest, backends::sodium>::make(options);
    test::require(BOOST_TEST(hashing.has_value()));
    for (std::size_t done = 0; done < length;) {
        std::size_t const size = std::min(pattern_chunk, length - done);
        test::require(BOOST_TEST(hashing->update(std::span(chunk).first(size)).has_value()));
        done += size;
    }
    std::vector<std::uint8_t> output(output_size);
    test::require(BOOST_TEST(hashing->finish(output).has_value()));
    return output;
}

// The output of a hasher on backends::sodium fed `message` in two pieces, split at `split`.
template <class Digest>
std::vector<std::uint8_t> hash_in_two(std::span<std::uint8_t const> message, std::size_t split,
                                      std::size_t output_size,
                                      hash::digest_options<Digest> const& options = {}) {
    auto hashing = hash::hasher<Digest, backends::sodium>::make(options);
    test::require(BOOST_TEST(hashing.has_value()));
    BOOST_TEST(hashing->update(message.first(split)).has_value());
    BOOST_TEST(hashing->update(message.subspan(split)).has_value());
    std::vector<std::uint8_t> output(output_size);
    test::require(BOOST_TEST(hashing->finish(output).has_value()));
    return output;
}

// The output of digest_of on backends::sodium.
template <class Digest>
std::vector<std::uint8_t> hash_at_once(std::span<std::uint8_t const> message,
                                       std::size_t output_size,
                                       hash::digest_options<Digest> const& options = {}) {
    std::vector<std::uint8_t> output(output_size);
    test::require(
        BOOST_TEST((hash::digest_of<Digest, backends::sodium>(output, message, options))));
    return output;
}

// One vector of RFC 9861 on Digest, the TurboSHAKE of its variant: by digest_of and by a hasher
// in two pieces, or a chunk at a time for the two longest patterns.
template <class Digest>
void check_rfc9861_case(test::rfc9861_turboshake_case const& vector, std::size_t index) {
    hash::digest_options<Digest> const options{.domain = vector.domain};
    std::vector<std::vector<std::uint8_t>> outputs;
    if (vector.pattern && vector.pattern_length > whole_pattern_limit) {
        outputs.push_back(
            hash_pattern_in_chunks<Digest>(vector.pattern_length, vector.length, options));
    } else {
        auto const message =
            vector.pattern ? pattern(vector.pattern_length) : test::from_hex(vector.message);
        outputs.push_back(hash_at_once<Digest>(message, vector.length, options));
        outputs.push_back(hash_in_two<Digest>(message, message.size() / 2, vector.length, options));
    }
    for (auto const& output : outputs) {
        if (!BOOST_TEST_EQ(test::to_hex(std::span(output).subspan(vector.offset)),
                           vector.expected)) {
            std::cerr << "  RFC 9861 vector " << index << ", TurboSHAKE" << vector.variant << '\n';
        }
    }
}

void check_rfc9861() {
    std::size_t index = 0;
    for (auto const& vector : test::rfc9861_turboshake) {
        if (vector.variant == 128) {
            check_rfc9861_case<digests::turboshake_128>(vector, index);
        } else {
            check_rfc9861_case<digests::turboshake_256>(vector, index);
        }
        ++index;
    }
    BOOST_TEST_EQ(index, 31U);
}

// One FIPS 202 example on Digest: by digest_of, and by a hasher in two pieces.
template <class Digest>
void check_fips202_case(std::span<std::uint8_t const> message, std::string_view expected,
                        std::string_view name) {
    auto const once = hash_at_once<Digest>(message, test::fips202_output_size);
    auto const pieces = hash_in_two<Digest>(message, message.size() / 3, once.size());
    if (!BOOST_TEST_EQ(test::to_hex(once), expected) ||
        !BOOST_TEST_EQ(test::to_hex(pieces), expected)) {
        std::cerr << "  FIPS 202 " << name << '\n';
    }
}

void check_fips202() {
    std::vector<std::uint8_t> const empty;
    std::vector<std::uint8_t> const a3(test::fips202_message_size, test::fips202_message_byte);
    check_fips202_case<digests::shake_128>(empty, test::fips202_shake_128_msg0, "SHAKE128 msg0");
    check_fips202_case<digests::shake_128>(a3, test::fips202_shake_128_msg1600, "SHAKE128 msg1600");
    check_fips202_case<digests::shake_256>(empty, test::fips202_shake_256_msg0, "SHAKE256 msg0");
    check_fips202_case<digests::shake_256>(a3, test::fips202_shake_256_msg1600, "SHAKE256 msg1600");
}

// `size` bytes of Boost.Hash2's Hash over `input`: one rate block per result(), the stream
// continued.
template <class Hash>
std::vector<std::uint8_t> hash2_stream(std::span<std::uint8_t const> input, std::size_t size) {
    Hash hashed;
    hashed.update(input.data(), input.size());
    std::vector<std::uint8_t> stream;
    while (stream.size() < size) {
        auto const block = hashed.result();
        stream.insert(stream.end(), block.begin(), block.end());
    }
    stream.resize(size);
    return stream;
}

// The output sizes of the agreement: around SHAKE256's rate (136) and SHAKE128's (168), and past
// several blocks.
constexpr std::array<std::size_t, 11> out_sizes{1, 32, 64, 136, 137, 167, 168, 169, 300, 337, 1000};

// SHAKE on backends::sodium against Boost.Hash2's stream on random inputs (the empty one first),
// by digest_of and by a hasher split at random; within the 32 or 64 bytes of backends::hash2's
// cell, against it as well.
template <class Digest, class Hash, std::size_t Hash2Limit>
void check_hash2_agreement(std::string_view name) {
    test::random_source random(test::agreement_seed);
    for (std::size_t i = 0; i < test::agreement_cases; ++i) {
        auto const message = random.bytes(i == 0 ? 0 : random.between(0, 600));
        std::size_t const size = out_sizes[i % out_sizes.size()];
        auto const expected = hash2_stream<Hash>(message, size);
        auto const once = hash_at_once<Digest>(message, size);
        auto const pieces = hash_in_two<Digest>(message, random.between(0, message.size()), size);
        bool agreed = BOOST_TEST(once == expected) && BOOST_TEST(pieces == expected);
        if (size <= Hash2Limit) {
            std::vector<std::uint8_t> on_hash2(size);
            agreed = BOOST_TEST((hash::digest_of<Digest, backends::hash2>(on_hash2, message))) &&
                     BOOST_TEST(on_hash2 == expected) && agreed;
        }
        if (!agreed) {
            std::cerr << "  " << name << ", seed " << test::agreement_seed << ", case " << i << ": "
                      << message.size() << " bytes in, " << size << " out\n";
        }
    }
}

// TurboSHAKE's domain byte on backends::sodium: outside 0x01..0x7F, invalid_parameters from
// digest_of and hasher::make, the output untouched; the default is 0x1F; each byte of the range
// is another function.
template <class Digest>
void check_domain(std::string_view name) {
    using traits = hash::detail::digest_traits<Digest>;
    using options = hash::digest_options<Digest>;
    BOOST_TEST(
        failed_with(traits::check(options{.domain = 0x00}), hash::error::invalid_parameters));
    BOOST_TEST(traits::check(options{.domain = 0x01}).has_value());
    BOOST_TEST(traits::check(options{.domain = 0x7F}).has_value());
    BOOST_TEST(
        failed_with(traits::check(options{.domain = 0x80}), hash::error::invalid_parameters));

    std::array<std::uint8_t, 3> const message{0x61, 0x62, 0x63};
    for (unsigned const refused : {0x00U, 0x80U, 0xFFU}) {
        hash::digest_options<Digest> const options{.domain = static_cast<std::uint8_t>(refused)};
        std::array<std::uint8_t, 32> output{};
        output.fill(0x5A);
        bool const rejected =
            failed_with(hash::digest_of<Digest, backends::sodium>(output, message, options),
                        hash::error::invalid_parameters) &&
            all_of(output, 0x5A);
        auto const made = hash::hasher<Digest, backends::sodium>::make(options);
        bool const not_made = made.has_error() && made.error() == hash::error::invalid_parameters;
        if (!BOOST_TEST(rejected) || !BOOST_TEST(not_made)) {
            std::cerr << "  " << name << ": domain byte " << refused << '\n';
        }
    }
    auto const standard = hash_at_once<Digest>(message, 32);
    BOOST_TEST(hash_at_once<Digest>(message, 32, {.domain = 0x1F}) == standard);
    BOOST_TEST(hash_at_once<Digest>(message, 32, {.domain = 0x01}) != standard);
    BOOST_TEST(hash_at_once<Digest>(message, 32, {.domain = 0x7F}) != standard);

    std::vector<std::uint8_t> none;
    BOOST_TEST(failed_with(hash::digest_of<Digest, backends::sodium>(none, message),
                           hash::error::invalid_output_size));
}

}  // namespace

int main() {
    check_rfc9861();
    check_fips202();
    check_hash2_agreement<digests::shake_128, boost::hash2::shake_128, 32>("shake_128");
    check_hash2_agreement<digests::shake_256, boost::hash2::shake_256, 64>("shake_256");
    check_domain<digests::turboshake_128>("turboshake_128");
    check_domain<digests::turboshake_256>("turboshake_256");
    return webcpp::test::exit_status(boost::report_errors());
}
