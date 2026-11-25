// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// HKDF on backends::bearssl, BearSSL's br_hkdf_*: RFC 5869's seven cases through hkdf (A.4 to A.7
// over br_sha1_vtable), A.7's absent salt spelled as HashLen zeros too; the four hmacs RFC 5869
// has no case for against backends::hash2; the guards at their limits, which refuse before
// BearSSL is reached; and the wipe of BearSSL's context after each call, reported through the
// seam WEBCPP_SECURE_TEST_WIPE_RECORD (spec sections 3.4 and 6.1).

#include <webcpp/hash/backends/bearssl.hpp>
#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>

#include <boost/core/lightweight_test.hpp>

#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/rfc5869.hpp"

#include <bearssl_kdf.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#ifndef WEBCPP_SECURE_TEST_WIPE_RECORD
#error "hkdf_bearssl_test is built with WEBCPP_SECURE_TEST_WIPE_RECORD (test/Jamfile)"
#endif

namespace hash = webcpp::hash;
using webcpp::test::from_hex;
using webcpp::test::rfc5869_case;
using webcpp::test::to_hex;

namespace {

// The wipes since the last clear: how many, the size of the last, and how many found a byte that
// was not zero.
struct record {
    std::size_t count = 0;
    std::size_t last_size = 0;
    std::size_t not_zero = 0;
};

// The seam's record, which detail::wipe reaches through a function of this test.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the seam's record
record wipes;

using hash::backends::bearssl;

// hkdf on backends::bearssl over Hmac, on one case and a spelling of its salt: the OKM, and one
// wipe, of BearSSL's whole context.
template <class Hmac>
void check(const rfc5869_case& c, std::span<std::uint8_t const> salt) {
    const auto ikm = from_hex(c.ikm);
    const auto info = from_hex(c.info);
    std::vector<std::uint8_t> okm(c.length);
    wipes = {};
    const auto derived = hash::hkdf<Hmac, bearssl>(okm, salt, ikm, info);
    BOOST_TEST(derived.has_value());
    BOOST_TEST_EQ(to_hex(okm), std::string(c.okm));
    BOOST_TEST_EQ(wipes.count, 1U);
    BOOST_TEST_EQ(wipes.last_size, sizeof(br_hkdf_context));
    BOOST_TEST_EQ(wipes.not_zero, 0U);
}

template <class Hmac>
void check(const rfc5869_case& c) {
    const auto salt = from_hex(c.salt);
    check<Hmac>(c, salt);
}

// hkdf over Hmac on backends::bearssl and on backends::hash2 give the same OKM, for an output that
// ends inside a block and one of 255 blocks, with an empty salt, IKM and info and with long ones.
template <class Hmac>
void agree() {
    constexpr std::size_t digest_size = typename Hmac::result_type().size();
    const std::vector<std::uint8_t> empty;
    std::vector<std::uint8_t> salt(150);
    std::vector<std::uint8_t> ikm(77);
    std::vector<std::uint8_t> info(300);
    for (std::size_t i = 0; i < salt.size(); ++i) {
        salt[i] = static_cast<std::uint8_t>((i * 7U) + 1U);
    }
    for (std::size_t i = 0; i < ikm.size(); ++i) {
        ikm[i] = static_cast<std::uint8_t>((i * 13U) + 5U);
    }
    for (std::size_t i = 0; i < info.size(); ++i) {
        info[i] = static_cast<std::uint8_t>((i * 3U) + 2U);
    }
    for (const std::size_t size : {std::size_t{1}, digest_size + 3, 255 * digest_size}) {
        for (const bool long_inputs : {false, true}) {
            const std::span<std::uint8_t const> s = long_inputs ? salt : empty;
            const std::span<std::uint8_t const> k = long_inputs ? ikm : empty;
            const std::span<std::uint8_t const> n = long_inputs ? info : empty;
            std::vector<std::uint8_t> theirs(size);
            std::vector<std::uint8_t> ours(size);
            const auto by_bearssl = hash::hkdf<Hmac, bearssl>(theirs, s, k, n);
            const auto by_hash2 = hash::hkdf<Hmac, hash::backends::hash2>(ours, s, k, n);
            BOOST_TEST(by_bearssl.has_value());
            BOOST_TEST(by_hash2.has_value());
            BOOST_TEST_EQ(to_hex(theirs), to_hex(ours));
        }
    }
}

bool all_of(std::span<std::uint8_t const> bytes, std::uint8_t value) {
    return std::ranges::all_of(bytes, [value](std::uint8_t b) { return b == value; });
}

// The guards of spec 2.8 refuse on backends::bearssl before BearSSL is reached: no wipe, the
// output as it was, and the byte past the output never written.
void guards() {
    using hmac = hash::hmac_sha2_256;
    constexpr std::uint8_t untouched = 0xaa;
    constexpr std::size_t most = std::size_t{255} * 32;
    const std::vector<std::uint8_t> input(16, 0x0b);
    const std::vector<std::uint8_t> info_at_limit(hash::hkdf_max_application_info_size, 0x01);
    const std::vector<std::uint8_t> info_past_limit(hash::hkdf_max_application_info_size + 1, 0x01);

    std::vector<std::uint8_t> buffer(most + 2, untouched);
    const auto refused = [&](std::size_t size, std::span<std::uint8_t const> info) {
        std::ranges::fill(buffer, untouched);
        wipes = {};
        const auto done =
            hash::hkdf<hmac, bearssl>(std::span(buffer).first(size), input, input, info);
        BOOST_TEST_EQ(wipes.count, 0U);
        BOOST_TEST(all_of(buffer, untouched));
        return done;
    };
    const auto empty = refused(0, input);
    BOOST_TEST(!empty.has_value() && empty.error() == hash::error::invalid_output_size);
    const auto too_long = refused(most + 1, input);
    BOOST_TEST(!too_long.has_value() && too_long.error() == hash::error::invalid_output_size);
    const auto long_info = refused(32, info_past_limit);
    BOOST_TEST(!long_info.has_value() && long_info.error() == hash::error::input_too_long);

    // At each limit: one byte, 255 digests, the longest info; the byte past the output is kept.
    for (const std::size_t size : {std::size_t{1}, most}) {
        std::ranges::fill(buffer, untouched);
        const auto output = std::span(buffer).first(size);
        std::vector<std::uint8_t> expected(size);
        const auto by_bearssl = hash::hkdf<hmac, bearssl>(output, input, input, info_at_limit);
        const auto by_hash2 =
            hash::hkdf<hmac, hash::backends::hash2>(expected, input, input, info_at_limit);
        BOOST_TEST(by_bearssl.has_value());
        BOOST_TEST(by_hash2.has_value());
        BOOST_TEST_EQ(to_hex(output), to_hex(expected));
        BOOST_TEST_EQ(buffer[size], untouched);
    }
}

}  // namespace

void webcpp::secure::test::wipe_record(void const* wiped_data, std::size_t byte_count) noexcept {
    const auto* const bytes = static_cast<unsigned char const*>(wiped_data);
    ++wipes.count;
    wipes.last_size = byte_count;
    if (!std::all_of(bytes, bytes + byte_count, [](unsigned char b) { return b == 0; })) {
        ++wipes.not_zero;
    }
}

int main() {
    using webcpp::test::a1;
    using webcpp::test::a2;
    using webcpp::test::a3;
    using webcpp::test::a4;
    using webcpp::test::a5;
    using webcpp::test::a6;
    using webcpp::test::a7;

    check<hash::hmac_sha2_256>(a1);
    check<hash::hmac_sha2_256>(a2);
    check<hash::hmac_sha2_256>(a3);
    check<hash::hmac_sha1_160>(a4);
    check<hash::hmac_sha1_160>(a5);
    check<hash::hmac_sha1_160>(a6);
    check<hash::hmac_sha1_160>(a7);
    // A.7's salt not provided, spelled as RFC 5869 2.2 defines it: HashLen (20) zero octets.
    const std::vector<std::uint8_t> zeros(20, 0);
    check<hash::hmac_sha1_160>(a7, zeros);

    agree<hash::hmac_md5_128>();
    agree<hash::hmac_sha1_160>();
    agree<hash::hmac_sha2_224>();
    agree<hash::hmac_sha2_256>();
    agree<hash::hmac_sha2_384>();
    agree<hash::hmac_sha2_512>();

    guards();

    return webcpp::test::exit_status(boost::report_errors());
}
