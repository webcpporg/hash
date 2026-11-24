// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A failure of OpenSSL (spec sections 2.8 and 7.5), provoked through the seam
// WEBCPP_HASH_DETAIL_TEST_OPENSSL_DIGEST, which the test's Jamfile defines to "NO-SUCH-DIGEST", a
// digest OpenSSL cannot fetch: every function returns backend_failure, hkdf_expand, hkdf (each also
// over pieces, whose EVP_MAC "HMAC" the seam's digest name fails), pbkdf2, digest_of and mac (HMAC,
// whose "digest" parameter the seam names) zero their output,
// hasher::make makes no hasher, and the thread's error queue is
// left as it was found, empty or holding an entry of the caller's. A guard's refusal still comes
// first.

#include <webcpp/hash/backends/openssl.hpp>
#include <webcpp/hash/byte_pieces.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/hash/pbkdf2.hpp>

#include <boost/core/lightweight_test.hpp>

#include <webcpp/test/exit_status.hpp>

#include <openssl/err.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

#ifndef WEBCPP_HASH_DETAIL_TEST_OPENSSL_DIGEST
#error "the test's Jamfile defines WEBCPP_HASH_DETAIL_TEST_OPENSSL_DIGEST"
#endif

namespace {

namespace hash = webcpp::hash;
using hmac = hash::hmac_sha2_256;
using hash::backends::openssl;

constexpr std::uint8_t untouched = 0x55;

bool all_of(std::span<std::uint8_t const> bytes, std::uint8_t value) {
    return std::ranges::all_of(bytes, [value](std::uint8_t b) { return b == value; });
}

/** The queue's entries, emptied; `first` is set to the oldest. */
std::size_t drain(unsigned long& first) {
    std::size_t count = 0;
    first = ERR_peek_error();
    while (ERR_get_error() != 0) {
        ++count;
    }
    return count;
}

/** HMAC names its digest by the same seam: mac zeroes its tag, a whole one and a cut one. */
void fail_hmac() {
    std::array<std::uint8_t, 13> const key{1, 2, 3};
    std::array<std::uint8_t, 22> const input{4, 5, 6};
    std::array<std::uint8_t, 32> whole{};
    std::array<std::uint8_t, 16> cut{};
    whole.fill(untouched);
    auto failed = hash::mac<hash::macs::hmac<hash::digests::sha2_256>, openssl>(whole, key, input);
    BOOST_TEST(failed.has_error() && failed.error() == hash::error::backend_failure);
    BOOST_TEST(all_of(whole, 0));
    cut.fill(untouched);
    failed = hash::mac<hash::macs::hmac<hash::digests::sm3>, openssl>(cut, {}, input);
    BOOST_TEST(failed.has_error() && failed.error() == hash::error::backend_failure);
    BOOST_TEST(all_of(cut, 0));
}

/** HKDF's three functions over pieces, their HMAC named by the same seam, each failing. */
void fail_each_over_pieces() {
    using piece = std::span<std::uint8_t const>;
    std::array<std::uint8_t, 13> const salt{1, 2, 3};
    std::array<std::uint8_t, 22> const ikm{4, 5, 6};
    std::array<std::uint8_t, 32> const prk{7, 8, 9};
    std::array<std::uint8_t, 10> const info{10, 11, 12};
    std::array<std::uint8_t, 42> output{};
    std::array<piece, 3> const ikm_pieces{piece(ikm).first(4), piece{}, piece(ikm).subspan(4)};
    std::array<piece, 2> const info_pieces{piece(info).first(3), piece(info).subspan(3)};

    auto const extracted = hash::hkdf_extract<hmac, openssl>(salt, ikm_pieces);
    BOOST_TEST(extracted.has_error() && extracted.error() == hash::error::backend_failure);

    output.fill(untouched);
    auto failed = hash::hkdf_expand<hmac, openssl>(output, prk, info_pieces);
    BOOST_TEST(failed.has_error() && failed.error() == hash::error::backend_failure);
    BOOST_TEST(all_of(output, 0));

    output.fill(untouched);
    failed = hash::hkdf<hmac, openssl>(output, salt, ikm_pieces, info_pieces);
    BOOST_TEST(failed.has_error() && failed.error() == hash::error::backend_failure);
    BOOST_TEST(all_of(output, 0));
}

/** Each of the four key derivations, and the digests, once, on OpenSSL, each failing. */
void fail_each() {
    std::array<std::uint8_t, 13> const salt{1, 2, 3};
    std::array<std::uint8_t, 22> const ikm{4, 5, 6};
    std::array<std::uint8_t, 32> const prk{7, 8, 9};
    std::array<std::uint8_t, 10> const info{10, 11, 12};
    std::array<std::uint8_t, 42> output{};

    auto const extracted = hash::hkdf_extract<hmac, openssl>(salt, ikm);
    BOOST_TEST(extracted.has_error() && extracted.error() == hash::error::backend_failure);

    output.fill(untouched);
    auto failed = hash::hkdf_expand<hmac, openssl>(output, prk, info);
    BOOST_TEST(failed.has_error() && failed.error() == hash::error::backend_failure);
    BOOST_TEST(all_of(output, 0));

    output.fill(untouched);
    failed = hash::hkdf<hmac, openssl>(output, salt, ikm, info);
    BOOST_TEST(failed.has_error() && failed.error() == hash::error::backend_failure);
    BOOST_TEST(all_of(output, 0));

    output.fill(untouched);
    failed = hash::pbkdf2<hmac, openssl>(output, ikm, salt, 2);
    BOOST_TEST(failed.has_error() && failed.error() == hash::error::backend_failure);
    BOOST_TEST(all_of(output, 0));

    // The digests fetch their EVP_MD by the same seam: digest_of zeroes its output (a fixed size
    // and SHAKE's), and hasher::make answers the failure.
    std::array<std::uint8_t, 32> digest{};
    digest.fill(untouched);
    failed = hash::digest_of<hash::digests::sha2_256, openssl>(digest, ikm);
    BOOST_TEST(failed.has_error() && failed.error() == hash::error::backend_failure);
    BOOST_TEST(all_of(digest, 0));
    digest.fill(untouched);
    failed = hash::digest_of<hash::digests::shake_256, openssl>(digest, ikm);
    BOOST_TEST(failed.has_error() && failed.error() == hash::error::backend_failure);
    BOOST_TEST(all_of(digest, 0));
    auto const made = hash::hasher<hash::digests::sm3, openssl>::make();
    BOOST_TEST(made.has_error() && made.error() == hash::error::backend_failure);

    // A guard's refusal reaches no backend: the output is untouched.
    output.fill(untouched);
    failed = hash::hkdf_expand<hmac, openssl>(output, info, info);
    BOOST_TEST(failed.has_error() && failed.error() == hash::error::invalid_key_size);
    BOOST_TEST(all_of(output, untouched));
}

}  // namespace

int main() {
    BOOST_TEST_EQ(std::strcmp(WEBCPP_HASH_DETAIL_TEST_OPENSSL_DIGEST, "NO-SUCH-DIGEST"), 0);

    BOOST_TEST_EQ(ERR_peek_error(), 0UL);
    fail_each();
    fail_each_over_pieces();
    fail_hmac();
    BOOST_TEST_EQ(ERR_peek_error(), 0UL);

    // NOLINTNEXTLINE(bugprone-signed-bitwise): OpenSSL's reason macro ORs signed flags
    ERR_raise(ERR_LIB_USER, ERR_R_PASSED_INVALID_ARGUMENT);
    unsigned long const ours = ERR_peek_last_error();
    fail_each();
    fail_each_over_pieces();
    fail_hmac();
    unsigned long first = 0;
    BOOST_TEST_EQ(drain(first), 1U);
    BOOST_TEST_EQ(first, ours);
    return webcpp::test::exit_status(boost::report_errors());
}
