// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// HKDF on backends::sodium: RFC 5869's A.1 to A.3 (SHA-256) and three SHA-512 cases, which
// backends::hash2 agrees with, through hkdf_extract, hkdf_expand and hkdf; the guards of spec 2.8
// at their limits for both hashes; empty salt, IKM and info, whose spans' data() is null. The test
// includes hkdf.hpp alone: a program that links libsodium and includes only the function's header
// gets the backend's engines (ruling R22).

#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/system/result.hpp>

#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/rfc5869.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

namespace hash = webcpp::hash;
using webcpp::test::from_hex;
using webcpp::test::rfc5869_case;
using webcpp::test::to_hex;

namespace {

using libsodium = hash::backends::sodium;
using webcpp_hash2 = hash::backends::hash2;

static_assert(hash::backend_has_v<libsodium, hash::kdfs::hkdf, hash::hmac_sha2_256>);
static_assert(hash::backend_has_v<libsodium, hash::kdfs::hkdf, hash::hmac_sha2_512>);
static_assert(!hash::backend_has_v<libsodium, hash::kdfs::hkdf, hash::hmac_sha1_160>);
static_assert(!hash::backend_has_v<libsodium, hash::kdfs::pbkdf2, hash::hmac_sha2_512>);
// Natively OpenSSL, then backends::hash2, lead the ranking; libsodium alone changes no default.
static_assert(
    std::is_same_v<hash::default_kdf_backend<hash::hmac_sha2_256>, hash::backends::hash2>);

// The three functions on one case, over Hmac on Backend, the case's salt spelled as given.
template <class Hmac, class Backend>
void check(const rfc5869_case& c, std::span<std::uint8_t const> salt) {
    const auto ikm = from_hex(c.ikm);
    const auto info = from_hex(c.info);

    auto prk = hash::hkdf_extract<Hmac, Backend>(salt, ikm);
    if (!BOOST_TEST(prk.has_value())) {
        return;
    }
    BOOST_TEST_EQ(to_hex(std::span<std::uint8_t const>(prk->data(), prk->size())),
                  std::string(c.prk));

    std::vector<std::uint8_t> okm(c.length);
    const auto expanded = hash::hkdf_expand<Hmac, Backend>(
        okm, std::span<std::uint8_t const>(prk->data(), prk->size()), info);
    BOOST_TEST(expanded.has_value());
    BOOST_TEST_EQ(to_hex(okm), std::string(c.okm));

    std::vector<std::uint8_t> together(c.length);
    const auto derived = hash::hkdf<Hmac, Backend>(together, salt, ikm, info);
    BOOST_TEST(derived.has_value());
    BOOST_TEST_EQ(to_hex(together), std::string(c.okm));
}

template <class Hmac>
void check_on_both(const rfc5869_case& c) {
    const auto salt = from_hex(c.salt);
    check<Hmac, libsodium>(c, salt);
    check<Hmac, webcpp_hash2>(c, salt);  // the agreement: the same literals on the other backend
}

// SHA-512 over RFC 5869's A.1 inputs and two others, written by a tool outside webcpp and
// libsodium: Python 3.15.2's hmac over hashlib.sha512, RFC 5869's two steps over hmac.new; the
// script and its output are in the stream's report. The first is A.1's shape (L = 42, inside one
// block), the second has no salt, IKM or info (L = 71, across two blocks), the third a salt, IKM
// and info longer than a block of 128 bytes' half and an output of 200 bytes (four blocks).
constexpr rfc5869_case sha512_a1_shape{
    .hash = "sha512",
    .ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    .salt = "000102030405060708090a0b0c",
    .info = "f0f1f2f3f4f5f6f7f8f9",
    .length = 42,
    .prk =
        "665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26"
        "c36238127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237",
    .okm =
        "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c14815793"
        "38da362cb8d9f925d7cb",
};

constexpr rfc5869_case sha512_empty{
    .hash = "sha512",
    .ikm = "",
    .salt = "",
    .info = "",
    .length = 71,
    .prk =
        "b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac673"
        "0c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47",
    .okm =
        "9d73c98e791e80ebe5b4cb45693aa32fdd44b5fa3edab3ec82f9d0f4d66905e2"
        "215ad0d4ac20fe570da59a5d189fdde60e55f283703cd19bc95ebb16fc1c868e"
        "8a3872492cc6c2",
};

constexpr rfc5869_case sha512_long{
    .hash = "sha512",
    .ikm =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        "404142434445464748494a4b4c4d4e4f",
    .salt =
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
    .info =
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
        "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
    .length = 200,
    .prk =
        "35672542907d4e142c00e84499e74e1de08be86535f924e022804ad775dde27e"
        "c86cd1e5b7d178c74489bdbeb30712beb82d4f97416c5a94ea81ebdf3e629e4a",
    .okm =
        "ce6c97192805b346e6161e821ed165673b84f400a2b514b2fe23d84cd189ddf1"
        "b695b48cbd1c8388441137b3ce28f16aa64ba33ba466b24df6cfcb021ecff235"
        "f6a2056ce3af1de44d572097a8505d9e7a9354e5796284151c2dd39c39b3cd3d"
        "8e50fcc383ebdec37476e03b721ef5efef873c281f018b8ca42e1245b2271f87"
        "1ba6585ee6b7c47ddf0e1e64685e87eab3e2b4df55874cc74d058879d2f22332"
        "72d5e3ee660dcad82cb9c7018fb089287c0538612abe485010009d505e5062c6"
        "e60beef755288e89",
};

constexpr std::uint8_t untouched = 0xaa;

std::vector<std::uint8_t> filled(std::size_t size, std::uint8_t value) {
    std::vector<std::uint8_t> bytes(size, value);
    return bytes;
}

bool all_of(std::span<std::uint8_t const> bytes, std::uint8_t value) {
    return std::ranges::all_of(bytes, [value](std::uint8_t b) { return b == value; });
}

// A call of hkdf_expand (a valid PRK of the digest size), or of hkdf, into `size` bytes of a buffer
// of 0xaa with one byte more, past its end, which no call may write.
template <class Hmac>
boost::system::result<void> derive_into(bool together, std::vector<std::uint8_t>& buffer,
                                        std::size_t size, std::span<std::uint8_t const> info) {
    constexpr std::size_t n = typename Hmac::result_type().size();
    const auto prk = filled(n, 0x0b);
    const auto salt = filled(13, 0x01);
    const auto ikm = filled(22, 0x0b);
    buffer = filled(size + 1, untouched);
    const std::span<std::uint8_t> out(buffer.data(), size);
    if (together) {
        return hash::hkdf<Hmac, libsodium>(out, salt, ikm, info);
    }
    return hash::hkdf_expand<Hmac, libsodium>(out, prk, info);
}

bool refused_with(const boost::system::result<void>& result, hash::error expected) {
    return result.has_error() && result.error() == expected;
}

// The output of 1 to 255 * n bytes, the info of at most 32,768; a refusal leaves the output (and
// the byte past it) as it was, and the longest output is written whole.
template <class Hmac>
void test_sizes(bool together) {
    constexpr std::size_t n = typename Hmac::result_type().size();
    const auto info = filled(10, 0xf0);
    std::vector<std::uint8_t> buffer;

    BOOST_TEST(refused_with(derive_into<Hmac>(together, buffer, 0, info),
                            hash::error::invalid_output_size));
    BOOST_TEST(all_of(buffer, untouched));

    BOOST_TEST(derive_into<Hmac>(together, buffer, 255 * n, info).has_value());
    BOOST_TEST(!all_of(std::span<std::uint8_t const>(buffer.data() + (254 * n), n), untouched));
    BOOST_TEST_EQ(buffer.back(), untouched);

    BOOST_TEST(refused_with(derive_into<Hmac>(together, buffer, (255 * n) + 1, info),
                            hash::error::invalid_output_size));
    BOOST_TEST(all_of(buffer, untouched));

    const auto longest_info = filled(32768, 0xf0);
    BOOST_TEST(derive_into<Hmac>(together, buffer, 42, longest_info).has_value());
    BOOST_TEST(!all_of(std::span<std::uint8_t const>(buffer.data(), 42), untouched));
    const auto too_long = filled(32769, 0xf0);
    BOOST_TEST(refused_with(derive_into<Hmac>(together, buffer, 42, too_long),
                            hash::error::input_too_long));
    BOOST_TEST(all_of(buffer, untouched));
}

// The PRK of exactly n bytes, and the guards' order (spec 2.8): the output, the PRK, the info.
template <class Hmac>
void test_prk_size_and_order() {
    constexpr std::size_t n = typename Hmac::result_type().size();
    const auto info = filled(10, 0xf0);
    std::vector<std::uint8_t> buffer(43, untouched);
    const std::span<std::uint8_t> out(buffer.data(), 42);
    for (const std::size_t size : {std::size_t{0}, n - 1, n + 1}) {
        const auto bad_prk = filled(size, 0x0b);
        BOOST_TEST(refused_with(hash::hkdf_expand<Hmac, libsodium>(out, bad_prk, info),
                                hash::error::invalid_key_size));
        BOOST_TEST(all_of(buffer, untouched));
    }

    const auto bad_prk = filled(n - 1, 0x0b);
    const auto too_long = filled(32769, 0xf0);
    BOOST_TEST(refused_with(
        hash::hkdf_expand<Hmac, libsodium>(std::span<std::uint8_t>(), bad_prk, too_long),
        hash::error::invalid_output_size));
    BOOST_TEST(refused_with(hash::hkdf_expand<Hmac, libsodium>(out, bad_prk, too_long),
                            hash::error::invalid_key_size));
}

template <class Hmac>
void test_guards() {
    test_sizes<Hmac>(false);
    test_sizes<Hmac>(true);
    test_prk_size_and_order<Hmac>();
}

// Empty salt, IKM and info are valid, their spans' data() null, and agree with backends::hash2 and
// with the spelled-out salt of RFC 5869 2.2 (HashLen zeros).
template <class Hmac>
void test_empty_inputs() {
    constexpr std::size_t n = typename Hmac::result_type().size();
    const std::span<std::uint8_t const> nothing;
    BOOST_TEST(nothing.data() == nullptr);
    const auto zeros = filled(n, 0);
    const auto ikm = filled(22, 0x0b);

    const auto empty_salt = hash::hkdf_extract<Hmac, libsodium>(nothing, ikm);
    const auto zero_salt = hash::hkdf_extract<Hmac, libsodium>(zeros, ikm);
    const auto reference = hash::hkdf_extract<Hmac, webcpp_hash2>(nothing, ikm);
    if (!BOOST_TEST(empty_salt.has_value() && zero_salt.has_value() && reference.has_value())) {
        return;
    }
    BOOST_TEST(*empty_salt == *zero_salt);
    BOOST_TEST(*empty_salt == *reference);

    const auto empty_ikm = hash::hkdf_extract<Hmac, libsodium>(zeros, nothing);
    const auto empty_ikm_reference = hash::hkdf_extract<Hmac, webcpp_hash2>(zeros, nothing);
    if (!BOOST_TEST(empty_ikm.has_value() && empty_ikm_reference.has_value())) {
        return;
    }
    BOOST_TEST(*empty_ikm == *empty_ikm_reference);

    // Everything empty, expanded across a block boundary.
    std::vector<std::uint8_t> okm(n + 7, untouched);
    std::vector<std::uint8_t> expected(n + 7, 0);
    BOOST_TEST((hash::hkdf<Hmac, libsodium>(okm, nothing, nothing, nothing).has_value()));
    BOOST_TEST((hash::hkdf<Hmac, webcpp_hash2>(expected, nothing, nothing, nothing).has_value()));
    BOOST_TEST(okm == expected);
    BOOST_TEST(!all_of(okm, untouched));

    std::vector<std::uint8_t> expanded(n + 7, untouched);
    BOOST_TEST((hash::hkdf_expand<Hmac, libsodium>(
                    expanded, std::span<std::uint8_t const>(empty_salt->data(), n), nothing)
                    .has_value()));
    std::vector<std::uint8_t> expanded_reference(n + 7, 0);
    BOOST_TEST(
        (hash::hkdf_expand<Hmac, webcpp_hash2>(
             expanded_reference, std::span<std::uint8_t const>(empty_salt->data(), n), nothing)
             .has_value()));
    BOOST_TEST(expanded == expanded_reference);
}

}  // namespace

int main() {
    using webcpp::test::a1;
    using webcpp::test::a2;
    using webcpp::test::a3;

    check_on_both<hash::hmac_sha2_256>(a1);
    check_on_both<hash::hmac_sha2_256>(a2);
    check_on_both<hash::hmac_sha2_256>(a3);
    // A.3's salt not provided, spelled as RFC 5869 2.2 defines it: HashLen (32) zero octets.
    const std::vector<std::uint8_t> zeros(32, 0);
    check<hash::hmac_sha2_256, libsodium>(a3, zeros);

    check_on_both<hash::hmac_sha2_512>(sha512_a1_shape);
    check_on_both<hash::hmac_sha2_512>(sha512_empty);
    check_on_both<hash::hmac_sha2_512>(sha512_long);

    test_guards<hash::hmac_sha2_256>();
    test_guards<hash::hmac_sha2_512>();
    test_empty_inputs<hash::hmac_sha2_256>();
    test_empty_inputs<hash::hmac_sha2_512>();

    return webcpp::test::exit_status(boost::report_errors());
}
