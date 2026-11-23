// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A failure of Botan (spec sections 2.8 and 7.5), provoked through the seam
// WEBCPP_HASH_DETAIL_TEST_BOTAN_NAME, which the test's Jamfile defines to "NO-SUCH-HASH", a name
// Botan does not know: its create_or_throw throws Lookup_Error, which the boundary catches, so
// that digest_of, a hasher's make, mac and every key derivation (Botan's KDF and PasswordHashFamily
// are made the same way) answer backend_failure, the output zeroed, and no exception leaves
// webcpp::hash. A guard's refusal still comes first. bcrypt reaches Botan through generate_bcrypt,
// which no name selects: its generator of the caller's salt, detail::botan_salt, throws on a second
// draw or a draw of another size, which the boundary would answer with backend_failure.

#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/backends/botan.hpp>
#include <webcpp/hash/bcrypt.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/kdf_standards.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/hash/pbkdf2.hpp>
#include <webcpp/hash/scrypt.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#ifndef WEBCPP_HASH_DETAIL_TEST_BOTAN_NAME
#error "the test's Jamfile defines WEBCPP_HASH_DETAIL_TEST_BOTAN_NAME"
#endif

namespace {

namespace hash = webcpp::hash;
namespace digests = webcpp::hash::digests;
namespace macs = webcpp::hash::macs;
using hash::backends::botan;

bool failed_with(boost::system::result<void> const& outcome, hash::error expected) {
    return outcome.has_error() && outcome.error() == expected;
}

bool zeroed(std::span<std::uint8_t const> output) {
    return std::ranges::all_of(output, [](std::uint8_t b) { return b == 0; });
}

std::array<std::uint8_t, 3> const abc{0x61, 0x62, 0x63};

// A digest of each kind: a HashFunction, an XOF, BLAKE2b unkeyed and keyed.
template <class Tag>
void digest_fails(std::size_t size, hash::digest_options<Tag> const& options = {}) {
    std::array<std::uint8_t, 64> output{};
    output.fill(0x55);
    auto const out = std::span(output).first(size);
    BOOST_TEST(
        failed_with(hash::digest_of<Tag, botan>(out, abc, options), hash::error::backend_failure));
    BOOST_TEST(zeroed(out));
    auto const made = hash::hasher<Tag, botan>::make(options);
    BOOST_TEST(made.has_error() && made.error() == hash::error::backend_failure);
}

// A MAC of each kind: HMAC (with a key Botan's HMAC would refuse, hashed first), KMAC, SipHash,
// keyed BLAKE2b.
template <class Tag>
void mac_fails(std::size_t size, std::size_t key_size) {
    std::array<std::uint8_t, 64> output{};
    output.fill(0x55);
    auto const out = std::span(output).first(size);
    std::vector<std::uint8_t> const key(key_size, 0x0b);
    BOOST_TEST(failed_with(hash::mac<Tag, botan>(out, key, abc), hash::error::backend_failure));
    BOOST_TEST(zeroed(out));
}

// Every key derivation of Botan's KDF and PasswordHashFamily: backend_failure, the output zeroed.
void kdfs_fail() {
    using hmac = hash::hmac_sha2_256;
    std::array<std::uint8_t, 32> output{};
    std::array<std::uint8_t, 16> const salt{1};
    auto const check = [&](boost::system::result<void> const& outcome) {
        BOOST_TEST(failed_with(outcome, hash::error::backend_failure));
        BOOST_TEST(zeroed(output));
        output.fill(0x55);
    };
    output.fill(0x55);
    auto const prk = hash::hkdf_extract<hmac, botan>(salt, abc);
    BOOST_TEST(prk.has_error() && prk.error() == hash::error::backend_failure);
    std::array<std::uint8_t, 32> const key{2};
    check(hash::hkdf_expand<hmac, botan>(output, key, abc));
    check(hash::hkdf<hmac, botan>(output, salt, abc, abc));
    check(hash::pbkdf2<hmac, botan>(output, abc, salt, 2));
    check(hash::argon2id<botan>(output, abc, salt, {.passes = 1, .memory = 8192}));
    check(hash::argon2<hash::kdfs::argon2d, botan>(output, abc, salt,
                                                   {.passes = 1, .memory_kibibytes = 8}));
    check(hash::scrypt<botan>(output, abc, salt, {.cost = 16, .block_size = 1, .parallelism = 1}));
    check(hash::bcrypt_pbkdf<botan>(output, abc, salt, 2));
    check(hash::kbkdf<hmac, botan>(output, abc));
    check(hash::sskdf<digests::sha2_256, botan>(output, abc));
    check(hash::x963kdf<digests::sha2_256, botan>(output, abc));
}

// The generator of bcrypt's salt yields the caller's 16 bytes once: a second draw, or a draw of
// another size, throws.
void salt_drawn_once() {
    std::array<std::uint8_t, 16> salt{};
    for (std::size_t i = 0; i < salt.size(); ++i) {
        salt.at(i) = static_cast<std::uint8_t>(i + 1);
    }
    hash::detail::botan_salt generator(salt);
    BOOST_TEST(generator.is_seeded());
    BOOST_TEST(!generator.accepts_input());
    std::array<std::uint8_t, 17> other{};
    bool threw = false;
    try {
        generator.randomize(std::span(other));
    } catch (Botan::Invalid_State const&) {
        threw = true;
    }
    BOOST_TEST(threw);
    std::array<std::uint8_t, 16> drawn{};
    generator.randomize(drawn);
    BOOST_TEST(drawn == salt);
    threw = false;
    try {
        generator.randomize(drawn);
    } catch (Botan::Invalid_State const&) {
        threw = true;
    }
    BOOST_TEST(threw);
    // bcrypt itself, which no name of Botan's selects, still computes under the seam.
    std::array<char, hash::bcrypt_hash_size> stored{};
    BOOST_TEST((hash::bcrypt<botan>(stored, abc, salt, {.cost = 4}).has_value()));
}

}  // namespace

int main() {
    kdfs_fail();
    salt_drawn_once();
    digest_fails<digests::sha2_256>(32);
    digest_fails<digests::whirlpool>(64);
    digest_fails<digests::shake_128>(64);
    digest_fails<digests::blake2b>(32, {.output_size = 32});
    std::array<std::uint8_t, 16> const key{};
    digest_fails<digests::blake2b>(64, {.key = key});

    mac_fails<macs::hmac<digests::sha2_256>>(32, 32);
    mac_fails<macs::hmac<digests::sha2_256>>(32, 9000);
    mac_fails<macs::kmac_128>(32, 32);
    mac_fails<macs::siphash_2_4>(8, 16);
    mac_fails<macs::blake2b_mac>(64, 64);

    // A guard's refusal comes before Botan: the output untouched.
    std::array<std::uint8_t, 31> short_output{};
    short_output.fill(0x55);
    BOOST_TEST(failed_with(hash::digest_of<digests::sha2_256, botan>(short_output, abc),
                           hash::error::invalid_output_size));
    BOOST_TEST(std::ranges::all_of(short_output, [](std::uint8_t b) { return b == 0x55; }));
    return webcpp::test::exit_status(boost::report_errors());
}
