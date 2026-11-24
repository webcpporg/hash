// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// OpenSSL's error queue (spec section 3.4): on an empty queue, hkdf_extract, hkdf_expand, hkdf
// (each also over pieces), pbkdf2, digest_of, a hasher's make, update and finish, mac (HMAC, KMAC,
// keyed BLAKE2s and SipHash), argon2 (Argon2d with a secret and associated data), argon2id, scrypt,
// kbkdf, sskdf and x963kdf on backends::openssl leave it empty, OpenSSL's first fetch and
// initialisation among them; an entry of the caller's survives each, and nothing of webcpp's is
// left beside it; a mark the caller set on its own entry survives them too, and the caller's pop to
// it still finds it. openssl_failure_test.cpp checks the same around a failure.

#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/backends/openssl.hpp>
#include <webcpp/hash/byte_pieces.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/kdf_standards.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/hash/pbkdf2.hpp>
#include <webcpp/hash/scrypt.hpp>

#include <boost/core/lightweight_test.hpp>

#include <webcpp/test/exit_status.hpp>

#include <openssl/err.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace {

namespace hash = webcpp::hash;
using hmac = hash::hmac_sha2_256;
using hash::backends::openssl;

/** The queue's entries, emptied; `first` is set to the oldest. */
std::size_t drain(unsigned long& first) {
    std::size_t count = 0;
    first = ERR_peek_error();
    while (ERR_get_error() != 0) {
        ++count;
    }
    return count;
}

/** HKDF's three functions over pieces once, on OpenSSL, each a success. */
void call_each_over_pieces(std::span<std::uint8_t const> salt, std::span<std::uint8_t const> ikm) {
    using piece = std::span<std::uint8_t const>;
    std::array<std::uint8_t, 42> output{};
    std::array<piece, 3> const pieces{ikm.first(4), piece{}, ikm.subspan(4)};
    auto const prk = hash::hkdf_extract<hmac, openssl>(salt, pieces);
    BOOST_TEST(prk.has_value());
    if (prk) {
        BOOST_TEST((hash::hkdf_expand<hmac, openssl>(
                        output, std::span<std::uint8_t const>(prk->data(), prk->size()), pieces)
                        .has_value()));
    }
    BOOST_TEST((hash::hkdf<hmac, openssl>(output, salt, pieces, pieces).has_value()));
}

/**
 Each of the four key derivations (HKDF's three also over pieces), the digest family, the MAC
 family, Argon2, scrypt and the key derivations of standards once, on OpenSSL, each a success.
*/
void call_each() {
    std::array<std::uint8_t, 13> const salt{1, 2, 3};
    std::array<std::uint8_t, 22> const ikm{4, 5, 6};
    std::array<std::uint8_t, 10> const info{7, 8, 9};
    std::array<std::uint8_t, 42> output{};
    auto prk = hash::hkdf_extract<hmac, openssl>(salt, ikm);
    BOOST_TEST(prk.has_value());
    if (prk) {
        BOOST_TEST((hash::hkdf_expand<hmac, openssl>(
                        output, std::span<std::uint8_t const>(prk->data(), prk->size()), info)
                        .has_value()));
    }
    BOOST_TEST((hash::hkdf<hmac, openssl>(output, salt, ikm, info).has_value()));
    call_each_over_pieces(salt, ikm);
    BOOST_TEST((hash::pbkdf2<hmac, openssl>(output, ikm, salt, 2).has_value()));

    std::array<std::uint8_t, 32> digest{};
    BOOST_TEST((hash::digest_of<hash::digests::sha2_256, openssl>(digest, ikm).has_value()));
    BOOST_TEST((hash::digest_of<hash::digests::blake2b, openssl>(digest, ikm, {.output_size = 32})
                    .has_value()));
    auto hashing = hash::hasher<hash::digests::shake_128, openssl>::make();
    BOOST_TEST(hashing.has_value());
    if (hashing) {
        BOOST_TEST(hashing->update(ikm).has_value());
        BOOST_TEST(hashing->finish(output).has_value());
    }

    namespace macs = hash::macs;
    std::array<std::uint8_t, 16> const key{1, 2, 3};
    BOOST_TEST((hash::mac<macs::hmac<hash::digests::sha2_256>, openssl>(digest, key, ikm)));
    BOOST_TEST((hash::mac<macs::kmac_256, openssl>(output, key, ikm, {.customisation = info})));
    BOOST_TEST((hash::mac<macs::blake2s_mac, openssl>(digest, key, ikm)));
    std::array<std::uint8_t, 8> short_tag{};
    BOOST_TEST((hash::mac<macs::siphash_2_4, openssl>(short_tag, key, ikm)));

    std::array<std::uint8_t, 16> const password_salt{1, 2, 3};
    BOOST_TEST((hash::argon2<hash::kdfs::argon2d, openssl>(digest, ikm, password_salt,
                                                           {.passes = 1,
                                                            .memory_kibibytes = 16,
                                                            .lanes = 2,
                                                            .secret = key,
                                                            .associated_data = info})
                    .has_value()));
    BOOST_TEST((hash::argon2id<openssl>(digest, ikm, password_salt, {.passes = 1, .memory = 8192})
                    .has_value()));
    BOOST_TEST(
        (hash::scrypt<openssl>(digest, ikm, salt, {.cost = 16, .block_size = 1, .parallelism = 1})
             .has_value()));

    BOOST_TEST(
        (hash::kbkdf<hmac, openssl>(output, ikm, {.label = salt, .context = info}).has_value()));
    BOOST_TEST((hash::sskdf<hash::digests::sha2_256, openssl>(output, ikm, info).has_value()));
    BOOST_TEST((hash::x963kdf<hash::digests::sha2_256, openssl>(output, ikm, info).has_value()));
}

}  // namespace

int main() {
    BOOST_TEST_EQ(ERR_peek_error(), 0UL);
    call_each();
    BOOST_TEST_EQ(ERR_peek_error(), 0UL);

    // NOLINTNEXTLINE(bugprone-signed-bitwise): OpenSSL's reason macro ORs signed flags
    ERR_raise(ERR_LIB_USER, ERR_R_PASSED_INVALID_ARGUMENT);
    unsigned long const ours = ERR_peek_last_error();
    call_each();
    unsigned long first = 0;
    BOOST_TEST_EQ(drain(first), 1U);
    BOOST_TEST_EQ(first, ours);

    // The caller's own mark on its entry: the backend's marks count on the same entry, and its pop
    // removes its own alone.
    // NOLINTNEXTLINE(bugprone-signed-bitwise): OpenSSL's reason macro ORs signed flags
    ERR_raise(ERR_LIB_USER, ERR_R_PASSED_INVALID_ARGUMENT);
    unsigned long const marked = ERR_peek_last_error();
    BOOST_TEST_EQ(ERR_set_mark(), 1);
    call_each();
    BOOST_TEST_EQ(ERR_count_to_mark(), 0);
    BOOST_TEST_EQ(ERR_pop_to_mark(), 1);
    BOOST_TEST_EQ(drain(first), 1U);
    BOOST_TEST_EQ(first, marked);
    // The caller's mark was its own: no second one is left for a pop to find.
    BOOST_TEST_EQ(ERR_pop_to_mark(), 0);
    return webcpp::test::exit_status(boost::report_errors());
}
