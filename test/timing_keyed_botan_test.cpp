// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// bcrypt, bcrypt_verify and bcrypt_pbkdf, which only backends::botan serves, and a cell of each
// other key derivation and password hash on it, hold detail::timing_guard (design D1, D4, D6,
// ruling H10): each enters its own guard first, through the seam, also for a call that a guard
// refuses before the backend, and Botan's boundary, which turns its exceptions into errors, holds
// none. The functions of the default backends are in timing_keyed_test.cpp.

#include "support/timing_seam.hpp"

#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/backends/botan.hpp>
#include <webcpp/hash/bcrypt.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/kdf_standards.hpp>
#include <webcpp/hash/pbkdf2.hpp>
#include <webcpp/hash/scrypt.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace {

namespace hash = webcpp::hash;
namespace test = webcpp::test;
namespace digests = webcpp::hash::digests;
namespace kdfs = webcpp::hash::kdfs;
using hash::backends::botan;
using hmac_sha2_256 = hash::hmac_sha2_256;

constexpr std::array<std::uint8_t, 32> key = [] {
    std::array<std::uint8_t, 32> bytes{};
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<std::uint8_t>(i + 1);
    }
    return bytes;
}();
std::array<std::uint8_t, 24> const info{9, 8, 7, 6, 5, 4, 3, 2, 1};
std::array<std::uint8_t, 16> const salt{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};

// bcrypt, bcrypt_verify and bcrypt_pbkdf each enter their own guard, at the lowest cost; a call
// that a guard refuses (a salt of 8 bytes, a malformed string, 0 rounds) enters it too.
void bcrypt_enters() {
    std::array<char, hash::bcrypt_hash_size> made{};
    test::require_enters("hash::bcrypt of cost 4 on botan", [&] {
        BOOST_TEST((hash::bcrypt<botan>(made, key, salt, {.cost = 4})).has_value());
    });
    std::array<char, hash::bcrypt_hash_size> again{};
    test::require_enters("hash::bcrypt with the same arguments on botan", [&] {
        BOOST_TEST((hash::bcrypt<botan>(again, key, salt, {.cost = 4})).has_value());
    });
    BOOST_TEST(made == again);
    test::require_enters("hash::bcrypt with a salt of 8 bytes on botan", [&] {
        BOOST_TEST(
            !(hash::bcrypt<botan>(again, key, std::span{salt}.first(8), {.cost = 4})).has_value());
    });

    std::string_view const text{made.data(), made.size()};
    test::require_enters("hash::bcrypt_verify of the right password on botan", [&] {
        auto const checked = hash::bcrypt_verify<botan>(key, text);
        BOOST_TEST(checked.has_value() && *checked);
    });
    test::require_enters("hash::bcrypt_verify of the wrong password on botan", [&] {
        auto const checked = hash::bcrypt_verify<botan>(salt, text);
        BOOST_TEST(checked.has_value() && !*checked);
    });
    test::require_enters("hash::bcrypt_verify of a string of the wrong form on botan", [&] {
        BOOST_TEST(!hash::bcrypt_verify<botan>(key, "not a bcrypt string").has_value());
    });

    std::array<std::uint8_t, 32> derived{};
    test::require_enters("hash::bcrypt_pbkdf of 1 round on botan", [&] {
        BOOST_TEST((hash::bcrypt_pbkdf<botan>(derived, key, salt, 1)).has_value());
    });
    test::require_enters("hash::bcrypt_pbkdf of 0 rounds on botan", [&] {
        BOOST_TEST(!(hash::bcrypt_pbkdf<botan>(derived, key, salt, 0)).has_value());
    });
}

// HKDF's three functions, one cell each: the template's guard covers Botan's engine, and no
// function of the backend holds one of its own.
void hkdf_enters() {
    std::array<std::uint8_t, 32> derived{};
    std::array<std::uint8_t, 0> none{};
    using prk_type = hmac_sha2_256::result_type;
    std::optional<prk_type> prk;
    test::require_enters("hash::hkdf_extract of a salt on botan", [&] {
        auto const made = hash::hkdf_extract<hmac_sha2_256, botan>(salt, key);
        if (BOOST_TEST(made.has_value())) {
            prk.emplace(*made);
        }
    });
    if (prk) {
        test::require_enters("hash::hkdf_expand of a prk on botan", [&] {
            BOOST_TEST((hash::hkdf_expand<hmac_sha2_256, botan>(derived, *prk, info)).has_value());
        });
    }
    test::require_enters("hash::hkdf of a salt on botan", [&] {
        BOOST_TEST((hash::hkdf<hmac_sha2_256, botan>(derived, salt, key, info)).has_value());
    });
    test::require_enters("hash::hkdf with an output of no byte on botan", [&] {
        BOOST_TEST(!(hash::hkdf<hmac_sha2_256, botan>(none, salt, key, info)).has_value());
    });
}

// The other key derivations and the password hashes over Botan's engines, each entering its
// template's guard, as hkdf_enters' functions do.
void derivations_enter() {
    std::array<std::uint8_t, 32> derived{};
    test::require_enters("hash::pbkdf2 of 1000 iterations on botan", [&] {
        BOOST_TEST((hash::pbkdf2<hmac_sha2_256, botan>(derived, key, salt, 1000)).has_value());
    });
    test::require_enters("hash::pbkdf2 of 0 iterations on botan", [&] {
        BOOST_TEST(!(hash::pbkdf2<hmac_sha2_256, botan>(derived, key, salt, 0)).has_value());
    });
    test::require_enters("hash::kbkdf of hmac_sha2_256 on botan", [&] {
        BOOST_TEST(
            (hash::kbkdf<hmac_sha2_256, botan>(derived, key, {.label = info, .context = salt}))
                .has_value());
    });
    test::require_enters("hash::kbkdf with a counter of 7 bits on botan", [&] {
        BOOST_TEST(
            !(hash::kbkdf<hmac_sha2_256, botan>(derived, key, {.counter_bits = 7})).has_value());
    });
    test::require_enters("hash::sskdf of sha2_256 on botan", [&] {
        BOOST_TEST((hash::sskdf<digests::sha2_256, botan>(derived, key, info)).has_value());
    });
    test::require_enters("hash::x963kdf of sha2_256 on botan", [&] {
        BOOST_TEST((hash::x963kdf<digests::sha2_256, botan>(derived, key, info)).has_value());
    });
    test::require_enters("hash::argon2id of the minimum parameters on botan", [&] {
        BOOST_TEST(
            (hash::argon2id<botan>(derived, key, salt, {.passes = 1, .memory = 8192})).has_value());
    });
    hash::argon2_parameters const family{.passes = 1, .memory_kib = 8};
    test::require_enters("hash::argon2 of argon2d on botan", [&] {
        BOOST_TEST((hash::argon2<kdfs::argon2d, botan>(derived, key, salt, family)).has_value());
    });
    test::require_enters("hash::argon2 of argon2i on botan", [&] {
        BOOST_TEST((hash::argon2<kdfs::argon2i, botan>(derived, key, salt, family)).has_value());
    });
    test::require_enters("hash::argon2 of argon2id on botan", [&] {
        BOOST_TEST((hash::argon2<kdfs::argon2id, botan>(derived, key, salt, family)).has_value());
    });
    test::require_enters("hash::scrypt of N = 16 on botan", [&] {
        BOOST_TEST(
            (hash::scrypt<botan>(derived, key, salt, {.n = 16, .r = 1, .p = 1})).has_value());
    });
    test::require_enters("hash::scrypt of N = 1 on botan", [&] {
        BOOST_TEST(
            !(hash::scrypt<botan>(derived, key, salt, {.n = 1, .r = 1, .p = 1})).has_value());
    });
}

}  // namespace

int main() {
    bcrypt_enters();
    hkdf_enters();
    derivations_enter();
    return webcpp::test::exit_status(boost::report_errors());
}
