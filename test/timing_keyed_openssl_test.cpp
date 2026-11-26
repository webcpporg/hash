// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The key derivations and the password hashes on backends::openssl hold
// webcpp::secure::timing_guard (design D1, D4, D6): each enters its own guard first, through the
// seam, also for a call that a guard refuses before the backend. The functions the default backends
// cover are in timing_keyed_test.cpp; here are the three that OpenSSL alone serves (kbkdf, sskdf
// and x963kdf) and, as a second cell of each template, hkdf, pbkdf2, argon2id, argon2 and scrypt.

#include "support/timing_seam.hpp"

#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/backends/openssl.hpp>
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

namespace {

namespace hash = webcpp::hash;
namespace test = webcpp::test;
namespace digests = webcpp::hash::digests;
namespace kdfs = webcpp::hash::kdfs;
using hash::backends::openssl;
using hmac_sha2_256 = hash::hmac_sha2_256;

constexpr std::array<std::uint8_t, 32> test_key = [] {
    std::array<std::uint8_t, 32> bytes{};
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<std::uint8_t>(i + 1);
    }
    return bytes;
}();
std::array<std::uint8_t, 24> const test_info{9, 8, 7, 6, 5, 4, 3, 2, 1};
std::array<std::uint8_t, 16> const test_salt{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};

// kbkdf, sskdf and x963kdf each enter their own guard; a call that a guard refuses (a counter
// width of 7 bits, an output of no byte) enters it too, and the guard changes no byte.
void standards_enter() {
    std::array<std::uint8_t, 40> derived{};
    test::require_enters("hash::kbkdf of hmac_sha2_256 on openssl", [&] {
        BOOST_TEST((hash::kbkdf<hmac_sha2_256, openssl>(derived, test_key,
                                                        {.label = test_info, .context = test_salt}))
                       .has_value());
    });
    test::require_enters("hash::kbkdf with a counter of 7 bits on openssl", [&] {
        BOOST_TEST(!(hash::kbkdf<hmac_sha2_256, openssl>(derived, test_key, {.counter_bits = 7}))
                        .has_value());
    });
    test::require_enters("hash::sskdf of sha2_256 on openssl", [&] {
        BOOST_TEST(
            (hash::sskdf<digests::sha2_256, openssl>(derived, test_key, test_info)).has_value());
    });
    std::array<std::uint8_t, 0> none{};
    test::require_enters("hash::sskdf with an output of no byte on openssl", [&] {
        BOOST_TEST(
            !(hash::sskdf<digests::sha2_256, openssl>(none, test_key, test_info)).has_value());
    });
    test::require_enters("hash::x963kdf of sha2_256 on openssl", [&] {
        BOOST_TEST(
            (hash::x963kdf<digests::sha2_256, openssl>(derived, test_key, test_info)).has_value());
    });
    test::require_enters("hash::x963kdf with an output of no byte on openssl", [&] {
        BOOST_TEST(
            !(hash::x963kdf<digests::sha2_256, openssl>(none, test_key, test_info)).has_value());
    });
}

// HKDF's three functions, which the default backends cover too, over OpenSSL's engines: the
// guard of the template covers each backend's (H2).
void hkdf_enters() {
    std::array<std::uint8_t, 32> derived{};
    using prk_type = hmac_sha2_256::result_type;
    std::optional<prk_type> prk;
    test::require_enters("hash::hkdf_extract of a salt on openssl", [&] {
        auto const made = hash::hkdf_extract<hmac_sha2_256, openssl>(test_salt, test_key);
        if (BOOST_TEST(made.has_value())) {
            prk.emplace(*made);
        }
    });
    if (prk) {
        test::require_enters("hash::hkdf_expand of a prk on openssl", [&] {
            BOOST_TEST(
                (hash::hkdf_expand<hmac_sha2_256, openssl>(derived, *prk, test_info)).has_value());
        });
    }
    test::require_enters("hash::hkdf of a salt on openssl", [&] {
        BOOST_TEST((hash::hkdf<hmac_sha2_256, openssl>(derived, test_salt, test_key, test_info))
                       .has_value());
    });
}

// The other key derivations and the password hashes over OpenSSL's engines, each entering its
// template's guard, as hkdf_enters' functions do.
void derivations_enter() {
    std::array<std::uint8_t, 32> derived{};
    test::require_enters("hash::pbkdf2 of 1000 iterations on openssl", [&] {
        BOOST_TEST(
            (hash::pbkdf2<hmac_sha2_256, openssl>(derived, test_key, test_salt, 1000)).has_value());
    });
    test::require_enters("hash::pbkdf2 of 0 iterations on openssl", [&] {
        BOOST_TEST(
            !(hash::pbkdf2<hmac_sha2_256, openssl>(derived, test_key, test_salt, 0)).has_value());
    });
    test::require_enters("hash::argon2id of the minimum parameters on openssl", [&] {
        BOOST_TEST(
            (hash::argon2id<openssl>(derived, test_key, test_salt, {.passes = 1, .memory = 8192}))
                .has_value());
    });
    hash::argon2_parameters const family{.passes = 1, .memory_kibibytes = 8};
    test::require_enters("hash::argon2 of argon2d on openssl", [&] {
        BOOST_TEST((hash::argon2<kdfs::argon2d, openssl>(derived, test_key, test_salt, family))
                       .has_value());
    });
    test::require_enters("hash::argon2 of argon2i on openssl", [&] {
        BOOST_TEST((hash::argon2<kdfs::argon2i, openssl>(derived, test_key, test_salt, family))
                       .has_value());
    });
    test::require_enters("hash::argon2 of argon2id on openssl", [&] {
        BOOST_TEST((hash::argon2<kdfs::argon2id, openssl>(derived, test_key, test_salt, family))
                       .has_value());
    });
    test::require_enters("hash::scrypt of N = 16 on openssl", [&] {
        BOOST_TEST((hash::scrypt<openssl>(derived, test_key, test_salt,
                                          {.cost = 16, .block_size = 1, .parallelism = 1}))
                       .has_value());
    });
    test::require_enters("hash::scrypt of N = 1 on openssl", [&] {
        BOOST_TEST(!(hash::scrypt<openssl>(derived, test_key, test_salt,
                                           {.cost = 1, .block_size = 1, .parallelism = 1}))
                        .has_value());
    });
}

}  // namespace

int main() {
    standards_enter();
    hkdf_enters();
    derivations_enter();
    return webcpp::test::exit_status(boost::report_errors());
}
