// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The family argon2 on backends::sodium (spec 2.15, ruling R24): Argon2i and Argon2id with one
// lane, no secret and no associated data. Three cases of libsodium's own Argon2i table, whose tags
// are read from pwhash_argon2i.exp; both variants against libsodium's core argon2_ctx on 20 cases
// each; argon2<kdfs::argon2id> against the function argon2id; and every value of RFC 9106 libsodium
// does not take answered with unsupported_by_backend, the output untouched. The test includes
// argon2.hpp alone: a program that links libsodium gets the backend's engines through it.

#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/kdf.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/system/result.hpp>

#include <webcpp/test/exit_status.hpp>

#include "require.hpp"
#include "support/argon2_reference.hpp"
#include "support/data_file.hpp"
#include "support/hex.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace {

namespace hash = webcpp::hash;
namespace test = webcpp::test;
namespace kdfs = webcpp::hash::kdfs;
namespace backends = webcpp::hash::backends;

// libsodium is the first backend of the order with a cell for each variant, a partial one
// (ruling R2): the default of both.
static_assert(hash::backend_has_v<backends::sodium, kdfs::argon2i, hash::argon2_parameters>);
static_assert(hash::backend_has_v<backends::sodium, kdfs::argon2id, hash::argon2_parameters>);
static_assert(!hash::backend_has_v<backends::sodium, kdfs::argon2d, hash::argon2_parameters>);
static_assert(std::is_same_v<hash::default_backend<kdfs::argon2i>, backends::sodium>);
static_assert(std::is_same_v<hash::default_backend<kdfs::argon2id>, backends::sodium>);
static_assert(&hash::argon2<kdfs::argon2i> == &hash::argon2<kdfs::argon2i, backends::sodium>);
static_assert(&hash::argon2<kdfs::argon2id> == &hash::argon2<kdfs::argon2id, backends::sodium>);

constexpr std::uint8_t untouched = 0xaa;

bool all_of(std::span<std::uint8_t const> bytes, std::uint8_t value) {
    return std::ranges::all_of(bytes, [value](std::uint8_t b) { return b == value; });
}

// A case of libsodium's test/default/pwhash_argon2i.c, tv(), at 77e1ce5, whose tag is the line of
// pwhash_argon2i.exp of the same index. The table's salts are 32 bytes and libsodium reads 16 of
// them (crypto_pwhash_SALTBYTES): the salt here is their first 16. libsodium divides its memory
// limit by 1,024 (memlimit / 1024U): the memory here is that quotient, in KiB.
struct libsodium_case {
    std::string_view password;
    std::string_view salt;
    std::size_t tag_size;
    std::uint32_t passes;
    std::uint32_t memory_kibibytes;
};

// The table's first three cases, each of which its .exp shows succeeding.
constexpr std::array libsodium_cases{
    libsodium_case{
        .password = "a347ae92bce9f80f6f595a4480fc9c2fe7e7d7148d371e9487d75f5c23008ffa"
                    "e065577a928febd9b1973a5a95073acdbeb6a030cfc0d79caa2dc5cd011cef02"
                    "c08da232d76d52dfbca38ca8dcbd665b17d1665f7cf5fe59772ec909733b24de"
                    "97d6f58d220b20c60d7c07ec1fd93c52c31020300c6c1facd77937a597c7a6",
        .salt = "5541fbc995d5c197ba290346d2c559de",
        .tag_size = 155,
        .passes = 5,
        .memory_kibibytes = 7086,  // 7256678 / 1024
    },
    libsodium_case{
        .password = "e125cee61c8cb7778d9e5ad0a6f5d978ce9f84de213a8556d9ffe202020ab4a6"
                    "ed9074a4eb3416f9b168f137510f3a30b70b96cbfa219ff99f6c6eaffb15c06b"
                    "60e00cc2890277f0fd3c622115772f7048adaebed86e",
        .salt = "f1192dd5dc2368b9cd421338b2243345",
        .tag_size = 250,
        .passes = 4,
        .memory_kibibytes = 7665,  // 7849083 / 1024
    },
    libsodium_case{
        .password = "92263cbf6ac376499f68a4289d3bb59e5a22335eba63a32e6410249155b956b6"
                    "a3b48d4a44906b18b897127300b375b8f834f1ceffc70880a885f47c33876717"
                    "e392be57f7da3ae58da4fd1f43daa7e44bb82d3717af4319349c24cd31e46d29"
                    "5856b0441b6b289992a11ced1cc3bf3011604590244a3eb737ff221129215e4e"
                    "4347f4915d41292b5173d196eb9add693be5319fdadc242906178bb6c0286c9b"
                    "6ca6012746711f58c8c392016b2fdfc09c64f0f6b6ab7b",
        .salt = "3b840e20e9555e9fb031c4ba1f1747ce",
        .tag_size = 249,
        .passes = 3,
        .memory_kibibytes = 7807,  // 7994791 / 1024
    },
};

// Each case on backends::sodium named and on the default, against its line of the .exp.
void test_libsodium_table() {
    auto const lines = test::read_lines(WEBCPP_TEST_SODIUM_VECTORS "/pwhash_argon2i.exp");
    test::require(lines.size() > libsodium_cases.size());
    for (std::size_t i = 0; i < libsodium_cases.size(); ++i) {
        auto const& c = libsodium_cases[i];
        auto const password = test::from_hex(c.password);
        auto const salt = test::from_hex(c.salt);
        hash::argon2_parameters const parameters{
            .passes = c.passes,
            .memory_kibibytes = c.memory_kibibytes,
        };
        std::vector<std::uint8_t> named(c.tag_size);
        std::vector<std::uint8_t> by_default(c.tag_size);
        bool const computed =
            hash::argon2<kdfs::argon2i, backends::sodium>(named, password, salt, parameters)
                .has_value() &&
            hash::argon2<kdfs::argon2i>(by_default, password, salt, parameters).has_value();
        if (!BOOST_TEST(computed) || !BOOST_TEST_EQ(test::to_hex(named), lines[i]) ||
            !BOOST_TEST_EQ(test::to_hex(by_default), lines[i])) {
            std::cerr << "  pwhash_argon2i.exp, line " << i + 1 << '\n';
        }
    }
}

// argon2<Variant> on backends::sodium against argon2_ctx with one lane, on 20 cases of a fixed
// seed: memory 8 to 256 KiB, from the variant's fewest passes to two more, a password of 0 to 64
// bytes, a tag of 16 to 80 bytes.
template <class Variant>
void test_against_argon2_ctx(argon2_type variant, std::uint32_t fewest_passes) {
    // A fixed seed on purpose: every run checks the same cases, and a failure reproduces.
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp): see above
    std::mt19937 random(20261117U);
    auto const between = [&random](std::uint32_t low, std::uint32_t high) {
        return std::uniform_int_distribution<std::uint32_t>(low, high)(random);
    };
    for (int i = 0; i < 20; ++i) {
        std::vector<std::uint8_t> password(between(0, 64));
        std::ranges::generate(password, [&] { return static_cast<std::uint8_t>(between(0, 255)); });
        std::array<std::uint8_t, 16> salt{};
        std::ranges::generate(salt, [&] { return static_cast<std::uint8_t>(between(0, 255)); });
        std::uint32_t const passes = between(fewest_passes, fewest_passes + 2);
        std::uint32_t const memory_kibibytes = between(8, 256);
        std::size_t const tag_size = between(16, 80);

        std::vector<std::uint8_t> expected(tag_size);
        int const code = test::argon2_reference(expected, {
                                                              .password = password,
                                                              .salt = salt,
                                                              .secret = {},
                                                              .associated_data = {},
                                                              .passes = passes,
                                                              .memory_kibibytes = memory_kibibytes,
                                                              .lanes = 1,
                                                              .variant = variant,
                                                          });
        BOOST_TEST_EQ(code, ARGON2_OK);

        std::vector<std::uint8_t> tag(tag_size);
        auto const done = hash::argon2<Variant, backends::sodium>(
            tag, password, salt,
            {.passes = passes, .memory_kibibytes = memory_kibibytes, .lanes = 1});
        if (!BOOST_TEST(done.has_value()) ||
            !BOOST_TEST_EQ(test::to_hex(tag), test::to_hex(expected))) {
            std::cerr << "  case " << i << ": passes " << passes << ", memory " << memory_kibibytes
                      << " KiB, password " << password.size() << " bytes, tag " << tag_size << '\n';
        }
    }
}

const std::array<std::uint8_t, 8> sample_password{'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
const std::array<std::uint8_t, 16> sample_salt{
    's', 'o', 'm', 'e', 's', 'a', 'l', 't',  // "somesalt" twice
    's', 'o', 'm', 'e', 's', 'a', 'l', 't',
};

// argon2<kdfs::argon2id> on libsodium is the function argon2id, whose memory counts bytes.
void test_argon2id_function() {
    for (std::uint32_t const memory_kibibytes : {8U, 64U, 1024U}) {
        std::array<std::uint8_t, 32> family{};
        std::array<std::uint8_t, 32> function{};
        BOOST_TEST(hash::argon2<kdfs::argon2id>(family, sample_password, sample_salt,
                                                {.passes = 2, .memory_kibibytes = memory_kibibytes})
                       .has_value());
        BOOST_TEST(hash::argon2id(function, sample_password, sample_salt,
                                  {.passes = 2, .memory = std::size_t{memory_kibibytes} * 1024})
                       .has_value());
        BOOST_TEST_EQ(test::to_hex(family), test::to_hex(function));
    }
}

// Expects argon2<Variant> on backends::sodium to refuse with `expected`, the output untouched.
template <class Variant>
void expect_refused(std::size_t output_size, std::span<std::uint8_t const> salt_bytes,
                    hash::argon2_parameters const& parameters, hash::error expected,
                    std::string_view label) {
    std::vector<std::uint8_t> output(output_size, untouched);
    auto const refused =
        hash::argon2<Variant, backends::sodium>(output, sample_password, salt_bytes, parameters);
    if (!BOOST_TEST(refused.has_error() && refused.error() == expected) ||
        !BOOST_TEST(all_of(output, untouched))) {
        std::cerr << "  " << label << '\n';
    }
}

// Every value of RFC 9106 that libsodium does not take: unsupported_by_backend before libsodium
// is called, never backend_failure (ruling R24).
template <class Variant>
void test_unsupported(std::uint32_t fewest_passes) {
    constexpr auto unsupported = hash::error::unsupported_by_backend;
    hash::argon2_parameters const cheapest{.passes = fewest_passes, .memory_kibibytes = 32};
    std::array<std::uint8_t, 8> secret{};
    secret.fill(0x03);
    std::array<std::uint8_t, 12> associated_data{};
    associated_data.fill(0x04);
    expect_refused<Variant>(32, sample_salt,
                            {.passes = fewest_passes, .memory_kibibytes = 32, .lanes = 4},
                            unsupported, "four lanes");
    expect_refused<Variant>(32, sample_salt,
                            {.passes = fewest_passes, .memory_kibibytes = 32, .lanes = 2},
                            unsupported, "two lanes");
    expect_refused<Variant>(
        32, sample_salt,
        {.passes = fewest_passes, .memory_kibibytes = 32, .lanes = 1, .secret = secret},
        unsupported, "a secret");
    expect_refused<Variant>(32, sample_salt,
                            {
                                .passes = fewest_passes,
                                .memory_kibibytes = 32,
                                .lanes = 1,
                                .associated_data = associated_data,
                            },
                            unsupported, "associated data");
    // RFC 9106's shortest tag, 4 bytes, and up to libsodium's 16.
    for (std::size_t const size : {4U, 8U, 15U}) {
        expect_refused<Variant>(size, sample_salt, cheapest, unsupported, "a short tag");
    }
    // RFC 9106's salts of 8 bytes on, but libsodium's 16 alone.
    std::array<std::uint8_t, 64> long_salt{};
    for (std::size_t const size : {8U, 15U, 17U, 32U, 64U}) {
        expect_refused<Variant>(32, std::span<std::uint8_t const>(long_salt.data(), size), cheapest,
                                unsupported, "a salt not of 16 bytes");
    }
    // On wasm32 libsodium's memory stops at 2 GiB, 2,097,152 KiB; natively at RFC 9106's own
    // bound, 2^32 - 1 KiB, which no uint32_t passes.
    if constexpr (std::numeric_limits<std::size_t>::max() == 0xffffffffU) {
        expect_refused<Variant>(32, sample_salt,
                                {.passes = fewest_passes, .memory_kibibytes = 2097153}, unsupported,
                                "past 2 GiB on wasm32");
    }
    // RFC 9106's guards come first: no lane is invalid_parameters, a salt of 7 bytes
    // invalid_salt_size, a tag of 3 bytes invalid_output_size.
    expect_refused<Variant>(32, sample_salt,
                            {.passes = fewest_passes, .memory_kibibytes = 32, .lanes = 0},
                            hash::error::invalid_parameters, "no lane");
    expect_refused<Variant>(32, sample_salt, {.passes = 0, .memory_kibibytes = 32, .lanes = 4},
                            hash::error::invalid_parameters, "no pass, four lanes");
    expect_refused<Variant>(32, sample_salt,
                            {.passes = fewest_passes, .memory_kibibytes = 31, .lanes = 4},
                            hash::error::invalid_parameters, "under 8 KiB per lane");
    expect_refused<Variant>(32, std::span<std::uint8_t const>(sample_salt.data(), 7),
                            {.passes = fewest_passes, .memory_kibibytes = 32, .lanes = 4},
                            hash::error::invalid_salt_size, "a salt of 7 bytes");
    expect_refused<Variant>(3, sample_salt,
                            {.passes = fewest_passes, .memory_kibibytes = 32, .lanes = 4},
                            hash::error::invalid_output_size, "a tag of 3 bytes");
}

// libsodium's Argon2i starts at 3 passes (crypto_pwhash_argon2i_OPSLIMIT_MIN); RFC 9106's 1 and 2
// are unsupported_by_backend, and 3 runs.
void test_argon2i_passes() {
    for (std::uint32_t const passes : {1U, 2U}) {
        expect_refused<kdfs::argon2i>(32, sample_salt, {.passes = passes, .memory_kibibytes = 32},
                                      hash::error::unsupported_by_backend,
                                      "Argon2i, 1 or 2 passes");
    }
    std::array<std::uint8_t, 16> tag{};
    BOOST_TEST(hash::argon2<kdfs::argon2i>(tag, sample_password, sample_salt,
                                           {.passes = 3, .memory_kibibytes = 8})
                   .has_value());
    // Argon2id runs from 1 pass, as RFC 9106 has it.
    BOOST_TEST(hash::argon2<kdfs::argon2id>(tag, sample_password, sample_salt,
                                            {.passes = 1, .memory_kibibytes = 8})
                   .has_value());
}

}  // namespace

int main() {
    test_libsodium_table();
    test_against_argon2_ctx<kdfs::argon2i>(Argon2_i, 3);
    test_against_argon2_ctx<kdfs::argon2id>(Argon2_id, 1);
    test_argon2id_function();
    test_unsupported<kdfs::argon2i>(3);
    test_unsupported<kdfs::argon2id>(1);
    test_argon2i_passes();
    return webcpp::test::exit_status(boost::report_errors());
}
