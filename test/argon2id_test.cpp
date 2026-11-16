// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// argon2id on backends::sodium: three cases of libsodium's own test table, argon2id against
// libsodium's core argon2_ctx with one lane on 20 random cases, every guard of spec 2.10 at its
// limits, a backend's failure, libsodium's -1 with and without ENOMEM, and the presets against
// libsodium's. The test includes argon2.hpp alone for argon2id: a program that links libsodium and
// includes only the function's header gets the backend's engine.

#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/kdf.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/result.hpp>

#include <webcpp/test/exit_status.hpp>

#include "support/argon2_reference.hpp"
#include "support/hex.hpp"

#include <sodium/crypto_pwhash_argon2id.h>  // the presets' functions, beside the macros

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace hash = webcpp::hash;
using webcpp::test::from_hex;
using webcpp::test::to_hex;

namespace test_backends {
namespace {

// A backend whose engine writes into the output, then fails: the public function zeroes it.
struct failing {};

// A backend whose engine records the costs it is called with and succeeds, with no work: a call
// past the guards, with libsodium's limits.
struct recording {};

// NOLINTBEGIN(cppcoreguidelines-avoid-non-const-global-variables): the recording engine's record
int recorded_calls = 0;
std::uint64_t recorded_passes = 0;
std::size_t recorded_memory = 0;
// NOLINTEND(cppcoreguidelines-avoid-non-const-global-variables)

}  // namespace
}  // namespace test_backends

template <>
struct webcpp::hash::detail::argon2id_engine<test_backends::failing> {
    static constexpr argon2id_limits limits{std::uint64_t{1} << 31U};

    static boost::system::result<void> derive(std::span<std::uint8_t> output,
                                              std::span<std::uint8_t const> /*password*/,
                                              std::span<std::uint8_t const> /*salt*/,
                                              std::uint64_t /*passes*/,
                                              std::size_t /*memory*/) noexcept {
        std::ranges::fill(output, std::uint8_t{0x55});
        return webcpp::hash::error::backend_failure;
    }
};

template <>
struct webcpp::hash::detail::argon2id_engine<test_backends::recording> {
    static constexpr argon2id_limits limits =
        argon2id_engine<webcpp::hash::backends::sodium>::limits;

    static boost::system::result<void> derive(std::span<std::uint8_t> /*output*/,
                                              std::span<std::uint8_t const> /*password*/,
                                              std::span<std::uint8_t const> /*salt*/,
                                              std::uint64_t passes, std::size_t memory) noexcept {
        ++test_backends::recorded_calls;
        test_backends::recorded_passes = passes;
        test_backends::recorded_memory = memory;
        return {};
    }
};

namespace {

constexpr std::uint8_t untouched = 0xaa;

bool all_of(std::span<std::uint8_t const> bytes, std::uint8_t value) {
    return std::ranges::all_of(bytes, [value](std::uint8_t b) { return b == value; });
}

// A case of libsodium's test/default/pwhash_argon2id.c, tv(), at 77e1ce5, with its output in
// pwhash_argon2id.exp. The table's salts are 32 bytes and libsodium reads 16 of them
// (crypto_pwhash_SALTBYTES): the salt here is their first 16. Its memory limits are not multiples
// of 1,024, which libsodium divides by 1,024 (memlimit / 1024U): the memory here is the limit
// rounded down to a multiple of 1,024, the same blocks, since argon2id refuses any other.
struct libsodium_case {
    std::string_view password;
    std::string_view salt;
    std::uint64_t passes;
    std::size_t memory;
    std::string_view tag;
};

// The table's first three cases, each of which its .exp shows succeeding.
constexpr std::array libsodium_cases{
    libsodium_case{
        .password = "a347ae92bce9f80f6f595a4480fc9c2fe7e7d7148d371e9487d75f5c23008ffa"
                    "e065577a928febd9b1973a5a95073acdbeb6a030cfc0d79caa2dc5cd011cef02"
                    "c08da232d76d52dfbca38ca8dcbd665b17d1665f7cf5fe59772ec909733b24de"
                    "97d6f58d220b20c60d7c07ec1fd93c52c31020300c6c1facd77937a597c7a6",
        .salt = "5541fbc995d5c197ba290346d2c559de",
        .passes = 5,
        .memory = 7256064,  // 7256678 rounded down
        .tag = "18acec5d6507739f203d1f5d9f1d862f7c2cdac4f19d2bdff64487e60d969e3c"
               "ed615337b9eec6ac4461c6ca07f0939741e57c24d0005c7ea171a0ee1e734824"
               "9d135b38f222e4dad7b9a033ed83f5ca27277393e316582033c74affe2566a2b"
               "ea47f91f0fd9fe49ece7e1f79f3ad6e9b23e0277c8ecc4b313225748dd2a80f5"
               "679534a0700e246a79a49b3f74eb89ec6205fe1eeb941c73b1fcf1",
    },
    libsodium_case{
        .password = "e125cee61c8cb7778d9e5ad0a6f5d978ce9f84de213a8556d9ffe202020ab4a6"
                    "ed9074a4eb3416f9b168f137510f3a30b70b96cbfa219ff99f6c6eaffb15c06b"
                    "60e00cc2890277f0fd3c622115772f7048adaebed86e",
        .salt = "f1192dd5dc2368b9cd421338b2243345",
        .passes = 4,
        .memory = 7848960,  // 7849083 rounded down
        .tag = "26bab5f101560e48c711da4f05e81f5a3802b7a93d5155b9cab153069cc42b8e"
               "9f910bfead747652a0708d70e4de0bada37218bd203a1201c36b42f9a269b675"
               "b1f30cfc36f35a3030e9c7f57dfba0d341a974c1886f708c3e8297efbfe411bb"
               "9d51375264bd7c70d57a8a56fc9de2c1c97c08776803ec2cd0140bba8e61dc0f"
               "4ad3d3d1a89b4b710af81bfe35a0eea193e18a6da0f5ec05542c9eefc4584458"
               "e1da715611ba09617384748bd43b9bf1f3a6df4ecd091d0875e08d6e2fd8a5c7"
               "ce08904b5160cd38167b76ec76ef2d310049055a564da23d4ebd2b87e421cc33"
               "c401e12d5cd8d936c9baf75ebdfb557d342d2858fc781da31860",
    },
    libsodium_case{
        .password = "92263cbf6ac376499f68a4289d3bb59e5a22335eba63a32e6410249155b956b6"
                    "a3b48d4a44906b18b897127300b375b8f834f1ceffc70880a885f47c33876717"
                    "e392be57f7da3ae58da4fd1f43daa7e44bb82d3717af4319349c24cd31e46d29"
                    "5856b0441b6b289992a11ced1cc3bf3011604590244a3eb737ff221129215e4e"
                    "4347f4915d41292b5173d196eb9add693be5319fdadc242906178bb6c0286c9b"
                    "6ca6012746711f58c8c392016b2fdfc09c64f0f6b6ab7b",
        .salt = "3b840e20e9555e9fb031c4ba1f1747ce",
        .passes = 3,
        .memory = 7994368,  // 7994791 rounded down
        .tag = "6eb45e668582d63788ca8f6e930ca60b045a795fca987344f9a7a135aa3b5132"
               "b50a34a3864c26581f1f56dd0bcbfafbfa92cd9bff6b24a734cfe88f854aef4b"
               "da0a7983120f44936e8ff31d29728ac08ccce6f3f916b3c63962755c23a1fa9b"
               "b4e8823fc867bfd18f28980d94bc5874423ab7f96cc0ab78d8fa21fbd00cd3a1"
               "d96a73fa439ccc3fc4eab1590677b06cc78b0f674dfb680f23022fb902022dd8"
               "620803229c6ddf79a8156ccfce48bbd76c05ab670634f206e5b2e896230baa74"
               "a856964dbd8511acb71d75a1506766a125d8ce037f1db72086ebc3bccaefbd8c"
               "d9380167c2530386544ebfbeadbe237784d102bb92a10fd242",
    },
};

void test_libsodium_table() {
    for (auto const& c : libsodium_cases) {
        auto const password = from_hex(c.password);
        auto const salt = from_hex(c.salt);
        std::vector<std::uint8_t> tag(c.tag.size() / 2);
        auto const done =
            hash::argon2id(tag, password, salt, {.passes = c.passes, .memory = c.memory});
        BOOST_TEST(done.has_value());
        BOOST_TEST_EQ(to_hex(tag), std::string(c.tag));
    }
}

// argon2id against argon2_ctx with one lane, on 20 cases of a fixed seed: memory 8 to 256 KiB,
// 1 to 3 passes, a password of 0 to 64 bytes, a tag of 16 to 80 bytes.
void test_against_argon2_ctx() {
    // A fixed seed on purpose: every run checks the same cases, and a failure reproduces.
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp): see above
    std::mt19937 random(20261115U);
    auto const between = [&random](std::uint32_t low, std::uint32_t high) {
        return std::uniform_int_distribution<std::uint32_t>(low, high)(random);
    };
    for (int i = 0; i < 20; ++i) {
        std::vector<std::uint8_t> password(between(0, 64));
        std::ranges::generate(password, [&] { return static_cast<std::uint8_t>(between(0, 255)); });
        std::array<std::uint8_t, hash::argon2id_salt_size> salt{};
        std::ranges::generate(salt, [&] { return static_cast<std::uint8_t>(between(0, 255)); });
        std::uint32_t const passes = between(1, 3);
        std::uint32_t const memory_kib = between(8, 256);
        std::size_t const tag_size = between(16, 80);

        std::vector<std::uint8_t> expected(tag_size);
        int const code = webcpp::test::argon2_reference(expected, {
                                                                      .password = password,
                                                                      .salt = salt,
                                                                      .secret = {},
                                                                      .associated_data = {},
                                                                      .passes = passes,
                                                                      .memory_kib = memory_kib,
                                                                      .lanes = 1,
                                                                  });
        BOOST_TEST_EQ(code, ARGON2_OK);

        std::vector<std::uint8_t> tag(tag_size);
        auto const done = hash::argon2id(
            tag, password, salt, {.passes = passes, .memory = std::size_t{memory_kib} * 1024});
        BOOST_TEST(done.has_value());
        BOOST_TEST_EQ(to_hex(tag), to_hex(expected));
    }
}

const std::array<std::uint8_t, 8> password{'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
const std::array<std::uint8_t, hash::argon2id_salt_size> salt{
    's', 'o', 'm', 'e', 's', 'a', 'l', 't',  // "somesalt" twice
    's', 'o', 'm', 'e', 's', 'a', 'l', 't',
};
constexpr hash::argon2id_parameters cheapest{.passes = 1, .memory = 8192};

// Expects argon2id's refusal with `expected`, the output untouched.
void expect_refused(std::span<std::uint8_t> output, std::span<std::uint8_t const> pass,
                    std::span<std::uint8_t const> salt_bytes,
                    hash::argon2id_parameters const& parameters, hash::error expected) {
    auto const refused = hash::argon2id(output, pass, salt_bytes, parameters);
    BOOST_TEST(refused.has_error() && refused.error() == expected);
}

void test_output_guard() {
    std::array<std::uint8_t, 16> buffer{};
    buffer.fill(untouched);
    auto const longest = std::uint64_t{0xffffffff};
    expect_refused(std::span<std::uint8_t>(buffer.data(), 15), password, salt, cheapest,
                   hash::error::invalid_output_size);
    expect_refused(std::span<std::uint8_t>(buffer.data(), 0), password, salt, cheapest,
                   hash::error::invalid_output_size);
    // Natively a span of 2^32 bytes over 16, which the guard refuses before anything reads or
    // writes it; on wasm32 no span is that long.
    if constexpr (std::numeric_limits<std::size_t>::max() > longest) {
        expect_refused(
            std::span<std::uint8_t>(buffer.data(), static_cast<std::size_t>(longest + 1)), password,
            salt, cheapest, hash::error::invalid_output_size);
    }
    BOOST_TEST(all_of(buffer, untouched));
    // 16 bytes, the shortest, with an empty password and the cheapest costs: a default span,
    // whose data() is null, against argon2_ctx with the same empty password.
    std::span<std::uint8_t const> const nothing{};
    BOOST_TEST(nothing.data() == nullptr);
    BOOST_TEST(hash::argon2id(buffer, nothing, salt, cheapest).has_value());
    std::array<std::uint8_t, 16> expected{};
    BOOST_TEST_EQ(webcpp::test::argon2_reference(expected, {.password = nothing,
                                                            .salt = salt,
                                                            .secret = {},
                                                            .associated_data = {},
                                                            .passes = 1,
                                                            .memory_kib = 8,
                                                            .lanes = 1}),
                  ARGON2_OK);
    BOOST_TEST_EQ(to_hex(buffer), to_hex(expected));
}

void test_salt_guard() {
    std::array<std::uint8_t, 16> buffer{};
    buffer.fill(untouched);
    std::array<std::uint8_t, 17> long_salt{};
    for (std::size_t const size : {0U, 8U, 15U, 17U}) {
        expect_refused(buffer, password, std::span<std::uint8_t const>(long_salt.data(), size),
                       cheapest, hash::error::invalid_salt_size);
    }
    // The output's guard comes first.
    expect_refused(std::span<std::uint8_t>(buffer.data(), 15), password,
                   std::span<std::uint8_t const>(long_salt.data(), 15), cheapest,
                   hash::error::invalid_output_size);
    BOOST_TEST(all_of(buffer, untouched));
}

void test_password_guard() {
    std::array<std::uint8_t, 16> buffer{};
    buffer.fill(untouched);
    auto const longest = std::uint64_t{0xffffffff};
    // Natively a password of 2^32 bytes over 8, refused before anything reads it.
    if constexpr (std::numeric_limits<std::size_t>::max() > longest) {
        std::span<std::uint8_t const> const past(password.data(),
                                                 static_cast<std::size_t>(longest + 1));
        expect_refused(buffer, past, salt, cheapest, hash::error::input_too_long);
        // The salt's guard comes first.
        expect_refused(buffer, past, std::span<std::uint8_t const>(salt.data(), 15), cheapest,
                       hash::error::invalid_salt_size);
    }
    BOOST_TEST(all_of(buffer, untouched));
}

void test_parameters_guard() {
    std::array<std::uint8_t, 16> buffer{};
    buffer.fill(untouched);
    auto const most_memory = static_cast<std::uint64_t>(crypto_pwhash_argon2id_MEMLIMIT_MAX);
    std::vector<hash::argon2id_parameters> const refused{
        {.passes = 0, .memory = 8192},
        {.passes = std::uint64_t{1} << 32U, .memory = 8192},
        {.passes = 1, .memory = 0},
        {.passes = 1, .memory = 7168},
        {.passes = 1, .memory = 8191},
        {.passes = 1, .memory = 8193},
        {.passes = 1, .memory = 9000},
        {.passes = 1, .memory = static_cast<std::size_t>(most_memory + 1024)},
    };
    for (auto const& parameters : refused) {
        expect_refused(buffer, password, salt, parameters, hash::error::invalid_parameters);
    }
    BOOST_TEST(all_of(buffer, untouched));
    // The most passes and libsodium's most memory pass every guard and reach the engine, which
    // records them (a real run would take 4 TiB, 2 GiB on wasm32); a KiB more is refused.
    hash::argon2id_parameters const largest{
        .passes = 0xffffffff,
        .memory = static_cast<std::size_t>(most_memory),
    };
    int const before = test_backends::recorded_calls;
    BOOST_TEST(
        hash::argon2id<test_backends::recording>(buffer, password, salt, largest).has_value());
    BOOST_TEST_EQ(test_backends::recorded_calls, before + 1);
    BOOST_TEST_EQ(test_backends::recorded_passes, largest.passes);
    BOOST_TEST_EQ(test_backends::recorded_memory, largest.memory);
    auto const past = hash::argon2id<test_backends::recording>(
        buffer, password, salt,
        {.passes = 1, .memory = static_cast<std::size_t>(most_memory + 1024)});
    BOOST_TEST(past.has_error() && past.error() == hash::error::invalid_parameters);
    BOOST_TEST_EQ(test_backends::recorded_calls, before + 1);

    // The password's guard comes before the parameters': natively a password of 2^32 bytes over
    // 8 with no passes is input_too_long, never read.
    if constexpr (std::numeric_limits<std::size_t>::max() > 0xffffffffU) {
        std::span<std::uint8_t const> const past_password(
            password.data(), static_cast<std::size_t>(std::uint64_t{0xffffffff} + 1));
        expect_refused(buffer, past_password, salt, {.passes = 0, .memory = 0},
                       hash::error::input_too_long);
    }
}

void test_backend_failure() {
    std::array<std::uint8_t, 16> buffer{};
    buffer.fill(untouched);
    auto failed = hash::argon2id<test_backends::failing>(buffer, password, salt, cheapest);
    BOOST_TEST(failed.has_error() && failed.error() == hash::error::backend_failure);
    BOOST_TEST(all_of(buffer, 0));

    // A guard's refusal reaches no backend.
    buffer.fill(untouched);
    failed = hash::argon2id<test_backends::failing>(buffer, password, salt,
                                                    {.passes = 0, .memory = 8192});
    BOOST_TEST(failed.has_error() && failed.error() == hash::error::invalid_parameters);
    BOOST_TEST(all_of(buffer, untouched));
}

// libsodium's -1 is errc::not_enough_memory with errno ENOMEM, backend_failure with any other
// errno, including the 0 the engine sets before the call.
void test_sodium_status() {
    using hash::detail::sodium_pwhash_status;
    BOOST_TEST(sodium_pwhash_status(0, ENOMEM).has_value());
    auto const out_of_memory = sodium_pwhash_status(-1, ENOMEM);
    BOOST_TEST(out_of_memory.has_error() &&
               out_of_memory.error() == boost::system::errc::not_enough_memory);
    for (int const error_number : {0, EINVAL, EFBIG}) {
        auto const failed = sodium_pwhash_status(-1, error_number);
        BOOST_TEST(failed.has_error() && failed.error() == hash::error::backend_failure);
    }
}

// The presets are libsodium's (backends/sodium.hpp also checks them against the macros).
void test_presets() {
    BOOST_TEST_EQ(hash::argon2id_interactive.passes, crypto_pwhash_argon2id_opslimit_interactive());
    BOOST_TEST_EQ(hash::argon2id_interactive.memory, crypto_pwhash_argon2id_memlimit_interactive());
    BOOST_TEST_EQ(hash::argon2id_moderate.passes, crypto_pwhash_argon2id_opslimit_moderate());
    BOOST_TEST_EQ(hash::argon2id_moderate.memory, crypto_pwhash_argon2id_memlimit_moderate());
    BOOST_TEST_EQ(hash::argon2id_sensitive.passes, crypto_pwhash_argon2id_opslimit_sensitive());
    BOOST_TEST_EQ(hash::argon2id_sensitive.memory, crypto_pwhash_argon2id_memlimit_sensitive());
    BOOST_TEST_EQ(hash::argon2id_salt_size, crypto_pwhash_argon2id_saltbytes());
}

// argon2id's default backend is default_backend's choice for kdfs::argon2id: backends::sodium, the
// one backend that has it.
static_assert(std::is_same_v<hash::default_backend<hash::kdfs::argon2id>, hash::backends::sodium>);
static_assert(&hash::argon2id<> == &hash::argon2id<hash::backends::sodium>);

}  // namespace

int main() {
    test_libsodium_table();
    test_against_argon2_ctx();
    test_output_guard();
    test_salt_guard();
    test_password_guard();
    test_parameters_guard();
    test_backend_failure();
    test_sodium_status();
    test_presets();
    return webcpp::test::exit_status(boost::report_errors());
}
