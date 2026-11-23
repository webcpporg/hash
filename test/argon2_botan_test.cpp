// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Argon2 on backends::botan (Botan 3.14.1's "Argon2d", "Argon2i" and "Argon2id", the lanes in
// turn):
// - RFC 9106, section 5's three cases (t 3, m 32 KiB, p 4, a secret and associated data) through
//   argon2<kdfs::argon2d, kdfs::argon2i, kdfs::argon2id>;
// - the function argon2id against the three cases of libsodium's own table that argon2id_test
//   checks on backends::sodium (Task 15), and against libsodium's crypto_pwhash_argon2id at one
//   lane (argon2id on backends::sodium) on random cases, the family's Argon2i and Argon2id too;
// - argon2<kdfs::argon2i> and argon2<kdfs::argon2id> against libsodium's core argon2_ctx on random
//   passwords, salts, secrets, associated data, passes, lanes, memory and tag sizes;
// - Botan's limits: 129 lanes and m above 8 GiB (2 GiB on wasm32) answering
//   unsupported_by_backend, the function argon2id's memory above them invalid_parameters, each
//   refusal leaving the output as it was;
// - backends::botan never a default (design D34), and its cells.

#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/argon2_reference.hpp"
#include "support/hex.hpp"
#include "support/random_cases.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace {

namespace hash = webcpp::hash;
namespace kdfs = webcpp::hash::kdfs;
namespace test = webcpp::test;
using hash::backends::botan;
using hash::backends::sodium;
using bytes = std::vector<std::uint8_t>;

constexpr std::uint8_t untouched = 0x5A;

bool all_of(std::span<std::uint8_t const> data, std::uint8_t value) {
    return std::ranges::all_of(data, [value](std::uint8_t byte) { return byte == value; });
}

bool failed_with(boost::system::result<void> const& outcome, hash::error expected) {
    return outcome.has_error() && outcome.error() == expected;
}

// ---- RFC 9106, section 5 ----

// The inputs of RFC 9106's three cases: password 32 bytes of 0x01, salt 16 of 0x02, secret 8 of
// 0x03, associated data 12 of 0x04; t = 3, m = 32 KiB, p = 4, a 32-byte tag.
struct rfc9106_inputs {
    std::array<std::uint8_t, 32> password{};
    std::array<std::uint8_t, 16> salt{};
    std::array<std::uint8_t, 8> secret{};
    std::array<std::uint8_t, 12> associated_data{};

    rfc9106_inputs() {
        password.fill(0x01);
        salt.fill(0x02);
        secret.fill(0x03);
        associated_data.fill(0x04);
    }

    [[nodiscard]] hash::argon2_parameters parameters() const {
        return {
            .passes = 3,
            .memory_kibibytes = 32,
            .lanes = 4,
            .secret = secret,
            .associated_data = associated_data,
        };
    }
};

template <class Variant>
std::string rfc9106_tag() {
    rfc9106_inputs const in;
    std::array<std::uint8_t, 32> tag{};
    auto const done = hash::argon2<Variant, botan>(tag, in.password, in.salt, in.parameters());
    BOOST_TEST(done.has_value());
    return test::to_hex(tag);
}

void check_rfc9106() {
    // RFC 9106, sections 5.1, 5.2 and 5.3, "Tag".
    BOOST_TEST_EQ(rfc9106_tag<kdfs::argon2d>(),
                  std::string("512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb"));
    BOOST_TEST_EQ(rfc9106_tag<kdfs::argon2i>(),
                  std::string("c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8"));
    BOOST_TEST_EQ(rfc9106_tag<kdfs::argon2id>(),
                  std::string("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"));
}

// ---- libsodium's table ----

// A case of libsodium's test/default/pwhash_argon2id.c, tv(), at 77e1ce5, with its output in
// pwhash_argon2id.exp, as argon2id_test.cpp holds it: the salt the first 16 bytes of the table's
// 32, the memory the table's limit rounded down to a multiple of 1,024.
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
        .memory = 7256064,
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
        .memory = 7848960,
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
        .memory = 7994368,
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

void check_libsodium_table() {
    for (auto const& c : libsodium_cases) {
        auto const password = test::from_hex(c.password);
        auto const salt = test::from_hex(c.salt);
        bytes tag(c.tag.size() / 2);
        auto const done =
            hash::argon2id<botan>(tag, password, salt, {.passes = c.passes, .memory = c.memory});
        BOOST_TEST(done.has_value());
        BOOST_TEST_EQ(test::to_hex(tag), std::string(c.tag));
    }
}

// ---- Agreement ----

// argon2<Variant> on backends::botan against argon2_ctx on random cases: passwords of 0 to 64
// bytes, salts of 8 to 32, a secret and associated data of 0 to 32 (empty one case in three),
// t of 1 to 3, p of 1 to 4, m of 8p to 256 KiB, tags of 16 to 80 bytes (argon2_ctx's shortest is
// libsodium's 16).
template <class Variant>
void agree_with_reference(argon2_type type, std::string_view name) {
    test::random_source rnd(test::agreement_seed);
    constexpr std::size_t cases = 40;
    for (std::size_t index = 0; index < cases; ++index) {
        auto const password = rnd.bytes(rnd.between(0, 64));
        auto const salt = rnd.bytes(rnd.between(8, 32));
        auto const secret = index % 3 == 0 ? bytes{} : rnd.bytes(rnd.between(1, 32));
        auto const associated_data = index % 3 == 1 ? bytes{} : rnd.bytes(rnd.between(1, 32));
        auto const passes = static_cast<std::uint32_t>(rnd.between(1, 3));
        auto const lanes = static_cast<std::uint32_t>(rnd.between(1, 4));
        auto const memory_kibibytes =
            static_cast<std::uint32_t>(rnd.between(std::size_t{8} * lanes, 256));
        std::size_t const tag_size = rnd.between(16, 80);
        bytes expected(tag_size);
        int const code = test::argon2_reference(expected, {
                                                              .password = password,
                                                              .salt = salt,
                                                              .secret = secret,
                                                              .associated_data = associated_data,
                                                              .passes = passes,
                                                              .memory_kibibytes = memory_kibibytes,
                                                              .lanes = lanes,
                                                              .variant = type,
                                                          });
        bytes tag(tag_size, untouched);
        auto const done = hash::argon2<Variant, botan>(tag, password, salt,
                                                       {
                                                           .passes = passes,
                                                           .memory_kibibytes = memory_kibibytes,
                                                           .lanes = lanes,
                                                           .secret = secret,
                                                           .associated_data = associated_data,
                                                       });
        if (!BOOST_TEST_EQ(code, ARGON2_OK) || !BOOST_TEST(done.has_value()) ||
            !BOOST_TEST_EQ(test::to_hex(tag), test::to_hex(expected))) {
            std::cerr << "  " << name << " case " << index << ": t " << passes << ", m "
                      << memory_kibibytes << ", p " << lanes << ", tag " << tag_size << '\n';
        }
    }
}

// libsodium at one lane: the function argon2id and the family's Argon2id and Argon2i on
// backends::sodium (crypto_pwhash_argon2id, crypto_pwhash_argon2i: a 16-byte salt, Argon2i at
// least 3 passes) against the same on backends::botan.
void agree_with_sodium() {
    test::random_source rnd(test::agreement_seed);
    constexpr std::size_t cases = 20;
    for (std::size_t index = 0; index < cases; ++index) {
        auto const password = rnd.bytes(rnd.between(0, 64));
        auto const salt = rnd.bytes(hash::argon2id_salt_size);
        auto const passes = static_cast<std::uint32_t>(rnd.between(3, 4));
        auto const memory_kibibytes = static_cast<std::uint32_t>(rnd.between(8, 256));
        std::size_t const tag_size = rnd.between(16, 80);
        hash::argon2id_parameters const costs{
            .passes = passes,
            .memory = std::size_t{memory_kibibytes} * 1024,
        };
        hash::argon2_parameters const family{
            .passes = passes,
            .memory_kibibytes = memory_kibibytes,
        };
        bytes expected(tag_size);
        bytes tag(tag_size);
        bool agreed = hash::argon2id<sodium>(expected, password, salt, costs).has_value() &&
                      hash::argon2id<botan>(tag, password, salt, costs).has_value() &&
                      tag == expected;
        agreed = agreed &&
                 hash::argon2<kdfs::argon2id, botan>(tag, password, salt, family).has_value() &&
                 tag == expected;
        agreed =
            agreed &&
            hash::argon2<kdfs::argon2i, sodium>(expected, password, salt, family).has_value() &&
            hash::argon2<kdfs::argon2i, botan>(tag, password, salt, family).has_value() &&
            tag == expected;
        if (!BOOST_TEST(agreed)) {
            std::cerr << "  libsodium case " << index << ": t " << passes << ", m "
                      << memory_kibibytes << ", tag " << tag_size << '\n';
        }
    }
}

// ---- Botan's limits ----

// 129 lanes and m past Botan's 8 GiB (2 GiB on wasm32) are unsupported_by_backend, the tag
// untouched, before any memory is allocated; 128 lanes are computed. The function argon2id refuses
// a memory past them with invalid_parameters, as every backend's limit of it.
void check_limits() {
    std::array<std::uint8_t, 16> const salt{};
    std::array<std::uint8_t, 32> tag{};
    tag.fill(untouched);
    for (auto const call : {
             +[](std::span<std::uint8_t> out, std::span<std::uint8_t const> s,
                 hash::argon2_parameters const& p) {
                 return hash::argon2<kdfs::argon2d, botan>(out, {}, s, p);
             },
             +[](std::span<std::uint8_t> out, std::span<std::uint8_t const> s,
                 hash::argon2_parameters const& p) {
                 return hash::argon2<kdfs::argon2i, botan>(out, {}, s, p);
             },
             +[](std::span<std::uint8_t> out, std::span<std::uint8_t const> s,
                 hash::argon2_parameters const& p) {
                 return hash::argon2<kdfs::argon2id, botan>(out, {}, s, p);
             },
         }) {
        BOOST_TEST(
            failed_with(call(tag, salt, {.passes = 1, .memory_kibibytes = 8 * 129, .lanes = 129}),
                        hash::error::unsupported_by_backend));
        constexpr std::uint32_t past = ((sizeof(std::size_t) == 4 ? 2U : 8U) * 1024U * 1024U) + 1;
        BOOST_TEST(failed_with(call(tag, salt, {.passes = 1, .memory_kibibytes = past}),
                               hash::error::unsupported_by_backend));
        BOOST_TEST(all_of(tag, untouched));
        BOOST_TEST(
            call(tag, salt, {.passes = 1, .memory_kibibytes = 8 * 128, .lanes = 128}).has_value());
        tag.fill(untouched);
    }
    constexpr std::uint64_t most = (sizeof(std::size_t) == 4 ? std::uint64_t{2} : 8) << 30U;
    static_assert(hash::detail::argon2id_engine<botan>::limits.memory == most);
    hash::argon2id_parameters const past_most{
        .passes = 1,
        .memory = static_cast<std::size_t>(most + 1024),
    };
    BOOST_TEST(failed_with(hash::argon2id<botan>(tag, {}, salt, past_most),
                           hash::error::invalid_parameters));
    BOOST_TEST(all_of(tag, untouched));
}

// ---- The cells and the defaults ----

static_assert(hash::backend_has_v<botan, kdfs::argon2id, void>);
static_assert(hash::backend_has_v<botan, kdfs::argon2d, hash::argon2_parameters>);
static_assert(hash::backend_has_v<botan, kdfs::argon2i, hash::argon2_parameters>);
static_assert(hash::backend_has_v<botan, kdfs::argon2id, hash::argon2_parameters>);
// Never a default (design D34): argon2id's and Argon2i's stay backends::sodium; Argon2d has none.
static_assert(std::is_same_v<hash::default_backend<kdfs::argon2id>, sodium>);
static_assert(std::is_same_v<hash::default_backend<kdfs::argon2d>, hash::detail::no_default>);

}  // namespace

int main() {
    check_rfc9106();
    check_libsodium_table();
    agree_with_reference<kdfs::argon2i>(Argon2_i, "argon2i");
    agree_with_reference<kdfs::argon2id>(Argon2_id, "argon2id");
    agree_with_sodium();
    check_limits();
    return webcpp::test::exit_status(boost::report_errors());
}
