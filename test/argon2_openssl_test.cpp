// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Argon2 on backends::openssl (OpenSSL 3.5.9's EVP_KDFs "ARGON2D", "ARGON2I" and "ARGON2ID", one
// thread):
// - RFC 9106, section 5's three cases (four lanes, a secret and associated data) through
//   argon2<kdfs::argon2d, kdfs::argon2i, kdfs::argon2id>, the Argon2i and Argon2id ones also
//   through libsodium's private core argon2_ctx;
// - every case of OpenSSL's own evpkdf_argon2.txt, read at run time: each that computes a tag,
//   and each expected failure the family can state refused by the family's guards;
// - argon2<kdfs::argon2i> and argon2<kdfs::argon2id> against argon2_ctx on random passwords,
//   salts, secrets, associated data, passes, lanes, memory and tag sizes;
// - libsodium's crypto_pwhash_argon2id and crypto_pwhash_argon2i at one lane, the first through
//   the function argon2id on backends::sodium, against the function argon2id and the family on
//   backends::openssl;
// - the function argon2id's memory limit on backends::openssl, the family's on wasm32
//   (OpenSSL sizes the memory in a size_t), each refusal leaving the output as it was;
// - backends::openssl never a default (design D34), and its cells.

#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/backends/openssl.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/test/exit_status.hpp>

#include "require.hpp"
#include "support/argon2_reference.hpp"
#include "support/evp_stanzas.hpp"
#include "support/hex.hpp"
#include "support/random_cases.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/system/result.hpp>

#include <sodium/crypto_pwhash_argon2i.h>  // through /third_party//sodium

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace {

namespace hash = webcpp::hash;
namespace kdfs = webcpp::hash::kdfs;
namespace test = webcpp::test;
namespace evp = webcpp::test::evp;
using hash::backends::openssl;
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
    auto const done = hash::argon2<Variant, openssl>(tag, in.password, in.salt, in.parameters());
    test::require(BOOST_TEST(done.has_value()));
    return test::to_hex(tag);
}

// argon2_ctx's tag of RFC 9106's inputs, for Argon2i or Argon2id.
std::string rfc9106_reference(argon2_type type) {
    rfc9106_inputs const in;
    std::array<std::uint8_t, 32> tag{};
    int const code = test::argon2_reference(tag, {
                                                     .password = in.password,
                                                     .salt = in.salt,
                                                     .secret = in.secret,
                                                     .associated_data = in.associated_data,
                                                     .passes = 3,
                                                     .memory_kibibytes = 32,
                                                     .lanes = 4,
                                                     .variant = type,
                                                 });
    BOOST_TEST_EQ(code, ARGON2_OK);
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
    BOOST_TEST_EQ(rfc9106_tag<kdfs::argon2i>(), rfc9106_reference(Argon2_i));
    BOOST_TEST_EQ(rfc9106_tag<kdfs::argon2id>(), rfc9106_reference(Argon2_id));
}

// ---- OpenSSL's evpkdf_argon2.txt ----

using evp::ctrl_bytes;
using evp::ctrl_value;
using evp::stanza;
using evp::value_of;

// A Ctrl's number, decimal or 0x hex, or `otherwise` when the stanza has no such Ctrl.
std::uint32_t ctrl_number(stanza const& lines, std::string_view name, std::uint32_t otherwise) {
    auto const value = value_of(lines, name);
    if (!value) {
        return otherwise;
    }
    return static_cast<std::uint32_t>(std::stoul(ctrl_value(*value), nullptr, 0));
}

// The stanza's tag through argon2 of the variant `Variant` on backends::openssl. OpenSSL's
// defaults stand where the stanza sets no Ctrl: t = 3, m = 8 KiB, p = 1, no secret or associated
// data. A stanza's Ctrl.threads and Ctrl.early_clean do not change the tag.
template <class Variant>
std::string evp_tag(stanza const& lines, std::size_t tag_size) {
    auto const ctrl = [&](std::string_view name) {
        auto const value = value_of(lines, name);
        return value ? ctrl_bytes(*value) : bytes{};
    };
    bytes const password = ctrl("Ctrl.pass");
    bytes const salt = ctrl("Ctrl.salt");
    bytes const secret = ctrl("Ctrl.secret");
    bytes const associated_data = ctrl("Ctrl.ad");
    bytes tag(tag_size);
    auto const done = hash::argon2<Variant, openssl>(
        tag, password, salt,
        {
            .passes = ctrl_number(lines, "Ctrl.iter", 3),
            .memory_kibibytes = ctrl_number(lines, "Ctrl.memcost", 8),
            .lanes = ctrl_number(lines, "Ctrl.lanes", 1),
            .secret = secret,
            .associated_data = associated_data,
        });
    if (!BOOST_TEST(done.has_value())) {
        return {};
    }
    return test::to_hex(tag);
}

// An expected failure of evpkdf_argon2.txt through the family, when it has the stanza's
// parameters: the family refuses the value OpenSSL refuses, with the error of its guard, the output
// untouched. Where the stanza sets no salt, a 16-byte one; no tag size, 32 bytes. A stanza of
// threads or of a version has no equivalent (argon2 runs one thread of version 0x13): false. The
// variant is the stanza's, and a failure names the expected failure's index and KDF.
template <class Variant>
bool refuses_evp_failure(stanza const& lines, std::size_t index, std::string_view kdf) {
    for (auto const& [key, value] : lines) {
        if (key.starts_with("Ctrl.") &&
            (value.starts_with("threads:") || value.starts_with("version:"))) {
            return false;
        }
    }
    auto const salt_ctrl = value_of(lines, "Ctrl.salt");
    bytes const salt = salt_ctrl ? ctrl_bytes(*salt_ctrl) : bytes(16, 0x02);
    std::size_t const tag_size = ctrl_number(lines, "Ctrl.size", 32);
    // The guard each stanza is for: the tag's size, the salt's, else the costs (t, m, p).
    hash::error expected = hash::error::invalid_parameters;
    if (value_of(lines, "Ctrl.size")) {
        expected = hash::error::invalid_output_size;
    } else if (salt.size() < 8) {
        expected = hash::error::invalid_salt_size;
    }
    bytes tag(tag_size, untouched);
    auto const refused = hash::argon2<Variant, openssl>(
        tag, {}, salt,
        {
            .passes = ctrl_number(lines, "Ctrl.iter", 3),
            .memory_kibibytes = ctrl_number(lines, "Ctrl.memcost", 8),
            .lanes = ctrl_number(lines, "Ctrl.lanes", 1),
        });
    if (!BOOST_TEST(failed_with(refused, expected)) || !BOOST_TEST(all_of(tag, untouched))) {
        std::cerr << "  evpkdf_argon2.txt, expected failure " << index << " (" << kdf
                  << "), which the family does not refuse with "
                  << hash::make_error_code(expected).message() << '\n';
    }
    return true;
}

// Every stanza of evpkdf_argon2.txt: 12 with an Output and no Result computed; of the 11 expected
// failures, the 7 the family can state refused by its guards (lanes 0, lanes 2^24, memory under 8
// or 8p, passes 0, a 3-byte tag, a 2-byte salt) and the 4 of threads or a version counted.
void check_evp_data() {
    std::size_t run = 0;
    std::size_t refused = 0;
    std::size_t no_equivalent = 0;
    for (auto const& lines : evp::read_stanzas(WEBCPP_TEST_OPENSSL_EVP_DATA "/evpkdf_argon2.txt")) {
        auto const kdf = value_of(lines, "KDF");
        if (!kdf) {
            continue;
        }
        if (value_of(lines, "Result")) {
            std::size_t const index = refused + no_equivalent;
            bool stated = false;
            if (*kdf == "ARGON2D") {
                stated = refuses_evp_failure<kdfs::argon2d>(lines, index, *kdf);
            } else if (*kdf == "ARGON2I") {
                stated = refuses_evp_failure<kdfs::argon2i>(lines, index, *kdf);
            } else {
                test::require(BOOST_TEST_EQ(*kdf, std::string("ARGON2ID")));
                stated = refuses_evp_failure<kdfs::argon2id>(lines, index, *kdf);
            }
            ++(stated ? refused : no_equivalent);
            continue;
        }
        std::string expected = *value_of(lines, "Output");
        std::ranges::transform(expected, expected.begin(), [](char c) {
            return static_cast<char>(c >= 'A' && c <= 'F' ? c - 'A' + 'a' : c);
        });
        std::size_t const tag_size = expected.size() / 2;
        std::string computed;
        if (*kdf == "ARGON2D") {
            computed = evp_tag<kdfs::argon2d>(lines, tag_size);
        } else if (*kdf == "ARGON2I") {
            computed = evp_tag<kdfs::argon2i>(lines, tag_size);
        } else {
            test::require(BOOST_TEST_EQ(*kdf, std::string("ARGON2ID")));
            computed = evp_tag<kdfs::argon2id>(lines, tag_size);
        }
        if (!BOOST_TEST_EQ(computed, expected)) {
            std::cerr << "  evpkdf_argon2.txt, case " << run << " (" << *kdf << ")\n";
        }
        ++run;
    }
    evp::count_is("evpkdf_argon2.txt", "stanzas computed", run, 12);
    evp::count_is("evpkdf_argon2.txt", "expected failures the family refuses", refused, 7);
    evp::count_is("evpkdf_argon2.txt", "expected failures of threads or a version", no_equivalent,
                  4);
}

// ---- Agreement ----

// argon2<Variant> on backends::openssl against argon2_ctx on random cases: passwords of 0 to 64
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
        auto const done = hash::argon2<Variant, openssl>(tag, password, salt,
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

// The function argon2id on backends::sodium (crypto_pwhash_argon2id: one lane, a 16-byte salt)
// against the function argon2id and the family's Argon2id on backends::openssl.
void agree_argon2id_with_sodium() {
    test::random_source rnd(test::agreement_seed);
    constexpr std::size_t cases = 20;
    for (std::size_t index = 0; index < cases; ++index) {
        auto const password = rnd.bytes(rnd.between(0, 64));
        auto const salt = rnd.bytes(hash::argon2id_salt_size);
        auto const passes = static_cast<std::uint32_t>(rnd.between(1, 3));
        auto const memory_kibibytes = static_cast<std::uint32_t>(rnd.between(8, 256));
        std::size_t const tag_size = rnd.between(16, 80);
        hash::argon2id_parameters const costs{
            .passes = passes,
            .memory = std::size_t{memory_kibibytes} * 1024,
        };

        bytes expected(tag_size);
        bytes function_tag(tag_size);
        bytes family_tag(tag_size);
        bool const all_done =
            hash::argon2id<sodium>(expected, password, salt, costs).has_value() &&
            hash::argon2id<openssl>(function_tag, password, salt, costs).has_value() &&
            hash::argon2<kdfs::argon2id, openssl>(
                family_tag, password, salt,
                {.passes = passes, .memory_kibibytes = memory_kibibytes})
                .has_value();
        if (!BOOST_TEST(all_done) ||
            !BOOST_TEST_EQ(test::to_hex(function_tag), test::to_hex(expected)) ||
            !BOOST_TEST_EQ(test::to_hex(family_tag), test::to_hex(expected))) {
            std::cerr << "  argon2id against libsodium, case " << index << '\n';
        }
    }
}

// libsodium's crypto_pwhash_argon2i (one lane, a 16-byte salt, at least 3 passes) against the
// family's Argon2i on backends::openssl.
void agree_argon2i_with_sodium() {
    test::random_source rnd(test::agreement_seed);
    constexpr std::size_t cases = 10;
    for (std::size_t index = 0; index < cases; ++index) {
        auto const password = rnd.bytes(rnd.between(0, 64));
        auto const salt = rnd.bytes(crypto_pwhash_argon2i_SALTBYTES);
        auto const passes = static_cast<std::uint32_t>(rnd.between(3, 4));
        auto const memory_kibibytes = static_cast<std::uint32_t>(rnd.between(8, 256));
        std::size_t const tag_size = rnd.between(16, 80);

        bytes expected(tag_size);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): libsodium types it char
        auto const* const password_chars = reinterpret_cast<char const*>(password.data());
        int const code = crypto_pwhash_argon2i(
            expected.data(), expected.size(), password_chars, password.size(), salt.data(), passes,
            std::size_t{memory_kibibytes} * 1024, crypto_pwhash_argon2i_ALG_ARGON2I13);
        bytes tag(tag_size);
        auto const done = hash::argon2<kdfs::argon2i, openssl>(
            tag, password, salt, {.passes = passes, .memory_kibibytes = memory_kibibytes});
        if (!BOOST_TEST_EQ(code, 0) || !BOOST_TEST(done.has_value()) ||
            !BOOST_TEST_EQ(test::to_hex(tag), test::to_hex(expected))) {
            std::cerr << "  argon2i against libsodium, case " << index << '\n';
        }
    }
}

// ---- Limits ----

void check_limits() {
    std::array<std::uint8_t, 32> output{};
    std::array<std::uint8_t, 16> const salt{};
    output.fill(untouched);
    // The function argon2id: OpenSSL takes m in KiB as a uint32_t and sizes the memory, m blocks
    // of 1 KiB, in a size_t: 4 TiB less 1 KiB natively, past which 4 TiB is refused; 4 GiB less
    // 1 KiB on wasm32, where no size_t a whole number of KiB is past it.
    constexpr std::uint64_t memory_limit = hash::detail::argon2id_engine<openssl>::limits.memory;
    static_assert(
        memory_limit ==
        std::min<std::uint64_t>(0xffffffff, std::numeric_limits<std::size_t>::max() / 1024) * 1024);
    if constexpr (std::numeric_limits<std::size_t>::max() - 1024 >= memory_limit) {
        auto const refused = hash::argon2id<openssl>(
            output, {}, salt,
            {.passes = 1, .memory = static_cast<std::size_t>(memory_limit + 1024)});
        BOOST_TEST(failed_with(refused, hash::error::invalid_parameters));
        BOOST_TEST(all_of(output, untouched));
    }

    // The family: m of at most 4,194,303 KiB on wasm32 (a size_t of 4 GiB less 1 KiB),
    // unsupported_by_backend past it; natively RFC 9106's whole range.
    constexpr std::uint32_t family_limit =
        hash::detail::argon2_engine<openssl, kdfs::argon2id>::limits.max_memory_kibibytes;
    static_assert(family_limit == (sizeof(std::size_t) == 4 ? 4194303U : 0xffffffffU));
    if constexpr (sizeof(std::size_t) == 4) {
        auto const refused = hash::argon2<kdfs::argon2id, openssl>(
            output, {}, salt, {.passes = 1, .memory_kibibytes = family_limit + 1});
        BOOST_TEST(failed_with(refused, hash::error::unsupported_by_backend));
        BOOST_TEST(all_of(output, untouched));
    }

    // RFC 9106's shortest tag, 4 bytes, which libsodium does not produce.
    std::array<std::uint8_t, 4> shortest{};
    shortest.fill(untouched);
    BOOST_TEST((hash::argon2<kdfs::argon2d, openssl>(shortest, {}, salt,
                                                     {.passes = 1, .memory_kibibytes = 8})
                    .has_value()));
    BOOST_TEST(!all_of(shortest, untouched));

    // The family's guards come before the backend: m below 8p.
    auto const refused = hash::argon2<kdfs::argon2d, openssl>(
        output, {}, salt, {.passes = 1, .memory_kibibytes = 31, .lanes = 4});
    BOOST_TEST(failed_with(refused, hash::error::invalid_parameters));
    BOOST_TEST(all_of(output, untouched));
}

// ---- Cells and defaults ----

static_assert(hash::backend_has_v<openssl, kdfs::argon2d, hash::argon2_parameters>);
static_assert(hash::backend_has_v<openssl, kdfs::argon2i, hash::argon2_parameters>);
static_assert(hash::backend_has_v<openssl, kdfs::argon2id, hash::argon2_parameters>);
static_assert(hash::backend_has_v<openssl, kdfs::argon2id, void>);
// backends::openssl is never a default (design D34): Argon2d has none, Argon2i and Argon2id are
// libsodium's.
static_assert(std::is_same_v<hash::default_backend<kdfs::argon2d>, hash::detail::no_default>);
static_assert(std::is_same_v<hash::default_backend<kdfs::argon2i>, sodium>);
static_assert(std::is_same_v<hash::default_backend<kdfs::argon2id>, sodium>);

}  // namespace

int main() {
    check_rfc9106();
    check_evp_data();
    agree_with_reference<kdfs::argon2i>(Argon2_i, "argon2i");
    agree_with_reference<kdfs::argon2id>(Argon2_id, "argon2id");
    agree_argon2id_with_sodium();
    agree_argon2i_with_sodium();
    check_limits();
    return webcpp::test::exit_status(boost::report_errors());
}
