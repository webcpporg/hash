// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// HKDF and PBKDF2 on backends::botan (Botan 3.14.1's "HKDF-Extract(HMAC(<h>))",
// "HKDF-Expand(HMAC(<h>))", "HKDF(HMAC(<h>))" and "PBKDF2(HMAC(<h>))"):
// - RFC 5869's seven cases (PRK and OKM) through hkdf_extract, hkdf_expand and hkdf, and the three
//   cases of hkdf_hash2_test.cpp over SHA3-256, BLAKE2b and RIPEMD-160;
// - PBKDF2, RFC 6070's cases 1, 2, 3, 5 and 6 (the fourth, 16,777,216 iterations, is
//   pbkdf2_rfc6070_long's) and RFC 7914 section 11's two;
// - the guards of spec 2.8 and 2.9 at their limits, each refusal leaving the output as it was, and
//   backend_limits<botan>'s iteration count (a size_t of Botan's: 2^32 - 1 on wasm32);
// - an HMAC key longer than Botan's HMAC takes (8,192 bytes), HKDF-Extract's salt and PBKDF2's
//   password, hashed first: the same output as backends::hash2's;
// - 1,000 seeded random cases each of HKDF (the three functions) and PBKDF2 against
//   backends::hash2 over every hmac Botan has;
// - backends::botan's cells, and backends::hash2 still the default.
// It includes hkdf.hpp and pbkdf2.hpp alone, which bring backends/botan.hpp in when the program
// links Botan.

#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/pbkdf2.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/random_cases.hpp"
#include "support/rfc5869.hpp"
#include "support/rfc6070.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/system/result.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <vector>

namespace {

namespace hash = webcpp::hash;
namespace kdfs = webcpp::hash::kdfs;
namespace test = webcpp::test;
using hash::backends::botan;
using hash::backends::hash2;
using bytes = std::vector<std::uint8_t>;

constexpr std::uint8_t untouched = 0x5A;

bool all_of(std::span<std::uint8_t const> data, std::uint8_t value) {
    return std::ranges::all_of(data, [value](std::uint8_t byte) { return byte == value; });
}

bool failed_with(boost::system::result<void> const& outcome, hash::error expected) {
    return outcome.has_error() && outcome.error() == expected;
}

std::span<std::uint8_t const> bytes_of(std::string_view text) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): the RFCs' ASCII as bytes
    return {reinterpret_cast<std::uint8_t const*>(text.data()), text.size()};
}

template <class Hmac>
constexpr std::size_t digest_size = typename Hmac::result_type().size();

// Every hmac of hmac.hpp backends::botan has: every one but hmac_ripemd_128 and hmac_sha2_512_224.
using botan_hmacs =
    std::tuple<hash::hmac_md5_128, hash::hmac_sha1_160, hash::hmac_sha2_224, hash::hmac_sha2_256,
               hash::hmac_sha2_384, hash::hmac_sha2_512, hash::hmac_sha2_512_256,
               hash::hmac_sha3_224, hash::hmac_sha3_256, hash::hmac_sha3_384, hash::hmac_sha3_512,
               hash::hmac_ripemd_160, hash::hmac_blake2b_512, hash::hmac_blake2s_256>;

template <class Types, class Check>
void for_each_type(Check check) {
    [&]<class... T>(std::tuple<T...>*) {
        (check.template operator()<T>(), ...);
    }(static_cast<Types*>(nullptr));
}

// ---- HKDF: RFC 5869 and three more hmacs ----

// The three functions on one case, over Hmac on Botan; `salt` is the case's own or another
// spelling of it.
template <class Hmac>
void check_hkdf(test::rfc5869_case const& c, std::span<std::uint8_t const> salt) {
    auto const ikm = test::from_hex(c.ikm);
    auto const info = test::from_hex(c.info);
    auto const prk = hash::hkdf_extract<Hmac, botan>(salt, ikm);
    if (!BOOST_TEST(prk.has_value())) {
        return;
    }
    std::span<std::uint8_t const> const key(prk->data(), prk->size());
    BOOST_TEST_EQ(test::to_hex(key), std::string(c.prk));
    bytes okm(c.length);
    BOOST_TEST((hash::hkdf_expand<Hmac, botan>(okm, key, info).has_value()));
    BOOST_TEST_EQ(test::to_hex(okm), std::string(c.okm));
    bytes together(c.length);
    BOOST_TEST((hash::hkdf<Hmac, botan>(together, salt, ikm, info).has_value()));
    BOOST_TEST_EQ(test::to_hex(together), std::string(c.okm));
}

template <class Hmac>
void check_hkdf(test::rfc5869_case const& c) {
    check_hkdf<Hmac>(c, test::from_hex(c.salt));
}

// hkdf_hash2_test.cpp's cases over hmacs RFC 5869 has none for (Python's hmac over hashlib).
constexpr test::rfc5869_case sha3_256_case{
    .hash = "sha3_256",
    .ikm =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        "404142434445464748494a4b4c4d4e4f",
    .salt =
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5",
    .info =
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
        "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
    .length = 100,
    .prk = "a8460495f6165e6bed5f5c86effd16aac659dd9269d55f236af7f3a1f0934303",
    .okm =
        "332794d33dcae7ddb1b4bda2eaf3057152461e1d50fc3c5e3a87d749fdbd0d49"
        "e49809140691c3f60be467dc8edb01294b15d78dae540846262238524496fb42"
        "9818bd4b682569cabe12c4c2c9e71efa17471399bb5f0ae72a541913771f6279"
        "4b5b7c8b",
};

constexpr test::rfc5869_case blake2b_512_case{
    .hash = "blake2b_512",
    .ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    .salt = "",
    .info = "",
    .length = 200,
    .prk =
        "39db468c9289015fd163c86a299ef5a95942835aed7103a2b9f30cc796e2d058"
        "6fc284a024c25fb18699c78e47273346fa35f076ac315e5906fe170ba1877c63",
    .okm =
        "817520332f597bd8f557a4b40fddfe7674f1edac6c8a1a36fa0546b649bfae4a"
        "2ed3f34d03fdef572d515780475d1abac98e7c7079880fe6e4e91a714b5cca4d"
        "e894b07019568c0fffb84ed89457fbb98ef7dfdeb366829ce61c7d42a45928d9"
        "cf2451709b5fa184a857d90f1d272fc70e8296ade68cfcf1cf8e9770664148c6"
        "7a1440926bfb33a6e15fd28e32c56f4d6e74f0fd4d94ff1bd18850e73fb7af3c"
        "07d217335a7fa4dd3cf37c73ba78dfc6b672d6fd1139913d2d0a54b388192f4d"
        "70c37e29f668d638",
};

constexpr test::rfc5869_case ripemd_160_case{
    .hash = "ripemd_160",
    .ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    .salt = "000102030405060708090a0b0c",
    .info = "f0f1f2f3f4f5f6f7f8f9",
    .length = 50,
    .prk = "ee783bc4f2019faf334ec85c466822125ec783fd",
    .okm =
        "8e2a6e5c36796c02636a4246873f35edf59684f394da0ec847b3643a"
        "a1f0059ce97de9843cf9db968a8869ce411dd40b12a6",
};

void check_rfc5869() {
    check_hkdf<hash::hmac_sha2_256>(test::a1);
    check_hkdf<hash::hmac_sha2_256>(test::a2);
    check_hkdf<hash::hmac_sha2_256>(test::a3);
    check_hkdf<hash::hmac_sha1_160>(test::a4);
    check_hkdf<hash::hmac_sha1_160>(test::a5);
    check_hkdf<hash::hmac_sha1_160>(test::a6);
    check_hkdf<hash::hmac_sha1_160>(test::a7);
    // A.7's salt not provided, spelled as RFC 5869 2.2 defines it: HashLen (20) zero octets.
    bytes const zeros(20, 0);
    check_hkdf<hash::hmac_sha1_160>(test::a7, zeros);
    check_hkdf<hash::hmac_sha3_256>(sha3_256_case);
    check_hkdf<hash::hmac_blake2b_512>(blake2b_512_case);
    check_hkdf<hash::hmac_ripemd_160>(ripemd_160_case);
}

// ---- PBKDF2: RFC 6070 and RFC 7914 ----

template <class Hmac>
void check_pbkdf2(test::pbkdf2_case const& c) {
    bytes derived(c.length);
    auto const done =
        hash::pbkdf2<Hmac, botan>(derived, bytes_of(c.password), bytes_of(c.salt), c.iterations);
    BOOST_TEST(done.has_value());
    BOOST_TEST_EQ(test::to_hex(derived), std::string(c.derived_key));
}

void check_rfc6070() {
    check_pbkdf2<hash::hmac_sha1_160>(test::rfc6070_1);
    check_pbkdf2<hash::hmac_sha1_160>(test::rfc6070_2);
    check_pbkdf2<hash::hmac_sha1_160>(test::rfc6070_3);
    check_pbkdf2<hash::hmac_sha1_160>(test::rfc6070_5);
    check_pbkdf2<hash::hmac_sha1_160>(test::rfc6070_6);
    check_pbkdf2<hash::hmac_sha2_256>(test::rfc7914_1);
    check_pbkdf2<hash::hmac_sha2_256>(test::rfc7914_2);
}

// ---- The guards at their limits ----

// Bytes of a fixed pattern, different for each `seed`.
bytes pattern(std::size_t size, unsigned seed) {
    bytes out(size);
    for (std::size_t i = 0; i < size; ++i) {
        out[i] = static_cast<std::uint8_t>((i * 131U) + (std::size_t{seed} * 29U) + 7U);
    }
    return out;
}

// Spec 2.8: an output of 0 or more than 255 digests, a PRK of another size than the digest's and
// an info of more than hkdf_max_info_size bytes, refused before Botan, the output untouched; the
// longest output and the longest info computed, as backends::hash2 computes them.
void check_hkdf_guards() {
    using hmac = hash::hmac_sha2_256;
    constexpr std::size_t h = digest_size<hmac>;
    bytes const salt = pattern(13, 1);
    bytes const ikm = pattern(22, 2);
    bytes const prk = pattern(h, 4);
    bytes const info = pattern(10, 3);

    bytes longer((255 * h) + 1, untouched);
    BOOST_TEST(failed_with(hash::hkdf<hmac, botan>(longer, salt, ikm, info),
                           hash::error::invalid_output_size));
    BOOST_TEST(failed_with(hash::hkdf_expand<hmac, botan>(longer, prk, info),
                           hash::error::invalid_output_size));
    BOOST_TEST(all_of(longer, untouched));
    BOOST_TEST(failed_with(hash::hkdf<hmac, botan>(std::span<std::uint8_t>{}, salt, ikm, info),
                           hash::error::invalid_output_size));
    bytes output(42, untouched);
    BOOST_TEST(failed_with(hash::hkdf_expand<hmac, botan>(output, pattern(h - 1, 4), info),
                           hash::error::invalid_key_size));
    BOOST_TEST(failed_with(hash::hkdf_expand<hmac, botan>(output, pattern(h + 1, 4), info),
                           hash::error::invalid_key_size));
    bytes const too_much_info = pattern(hash::hkdf_max_info_size + 1, 3);
    BOOST_TEST(failed_with(hash::hkdf<hmac, botan>(output, salt, ikm, too_much_info),
                           hash::error::input_too_long));
    BOOST_TEST(failed_with(hash::hkdf_expand<hmac, botan>(output, prk, too_much_info),
                           hash::error::input_too_long));
    BOOST_TEST(all_of(output, untouched));

    bytes const longest_info = pattern(hash::hkdf_max_info_size, 3);
    for (std::size_t const size : {std::size_t{1}, 255 * h}) {
        bytes expected(size);
        bytes derived(size, untouched);
        BOOST_TEST((hash::hkdf<hmac, hash2>(expected, salt, ikm, longest_info).has_value()));
        BOOST_TEST((hash::hkdf<hmac, botan>(derived, salt, ikm, longest_info).has_value()));
        BOOST_TEST(derived == expected);
        BOOST_TEST((hash::hkdf_expand<hmac, hash2>(expected, prk, longest_info).has_value()));
        BOOST_TEST((hash::hkdf_expand<hmac, botan>(derived, prk, longest_info).has_value()));
        BOOST_TEST(derived == expected);
    }
}

// Spec 2.9: an empty output and no iteration, refused before Botan, the output untouched; and
// backend_limits<botan>'s count, Botan's size_t: past 2^32 - 1 on wasm32 invalid_iterations, which
// the guards check without running it, elsewhere no limit; and natively Botan's 2^32 - 2 blocks.
void check_pbkdf2_guards() {
    using hmac = hash::hmac_sha2_256;
    bytes const password = pattern(8, 5);
    bytes const salt = pattern(4, 6);
    bytes output(32, untouched);
    BOOST_TEST(failed_with(hash::pbkdf2<hmac, botan>(std::span<std::uint8_t>{}, password, salt, 1),
                           hash::error::invalid_output_size));
    BOOST_TEST(failed_with(hash::pbkdf2<hmac, botan>(output, password, salt, 0),
                           hash::error::invalid_iterations));
    BOOST_TEST(all_of(output, untouched));
    constexpr std::uint64_t past_32_bits = std::uint64_t{1} << 32U;
    auto const guarded = hash::detail::pbkdf2_guards<hmac, botan>(32, 8, 4, past_32_bits);
    if constexpr (sizeof(std::size_t) == 4) {
        BOOST_TEST(failed_with(guarded, hash::error::invalid_iterations));
        BOOST_TEST(failed_with(hash::pbkdf2<hmac, botan>(output, password, salt, past_32_bits),
                               hash::error::invalid_iterations));
        BOOST_TEST(all_of(output, untouched));
        BOOST_TEST(
            (hash::detail::pbkdf2_guards<hmac, botan>(32, 8, 4, past_32_bits - 1).has_value()));
    } else {
        BOOST_TEST(guarded.has_value());
        // Botan derives at most 2^32 - 2 blocks, one fewer than RFC 8018: the last block's outputs
        // are invalid_output_size on backends::botan, as the guards answer without running them,
        // and the RFC's own bound holds on backends::hash2.
        constexpr std::uint64_t most = std::uint64_t{0xfffffffe} * 32;
        BOOST_TEST((hash::detail::pbkdf2_guards<hmac, botan>(most, 8, 4, 1).has_value()));
        BOOST_TEST(failed_with(hash::detail::pbkdf2_guards<hmac, botan>(most + 1, 8, 4, 1),
                               hash::error::invalid_output_size));
        BOOST_TEST((hash::detail::pbkdf2_guards<hmac, hash2>(most + 1, 8, 4, 1).has_value()));
    }
    static_assert(hash::detail::backend_limits<botan>::pbkdf2_iterations ==
                  std::numeric_limits<std::size_t>::max());
}

// A key of more than Botan's HMAC's 8,192 bytes: HKDF-Extract's salt and PBKDF2's password, hashed
// first, give backends::hash2's output; so does a key of exactly 8,192 bytes, which Botan takes.
template <class Hmac>
void check_long_keys() {
    for (std::size_t const size : {std::size_t{8192}, std::size_t{8193}, std::size_t{20000}}) {
        bytes const key = pattern(size, 7);
        bytes const other = pattern(30, 8);
        auto const ours = hash::hkdf_extract<Hmac, botan>(key, other);
        auto const theirs = hash::hkdf_extract<Hmac, hash2>(key, other);
        if (!BOOST_TEST(ours.has_value() && theirs.has_value()) || !BOOST_TEST(*ours == *theirs)) {
            std::cerr << "  hkdf_extract, salt of " << size << " bytes\n";
        }
        bytes expected(digest_size<Hmac> + 3);
        bytes derived(expected.size());
        BOOST_TEST((hash::hkdf<Hmac, hash2>(expected, key, other, other).has_value()));
        BOOST_TEST((hash::hkdf<Hmac, botan>(derived, key, other, other).has_value()));
        BOOST_TEST(derived == expected);
        BOOST_TEST((hash::pbkdf2<Hmac, hash2>(expected, key, other, 3).has_value()));
        BOOST_TEST((hash::pbkdf2<Hmac, botan>(derived, key, other, 3).has_value()));
        if (!BOOST_TEST(derived == expected)) {
            std::cerr << "  pbkdf2, password of " << size << " bytes\n";
        }
    }
}

// ---- Agreement with backends::hash2 ----

template <class Hmac>
void agree_hkdf() {
    constexpr std::size_t h = digest_size<Hmac>;
    test::random_source rnd(test::agreement_seed);
    for (std::size_t index = 0; index < test::agreement_cases; ++index) {
        auto const c = test::next_hkdf_case(rnd, index, h);
        auto const ours = hash::hkdf_extract<Hmac, botan>(c.salt, c.ikm);
        auto const theirs = hash::hkdf_extract<Hmac, hash2>(c.salt, c.ikm);
        bool agreed = ours.has_value() && theirs.has_value() && *ours == *theirs;
        bytes expected(c.output);
        bytes derived(c.output);
        if (agreed) {
            std::span<std::uint8_t const> const prk(theirs->data(), theirs->size());
            agreed = hash::hkdf_expand<Hmac, hash2>(expected, prk, c.info).has_value() &&
                     hash::hkdf_expand<Hmac, botan>(derived, prk, c.info).has_value() &&
                     derived == expected &&
                     hash::hkdf<Hmac, botan>(derived, c.salt, c.ikm, c.info).has_value() &&
                     derived == expected;
        }
        if (!BOOST_TEST(agreed)) {
            std::cerr << "  hkdf, digest of " << h << " bytes, case " << index << ", seed "
                      << test::agreement_seed << '\n';
        }
    }
}

template <class Hmac>
void agree_pbkdf2() {
    constexpr std::size_t h = digest_size<Hmac>;
    test::random_source rnd(test::agreement_seed);
    for (std::size_t index = 0; index < test::agreement_cases; ++index) {
        auto const c = test::next_pbkdf2_case(rnd, index, h);
        bytes expected(c.output);
        bytes derived(c.output);
        bool const agreed =
            hash::pbkdf2<Hmac, hash2>(expected, c.password, c.salt, c.iterations).has_value() &&
            hash::pbkdf2<Hmac, botan>(derived, c.password, c.salt, c.iterations).has_value() &&
            derived == expected;
        if (!BOOST_TEST(agreed)) {
            std::cerr << "  pbkdf2, digest of " << h << " bytes, case " << index << ", seed "
                      << test::agreement_seed << '\n';
        }
    }
}

// ---- The cells and the defaults ----

static_assert(hash::backend_has_v<botan, kdfs::hkdf, hash::hmac_sha2_256>);
static_assert(hash::backend_has_v<botan, kdfs::hkdf_extract, hash::hmac_blake2s_256>);
static_assert(hash::backend_has_v<botan, kdfs::hkdf_expand, hash::hmac_md5_128>);
static_assert(!hash::backend_has_v<botan, kdfs::hkdf, hash::hmac_ripemd_128>);
static_assert(!hash::backend_has_v<botan, kdfs::hkdf, hash::hmac_sha2_512_224>);
static_assert(hash::backend_has_v<botan, kdfs::pbkdf2, hash::hmac_sha3_512>);
static_assert(!hash::backend_has_v<botan, kdfs::pbkdf2, hash::hmac_sha2_512_224>);
static_assert(!hash::backend_has_v<botan, kdfs::pbkdf2, hash::hmac_ripemd_128>);
// backends::botan is never a default (design D34): backends::hash2 stays HKDF's and PBKDF2's.
static_assert(std::is_same_v<hash::default_kdf_backend<hash::hmac_sha2_256>, hash2>);
static_assert(std::is_same_v<hash::default_kdf_backend<hash::hmac_sha2_256, kdfs::pbkdf2>, hash2>);

}  // namespace

int main() {
    check_rfc5869();
    check_rfc6070();
    check_hkdf_guards();
    check_pbkdf2_guards();
    check_long_keys<hash::hmac_sha2_256>();
    check_long_keys<hash::hmac_sha3_512>();
    check_long_keys<hash::hmac_blake2b_512>();
    for_each_type<botan_hmacs>([]<class Hmac> {
        agree_hkdf<Hmac>();
        agree_pbkdf2<Hmac>();
    });
    return webcpp::test::exit_status(boost::report_errors());
}
