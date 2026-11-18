// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The key derivations of standards on backends::openssl (OpenSSL 3.5.9's EVP_KDFs "KBKDF",
// "SSKDF" and "X963KDF"):
// - every HMAC case of OpenSSL's evpkdf_kbkdf_counter.txt (NIST CAVP's counter-mode vectors: the
//   raw fixed input in the context, no separator and no L, r of 8 to 32), every hash-form case of
//   evpkdf_ss.txt and every case of evpkdf_x963.txt, read at run time, each count asserted;
// - kbkdf over every hmac backends::openssl has, with labels, contexts, the separator, L and each
//   counter width, sskdf over every digest of SP 800-56C and x963kdf over every digest of FIPS
//   180-4, against a second implementation over Boost.Hash2 on random cases;
// - the standards' guards, each refusal leaving the output as it was: the counter's width, the
//   output (empty, past 2^r - 1 blocks, past L's 32 bits), the empty key or secret;
// - no default (design D34), and backends::openssl's cells.
// The limits past 2^29 bytes are openssl_limits_test's, natively.

#include <webcpp/hash/algorithms.hpp>
#include <webcpp/hash/backends/openssl.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/hash/kdf_standards.hpp>
#include <webcpp/test/exit_status.hpp>

#include "require.hpp"
#include "support/evp_stanzas.hpp"
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
#include <tuple>
#include <type_traits>
#include <vector>

namespace {

namespace hash = webcpp::hash;
namespace kdfs = webcpp::hash::kdfs;
namespace digests = webcpp::hash::digests;
namespace test = webcpp::test;
namespace evp = webcpp::test::evp;
using hash::backends::openssl;
using bytes = std::vector<std::uint8_t>;

constexpr std::uint8_t untouched = 0x5A;

bool all_of(std::span<std::uint8_t const> data, std::uint8_t value) {
    return std::ranges::all_of(data, [value](std::uint8_t byte) { return byte == value; });
}

bool failed_with(boost::system::result<void> const& outcome, hash::error expected) {
    return outcome.has_error() && outcome.error() == expected;
}

// ---- The digests and hmacs ----

// A tag of digests, its Boost.Hash2 hash and its hmac.
template <class Tag, class Hash>
struct digest_of_tag {
    using tag = Tag;
    using hash2 = Hash;
    using hmac = boost::hash2::hmac<Hash>;
};

using sha1 = digest_of_tag<digests::sha1, hash::sha1_160>;
using sha2_224 = digest_of_tag<digests::sha2_224, hash::sha2_224>;
using sha2_256 = digest_of_tag<digests::sha2_256, hash::sha2_256>;
using sha2_384 = digest_of_tag<digests::sha2_384, hash::sha2_384>;
using sha2_512 = digest_of_tag<digests::sha2_512, hash::sha2_512>;
using sha2_512_224 = digest_of_tag<digests::sha2_512_224, hash::sha2_512_224>;
using sha2_512_256 = digest_of_tag<digests::sha2_512_256, hash::sha2_512_256>;
using sha3_224 = digest_of_tag<digests::sha3_224, hash::sha3_224>;
using sha3_256 = digest_of_tag<digests::sha3_256, hash::sha3_256>;
using sha3_384 = digest_of_tag<digests::sha3_384, hash::sha3_384>;
using sha3_512 = digest_of_tag<digests::sha3_512, hash::sha3_512>;

// The digests of FIPS 180-4, x963kdf's; with SHA-3, sskdf's.
using fips180_digests =
    std::tuple<sha1, sha2_224, sha2_256, sha2_384, sha2_512, sha2_512_224, sha2_512_256>;
using sp800_56c_digests = decltype(std::tuple_cat(
    fips180_digests{}, std::tuple<sha3_224, sha3_256, sha3_384, sha3_512>{}));

// Every hmac of hmac.hpp backends::openssl has: every one but hmac_ripemd_128.
using openssl_hmacs =
    std::tuple<hash::hmac_md5_128, hash::hmac_sha1_160, hash::hmac_sha2_224, hash::hmac_sha2_256,
               hash::hmac_sha2_384, hash::hmac_sha2_512, hash::hmac_sha2_512_224,
               hash::hmac_sha2_512_256, hash::hmac_sha3_224, hash::hmac_sha3_256,
               hash::hmac_sha3_384, hash::hmac_sha3_512, hash::hmac_ripemd_160,
               hash::hmac_blake2b_512, hash::hmac_blake2s_256>;

// Calls check.template operator()<T>() for each type of the tuple Types.
template <class Types, class Check>
void for_each_type(Check check) {
    [&]<class... T>(std::tuple<T...>*) {
        (check.template operator()<T>(), ...);
    }(static_cast<Types*>(nullptr));
}

// Calls check.template operator()<D>() for the digest OpenSSL's test files name `name`; false
// for a name this test does not know.
template <class Check>
bool with_digest(std::string_view name, Check check) {
    if (name == "SHA1") {
        check.template operator()<sha1>();
    } else if (name == "SHA224" || name == "SHA2-224") {
        check.template operator()<sha2_224>();
    } else if (name == "SHA256") {
        check.template operator()<sha2_256>();
    } else if (name == "SHA384") {
        check.template operator()<sha2_384>();
    } else if (name == "SHA512") {
        check.template operator()<sha2_512>();
    } else {
        return false;
    }
    return true;
}

// The digest's size in bytes.
template <class Hash>
constexpr std::size_t digest_size() {
    return typename Hash::result_type().size();
}

// ---- A second implementation, over Boost.Hash2 ----

void append_big_endian(bytes& out, std::uint64_t value, std::size_t size) {
    for (std::size_t i = size; i > 0; --i) {
        out.push_back(static_cast<std::uint8_t>(value >> (8 * (i - 1))));
    }
}

// SP 800-108r1 section 4.1: K(i) = PRF(K_IN, [i]_r || Label || 0x00 || Context || [L]_32), each
// part as options states.
template <class Hmac>
bytes reference_kbkdf(std::size_t size, std::span<std::uint8_t const> key,
                      hash::kbkdf_options const& options) {
    bytes out;
    for (std::uint64_t counter = 1; out.size() < size; ++counter) {
        bytes input;
        append_big_endian(input, counter, options.counter_bits / 8);
        input.insert(input.end(), options.label.begin(), options.label.end());
        if (options.separator) {
            input.push_back(0);
        }
        input.insert(input.end(), options.context.begin(), options.context.end());
        if (options.length) {
            append_big_endian(input, std::uint64_t{size} * 8, 4);
        }
        Hmac prf(key.data(), key.size());
        prf.update(input.data(), input.size());
        auto const block = prf.result();
        out.insert(out.end(), block.begin(), block.end());
    }
    out.resize(size);
    return out;
}

// SP 800-56C's H(counter || Z || FixedInfo), or X9.63's H(Z || counter || SharedInfo).
template <class Hash>
bytes reference_digest_kdf(std::size_t size, std::span<std::uint8_t const> secret,
                           std::span<std::uint8_t const> info, bool counter_first) {
    bytes out;
    for (std::uint64_t counter = 1; out.size() < size; ++counter) {
        bytes counter_bytes;
        append_big_endian(counter_bytes, counter, 4);
        Hash h;
        if (counter_first) {
            h.update(counter_bytes.data(), counter_bytes.size());
            h.update(secret.data(), secret.size());
        } else {
            h.update(secret.data(), secret.size());
            h.update(counter_bytes.data(), counter_bytes.size());
        }
        h.update(info.data(), info.size());
        auto const block = h.result();
        out.insert(out.end(), block.begin(), block.end());
    }
    out.resize(size);
    return out;
}

// ---- OpenSSL's test files ----

std::string lower(std::string text) {
    std::ranges::transform(text, text.begin(), [](char c) {
        return static_cast<char>(c >= 'A' && c <= 'F' ? c - 'A' + 'a' : c);
    });
    return text;
}

// The counts of a file: the stanzas computed, and those left out, each kind counted.
struct evp_counts {
    std::size_t run = 0;
    std::size_t fips_only = 0;
    std::size_t other = 0;
};

// Every HMAC stanza of evpkdf_kbkdf_counter.txt available in the default provider: 82 run (NIST
// CAVP's counter-mode HMAC vectors over SHA-1 and SHA-2, r of 8 to 32, and one case of OpenSSL's
// own); 2 for the FIPS provider alone and 49 over CMAC (a block cipher, not hash's) left out.
void check_kbkdf_evp() {
    evp_counts counts;
    for (auto const& lines :
         evp::read_stanzas(WEBCPP_TEST_OPENSSL_EVP_DATA "/evpkdf_kbkdf_counter.txt")) {
        if (!evp::value_of(lines, "KDF")) {
            continue;
        }
        if (evp::value_of(lines, "Availablein") == "fips") {
            ++counts.fips_only;
            continue;
        }
        if (evp::value_of(lines, "Ctrl.mac") != "mac:HMAC") {
            ++counts.other;
            continue;
        }
        test::require(BOOST_TEST(evp::value_of(lines, "Ctrl.mode") == "mode:COUNTER"));
        test::require(BOOST_TEST(evp::value_of(lines, "Ctrl.use-l") == "use-l:0"));
        test::require(BOOST_TEST(evp::value_of(lines, "Ctrl.use-separator") == "use-separator:0"));
        bytes const key = evp::ctrl_bytes(*evp::value_of(lines, "Ctrl.hexkey"));
        bytes const context = evp::joined_bytes(lines, "Ctrl.hexinfo");
        auto const counter_bits = static_cast<std::uint32_t>(
            std::stoul(evp::ctrl_value(*evp::value_of(lines, "Ctrl.r"))));
        std::string const expected = lower(*evp::value_of(lines, "Output"));
        std::string const digest = evp::ctrl_value(*evp::value_of(lines, "Ctrl.digest"));
        std::string computed;
        bool const known = with_digest(digest, [&]<class D> {
            bytes output(expected.size() / 2);
            auto const done =
                hash::kbkdf<typename D::hmac, openssl>(output, key,
                                                       {
                                                           .context = context,
                                                           .counter_bits = counter_bits,
                                                           .separator = false,
                                                           .length = false,
                                                       });
            if (BOOST_TEST(done.has_value())) {
                computed = test::to_hex(output);
            }
        });
        if (!BOOST_TEST(known) || !BOOST_TEST_EQ(computed, expected)) {
            std::cerr << "  evpkdf_kbkdf_counter.txt, HMAC case " << counts.run << " (" << digest
                      << ", r " << counter_bits << ")\n";
        }
        ++counts.run;
    }
    BOOST_TEST_EQ(counts.run, 82U);
    BOOST_TEST_EQ(counts.fips_only, 2U);
    BOOST_TEST_EQ(counts.other, 49U);
}

// Every hash-form stanza of evpkdf_ss.txt available in the default provider: 75 run; 6 for the
// FIPS provider alone, 1 over SHAKE-256 (an expected failure, which sskdf refuses at compile time)
// and 90 over HMAC or KMAC (SP 800-56C's other forms) left out.
void check_sskdf_evp() {
    evp_counts counts;
    std::size_t xof = 0;
    for (auto const& lines : evp::read_stanzas(WEBCPP_TEST_OPENSSL_EVP_DATA "/evpkdf_ss.txt")) {
        if (!evp::value_of(lines, "KDF")) {
            continue;
        }
        if (evp::value_of(lines, "Availablein") == "fips") {
            ++counts.fips_only;
            continue;
        }
        if (evp::value_of(lines, "Ctrl.mac")) {
            ++counts.other;
            continue;
        }
        std::string const digest = evp::ctrl_value(*evp::value_of(lines, "Ctrl.digest"));
        if (evp::value_of(lines, "Result")) {
            BOOST_TEST_EQ(digest, std::string("SHAKE-256"));
            ++xof;
            continue;
        }
        bytes const secret = evp::ctrl_bytes(*evp::value_of(lines, "Ctrl.hexsecret"));
        bytes const info = evp::joined_bytes(lines, "Ctrl.hexinfo");
        std::string const expected = lower(*evp::value_of(lines, "Output"));
        std::string computed;
        bool const known = with_digest(digest, [&]<class D> {
            bytes output(expected.size() / 2);
            auto const done = hash::sskdf<typename D::tag, openssl>(output, secret, info);
            if (BOOST_TEST(done.has_value())) {
                computed = test::to_hex(output);
            }
        });
        if (!BOOST_TEST(known) || !BOOST_TEST_EQ(computed, expected)) {
            std::cerr << "  evpkdf_ss.txt, hash case " << counts.run << " (" << digest << ")\n";
        }
        ++counts.run;
    }
    BOOST_TEST_EQ(counts.run, 75U);
    BOOST_TEST_EQ(counts.fips_only, 6U);
    BOOST_TEST_EQ(xof, 1U);
    BOOST_TEST_EQ(counts.other, 90U);
}

// Every stanza of evpkdf_x963.txt available in the default provider: 17 run (X963KDF and its
// alias X942KDF-CONCAT); 6 for the FIPS provider alone left out.
void check_x963kdf_evp() {
    evp_counts counts;
    for (auto const& lines : evp::read_stanzas(WEBCPP_TEST_OPENSSL_EVP_DATA "/evpkdf_x963.txt")) {
        auto const kdf = evp::value_of(lines, "KDF");
        if (!kdf) {
            continue;
        }
        if (evp::value_of(lines, "Availablein") == "fips") {
            ++counts.fips_only;
            continue;
        }
        test::require(BOOST_TEST(*kdf == "X963KDF" || *kdf == "X942KDF-CONCAT"));
        test::require(BOOST_TEST(!evp::value_of(lines, "Result")));
        std::string const digest = evp::ctrl_value(*evp::value_of(lines, "Ctrl.digest"));
        bytes const secret = evp::ctrl_bytes(*evp::value_of(lines, "Ctrl.hexsecret"));
        bytes const info = evp::joined_bytes(lines, "Ctrl.hexinfo");
        std::string const expected = lower(*evp::value_of(lines, "Output"));
        std::string computed;
        bool const known = with_digest(digest, [&]<class D> {
            bytes output(expected.size() / 2);
            auto const done = hash::x963kdf<typename D::tag, openssl>(output, secret, info);
            if (BOOST_TEST(done.has_value())) {
                computed = test::to_hex(output);
            }
        });
        if (!BOOST_TEST(known) || !BOOST_TEST_EQ(computed, expected)) {
            std::cerr << "  evpkdf_x963.txt, case " << counts.run << " (" << digest << ")\n";
        }
        ++counts.run;
    }
    BOOST_TEST_EQ(counts.run, 17U);
    BOOST_TEST_EQ(counts.fips_only, 6U);
}

// ---- Agreement with the second implementation ----

constexpr std::size_t cases_per_function = 40;
constexpr std::array<std::uint32_t, 4> counter_widths{8, 16, 24, 32};

// kbkdf over Hmac on random keys (1 to 100 bytes, past the block size), labels and contexts
// (empty one case in four), every counter width, with and without the separator and L, outputs of
// 1 byte to 3 digests and 5 bytes; and the longest output r = 8 allows, 255 digests.
template <class Hmac>
void agree_kbkdf(test::random_source& rnd) {
    constexpr std::size_t h = digest_size<Hmac>();
    for (std::size_t index = 0; index < cases_per_function; ++index) {
        bytes const key = rnd.bytes(rnd.between(1, 100));
        bytes const label = rnd.between(0, 3) == 0 ? bytes{} : rnd.bytes(rnd.between(1, 40));
        bytes const context = rnd.between(0, 3) == 0 ? bytes{} : rnd.bytes(rnd.between(1, 40));
        hash::kbkdf_options const options{
            .label = label,
            .context = context,
            .counter_bits = counter_widths.at(index % counter_widths.size()),
            .separator = (index / 4) % 2 == 0,
            .length = (index / 8) % 2 == 0,
        };
        bytes output(rnd.between(1, (3 * h) + 5));
        auto const done = hash::kbkdf<Hmac, openssl>(output, key, options);
        if (!BOOST_TEST(done.has_value()) ||
            !BOOST_TEST_EQ(test::to_hex(output),
                           test::to_hex(reference_kbkdf<Hmac>(output.size(), key, options)))) {
            std::cerr << "  kbkdf case " << index << ", digest of " << h << " bytes, seed "
                      << test::agreement_seed << '\n';
        }
    }
    bytes const key = rnd.bytes(h);
    hash::kbkdf_options const options{.label = key, .counter_bits = 8};
    bytes output(255 * h);
    BOOST_TEST((hash::kbkdf<Hmac, openssl>(output, key, options).has_value()));
    BOOST_TEST_EQ(test::to_hex(output),
                  test::to_hex(reference_kbkdf<Hmac>(output.size(), key, options)));
}

// sskdf or x963kdf over D on random secrets (1 to 100 bytes) and infos (empty one case in four),
// outputs of 1 byte to 3 digests and 5 bytes.
template <class D, bool CounterFirst>
void agree_digest_kdf(test::random_source& rnd) {
    constexpr std::size_t h = digest_size<typename D::hash2>();
    for (std::size_t index = 0; index < cases_per_function; ++index) {
        bytes const secret = rnd.bytes(rnd.between(1, 100));
        bytes const info = rnd.between(0, 3) == 0 ? bytes{} : rnd.bytes(rnd.between(1, 100));
        bytes output(rnd.between(1, (3 * h) + 5));
        boost::system::result<void> done;
        if constexpr (CounterFirst) {
            done = hash::sskdf<typename D::tag, openssl>(output, secret, info);
        } else {
            done = hash::x963kdf<typename D::tag, openssl>(output, secret, info);
        }
        bytes const expected =
            reference_digest_kdf<typename D::hash2>(output.size(), secret, info, CounterFirst);
        if (!BOOST_TEST(done.has_value()) ||
            !BOOST_TEST_EQ(test::to_hex(output), test::to_hex(expected))) {
            std::cerr << "  " << (CounterFirst ? "sskdf" : "x963kdf") << " case " << index
                      << ", digest of " << h << " bytes, seed " << test::agreement_seed << '\n';
        }
    }
}

void check_agreement() {
    test::random_source rnd(test::agreement_seed);
    for_each_type<openssl_hmacs>([&]<class Hmac> { agree_kbkdf<Hmac>(rnd); });
    for_each_type<sp800_56c_digests>([&]<class D> { agree_digest_kdf<D, true>(rnd); });
    for_each_type<fips180_digests>([&]<class D> { agree_digest_kdf<D, false>(rnd); });
}

// ---- The standards' guards ----

void check_kbkdf_guards() {
    using hmac = hash::hmac_sha2_256;
    std::array<std::uint8_t, 16> const key{1, 2, 3};
    std::array<std::uint8_t, 32> output{};
    output.fill(untouched);
    for (std::uint32_t const width : {0U, 1U, 7U, 12U, 31U, 33U, 64U}) {
        BOOST_TEST(failed_with(hash::kbkdf<hmac, openssl>(output, key, {.counter_bits = width}),
                               hash::error::invalid_parameters));
    }
    BOOST_TEST(failed_with(hash::kbkdf<hmac, openssl>(std::span<std::uint8_t>{}, key),
                           hash::error::invalid_output_size));
    BOOST_TEST(failed_with(hash::kbkdf<hmac, openssl>(output, std::span<std::uint8_t const>{}),
                           hash::error::invalid_key_size));
    BOOST_TEST(all_of(output, untouched));

    // n = ceil(L / h) is at most 2^r - 1: 255 blocks of 32 bytes for r = 8, 65,535 for r = 16.
    bytes longer((std::size_t{255} * 32) + 1, untouched);
    BOOST_TEST(failed_with(hash::kbkdf<hmac, openssl>(longer, key, {.counter_bits = 8}),
                           hash::error::invalid_output_size));
    BOOST_TEST(all_of(longer, untouched));
    longer.assign((std::size_t{65535} * 32) + 1, untouched);
    BOOST_TEST(failed_with(hash::kbkdf<hmac, openssl>(longer, key, {.counter_bits = 16}),
                           hash::error::invalid_output_size));
    BOOST_TEST(all_of(longer, untouched));
    longer.resize(std::size_t{65535} * 32);
    BOOST_TEST((hash::kbkdf<hmac, openssl>(longer, key, {.counter_bits = 16}).has_value()));
}

template <bool CounterFirst>
void check_digest_kdf_guards() {
    auto const call = [](std::span<std::uint8_t> output, std::span<std::uint8_t const> secret) {
        if constexpr (CounterFirst) {
            return hash::sskdf<digests::sha2_256, openssl>(output, secret);
        } else {
            return hash::x963kdf<digests::sha2_256, openssl>(output, secret);
        }
    };
    std::array<std::uint8_t, 16> const secret{1, 2, 3};
    std::array<std::uint8_t, 32> output{};
    output.fill(untouched);
    BOOST_TEST(failed_with(call({}, secret), hash::error::invalid_output_size));
    BOOST_TEST(failed_with(call(output, {}), hash::error::invalid_key_size));
    BOOST_TEST(all_of(output, untouched));
    // An empty info is FixedInfo's or SharedInfo's none.
    BOOST_TEST(call(output, secret).has_value());
    BOOST_TEST_EQ(test::to_hex(output), test::to_hex(reference_digest_kdf<hash::sha2_256>(
                                            output.size(), secret, {}, CounterFirst)));
}

// ---- The cells and the defaults ----

static_assert(hash::backend_has_v<openssl, kdfs::kbkdf_hmac, hash::hmac_sha2_256>);
static_assert(hash::backend_has_v<openssl, kdfs::kbkdf_hmac, hash::hmac_blake2s_256>);
static_assert(!hash::backend_has_v<openssl, kdfs::kbkdf_hmac, hash::hmac_ripemd_128>);
static_assert(hash::backend_has_v<openssl, kdfs::sskdf, void>);
static_assert(hash::backend_has_v<openssl, kdfs::x963kdf, void>);
static_assert(!hash::backend_has_v<hash::backends::hash2, kdfs::kbkdf_hmac, hash::hmac_sha2_256>);
static_assert(!hash::backend_has_v<hash::backends::sodium, kdfs::sskdf, void>);
// Never a default (design D34): no backend of hash2, xkcp, blake3 and sodium has them.
static_assert(std::is_same_v<hash::default_backend<kdfs::kbkdf_hmac, hash::hmac_sha2_256>,
                             hash::detail::no_default>);
static_assert(std::is_same_v<hash::default_backend<kdfs::sskdf>, hash::detail::no_default>);
static_assert(std::is_same_v<hash::default_backend<kdfs::x963kdf>, hash::detail::no_default>);
// The standards' digests: SP 800-56C's approved hashes; FIPS 180-4's for X9.63.
static_assert(hash::detail::standard_kdf_digest<digests::sha3_256>::sskdf);
static_assert(!hash::detail::standard_kdf_digest<digests::sha3_256>::x963);
static_assert(!hash::detail::standard_kdf_digest<digests::md5>::sskdf);
static_assert(!hash::detail::standard_kdf_digest<digests::shake_256>::sskdf);

}  // namespace

int main() {
    check_kbkdf_evp();
    check_sskdf_evp();
    check_x963kdf_evp();
    check_agreement();
    check_kbkdf_guards();
    check_digest_kdf_guards<true>();
    check_digest_kdf_guards<false>();
    return webcpp::test::exit_status(boost::report_errors());
}
