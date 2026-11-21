// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The key derivations of standards on backends::botan (Botan 3.14.1's
// "SP800-108-Counter(HMAC(<h>),<r>,32)", "SP800-56A(<h>)" and "KDF2(<h>)"):
// - OpenSSL's evpkdf_kbkdf_counter.txt (NIST CAVP's counter-mode vectors), read at run time as
//   kdf_standards_openssl_test reads it: each HMAC case has the separator and L off, a fixed input
//   Botan cannot write, so none is computed and each answers unsupported_by_backend, the output
//   untouched; the HMAC cases of Botan's kdf/sp800_108_ctr.vec with L in 32 bits (BouncyCastle's,
//   and a script of Cryptodome's for r of 8 to 24), which have both, are computed;
// - every hash-form case of evpkdf_ss.txt and every case of evpkdf_x963.txt;
// - kbkdf over every hmac backends::botan has (keys past Botan's HMAC's 8,192 bytes among them),
//   sskdf over every digest of SP 800-56C but SHA-512/224 and x963kdf over every digest of SEC 1 v2
//   against a second implementation over Boost.Hash2 on random cases;
// - natively, 100 random cases each against backends::openssl;
// - the separator or L off answering unsupported_by_backend; no default (design D34) and the
//   cells.

#include <webcpp/hash/algorithms.hpp>
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
#include <map>
#include <optional>
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
using hash::backends::botan;
using bytes = std::vector<std::uint8_t>;

constexpr std::uint8_t untouched = 0x5A;

bool all_of(std::span<std::uint8_t const> data, std::uint8_t value) {
    return std::ranges::all_of(data, [value](std::uint8_t byte) { return byte == value; });
}

bool failed_with(boost::system::result<void> const& outcome, hash::error expected) {
    return outcome.has_error() && outcome.error() == expected;
}

// ---- The digests and hmacs ----

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
using sha2_512_256 = digest_of_tag<digests::sha2_512_256, hash::sha2_512_256>;
using sha3_224 = digest_of_tag<digests::sha3_224, hash::sha3_224>;
using sha3_256 = digest_of_tag<digests::sha3_256, hash::sha3_256>;
using sha3_384 = digest_of_tag<digests::sha3_384, hash::sha3_384>;
using sha3_512 = digest_of_tag<digests::sha3_512, hash::sha3_512>;

// The hash functions of SEC 1 v2, section 3.5, x963kdf's; with SHA-512/256 and SHA-3, the sskdf
// digests Botan has (every one of SP 800-56C but SHA-512/224).
using sec1_digests = std::tuple<sha1, sha2_224, sha2_256, sha2_384, sha2_512>;
using botan_sskdf_digests = decltype(std::tuple_cat(
    sec1_digests{}, std::tuple<sha2_512_256, sha3_224, sha3_256, sha3_384, sha3_512>{}));

// Every hmac of hmac.hpp backends::botan has.
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

// Calls check for the digest a test file names `name`: OpenSSL's spelling or Botan's; false for
// one this test does not know.
template <class Check>
bool with_digest(std::string_view name, Check check) {
    if (name == "SHA1" || name == "SHA-1") {
        check.template operator()<sha1>();
    } else if (name == "SHA224" || name == "SHA2-224" || name == "SHA-224") {
        check.template operator()<sha2_224>();
    } else if (name == "SHA256" || name == "SHA-256") {
        check.template operator()<sha2_256>();
    } else if (name == "SHA384" || name == "SHA-384") {
        check.template operator()<sha2_384>();
    } else if (name == "SHA512" || name == "SHA-512") {
        check.template operator()<sha2_512>();
    } else {
        return false;
    }
    return true;
}

template <class Hash>
constexpr std::size_t digest_size() {
    return typename Hash::result_type().size();
}

std::string lower(std::string text) {
    std::ranges::transform(text, text.begin(), [](char c) {
        return static_cast<char>(c >= 'A' && c <= 'F' ? c - 'A' + 'a' : c);
    });
    return text;
}

// ---- A second implementation, over Boost.Hash2 ----

void append_big_endian(bytes& out, std::uint64_t value, std::size_t size) {
    for (std::size_t i = size; i > 0; --i) {
        out.push_back(static_cast<std::uint8_t>(value >> (8 * (i - 1))));
    }
}

// SP 800-108r1 section 4.1: K(i) = PRF(K_IN, [i]_r || Label || 0x00 || Context || [L]_32).
template <class Hmac>
bytes reference_kbkdf(std::size_t size, std::span<std::uint8_t const> key,
                      hash::kbkdf_options const& options) {
    bytes out;
    for (std::uint64_t counter = 1; out.size() < size; ++counter) {
        bytes input;
        append_big_endian(input, counter, options.counter_bits / 8);
        input.insert(input.end(), options.label.begin(), options.label.end());
        input.push_back(0);
        input.insert(input.end(), options.context.begin(), options.context.end());
        append_big_endian(input, std::uint64_t{size} * 8, 4);
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

// ---- The test files ----

// Every HMAC stanza of evpkdf_kbkdf_counter.txt available in the default provider (82): each has
// the separator and L off (use-l:0, use-separator:0), so that none has a fixed input Botan writes:
// each is refused with unsupported_by_backend, the output untouched, and none is computed.
void check_kbkdf_evp() {
    std::size_t refused = 0;
    std::size_t with_both = 0;
    for (auto const& lines :
         evp::read_stanzas(WEBCPP_TEST_OPENSSL_EVP_DATA "/evpkdf_kbkdf_counter.txt")) {
        if (!evp::value_of(lines, "KDF") || evp::value_of(lines, "Availablein") == "fips" ||
            evp::value_of(lines, "Ctrl.mac") != "mac:HMAC") {
            continue;
        }
        bool const separator = evp::value_of(lines, "Ctrl.use-separator") != "use-separator:0";
        bool const length = evp::value_of(lines, "Ctrl.use-l") != "use-l:0";
        if (separator && length) {
            ++with_both;
            continue;
        }
        bytes const key = evp::ctrl_bytes(*evp::value_of(lines, "Ctrl.hexkey"));
        bytes const context = evp::joined_bytes(lines, "Ctrl.hexinfo");
        auto const counter_bits = static_cast<std::uint32_t>(
            std::stoul(evp::ctrl_value(*evp::value_of(lines, "Ctrl.r"))));
        std::size_t const size = evp::value_of(lines, "Output")->size() / 2;
        std::string const digest = evp::ctrl_value(*evp::value_of(lines, "Ctrl.digest"));
        bool fine = false;
        bool const known = with_digest(digest, [&]<class D> {
            bytes output(size, untouched);
            fine =
                failed_with(hash::kbkdf<typename D::hmac, botan>(output, key,
                                                                 {
                                                                     .context = context,
                                                                     .counter_bits = counter_bits,
                                                                     .separator = separator,
                                                                     .length = length,
                                                                 }),
                            hash::error::unsupported_by_backend) &&
                all_of(output, untouched);
        });
        if (!BOOST_TEST(known) || !BOOST_TEST(fine)) {
            std::cerr << "  evpkdf_kbkdf_counter.txt, HMAC case " << refused << " (" << digest
                      << ", r " << counter_bits << ") not refused\n";
        }
        ++refused;
    }
    evp::count_is("evpkdf_kbkdf_counter.txt", "HMAC stanzas with the separator and L", with_both,
                  0);
    evp::count_is("evpkdf_kbkdf_counter.txt", "HMAC stanzas refused", refused, 82);
}

// A section of Botan's kdf/sp800_108_ctr.vec kbkdf computes: its digest, as the file names it,
// and r.
struct kbkdf_section {
    std::string digest;
    std::uint32_t counter_bits;
};

// The section a header line opens, [SP800-108-Counter(HMAC(<h>))] (r = 32, L = 32) or
// [SP800-108-Counter(HMAC(<h>),<r>,32)]; none for a CMAC section or one whose L is not 32 bits.
std::optional<kbkdf_section> kbkdf_section_of(std::string_view header) {
    constexpr std::string_view prefix = "[SP800-108-Counter(HMAC(";
    if (!header.starts_with(prefix)) {
        return std::nullopt;
    }
    std::string_view const rest = header.substr(prefix.size());
    std::size_t const close = rest.find(')');
    std::string_view const lengths = rest.substr(close + 1);
    std::string const digest(rest.substr(0, close));
    if (lengths == ")]") {
        return kbkdf_section{.digest = digest, .counter_bits = 32};
    }
    if (!lengths.ends_with(",32)]")) {
        return std::nullopt;
    }
    auto const bits =
        static_cast<std::uint32_t>(std::stoul(std::string(lengths.substr(1, lengths.size() - 6))));
    return kbkdf_section{.digest = digest, .counter_bits = bits};
}

// The HMAC cases of Botan's kdf/sp800_108_ctr.vec whose L is 32 bits, the one kbkdf writes: its
// [SP800-108-Counter(HMAC(<h>))] sections (r = 32; BouncyCastle's) and
// [SP800-108-Counter(HMAC(SHA-256),<r>,32)] (a script of Cryptodome's), the salt the context.
void check_kbkdf_vec() {
    std::map<std::string, std::size_t> counts;
    std::optional<kbkdf_section> section;
    bytes salt;
    bytes secret;
    bytes label;
    for (auto const& line :
         evp::read_lines(std::string(WEBCPP_TEST_BOTAN_VECTORS) + "/kdf/sp800_108_ctr.vec")) {
        std::string_view const text(line);
        if (text.starts_with('[')) {
            section = kbkdf_section_of(text);
        } else if (text.starts_with("Salt = ")) {
            salt = test::from_hex(text.substr(7));
        } else if (text.starts_with("Secret = ")) {
            secret = test::from_hex(text.substr(9));
        } else if (text.starts_with("Label = ")) {
            label = test::from_hex(text.substr(8));
        } else if (text.starts_with("Output = ") && section) {
            std::string const expected = lower(std::string(text.substr(9)));
            std::string computed;
            bool const known = with_digest(section->digest, [&]<class D> {
                bytes output(expected.size() / 2);
                auto const done = hash::kbkdf<typename D::hmac, botan>(
                    output, secret,
                    {.label = label, .context = salt, .counter_bits = section->counter_bits});
                if (BOOST_TEST(done.has_value())) {
                    computed = test::to_hex(output);
                }
            });
            std::string const name =
                section->digest + ", r " + std::to_string(section->counter_bits);
            if (!BOOST_TEST(known) || !BOOST_TEST_EQ(computed, expected)) {
                std::cerr << "  sp800_108_ctr.vec, " << name << " case " << counts[name] << '\n';
            }
            ++counts[name];
        }
    }
    BOOST_TEST_EQ(counts["SHA-1, r 32"], 30U);
    BOOST_TEST_EQ(counts["SHA-256, r 32"], 34U);
    BOOST_TEST_EQ(counts["SHA-384, r 32"], 30U);
    BOOST_TEST_EQ(counts["SHA-512, r 32"], 30U);
    BOOST_TEST_EQ(counts["SHA-256, r 8"], 4U);
    BOOST_TEST_EQ(counts["SHA-256, r 16"], 4U);
    BOOST_TEST_EQ(counts["SHA-256, r 24"], 4U);
}

// Every hash-form stanza of evpkdf_ss.txt available in the default provider: 75 computed; the
// SHAKE-256 one (an expected failure, which sskdf refuses at compile time) left out.
void check_sskdf_evp() {
    std::size_t run = 0;
    for (auto const& lines : evp::read_stanzas(WEBCPP_TEST_OPENSSL_EVP_DATA "/evpkdf_ss.txt")) {
        if (!evp::value_of(lines, "KDF") || evp::value_of(lines, "Availablein") == "fips" ||
            evp::value_of(lines, "Ctrl.mac") || evp::value_of(lines, "Result")) {
            continue;
        }
        std::string const digest = evp::ctrl_value(*evp::value_of(lines, "Ctrl.digest"));
        bytes const secret = evp::ctrl_bytes(*evp::value_of(lines, "Ctrl.hexsecret"));
        bytes const info = evp::joined_bytes(lines, "Ctrl.hexinfo");
        std::string const expected = lower(*evp::value_of(lines, "Output"));
        std::string computed;
        bool const known = with_digest(digest, [&]<class D> {
            bytes output(expected.size() / 2);
            if (BOOST_TEST(
                    (hash::sskdf<typename D::tag, botan>(output, secret, info).has_value()))) {
                computed = test::to_hex(output);
            }
        });
        if (!BOOST_TEST(known) || !BOOST_TEST_EQ(computed, expected)) {
            std::cerr << "  evpkdf_ss.txt, hash case " << run << " (" << digest << ")\n";
        }
        ++run;
    }
    evp::count_is("evpkdf_ss.txt", "hash-form stanzas computed", run, 75);
}

// Every stanza of evpkdf_x963.txt available in the default provider: 17 computed.
void check_x963kdf_evp() {
    std::size_t run = 0;
    for (auto const& lines : evp::read_stanzas(WEBCPP_TEST_OPENSSL_EVP_DATA "/evpkdf_x963.txt")) {
        if (!evp::value_of(lines, "KDF") || evp::value_of(lines, "Availablein") == "fips") {
            continue;
        }
        std::string const digest = evp::ctrl_value(*evp::value_of(lines, "Ctrl.digest"));
        bytes const secret = evp::ctrl_bytes(*evp::value_of(lines, "Ctrl.hexsecret"));
        bytes const info = evp::joined_bytes(lines, "Ctrl.hexinfo");
        std::string const expected = lower(*evp::value_of(lines, "Output"));
        std::string computed;
        bool const known = with_digest(digest, [&]<class D> {
            bytes output(expected.size() / 2);
            if (BOOST_TEST(
                    (hash::x963kdf<typename D::tag, botan>(output, secret, info).has_value()))) {
                computed = test::to_hex(output);
            }
        });
        if (!BOOST_TEST(known) || !BOOST_TEST_EQ(computed, expected)) {
            std::cerr << "  evpkdf_x963.txt, case " << run << " (" << digest << ")\n";
        }
        ++run;
    }
    evp::count_is("evpkdf_x963.txt", "stanzas computed", run, 17);
}

// ---- Agreement ----

constexpr std::size_t cases_per_function = 40;
constexpr std::array<std::uint32_t, 4> counter_widths{8, 16, 24, 32};

// kbkdf over Hmac on random keys (1 to 100 bytes, past the block size; one case in eight 8,192 to
// 9,000 bytes, past Botan's HMAC's key), labels and contexts (empty one case in four), every
// counter width, outputs of 1 byte to 3 digests and 5 bytes.
template <class Hmac>
void agree_kbkdf(test::random_source& rnd) {
    constexpr std::size_t h = digest_size<Hmac>();
    for (std::size_t index = 0; index < cases_per_function; ++index) {
        bytes const key = rnd.bytes(index % 8 == 7 ? rnd.between(8192, 9000) : rnd.between(1, 100));
        bytes const label = rnd.between(0, 3) == 0 ? bytes{} : rnd.bytes(rnd.between(1, 40));
        bytes const context = rnd.between(0, 3) == 0 ? bytes{} : rnd.bytes(rnd.between(1, 40));
        hash::kbkdf_options const options{
            .label = label,
            .context = context,
            .counter_bits = counter_widths.at(index % counter_widths.size()),
        };
        bytes output(rnd.between(1, (3 * h) + 5));
        auto const done = hash::kbkdf<Hmac, botan>(output, key, options);
        if (!BOOST_TEST(done.has_value()) ||
            !BOOST_TEST_EQ(test::to_hex(output),
                           test::to_hex(reference_kbkdf<Hmac>(output.size(), key, options)))) {
            std::cerr << "  kbkdf case " << index << ", digest of " << h << " bytes, key "
                      << key.size() << ", seed " << test::agreement_seed << '\n';
        }
    }
}

template <class D, bool CounterFirst>
void agree_digest_kdf(test::random_source& rnd) {
    constexpr std::size_t h = digest_size<typename D::hash2>();
    for (std::size_t index = 0; index < cases_per_function; ++index) {
        bytes const secret = rnd.bytes(rnd.between(1, 100));
        bytes const info = rnd.between(0, 3) == 0 ? bytes{} : rnd.bytes(rnd.between(1, 100));
        bytes output(rnd.between(1, (3 * h) + 5));
        boost::system::result<void> done;
        if constexpr (CounterFirst) {
            done = hash::sskdf<typename D::tag, botan>(output, secret, info);
        } else {
            done = hash::x963kdf<typename D::tag, botan>(output, secret, info);
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
    for_each_type<botan_hmacs>([&]<class Hmac> { agree_kbkdf<Hmac>(rnd); });
    for_each_type<botan_sskdf_digests>([&]<class D> { agree_digest_kdf<D, true>(rnd); });
    for_each_type<sec1_digests>([&]<class D> { agree_digest_kdf<D, false>(rnd); });
}

#ifdef WEBCPP_HASH_HAS_OPENSSL
// Natively, backends::openssl on 100 random cases each: kbkdf over every hmac both have, sskdf and
// x963kdf over every digest both have.
constexpr std::size_t openssl_cases = 100;

template <class Hmac>
void agree_kbkdf_with_openssl(test::random_source& rnd) {
    constexpr std::size_t h = digest_size<Hmac>();
    for (std::size_t index = 0; index < openssl_cases; ++index) {
        bytes const key = rnd.bytes(rnd.between(1, 200));
        bytes const label = rnd.bytes(rnd.between(0, 40));
        bytes const context = rnd.bytes(rnd.between(0, 40));
        hash::kbkdf_options const options{
            .label = label,
            .context = context,
            .counter_bits = counter_widths.at(index % counter_widths.size()),
        };
        bytes ours(rnd.between(1, (4 * h) + 3));
        bytes theirs(ours.size());
        bool const agreed =
            hash::kbkdf<Hmac, botan>(ours, key, options).has_value() &&
            hash::kbkdf<Hmac, hash::backends::openssl>(theirs, key, options).has_value() &&
            ours == theirs;
        if (!BOOST_TEST(agreed)) {
            std::cerr << "  kbkdf against OpenSSL, case " << index << ", digest of " << h
                      << " bytes\n";
        }
    }
}

template <class D, bool CounterFirst>
void agree_digest_kdf_with_openssl(test::random_source& rnd) {
    for (std::size_t index = 0; index < openssl_cases; ++index) {
        bytes const secret = rnd.bytes(rnd.between(1, 200));
        bytes const info = rnd.bytes(rnd.between(0, 200));
        bytes ours(rnd.between(1, 300));
        bytes theirs(ours.size());
        bool agreed = false;
        if constexpr (CounterFirst) {
            agreed = hash::sskdf<typename D::tag, botan>(ours, secret, info).has_value() &&
                     hash::sskdf<typename D::tag, hash::backends::openssl>(theirs, secret, info)
                         .has_value();
        } else {
            agreed = hash::x963kdf<typename D::tag, botan>(ours, secret, info).has_value() &&
                     hash::x963kdf<typename D::tag, hash::backends::openssl>(theirs, secret, info)
                         .has_value();
        }
        if (!BOOST_TEST(agreed && ours == theirs)) {
            std::cerr << "  " << (CounterFirst ? "sskdf" : "x963kdf") << " against OpenSSL, case "
                      << index << '\n';
        }
    }
}

void check_openssl() {
    test::random_source rnd(test::agreement_seed + 1);
    for_each_type<botan_hmacs>([&]<class Hmac> { agree_kbkdf_with_openssl<Hmac>(rnd); });
    for_each_type<botan_sskdf_digests>(
        [&]<class D> { agree_digest_kdf_with_openssl<D, true>(rnd); });
    for_each_type<sec1_digests>([&]<class D> { agree_digest_kdf_with_openssl<D, false>(rnd); });
}
#endif

// ---- The fixed inputs Botan does not write ----

// The separator off, L off, or both: unsupported_by_backend, the output untouched; the standard's
// guards still come first (a counter width of 7 is invalid_parameters).
void check_partial_kbkdf() {
    using hmac = hash::hmac_sha2_256;
    std::array<std::uint8_t, 16> const key{1, 2, 3};
    std::array<std::uint8_t, 32> output{};
    output.fill(untouched);
    BOOST_TEST(failed_with(hash::kbkdf<hmac, botan>(output, key, {.separator = false}),
                           hash::error::unsupported_by_backend));
    BOOST_TEST(failed_with(hash::kbkdf<hmac, botan>(output, key, {.length = false}),
                           hash::error::unsupported_by_backend));
    BOOST_TEST(
        failed_with(hash::kbkdf<hmac, botan>(output, key, {.separator = false, .length = false}),
                    hash::error::unsupported_by_backend));
    BOOST_TEST(
        failed_with(hash::kbkdf<hmac, botan>(output, key, {.counter_bits = 7, .separator = false}),
                    hash::error::invalid_parameters));
    BOOST_TEST(all_of(output, untouched));
}

// Botan's KDF2 derives at most 2^32 - 2 blocks, one fewer than ANSI X9.63: natively an output of
// one byte more is unsupported_by_backend, refused before any byte is touched (the span is longer
// than its buffer, which nothing reads or writes).
void check_x963kdf_limit() {
    if constexpr (sizeof(std::size_t) == 8) {
        std::array<std::uint8_t, 16> buffer{};
        buffer.fill(untouched);
        std::array<std::uint8_t, 16> const secret{1, 2, 3};
        std::size_t const past = (std::size_t{0xfffffffe} * 32) + 1;
        static_assert(hash::detail::x963kdf_engine<botan, digests::sha2_256>::limits.max_output ==
                      std::uint64_t{0xfffffffe} * 32);
        BOOST_TEST(failed_with(hash::x963kdf<digests::sha2_256, botan>(
                                   std::span<std::uint8_t>(buffer.data(), past), secret),
                               hash::error::unsupported_by_backend));
        BOOST_TEST(all_of(buffer, untouched));
    }
}

// ---- The cells and the defaults ----

static_assert(hash::backend_has_v<botan, kdfs::kbkdf_hmac, hash::hmac_sha2_256>);
static_assert(hash::backend_has_v<botan, kdfs::kbkdf_hmac, hash::hmac_blake2s_256>);
static_assert(!hash::backend_has_v<botan, kdfs::kbkdf_hmac, hash::hmac_ripemd_128>);
static_assert(!hash::backend_has_v<botan, kdfs::kbkdf_hmac, hash::hmac_sha2_512_224>);
static_assert(hash::backend_has_v<botan, kdfs::sskdf, void>);
static_assert(hash::backend_has_v<botan, kdfs::x963kdf, void>);
static_assert(std::is_same_v<hash::default_backend<kdfs::kbkdf_hmac, hash::hmac_sha2_256>,
                             hash::detail::no_default>);
static_assert(std::is_same_v<hash::default_backend<kdfs::sskdf>, hash::detail::no_default>);
static_assert(std::is_same_v<hash::default_backend<kdfs::x963kdf>, hash::detail::no_default>);

}  // namespace

int main() {
    check_kbkdf_evp();
    check_kbkdf_vec();
    check_sskdf_evp();
    check_x963kdf_evp();
    check_agreement();
#ifdef WEBCPP_HASH_HAS_OPENSSL
    check_openssl();
#endif
    check_partial_kbkdf();
    check_x963kdf_limit();
    return webcpp::test::exit_status(boost::report_errors());
}
