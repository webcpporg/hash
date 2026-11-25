// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The families on backends::bearssl (spec 2.15): BearSSL's br_md5, br_sha1, br_sha224 to
// br_sha512, br_md5sha1 (TLS 1.0's 36 bytes, MD5 followed by SHA-1) and br_shake (SHAKE128 and
// SHAKE256, any output size) through digest_of and hasher, and its HMAC (br_hmac_*) through mac,
// against Boost.Hash2 on random inputs, fed to the hasher in random pieces; the fixed digests
// against RFC 1321's and FIPS 180's printed digests of "abc", an oracle that is not Hash2; HMAC
// against RFC 4231 (SHA-2) and RFC 2202 (MD5, SHA-1); SHAKE against FIPS 202's empty-input
// outputs; the wipe of BearSSL's contexts after a call, when a hasher finishes and when a hasher
// is dropped unfinished, reported through the seam WEBCPP_SECURE_TEST_WIPE_RECORD (spec 6.1);
// and backends::bearssl never a default (design D34).

#include <webcpp/hash/backends/bearssl.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/random_cases.hpp"
#include "support/rfc2202.hpp"
#include "support/rfc4231.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/hmac.hpp>
#include <boost/hash2/md5.hpp>
#include <boost/hash2/sha1.hpp>
#include <boost/hash2/sha2.hpp>
#include <boost/hash2/sha3.hpp>

#include <bearssl_hash.h>
#include <bearssl_hmac.h>
#include <bearssl_kdf.h>

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

#ifndef WEBCPP_SECURE_TEST_WIPE_RECORD
#error "families_bearssl_test is built with WEBCPP_SECURE_TEST_WIPE_RECORD (test/Jamfile)"
#endif

namespace {

namespace hash = webcpp::hash;
namespace digests = webcpp::hash::digests;
namespace macs = webcpp::hash::macs;
namespace test = webcpp::test;
using hash::backends::bearssl;

// The wipes since the last clear: the sizes of the first 16, how many in all, and how many found
// a byte not zero.
struct record {
    std::array<std::size_t, 16> sizes{};
    std::size_t count = 0;
    std::size_t not_zero = 0;

    // How many of the recorded wipes were of `size` bytes.
    [[nodiscard]] std::size_t of_size(std::size_t size) const {
        auto const recorded = std::span(sizes).first(std::min(count, sizes.size()));
        return static_cast<std::size_t>(std::ranges::count(recorded, size));
    }
};

// The seam's record, which secure::detail::wipe reaches through a function of this test.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the seam's record
record wipes;

// The number of random cases of each digest and hmac (the first ones empty).
constexpr std::size_t cases = 300;

// A random input of case `index`: the first empty, then up to 300 bytes, every 16th up to 3,000.
std::vector<std::uint8_t> next_input(test::random_source& rnd, std::size_t index) {
    if (index == 0) {
        return {};
    }
    std::size_t const longest = index % 16 == 0 ? 3000 : 300;
    return rnd.bytes(rnd.between(0, longest));
}

// The hasher's run over `input` fed in random pieces (empty ones included), into `output`; the
// record is cleared once the hasher is made, so that it holds the wipes from the first piece on.
template <class Tag>
bool hash_in_pieces(test::random_source& rnd, std::span<std::uint8_t const> input,
                    std::span<std::uint8_t> output) {
    auto made = hash::hasher<Tag, bearssl>::make();
    if (!made) {
        return false;
    }
    // From here the record holds the wipes of the hash's own end.
    wipes = {};
    std::size_t offset = 0;
    while (offset < input.size()) {
        std::size_t const piece = std::min(rnd.between(0, 200), input.size() - offset);
        if (!made->update(input.subspan(offset, piece))) {
            return false;
        }
        offset += piece;
    }
    return made->finish(output).has_value();
}

// A dropped hasher wipes its state: one hasher of `Tag` made and fed, then destroyed unfinished,
// wipes BearSSL's context, of `Context`, once.
template <class Tag, class Context>
void wipe_on_drop() {
    {
        auto made = hash::hasher<Tag, bearssl>::make();
        if (!BOOST_TEST(made.has_value())) {
            return;
        }
        BOOST_TEST(made->update(test::from_hex("616263")).has_value());
        wipes = {};
    }
    BOOST_TEST_EQ(wipes.count, 1U);
    BOOST_TEST_EQ(wipes.of_size(sizeof(Context)), 1U);
    BOOST_TEST_EQ(wipes.not_zero, 0U);
}

// A fixed-size digest on backends::bearssl, through digest_of and hasher, against `reference`,
// which gives the expected bytes of an input; and the wipe of BearSSL's context, of `Context`,
// after digest_of, when the hasher finishes and when one is dropped unfinished.
template <class Tag, class Context, class Reference>
void agree_digest(std::string_view name, std::size_t size, Reference reference) {
    test::random_source rnd(test::agreement_seed);
    for (std::size_t index = 0; index < cases; ++index) {
        auto const input = next_input(rnd, index);
        std::vector<std::uint8_t> const expected = reference(input);
        BOOST_TEST_EQ(expected.size(), size);
        std::vector<std::uint8_t> once(size);
        wipes = {};
        BOOST_TEST((hash::digest_of<Tag, bearssl>(once, input).has_value()));
        BOOST_TEST_EQ(wipes.of_size(sizeof(Context)), 1U);
        BOOST_TEST_EQ(wipes.not_zero, 0U);
        std::vector<std::uint8_t> pieces(size);
        BOOST_TEST(hash_in_pieces<Tag>(rnd, input, pieces));
        BOOST_TEST_EQ(wipes.of_size(sizeof(Context)), 1U);
        BOOST_TEST_EQ(wipes.not_zero, 0U);
        if (!BOOST_TEST(once == expected) || !BOOST_TEST(pieces == expected)) {
            std::cerr << "  " << name << " of input " << input.size() << " (seed "
                      << test::agreement_seed << ", case " << index << ")\n";
        }
    }
    wipe_on_drop<Tag, Context>();
}

// The digest of "abc" on backends::bearssl, through digest_of and hasher, is `expected`, a
// standard's printed value.
template <class Tag>
void known_answer(std::string_view standard, std::string_view expected) {
    auto const abc = test::from_hex("616263");
    std::vector<std::uint8_t> once(expected.size() / 2);
    BOOST_TEST((hash::digest_of<Tag, bearssl>(once, abc).has_value()));
    std::vector<std::uint8_t> pieces(expected.size() / 2);
    test::random_source rnd(test::agreement_seed);
    BOOST_TEST(hash_in_pieces<Tag>(rnd, abc, pieces));
    if (!BOOST_TEST_EQ(test::to_hex(once), std::string(expected)) ||
        !BOOST_TEST_EQ(test::to_hex(pieces), std::string(expected))) {
        std::cerr << "  " << standard << '\n';
    }
}

// Boost.Hash2's `Hash` of an input, as bytes.
template <class Hash>
std::vector<std::uint8_t> hash2_of(std::span<std::uint8_t const> input) {
    Hash hashed;
    hashed.update(input.data(), input.size());
    auto const result = hashed.result();
    return {result.begin(), result.end()};
}

void check_digests() {
    agree_digest<digests::md5, br_md5_context>("md5", 16, hash2_of<boost::hash2::md5_128>);
    agree_digest<digests::sha1, br_sha1_context>("sha1", 20, hash2_of<boost::hash2::sha1_160>);
    agree_digest<digests::sha2_224, br_sha224_context>("sha2_224", 28,
                                                       hash2_of<boost::hash2::sha2_224>);
    agree_digest<digests::sha2_256, br_sha256_context>("sha2_256", 32,
                                                       hash2_of<boost::hash2::sha2_256>);
    agree_digest<digests::sha2_384, br_sha384_context>("sha2_384", 48,
                                                       hash2_of<boost::hash2::sha2_384>);
    agree_digest<digests::sha2_512, br_sha512_context>("sha2_512", 64,
                                                       hash2_of<boost::hash2::sha2_512>);
    // TLS 1.0's MD5-SHA1: Hash2's md5_128 of the input followed by its sha1_160.
    agree_digest<digests::md5_sha1, br_md5sha1_context>(
        "md5_sha1", 36, [](std::span<std::uint8_t const> input) {
            auto joined = hash2_of<boost::hash2::md5_128>(input);
            auto const sha1 = hash2_of<boost::hash2::sha1_160>(input);
            joined.insert(joined.end(), sha1.begin(), sha1.end());
            return joined;
        });

    // "abc": RFC 1321 (A.5), RFC 3174 (7.3, test 1) and FIPS 180-2's examples (SHA-224 from its
    // change notice); MD5-SHA1's is RFC 1321's followed by RFC 3174's.
    known_answer<digests::md5>("RFC 1321 MD5", "900150983cd24fb0d6963f7d28e17f72");
    known_answer<digests::sha1>("RFC 3174 SHA-1", "a9993e364706816aba3e25717850c26c9cd0d89d");
    known_answer<digests::sha2_224>("FIPS 180-2 SHA-224",
                                    "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
    known_answer<digests::sha2_256>(
        "FIPS 180-2 SHA-256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    known_answer<digests::sha2_384>("FIPS 180-2 SHA-384",
                                    "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163"
                                    "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
    known_answer<digests::sha2_512>(
        "FIPS 180-2 SHA-512",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    known_answer<digests::md5_sha1>(
        "RFC 1321 then RFC 3174",
        "900150983cd24fb0d6963f7d28e17f72a9993e364706816aba3e25717850c26c9cd0d89d");
}

// Boost.Hash2's SHAKE stream of an input, `size` bytes: each result() of Hash2's shake is the next
// block of the rate, which this test relies on and checks at compile time.
template <class Shake>
std::vector<std::uint8_t> shake_stream(std::span<std::uint8_t const> input, std::size_t size) {
    static_assert(typename Shake::result_type().size() == Shake::block_size,
                  "each result() of Boost.Hash2's SHAKE is one block of the rate");
    Shake hashed;
    hashed.update(input.data(), input.size());
    std::vector<std::uint8_t> stream;
    while (stream.size() < size) {
        auto const block = hashed.result();
        stream.insert(stream.end(), block.begin(), block.end());
    }
    stream.resize(size);
    return stream;
}

// SHAKE on backends::bearssl, any output size from 1 byte, through digest_of and hasher, against
// Boost.Hash2's stream; FIPS 202's output of the empty input; the guards; and the wipes, as
// agree_digest's.
template <class Tag, class Shake>
void agree_shake(std::string_view name, std::string_view empty_output) {
    test::random_source rnd(test::agreement_seed);
    for (std::size_t index = 0; index < cases; ++index) {
        auto const input = next_input(rnd, index);
        // Output sizes across several blocks of the rate, the shortest first.
        std::size_t const size = index == 0 ? 1 : rnd.between(1, 700);
        auto const expected = shake_stream<Shake>(input, size);
        std::vector<std::uint8_t> once(size);
        wipes = {};
        BOOST_TEST((hash::digest_of<Tag, bearssl>(once, input).has_value()));
        BOOST_TEST_EQ(wipes.of_size(sizeof(br_shake_context)), 1U);
        BOOST_TEST_EQ(wipes.not_zero, 0U);
        std::vector<std::uint8_t> pieces(size);
        BOOST_TEST(hash_in_pieces<Tag>(rnd, input, pieces));
        BOOST_TEST_EQ(wipes.of_size(sizeof(br_shake_context)), 1U);
        BOOST_TEST_EQ(wipes.not_zero, 0U);
        if (!BOOST_TEST(once == expected) || !BOOST_TEST(pieces == expected)) {
            std::cerr << "  " << name << " of input " << input.size() << ", output " << size
                      << " (seed " << test::agreement_seed << ", case " << index << ")\n";
        }
    }
    wipe_on_drop<Tag, br_shake_context>();

    std::vector<std::uint8_t> first(empty_output.size() / 2);
    BOOST_TEST((hash::digest_of<Tag, bearssl>(first, {}).has_value()));
    BOOST_TEST_EQ(test::to_hex(first), std::string(empty_output));

    // The family's guard: no output is invalid_output_size, before BearSSL is reached.
    std::vector<std::uint8_t> none;
    auto const refused = hash::digest_of<Tag, bearssl>(none, {});
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::invalid_output_size);
}

void check_shake() {
    // FIPS 202's SHAKE128("") and SHAKE256(""), the first 32 and 64 bytes (NIST's examples).
    agree_shake<digests::shake_128, boost::hash2::shake_128>(
        "shake_128", "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
    agree_shake<digests::shake_256, boost::hash2::shake_256>(
        "shake_256",
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be");
}

// HMAC over `Digest` on backends::bearssl against Boost.Hash2's `hmac<Hash>`, keys of 0 to 200
// bytes (past every block size) and tags of 10 bytes to the digest's size, the digest cut (RFC
// 2104, section 5); and the wipe of BearSSL's two contexts.
template <class Digest, class Hash>
void agree_hmac(std::string_view name) {
    using tag = macs::hmac<Digest>;
    std::size_t const size = typename Hash::result_type().size();
    test::random_source rnd(test::agreement_seed);
    for (std::size_t index = 0; index < cases; ++index) {
        auto const key = index == 0 ? std::vector<std::uint8_t>{} : rnd.bytes(rnd.between(0, 200));
        auto const input = next_input(rnd, index);
        std::size_t const output = index == 0 ? size : rnd.between(10, size);
        boost::hash2::hmac<Hash> reference(key.data(), key.size());
        reference.update(input.data(), input.size());
        auto const whole = reference.result();
        std::vector<std::uint8_t> const expected(whole.begin(), whole.begin() + output);
        std::vector<std::uint8_t> computed(output);
        wipes = {};
        BOOST_TEST((hash::mac<tag, bearssl>(computed, key, input).has_value()));
        BOOST_TEST_EQ(wipes.of_size(sizeof(br_hmac_key_context)), 1U);
        BOOST_TEST_EQ(wipes.of_size(sizeof(br_hmac_context)), 1U);
        BOOST_TEST_EQ(wipes.not_zero, 0U);
        if (!BOOST_TEST(computed == expected)) {
            std::cerr << "  hmac " << name << " of key " << key.size() << ", input " << input.size()
                      << ", tag " << output << " (seed " << test::agreement_seed << ", case "
                      << index << ")\n";
        }
    }

    // The family's guards: a tag under 10 bytes or past the digest is refused before BearSSL.
    for (std::size_t const output : {std::size_t{9}, size + 1}) {
        std::vector<std::uint8_t> refused_tag(output, 0x5A);
        auto const refused = hash::mac<tag, bearssl>(refused_tag, {}, {});
        BOOST_TEST(refused.has_error() && refused.error() == hash::error::invalid_output_size);
        BOOST_TEST(std::ranges::all_of(refused_tag, [](std::uint8_t b) { return b == 0x5A; }));
    }
}

// One printed case: the tag of `data` under `key`, of `length` bytes, is `expected`.
template <class Digest>
void check_printed(std::string_view section, std::string_view key, std::string_view data,
                   std::size_t length, std::string_view expected) {
    std::vector<std::uint8_t> computed(length);
    BOOST_TEST(
        (hash::mac<macs::hmac<Digest>, bearssl>(computed, test::from_hex(key), test::from_hex(data))
             .has_value()));
    if (!BOOST_TEST_EQ(test::to_hex(computed), std::string(expected))) {
        std::cerr << "  " << section << '\n';
    }
}

void check_hmac() {
    agree_hmac<digests::md5, boost::hash2::md5_128>("md5");
    agree_hmac<digests::sha1, boost::hash2::sha1_160>("sha1");
    agree_hmac<digests::sha2_224, boost::hash2::sha2_224>("sha2_224");
    agree_hmac<digests::sha2_256, boost::hash2::sha2_256>("sha2_256");
    agree_hmac<digests::sha2_384, boost::hash2::sha2_384>("sha2_384");
    agree_hmac<digests::sha2_512, boost::hash2::sha2_512>("sha2_512");

    // RFC 4231's seven cases (case 5 cut to 16 bytes), over each SHA-2.
    for (auto const& c : test::rfc4231_cases) {
        auto const length = [&](std::size_t whole) { return c.length == 0 ? whole : c.length; };
        check_printed<digests::sha2_224>("RFC 4231 SHA-224", c.key, c.data, length(28), c.sha224);
        check_printed<digests::sha2_256>("RFC 4231 SHA-256", c.key, c.data, length(32), c.sha256);
        check_printed<digests::sha2_384>("RFC 4231 SHA-384", c.key, c.data, length(48), c.sha384);
        check_printed<digests::sha2_512>("RFC 4231 SHA-512", c.key, c.data, length(64), c.sha512);
    }
    // RFC 2202's seven cases of HMAC-MD5 and HMAC-SHA-1 (case 5 its 12-byte "digest-96").
    for (auto const& c : test::rfc2202_md5_cases) {
        check_printed<digests::md5>("RFC 2202 HMAC-MD5", c.key, c.data, c.length, c.mac);
    }
    for (auto const& c : test::rfc2202_sha1_cases) {
        check_printed<digests::sha1>("RFC 2202 HMAC-SHA-1", c.key, c.data, c.length, c.mac);
    }
}

// What backends::bearssl has, and that it is no tag's default (design D34): its tags keep the
// default of D34's order, the first of backends::hash2, xkcp, blake3 and sodium, or none.
template <class Tag>
constexpr bool on_bearssl_alone_by_name =
    hash::backend_has_v<bearssl, Tag, void> && !std::is_same_v<hash::default_backend<Tag>, bearssl>;

static_assert(on_bearssl_alone_by_name<digests::md5>);
static_assert(on_bearssl_alone_by_name<digests::sha1>);
static_assert(on_bearssl_alone_by_name<digests::sha2_224>);
static_assert(on_bearssl_alone_by_name<digests::sha2_256>);
static_assert(on_bearssl_alone_by_name<digests::sha2_384>);
static_assert(on_bearssl_alone_by_name<digests::sha2_512>);
static_assert(on_bearssl_alone_by_name<digests::md5_sha1>);
static_assert(on_bearssl_alone_by_name<digests::shake_128>);
static_assert(on_bearssl_alone_by_name<digests::shake_256>);
static_assert(on_bearssl_alone_by_name<macs::hmac<digests::md5>>);
static_assert(on_bearssl_alone_by_name<macs::hmac<digests::sha1>>);
static_assert(on_bearssl_alone_by_name<macs::hmac<digests::sha2_224>>);
static_assert(on_bearssl_alone_by_name<macs::hmac<digests::sha2_256>>);
static_assert(on_bearssl_alone_by_name<macs::hmac<digests::sha2_384>>);
static_assert(on_bearssl_alone_by_name<macs::hmac<digests::sha2_512>>);
static_assert(std::is_same_v<hash::default_backend<digests::md5_sha1>, hash::detail::no_default>);
// BearSSL has no SHA-512/224, SHA-512/256 nor SHA-3 fixed digest.
static_assert(!hash::backend_has_v<bearssl, digests::sha2_512_256, void>);
static_assert(!hash::backend_has_v<bearssl, digests::sha3_256, void>);
static_assert(!hash::backend_has_v<bearssl, macs::hmac<digests::sha3_256>, void>);

}  // namespace

void webcpp::secure::test::wipe_record(void const* wiped_data, std::size_t byte_count) noexcept {
    auto const* const bytes = static_cast<unsigned char const*>(wiped_data);
    if (wipes.count < wipes.sizes.size()) {
        wipes.sizes[wipes.count] = byte_count;
    }
    ++wipes.count;
    if (!std::all_of(bytes, bytes + byte_count, [](unsigned char b) { return b == 0; })) {
        ++wipes.not_zero;
    }
}

int main() {
    check_digests();
    check_shake();
    check_hmac();
    return webcpp::test::exit_status(boost::report_errors());
}
