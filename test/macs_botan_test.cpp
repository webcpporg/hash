// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The MACs of backends::botan (spec 2.15, design D44): Botan 3.14.1's MessageAuthenticationCode,
// each tag through mac:
// - HMAC over every digest of the column against Boost.Hash2's hmac<H> on random keys (past every
//   block size, and past Botan's 8,192 bytes, which backends::botan hashes first), inputs and tag
//   sizes, H being Hash2's digest, its Keccak (keccak_base with the padding byte 0x01), or, for
//   SM3, Streebog, Whirlpool and Skein-512, which Hash2 lacks, backends::botan's own hasher in
//   Hash2's form (Botan's HMAC against Hash2's construction); RFC 4231's cases over the SHA-2;
//   HMAC-Streebog-256 and -512 against RFC 7836 section 4.1.1's examples;
// - KMAC128 and KMAC256: NIST's samples in OpenSSL's evpmac_common.txt and backends::xkcp on
//   random keys, customisations, inputs and tag sizes; a key of 193 bytes and the XOF form
//   unsupported_by_backend, the output untouched;
// - SipHash-2-4 against Wycheproof's siphash_2_4_test.json and backends::hash2;
// - keyed BLAKE2b against BLAKE2's blake2b-kat.txt and libsodium at every key and tag size;
// - backends::botan never a default (design D34).

#include <webcpp/hash/backends/botan.hpp>
#include <webcpp/hash/backends/sodium.hpp>
#include <webcpp/hash/backends/xkcp.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/test/exit_status.hpp>

#include "require.hpp"
#include "support/data_file.hpp"
#include "support/hex.hpp"
#include "support/random_cases.hpp"
#include "support/rfc4231.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/blake2.hpp>
#include <boost/hash2/digest.hpp>
#include <boost/hash2/hmac.hpp>
#include <boost/hash2/md5.hpp>
#include <boost/hash2/ripemd.hpp>
#include <boost/hash2/sha1.hpp>
#include <boost/hash2/sha2.hpp>
#include <boost/hash2/sha3.hpp>
#include <boost/json.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace {

namespace hash = webcpp::hash;
namespace digests = webcpp::hash::digests;
namespace macs = webcpp::hash::macs;
namespace json = boost::json;
namespace test = webcpp::test;
using hash::backends::botan;
using bytes = std::vector<std::uint8_t>;

bool failed_with(boost::system::result<void> const& outcome, hash::error expected) {
    return outcome.has_error() && outcome.error() == expected;
}

// Whether every byte is `value`.
bool all_of(std::span<std::uint8_t const> data, std::uint8_t value) {
    return std::ranges::all_of(data, [value](std::uint8_t byte) { return byte == value; });
}

// The number of random cases of each MAC.
constexpr std::size_t cases = 1000;

// A random input of case `index`: the first empty, then up to 300 bytes, every 16th up to 3,000.
bytes next_input(test::random_source& rnd, std::size_t index) {
    if (index == 0) {
        return {};
    }
    std::size_t const longest = index % 16 == 0 ? 3000 : 300;
    return rnd.bytes(rnd.between(0, longest));
}

// ---- HMAC ----

// A digest of backends::botan as a hash of Boost.Hash2's form, over its own hasher: so that
// Botan's HMAC over a digest Hash2 lacks is checked against Hash2's HMAC construction.
template <class Digest, std::size_t Size, std::size_t Block>
class botan_hash {
public:
    using result_type = boost::hash2::digest<Size>;
    static constexpr std::size_t block_size = Block;

    botan_hash() : hashing_(*hash::hasher<Digest, botan>::make()) {}

    void update(void const* data, std::size_t size) {
        test::require(BOOST_TEST(
            hashing_.update({static_cast<std::uint8_t const*>(data), size}).has_value()));
    }

    void update(unsigned char const* data, std::size_t size) {
        update(static_cast<void const*>(data), size);
    }

    result_type result() {
        result_type out;
        test::require(BOOST_TEST(hashing_.finish({out.data(), out.size()}).has_value()));
        return out;
    }

private:
    hash::hasher<Digest, botan> hashing_;
};

// Boost.Hash2's Keccak with the original padding (byte 0x01), of `Bits` output bits.
template <int Bits>
using keccak_hash = boost::hash2::detail::keccak_base<0x01, 2 * Bits, Bits>;

// HMAC over `Digest` on Botan against Boost.Hash2's hmac<Hash>: random keys of 0 to 200 bytes
// (past every block size, so that a long key is hashed first), every 100th of 8,193 to 9,000
// bytes (past Botan's HMAC key limit), random inputs, and every tag size from 10 bytes to the
// digest's in turn (the digest cut, RFC 2104 section 5).
template <class Digest, class Hash>
void agree_hmac(std::string_view name, std::size_t count = cases) {
    test::random_source rnd(test::agreement_seed);
    using result_type = Hash::result_type;
    constexpr std::size_t digest_size = result_type{}.size();
    for (std::size_t index = 0; index < count; ++index) {
        // Every 100th key is past Botan's HMAC limit, which backends::botan hashes first.
        std::size_t key_size = index % 100 == 1 ? rnd.between(8193, 9000) : rnd.between(0, 200);
        if (index == 0) {
            key_size = 0;
        }
        auto const key = rnd.bytes(key_size);
        auto const input = next_input(rnd, index);
        std::size_t const tag_size = 10 + (index % (digest_size - 9));
        boost::hash2::hmac<Hash> oracle(key.data(), key.size());
        oracle.update(input.data(), input.size());
        auto const expected = oracle.result();
        bytes tag(tag_size, 0x5A);
        bool const computed = hash::mac<macs::hmac<Digest>, botan>(tag, key, input).has_value();
        if (!BOOST_TEST(computed) ||
            !BOOST_TEST_EQ(
                test::to_hex(tag),
                test::to_hex(std::span(expected.data(), expected.size()).first(tag_size)))) {
            std::cerr << "  hmac over " << name << ", case " << index << ", key " << key.size()
                      << ", input " << input.size() << ", tag " << tag_size << '\n';
            return;
        }
    }
}

// RFC 4231's seven cases over SHA-224 to SHA-512 (case 5 printed cut to 16 bytes).
void check_rfc4231() {
    for (std::size_t number = 1; auto const& vector : test::rfc4231_cases) {
        auto const key = test::from_hex(vector.key);
        auto const data = test::from_hex(vector.data);
        auto const one = [&]<class Digest>(std::string_view expected) {
            bytes tag(expected.size() / 2);
            bool const computed = hash::mac<macs::hmac<Digest>, botan>(tag, key, data).has_value();
            if (!BOOST_TEST(computed) || !BOOST_TEST_EQ(test::to_hex(tag), expected)) {
                std::cerr << "  RFC 4231 test case " << number << '\n';
            }
        };
        one.operator()<digests::sha2_224>(vector.sha224);
        one.operator()<digests::sha2_256>(vector.sha256);
        one.operator()<digests::sha2_384>(vector.sha384);
        one.operator()<digests::sha2_512>(vector.sha512);
        ++number;
    }
}

// RFC 7836 section 4.1.1's examples: HMAC_GOSTR3411_2012_256 and _512 of T under K, copied as the
// RFC writes their bytes.
void check_rfc7836() {
    auto const key =
        test::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    auto const data = test::from_hex("0126bdb87800af214341456563780100");
    bytes tag_256(32);
    BOOST_TEST((hash::mac<macs::hmac<digests::streebog_256>, botan>(tag_256, key, data)));
    BOOST_TEST_EQ(test::to_hex(tag_256),
                  "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9");
    bytes tag_512(64);
    BOOST_TEST((hash::mac<macs::hmac<digests::streebog_512>, botan>(tag_512, key, data)));
    BOOST_TEST_EQ(test::to_hex(tag_512),
                  "a59bab22ecae19c65fbde6e5f4e9f5d8549d31f037f9df9b905500e171923a77"
                  "3d5f1530f2ed7e964cb2eedc29e9ad2f3afe93b2814f79f5000ffc0366c251e6");
}

void check_hmac() {
    namespace h2 = boost::hash2;
    agree_hmac<digests::md5, h2::md5_128>("md5");
    agree_hmac<digests::sha1, h2::sha1_160>("sha1");
    agree_hmac<digests::sha2_224, h2::sha2_224>("sha2_224");
    agree_hmac<digests::sha2_256, h2::sha2_256>("sha2_256");
    agree_hmac<digests::sha2_384, h2::sha2_384>("sha2_384");
    agree_hmac<digests::sha2_512, h2::sha2_512>("sha2_512");
    agree_hmac<digests::sha2_512_256, h2::sha2_512_256>("sha2_512_256");
    agree_hmac<digests::sha3_224, h2::sha3_224>("sha3_224");
    agree_hmac<digests::sha3_256, h2::sha3_256>("sha3_256");
    agree_hmac<digests::sha3_384, h2::sha3_384>("sha3_384");
    agree_hmac<digests::sha3_512, h2::sha3_512>("sha3_512");
    agree_hmac<digests::keccak_224, keccak_hash<224>>("keccak_224");
    agree_hmac<digests::keccak_256, keccak_hash<256>>("keccak_256");
    agree_hmac<digests::keccak_384, keccak_hash<384>>("keccak_384");
    agree_hmac<digests::keccak_512, keccak_hash<512>>("keccak_512");
    agree_hmac<digests::ripemd_160, h2::ripemd_160>("ripemd_160");
    agree_hmac<digests::blake2b, h2::blake2b_512>("blake2b");
    agree_hmac<digests::blake2s_256, h2::blake2s_256>("blake2s_256");
    // Over Botan's own hasher: fewer cases, each hasher a call of its own.
    agree_hmac<digests::sm3, botan_hash<digests::sm3, 32, 64>>("sm3", 200);
    agree_hmac<digests::streebog_256, botan_hash<digests::streebog_256, 32, 64>>("streebog_256",
                                                                                 200);
    agree_hmac<digests::streebog_512, botan_hash<digests::streebog_512, 64, 64>>("streebog_512",
                                                                                 200);
    agree_hmac<digests::whirlpool, botan_hash<digests::whirlpool, 64, 64>>("whirlpool", 200);
    agree_hmac<digests::skein_512, botan_hash<digests::skein_512, 64, 64>>("skein_512", 200);
    check_rfc4231();
    check_rfc7836();

    // The family's guards hold on Botan: a tag under 10 bytes or past the digest is refused, the
    // output untouched.
    std::array<std::uint8_t, 3> const input{0x61, 0x62, 0x63};
    bytes short_tag(9, 0x5A);
    BOOST_TEST(failed_with(hash::mac<macs::hmac<digests::sha2_256>, botan>(short_tag, {}, input),
                           hash::error::invalid_output_size));
    BOOST_TEST(all_of(short_tag, 0x5A));
}

// ---- KMAC ----

// The stanzas of evpmac_common.txt: their "Name = value" lines, in order.
using stanza = std::vector<std::pair<std::string, std::string>>;

std::vector<stanza> read_stanzas(std::string const& path) {
    std::vector<stanza> stanzas(1);
    for (auto const& line : test::read_lines(path)) {
        if (line.empty()) {
            if (!stanzas.back().empty()) {
                stanzas.emplace_back();
            }
            continue;
        }
        auto const separator = line.find(" = ");
        if (line.front() == '#' || separator == std::string::npos) {
            continue;
        }
        stanzas.back().emplace_back(line.substr(0, separator), line.substr(separator + 3));
    }
    return stanzas;
}

// The value of the first line named `name`, empty when there is none.
std::string value_of(stanza const& lines, std::string_view name) {
    auto const found =
        std::ranges::find_if(lines, [name](auto const& line) { return line.first == name; });
    return found == lines.end() ? std::string{} : found->second;
}

// The bytes of an EVP value: hex, or a quoted string's characters.
bytes value_bytes(std::string const& value) {
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
        return {value.begin() + 1, value.end() - 1};
    }
    return test::from_hex(value);
}

// KMAC on Botan, in the form the options give.
template <class Mac>
boost::system::result<void> kmac(std::span<std::uint8_t> tag, std::span<std::uint8_t const> key,
                                 std::span<std::uint8_t const> input,
                                 std::span<std::uint8_t const> custom, bool xof = false) {
    return hash::mac<Mac, botan>(tag, key, input, {.customisation = custom, .xof = xof});
}

// The KMAC cases of evpmac_common.txt with a published Output: NIST's samples (SP 800-185's KMAC
// examples) and NIST ACVP's long customisation. Botan computes the fixed-length ones; the XOF
// ones (XOF = 1, or Ctrl = xof:1) are unsupported_by_backend, the output untouched; a tag under
// SP 800-185's 32 bits is the family's refusal on every backend.
void check_kmac_evp_data() {
    std::size_t computed = 0;
    std::size_t xof = 0;
    for (auto const& lines : read_stanzas(WEBCPP_TEST_OPENSSL_EVP_DATA "/evpmac_common.txt")) {
        auto const name = value_of(lines, "MAC");
        auto const output = value_of(lines, "Output");
        if ((name != "KMAC128" && name != "KMAC256") || output.empty() ||
            value_of(lines, "Availablein") == "fips") {
            continue;
        }
        bool const is_xof =
            value_of(lines, "XOF") == "1" || std::ranges::any_of(lines, [](auto const& line) {
                return line.first == "Ctrl" && line.second == "xof:1";
            });
        auto const key = value_bytes(value_of(lines, "Key"));
        auto const input = value_bytes(value_of(lines, "Input"));
        auto const custom = value_bytes(value_of(lines, "Custom"));
        auto const expected = test::to_hex(test::from_hex(output));
        bytes tag(expected.size() / 2, 0x5A);
        if (tag.size() < 4) {
            continue;
        }
        auto const outcome = name == "KMAC128"
                                 ? kmac<macs::kmac_128>(tag, key, input, custom, is_xof)
                                 : kmac<macs::kmac_256>(tag, key, input, custom, is_xof);
        if (is_xof) {
            BOOST_TEST(failed_with(outcome, hash::error::unsupported_by_backend));
            BOOST_TEST(all_of(tag, 0x5A));
            ++xof;
            continue;
        }
        if (!BOOST_TEST(outcome.has_value()) || !BOOST_TEST_EQ(test::to_hex(tag), expected)) {
            std::cerr << "  " << name << ", tag " << tag.size() << '\n';
        }
        ++computed;
    }
    // At OpenSSL 3.5.9's pin: 6 fixed-length cases computed, 14 XOF cases refused (and 2 of a
    // 3-byte tag, under SP 800-185's floor, left out).
    BOOST_TEST_EQ(computed, 6U);
    BOOST_TEST_EQ(xof, 14U);
}

// KMAC on Botan against backends::xkcp on random keys of 0 to 192 bytes (Botan's limit),
// customisations of 0 to 512 bytes, inputs and tags of 4 to 300 bytes (past a rate).
template <class Mac>
void agree_kmac(std::string_view name) {
    test::random_source rnd(test::agreement_seed);
    for (std::size_t index = 0; index < cases; ++index) {
        std::size_t key_size = index == 1 ? 192 : rnd.between(0, 192);
        if (index == 0) {
            key_size = 0;
        }
        auto const key = rnd.bytes(key_size);
        auto const custom = index == 0 ? bytes{} : rnd.bytes(rnd.between(0, 512));
        auto const input = next_input(rnd, index);
        std::size_t const tag_size = index == 1 ? 4 : rnd.between(4, 300);
        bytes tag(tag_size, 0x5A);
        bytes expected(tag_size);
        bool const computed = kmac<Mac>(tag, key, input, custom).has_value();
        test::require(BOOST_TEST(
            (hash::mac<Mac, hash::backends::xkcp>(expected, key, input, {.customisation = custom})
                 .has_value())));
        if (!BOOST_TEST(computed) || !BOOST_TEST_EQ(test::to_hex(tag), test::to_hex(expected))) {
            std::cerr << "  " << name << ", case " << index << ", key " << key.size()
                      << ", customisation " << custom.size() << ", input " << input.size()
                      << ", tag " << tag_size << '\n';
            return;
        }
    }

    // Botan's limits, before Botan is called: a key of 193 bytes and the XOF form.
    std::array<std::uint8_t, 3> const input{0x61, 0x62, 0x63};
    bytes const key193(193, 0x0b);
    bytes tag(32, 0x5A);
    BOOST_TEST(failed_with(kmac<Mac>(tag, key193, input, {}), hash::error::unsupported_by_backend));
    BOOST_TEST(all_of(tag, 0x5A));
    bytes const key32(32, 0x0b);
    BOOST_TEST(
        failed_with(kmac<Mac>(tag, key32, input, {}, true), hash::error::unsupported_by_backend));
    BOOST_TEST(all_of(tag, 0x5A));
}

// ---- SipHash ----

// The groups of a Wycheproof file of testvectors_v1.
json::value read_wycheproof(std::string const& file) {
    auto const path = std::string(WEBCPP_TEST_WYCHEPROOF "/testvectors_v1/") + file;
    boost::system::error_code ec;
    auto doc = json::parse(test::read_text(path), ec);
    test::require(BOOST_TEST(!ec));
    return doc;
}

// Every case of Wycheproof's siphash_2_4_test.json: a valid case's tag is computed, an invalid
// one's (a modified tag) is not; and backends::hash2 on random keys and inputs.
void check_siphash() {
    auto const doc = read_wycheproof("siphash_2_4_test.json");
    std::size_t run = 0;
    for (auto const& group : doc.at("testGroups").as_array()) {
        auto const tag_size = static_cast<std::size_t>(group.at("tagSize").as_int64() / 8);
        for (auto const& entry : group.at("tests").as_array()) {
            auto const& vector = entry.as_object();
            auto const key = test::from_hex(vector.at("key").as_string());
            auto const message = test::from_hex(vector.at("msg").as_string());
            bytes tag(tag_size);
            bool const computed =
                hash::mac<macs::siphash_2_4, botan>(tag, key, message).has_value();
            bool const valid = vector.at("result").as_string() == "valid";
            bool const same = test::to_hex(tag) == vector.at("tag").as_string();
            if (!BOOST_TEST(computed) || !BOOST_TEST_EQ(same, valid)) {
                std::cerr << "  siphash_2_4_test.json, tcId " << vector.at("tcId").as_int64()
                          << '\n';
            }
            ++run;
        }
    }
    BOOST_TEST_EQ(run, static_cast<std::size_t>(doc.at("numberOfTests").as_int64()));

    test::random_source rnd(test::agreement_seed);
    for (std::size_t index = 0; index < cases; ++index) {
        auto const key = rnd.bytes(16);
        auto const input = next_input(rnd, index);
        std::array<std::uint8_t, 8> tag{};
        std::array<std::uint8_t, 8> expected{};
        bool const computed = hash::mac<macs::siphash_2_4, botan>(tag, key, input).has_value();
        test::require(BOOST_TEST(
            (hash::mac<macs::siphash_2_4, hash::backends::hash2>(expected, key, input))));
        if (!BOOST_TEST(computed && tag == expected)) {
            std::cerr << "  siphash_2_4 against backends::hash2, case " << index << '\n';
            return;
        }
    }
}

// ---- Keyed BLAKE2b ----

// The value after "<name>:\t" on a line of blake2b-kat.txt.
std::string kat_value(std::string const& line, std::string_view name) {
    std::string const prefix = std::string(name) + ":\t";
    test::require(BOOST_TEST(line.starts_with(prefix)));
    return line.substr(prefix.size());
}

// Every case of BLAKE2's blake2b-kat.txt (a 64-byte key, inputs of 0 to 255 bytes, a 64-byte
// tag); libsodium's keyed BLAKE2b at every key and tag size from 1 to 64 bytes.
void check_blake2b_mac() {
    auto const lines = test::read_lines(WEBCPP_TEST_BLAKE2_VECTORS "/blake2b-kat.txt");
    std::size_t run = 0;
    for (std::size_t index = 0; index + 2 < lines.size(); ++index) {
        if (!lines[index].starts_with("in:")) {
            continue;
        }
        auto const input = test::from_hex(kat_value(lines[index], "in"));
        auto const key = test::from_hex(kat_value(lines[index + 1], "key"));
        auto const expected = kat_value(lines[index + 2], "hash");
        bytes tag(64);
        BOOST_TEST((hash::mac<macs::blake2b_mac, botan>(tag, key, input)));
        if (!BOOST_TEST_EQ(test::to_hex(tag), expected)) {
            std::cerr << "  blake2b-kat.txt, input " << input.size() << '\n';
        }
        index += 2;
        ++run;
    }
    BOOST_TEST_EQ(run, 256U);

    test::random_source rnd(test::agreement_seed);
    for (std::size_t index = 0; index < std::size_t{64} * 8; ++index) {
        auto const key = rnd.bytes((index % 64) + 1);
        std::size_t const tag_size = ((index / 8) % 64) + 1;
        auto const input = next_input(rnd, index);
        bytes tag(tag_size);
        bytes expected(tag_size);
        bool const computed = hash::mac<macs::blake2b_mac, botan>(tag, key, input).has_value();
        test::require(BOOST_TEST(
            (hash::mac<macs::blake2b_mac, hash::backends::sodium>(expected, key, input))));
        if (!BOOST_TEST(computed && tag == expected)) {
            std::cerr << "  blake2b_mac against libsodium, key " << key.size() << ", tag "
                      << tag_size << '\n';
            return;
        }
    }
}

// backends::botan has each of these tags, and is the default of none (design D34).
template <class... Tag>
constexpr bool in_botan_by_name() {
    return ((hash::backend_has_v<botan, Tag, void> &&
             !std::is_same_v<hash::default_backend<Tag>, botan>) &&
            ...);
}

static_assert(
    in_botan_by_name<
        macs::hmac<digests::md5>, macs::hmac<digests::sha1>, macs::hmac<digests::sha2_224>,
        macs::hmac<digests::sha2_256>, macs::hmac<digests::sha2_384>, macs::hmac<digests::sha2_512>,
        macs::hmac<digests::sha2_512_256>, macs::hmac<digests::sha3_224>,
        macs::hmac<digests::sha3_256>, macs::hmac<digests::sha3_384>, macs::hmac<digests::sha3_512>,
        macs::hmac<digests::keccak_224>, macs::hmac<digests::keccak_256>,
        macs::hmac<digests::keccak_384>, macs::hmac<digests::keccak_512>,
        macs::hmac<digests::ripemd_160>, macs::hmac<digests::blake2b>,
        macs::hmac<digests::blake2s_256>, macs::hmac<digests::sm3>,
        macs::hmac<digests::streebog_256>, macs::hmac<digests::streebog_512>,
        macs::hmac<digests::whirlpool>, macs::hmac<digests::skein_512>, macs::kmac_128,
        macs::kmac_256, macs::siphash_2_4, macs::blake2b_mac>());
// Botan's SipHash has an 8-byte tag alone, and its BLAKE2 MAC is BLAKE2b's (design D44).
static_assert(!hash::backend_has_v<botan, macs::siphash_2_4x, void>);
static_assert(!hash::backend_has_v<botan, macs::blake2s_mac, void>);
static_assert(!hash::backend_has_v<botan, macs::hmac<digests::sha2_512_224>, void>);

}  // namespace

int main() {
    check_hmac();
    check_kmac_evp_data();
    agree_kmac<macs::kmac_128>("kmac_128");
    agree_kmac<macs::kmac_256>("kmac_256");
    check_siphash();
    check_blake2b_mac();
    return webcpp::test::exit_status(boost::report_errors());
}
