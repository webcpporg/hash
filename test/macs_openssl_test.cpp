// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The MACs of backends::openssl (spec 2.15): OpenSSL 3.5.9's default provider through
// EVP_MAC_fetch, EVP_MAC_init, EVP_MAC_update and EVP_MAC_final, each tag through mac:
// - HMAC over every digest of a fixed size OpenSSL has: Wycheproof's HMAC files (SHA-1, the SHA-2,
//   the SHA-3 and SM3), and Boost.Hash2's hmac<H> on random keys, inputs and tag sizes, H being
//   Hash2's digest, its Keccak (keccak_base with the padding byte 0x01) and backends::openssl's
//   own SM3 hasher for SM3 (OpenSSL's HMAC against Hash2's); none over MD5-SHA1, which no
//   standard defines;
// - KMAC128 and KMAC256, fixed-length and XOF: the NIST samples and NIST ACVP's long
//   customisation in OpenSSL's evpmac_common.txt, Wycheproof's KMAC files, and a second
//   implementation of SP 800-185 over Boost.Hash2's Keccak (keccak_base with cSHAKE's padding
//   byte 0x04) on random keys, customisations, inputs and tag sizes; OpenSSL's narrower limits
//   (key 4 to 512 bytes, customisation at most 512, tag at most 2,097,151) answered with
//   unsupported_by_backend;
// - keyed BLAKE2b and BLAKE2s (BLAKE2BMAC, BLAKE2SMAC): BLAKE2's testvectors (blake2b-kat.txt's
//   keyed BLAKE2b, blake2-kat.json's keyed BLAKE2s; ruling R45), OpenSSL's evpmac_blake.txt,
//   digests::blake2b on backends::sodium at every tag size and Boost.Hash2's keyed blake2s_256;
// - SipHash-2-4 and SipHash-2-4x (SIPHASH, sizes 8 and 16): Wycheproof's files, OpenSSL's
//   evpmac_siphash.txt, backends::hash2 and backends::sodium on random keys and inputs;
// - backends::openssl never a default (design D34).

#include <webcpp/hash/backends/openssl.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/test/exit_status.hpp>

#include "require.hpp"
#include "support/evp_stanzas.hpp"
#include "support/hex.hpp"
#include "support/random_cases.hpp"

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
#include <cstdlib>
#include <iostream>
#include <optional>
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
namespace evp = webcpp::test::evp;
using hash::backends::openssl;
using bytes = std::vector<std::uint8_t>;

using evp::read_lines;
using evp::read_text;

bool failed_with(boost::system::result<void> const& outcome, hash::error expected) {
    return outcome.has_error() && outcome.error() == expected;
}

// Whether every byte is `value`.
bool all_of(std::span<std::uint8_t const> data, std::uint8_t value) {
    return std::ranges::all_of(data, [value](std::uint8_t byte) { return byte == value; });
}

using evp::read_stanzas;
using evp::stanza;
using evp::value_bytes;
using evp::value_of;
using evp::values_of;

// The groups of a Wycheproof file of testvectors_v1, after checking its number of tests.
json::value read_wycheproof(std::string const& file) {
    auto const path = std::string(WEBCPP_TEST_WYCHEPROOF "/testvectors_v1/") + file;
    boost::system::error_code ec;
    auto doc = json::parse(read_text(path), ec);
    test::require(BOOST_TEST(!ec));
    return doc;
}

// Every case of a Wycheproof MAC file through mac<Mac, openssl>: a valid case's tag is computed,
// an invalid one's (a modified tag) is not; every case of the file is run.
template <class Mac>
void check_wycheproof(std::string const& file, hash::mac_options<Mac> const& options = {}) {
    auto const doc = read_wycheproof(file);
    std::size_t run = 0;
    for (auto const& group : doc.at("testGroups").as_array()) {
        auto const tag_size = static_cast<std::size_t>(group.at("tagSize").as_int64() / 8);
        for (auto const& entry : group.at("tests").as_array()) {
            auto const& vector = entry.as_object();
            auto const key = test::from_hex(vector.at("key").as_string());
            auto const message = test::from_hex(vector.at("msg").as_string());
            bytes tag(tag_size);
            bool const computed = hash::mac<Mac, openssl>(tag, key, message, options).has_value();
            bool const valid = vector.at("result").as_string() == "valid";
            bool const same = test::to_hex(tag) == vector.at("tag").as_string();
            if (!BOOST_TEST(computed) || !BOOST_TEST_EQ(same, valid)) {
                std::cerr << "  " << file << ", tcId " << vector.at("tcId").as_int64() << '\n';
            }
            ++run;
        }
    }
    BOOST_TEST_EQ(run, static_cast<std::size_t>(doc.at("numberOfTests").as_int64()));
}

// ---- HMAC ----

// SM3 as a hash of Boost.Hash2's form, over backends::openssl's own hasher: so that OpenSSL's
// HMAC-SM3 is checked against Hash2's HMAC construction (Wycheproof's file checks the values).
class sm3_hash {
public:
    using result_type = boost::hash2::digest<32>;
    static constexpr std::size_t block_size = 64;

    sm3_hash() : hashing_(*hash::hasher<digests::sm3, openssl>::make()) {}

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
    hash::hasher<digests::sm3, openssl> hashing_;
};

// Boost.Hash2's Keccak with the original padding (byte 0x01), of `Bits` output bits.
template <int Bits>
using keccak_hash = boost::hash2::detail::keccak_base<0x01, 2 * Bits, Bits>;

// The number of random cases of each MAC.
constexpr std::size_t cases = 200;

// A random input of case `index`: the first empty, then up to 300 bytes, every 16th up to 3,000.
bytes next_input(test::random_source& rnd, std::size_t index) {
    if (index == 0) {
        return {};
    }
    std::size_t const longest = index % 16 == 0 ? 3000 : 300;
    return rnd.bytes(rnd.between(0, longest));
}

// HMAC over `Digest` on OpenSSL against Boost.Hash2's hmac<Hash>: random keys of 0 to 200 bytes
// (past every block size, so that a long key is hashed first), random inputs, and every tag size
// from 10 bytes to the digest's in turn (the digest cut, RFC 2104 section 5).
template <class Digest, class Hash>
void agree_hmac(std::string_view name) {
    test::random_source rnd(test::agreement_seed);
    using result_type = Hash::result_type;
    constexpr std::size_t digest_size = result_type{}.size();
    for (std::size_t index = 0; index < cases; ++index) {
        auto const key = index == 0 ? bytes{} : rnd.bytes(rnd.between(0, 200));
        auto const input = next_input(rnd, index);
        std::size_t const tag_size = 10 + (index % (digest_size - 9));
        boost::hash2::hmac<Hash> oracle(key.data(), key.size());
        oracle.update(input.data(), input.size());
        auto const expected = oracle.result();
        bytes tag(tag_size, 0x5A);
        bool const computed = hash::mac<macs::hmac<Digest>, openssl>(tag, key, input).has_value();
        if (!BOOST_TEST(computed) ||
            !BOOST_TEST_EQ(
                test::to_hex(tag),
                test::to_hex(std::span(expected.data(), expected.size()).first(tag_size)))) {
            std::cerr << "  hmac over " << name << ", case " << index << ", key " << key.size()
                      << ", input " << input.size() << ", tag " << tag_size << '\n';
        }
    }
}

void check_hmac() {
    namespace h2 = boost::hash2;
    agree_hmac<digests::md5, h2::md5_128>("md5");
    agree_hmac<digests::sha1, h2::sha1_160>("sha1");
    agree_hmac<digests::sha2_224, h2::sha2_224>("sha2_224");
    agree_hmac<digests::sha2_256, h2::sha2_256>("sha2_256");
    agree_hmac<digests::sha2_384, h2::sha2_384>("sha2_384");
    agree_hmac<digests::sha2_512, h2::sha2_512>("sha2_512");
    agree_hmac<digests::sha2_512_224, h2::sha2_512_224>("sha2_512_224");
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
    agree_hmac<digests::sm3, sm3_hash>("sm3");

    check_wycheproof<macs::hmac<digests::sha1>>("hmac_sha1_test.json");
    check_wycheproof<macs::hmac<digests::sha2_224>>("hmac_sha224_test.json");
    check_wycheproof<macs::hmac<digests::sha2_256>>("hmac_sha256_test.json");
    check_wycheproof<macs::hmac<digests::sha2_384>>("hmac_sha384_test.json");
    check_wycheproof<macs::hmac<digests::sha2_512>>("hmac_sha512_test.json");
    check_wycheproof<macs::hmac<digests::sha2_512_224>>("hmac_sha512_224_test.json");
    check_wycheproof<macs::hmac<digests::sha2_512_256>>("hmac_sha512_256_test.json");
    check_wycheproof<macs::hmac<digests::sha3_224>>("hmac_sha3_224_test.json");
    check_wycheproof<macs::hmac<digests::sha3_256>>("hmac_sha3_256_test.json");
    check_wycheproof<macs::hmac<digests::sha3_384>>("hmac_sha3_384_test.json");
    check_wycheproof<macs::hmac<digests::sha3_512>>("hmac_sha3_512_test.json");
    check_wycheproof<macs::hmac<digests::sm3>>("hmac_sm3_test.json");

    // The family's guards hold on OpenSSL: a tag under 10 bytes or past the digest is refused,
    // the output untouched; an empty key is a key.
    std::array<std::uint8_t, 3> const input{0x61, 0x62, 0x63};
    bytes short_tag(9, 0x5A);
    BOOST_TEST(failed_with(hash::mac<macs::hmac<digests::sha2_256>, openssl>(short_tag, {}, input),
                           hash::error::invalid_output_size));
    BOOST_TEST(all_of(short_tag, 0x5A));
    bytes long_tag(33, 0x5A);
    BOOST_TEST(failed_with(hash::mac<macs::hmac<digests::sha2_256>, openssl>(long_tag, {}, input),
                           hash::error::invalid_output_size));
    BOOST_TEST(all_of(long_tag, 0x5A));
}

// ---- KMAC ----

// SP 800-185 section 2.3.1's left_encode(x): the bytes of x, big-endian and at least one,
// preceded by their number.
bytes left_encode(std::uint64_t value) {
    bytes digits;
    do {
        digits.insert(digits.begin(), static_cast<std::uint8_t>(value & 0xFFU));
        value >>= 8U;
    } while (value != 0);
    digits.insert(digits.begin(), static_cast<std::uint8_t>(digits.size()));
    return digits;
}

// SP 800-185 section 2.3.1's right_encode(x): the bytes of x followed by their number.
bytes right_encode(std::uint64_t value) {
    bytes digits = left_encode(value);
    digits.push_back(digits.front());
    digits.erase(digits.begin());
    return digits;
}

// SP 800-185 section 2.3.2's encode_string(S): left_encode of its length in bits, then S.
bytes encode_string(std::span<std::uint8_t const> text) {
    bytes encoded = left_encode(8 * static_cast<std::uint64_t>(text.size()));
    encoded.insert(encoded.end(), text.begin(), text.end());
    return encoded;
}

// SP 800-185 section 2.3.3's bytepad(X, w): left_encode(w), X, then zeros to a multiple of w.
bytes bytepad(bytes padded, std::size_t width) {
    bytes const prefix = left_encode(width);
    padded.insert(padded.begin(), prefix.begin(), prefix.end());
    padded.resize((padded.size() + width - 1) / width * width, 0);
    return padded;
}

// KMAC (SP 800-185 section 4.3), the second implementation: cSHAKE (section 3.3) with N = "KMAC"
// over Boost.Hash2's Keccak with cSHAKE's padding byte 0x04, whose result() squeezes one rate
// block after another. `Capacity` is 256 for KMAC128, 512 for KMAC256.
template <int Capacity>
bytes kmac_reference(std::span<std::uint8_t const> key, std::span<std::uint8_t const> input,
                     std::span<std::uint8_t const> customisation, std::size_t tag_size, bool xof) {
    using sponge_type = boost::hash2::detail::keccak_base<0x04, Capacity, 1600 - Capacity>;
    constexpr std::size_t rate = (1600 - Capacity) / 8;
    constexpr std::array<std::uint8_t, 4> function_name{'K', 'M', 'A', 'C'};
    bytes header = encode_string(function_name);
    bytes const custom = encode_string(customisation);
    header.insert(header.end(), custom.begin(), custom.end());
    sponge_type sponge;
    auto const absorb = [&sponge](std::span<std::uint8_t const> part) {
        sponge.update(part.data(), part.size());
    };
    absorb(bytepad(header, rate));
    absorb(bytepad(encode_string(key), rate));
    absorb(input);
    absorb(right_encode(xof ? 0 : 8 * static_cast<std::uint64_t>(tag_size)));
    bytes tag;
    while (tag.size() < tag_size) {
        auto const block = sponge.result();
        std::size_t const taken = std::min(rate, tag_size - tag.size());
        tag.insert(tag.end(), block.begin(), block.begin() + static_cast<std::ptrdiff_t>(taken));
    }
    return tag;
}

// One KMAC case of evpmac_common.txt, read from its stanza.
struct kmac_case {
    bool kmac_128 = true;
    bytes key;
    bytes input;
    bytes customisation;
    bool xof = false;
    std::size_t tag_size = 0;
    std::optional<std::string> output;
    bool refused = false;
};

// The case a stanza names: XOF = 1 or Ctrl = xof:1 for the XOF form; the tag's size from Output,
// else Ctrl = size:N, else OpenSSL's default (KMAC128's 32 bytes, KMAC256's 64); Result for a
// case OpenSSL refuses.
kmac_case read_kmac_case(stanza const& lines) {
    kmac_case read{
        .kmac_128 = value_of(lines, "MAC") == "KMAC128",
        .key = value_bytes(*value_of(lines, "Key")),
        .input = value_bytes(value_of(lines, "Input").value_or("")),
        .customisation = value_bytes(value_of(lines, "Custom").value_or("\"\"")),
        .xof = value_of(lines, "XOF") == "1",
        .tag_size = 0,
        .output = value_of(lines, "Output"),
        .refused = value_of(lines, "Result").has_value(),
    };
    read.tag_size = read.kmac_128 ? 32 : 64;
    for (auto const& control : values_of(lines, "Ctrl")) {
        if (control == "xof:1") {
            read.xof = true;
        } else if (control.starts_with("size:")) {
            read.tag_size = std::stoul(control.substr(5));
        }
    }
    if (read.output) {
        read.tag_size = read.output->size() / 2;
    }
    return read;
}

// The case's tag through mac on OpenSSL.
boost::system::result<void> compute_kmac(kmac_case const& kmac, std::span<std::uint8_t> tag) {
    if (kmac.kmac_128) {
        return hash::mac<macs::kmac_128, openssl>(
            tag, kmac.key, kmac.input, {.customisation = kmac.customisation, .xof = kmac.xof});
    }
    return hash::mac<macs::kmac_256, openssl>(
        tag, kmac.key, kmac.input, {.customisation = kmac.customisation, .xof = kmac.xof});
}

// The case's tag through the second implementation.
bytes reference_kmac(kmac_case const& kmac) {
    return kmac.kmac_128 ? kmac_reference<256>(kmac.key, kmac.input, kmac.customisation,
                                               kmac.tag_size, kmac.xof)
                         : kmac_reference<512>(kmac.key, kmac.input, kmac.customisation,
                                               kmac.tag_size, kmac.xof);
}

// The KMAC cases of evpmac_common.txt: NIST's samples (SP 800-185's KMAC and KMACXOF examples)
// and NIST ACVP's long customisation, fixed-length and XOF. The default provider's 3-byte tags
// are under SP 800-185's 32-bit floor, which mac refuses (invalid_output_size); a customisation
// past 512 bytes and a tag of 2,097,152 bytes are OpenSSL's own limits (unsupported_by_backend);
// the FIPS provider's cases are left out.
void check_kmac_evp_data() {
    std::size_t run = 0;
    std::size_t short_tags = 0;
    std::size_t refused = 0;
    std::size_t fips = 0;
    for (auto const& lines : read_stanzas(WEBCPP_TEST_OPENSSL_EVP_DATA "/evpmac_common.txt")) {
        auto const name = value_of(lines, "MAC");
        if (name != "KMAC128" && name != "KMAC256") {
            continue;
        }
        if (value_of(lines, "Availablein") == "fips") {
            ++fips;
            continue;
        }
        auto const kmac = read_kmac_case(lines);
        bytes tag(kmac.tag_size, 0x5A);
        auto const outcome = compute_kmac(kmac, tag);
        if (kmac.refused) {
            BOOST_TEST(failed_with(outcome, hash::error::unsupported_by_backend));
            BOOST_TEST(all_of(tag, 0x5A));
            ++refused;
            continue;
        }
        if (kmac.tag_size < 4) {
            BOOST_TEST(failed_with(outcome, hash::error::invalid_output_size));
            ++short_tags;
            continue;
        }
        auto const expected = test::to_hex(test::from_hex(*kmac.output));
        if (!BOOST_TEST(outcome.has_value()) || !BOOST_TEST_EQ(test::to_hex(tag), expected)) {
            std::cerr << "  " << *name << ", tag " << kmac.tag_size << ", xof " << kmac.xof << '\n';
        }
        // The second implementation agrees on every published case.
        BOOST_TEST_EQ(test::to_hex(reference_kmac(kmac)), expected);
        ++run;
    }
    // At OpenSSL 3.5.9's pin.
    evp::count_is("evpmac_common.txt", "KMAC stanzas computed", run, 20);
    evp::count_is("evpmac_common.txt", "KMAC stanzas of a short tag", short_tags, 2);
    evp::count_is("evpmac_common.txt", "KMAC stanzas refused", refused, 2);
    evp::count_is("evpmac_common.txt", "KMAC stanzas of the FIPS provider", fips, 6);
}

// KMAC on OpenSSL against the second implementation on random keys of 4 to 512 bytes (OpenSSL's
// limits), customisations of 0 to 512 bytes, inputs, tags of 4 to 300 bytes (past a rate) and both
// forms; and the XOF form's shorter tag the start of its longer, the fixed form's not.
template <class Mac, int Capacity>
void agree_kmac(std::string_view name) {
    test::random_source rnd(test::agreement_seed);
    for (std::size_t index = 0; index < cases; ++index) {
        auto const key = rnd.bytes(index == 0 ? 4 : rnd.between(4, 512));
        auto const custom = index == 0 ? bytes{} : rnd.bytes(rnd.between(0, 512));
        auto const input = next_input(rnd, index);
        std::size_t const tag_size = index == 1 ? 4 : rnd.between(4, 300);
        bool const xof = index % 2 == 1;
        bytes tag(tag_size, 0x5A);
        bool const computed =
            hash::mac<Mac, openssl>(tag, key, input, {.customisation = custom, .xof = xof})
                .has_value();
        auto const expected = kmac_reference<Capacity>(key, input, custom, tag_size, xof);
        if (!BOOST_TEST(computed) || !BOOST_TEST_EQ(test::to_hex(tag), test::to_hex(expected))) {
            std::cerr << "  " << name << ", case " << index << ", key " << key.size()
                      << ", customisation " << custom.size() << ", input " << input.size()
                      << ", tag " << tag_size << ", xof " << xof << '\n';
        }
    }

    std::array<std::uint8_t, 32> const key{};
    std::array<std::uint8_t, 3> const input{0x61, 0x62, 0x63};
    bytes longer(64);
    bytes shorter(32);
    test::require(BOOST_TEST((hash::mac<Mac, openssl>(longer, key, input, {.xof = true}))));
    test::require(BOOST_TEST((hash::mac<Mac, openssl>(shorter, key, input, {.xof = true}))));
    BOOST_TEST(std::ranges::equal(shorter, std::span(longer).first(32)));
    test::require(BOOST_TEST((hash::mac<Mac, openssl>(longer, key, input))));
    test::require(BOOST_TEST((hash::mac<Mac, openssl>(shorter, key, input))));
    BOOST_TEST(!std::ranges::equal(shorter, std::span(longer).first(32)));
}

// OpenSSL's KMAC limits, narrower than SP 800-185's (ruling R41, finding B-M8): a key of 3 or 513
// bytes, a customisation of 513 bytes and a tag of 2,097,152 bytes are unsupported_by_backend, the
// output untouched; 4 and 512 bytes of key, 512 of customisation and 2,097,151 of tag are taken.
// A tag of 3 bytes is under SP 800-185's floor, on every backend (invalid_output_size).
template <class Mac, int Capacity>
void check_kmac_limits() {
    std::array<std::uint8_t, 3> const input{0x61, 0x62, 0x63};
    auto const refused = [&](std::span<std::uint8_t const> key, std::size_t tag_size,
                             std::span<std::uint8_t const> custom) {
        bytes tag(tag_size, 0x5A);
        bool const answered =
            failed_with(hash::mac<Mac, openssl>(tag, key, input, {.customisation = custom}),
                        hash::error::unsupported_by_backend);
        return answered && all_of(tag, 0x5A);
    };
    bytes const key3(3, 0x0b);
    bytes const key4(4, 0x0b);
    bytes const key512(512, 0x0b);
    bytes const key513(513, 0x0b);
    bytes const custom512(512, 0x43);
    bytes const custom513(513, 0x43);
    BOOST_TEST(refused(key3, 32, {}));
    BOOST_TEST(refused(key513, 32, {}));
    BOOST_TEST(refused(key4, 32, custom513));
    BOOST_TEST(refused(key4, 2097152, {}));

    bytes tag(32);
    BOOST_TEST((hash::mac<Mac, openssl>(tag, key4, input, {.customisation = custom512})));
    BOOST_TEST_EQ(test::to_hex(tag),
                  test::to_hex(kmac_reference<Capacity>(key4, input, custom512, 32, false)));
    BOOST_TEST((hash::mac<Mac, openssl>(tag, key512, input)));
    BOOST_TEST_EQ(test::to_hex(tag),
                  test::to_hex(kmac_reference<Capacity>(key512, input, {}, 32, false)));
    bytes longest(2097151);
    BOOST_TEST((hash::mac<Mac, openssl>(longest, key4, input, {.xof = true})));
    auto const expected = kmac_reference<Capacity>(key4, input, {}, 64, true);
    BOOST_TEST(std::ranges::equal(std::span(longest).first(64), expected));

    bytes short_tag(3, 0x5A);
    BOOST_TEST(failed_with(hash::mac<Mac, openssl>(short_tag, key4, input),
                           hash::error::invalid_output_size));
    BOOST_TEST(all_of(short_tag, 0x5A));
}

void check_kmac() {
    check_kmac_evp_data();
    check_wycheproof<macs::kmac_128>("kmac128_no_customization_test.json");
    check_wycheproof<macs::kmac_256>("kmac256_no_customization_test.json");
    agree_kmac<macs::kmac_128, 256>("kmac_128");
    agree_kmac<macs::kmac_256, 512>("kmac_256");
    check_kmac_limits<macs::kmac_128, 256>();
    check_kmac_limits<macs::kmac_256, 512>();
}

// ---- Keyed BLAKE2 ----

// The value after "<name>:\t" on a line of blake2b-kat.txt; a line of another form ends the test.
std::string kat_value(std::string const& line, std::string_view name) {
    std::string const prefix = std::string(name) + ":\t";
    if (!line.starts_with(prefix)) {
        std::cerr << "blake2b-kat.txt: expected " << name << ", read: " << line << '\n';
        std::abort();
    }
    return line.substr(prefix.size());
}

// Every case of BLAKE2's testvectors/blake2b-kat.txt (ruling R45), the keyed BLAKE2b: a 64-byte
// key, inputs of 0 to 255 bytes, a 64-byte tag.
void check_blake2b_kat() {
    auto const lines = read_lines(WEBCPP_TEST_BLAKE2_VECTORS "/blake2b-kat.txt");
    std::size_t run = 0;
    for (std::size_t index = 0; index + 2 < lines.size(); ++index) {
        if (!lines[index].starts_with("in:")) {
            continue;
        }
        auto const input = test::from_hex(kat_value(lines[index], "in"));
        auto const key = test::from_hex(kat_value(lines[index + 1], "key"));
        auto const expected = kat_value(lines[index + 2], "hash");
        bytes tag(64);
        BOOST_TEST((hash::mac<macs::blake2b_mac, openssl>(tag, key, input)));
        if (!BOOST_TEST_EQ(test::to_hex(tag), expected)) {
            std::cerr << "  blake2b-kat.txt, input " << input.size() << '\n';
        }
        index += 2;
        ++run;
    }
    BOOST_TEST_EQ(run, 256U);
}

// Every keyed BLAKE2s case of BLAKE2's testvectors/blake2-kat.json (ruling R45): a 32-byte key,
// inputs of 0 to 255 bytes, a 32-byte tag.
void check_blake2s_kat() {
    boost::system::error_code ec;
    auto const doc = json::parse(read_text(WEBCPP_TEST_BLAKE2_VECTORS "/blake2-kat.json"), ec);
    test::require(BOOST_TEST(!ec));
    std::size_t run = 0;
    for (auto const& entry : doc.as_array()) {
        auto const& vector = entry.as_object();
        if (vector.at("hash").as_string() != "blake2s" || vector.at("key").as_string().empty()) {
            continue;
        }
        auto const key = test::from_hex(vector.at("key").as_string());
        auto const input = test::from_hex(vector.at("in").as_string());
        bytes tag(32);
        BOOST_TEST((hash::mac<macs::blake2s_mac, openssl>(tag, key, input)));
        if (!BOOST_TEST_EQ(test::to_hex(tag), vector.at("out").as_string())) {
            std::cerr << "  blake2-kat.json, blake2s, input " << input.size() << '\n';
        }
        ++run;
    }
    BOOST_TEST_EQ(run, 256U);
}

// The keyed BLAKE2 cases of OpenSSL's evpmac_blake.txt that mac computes: neither salt nor
// personalisation (mac_options of macs::blake2b_mac and blake2s_mac have none), at every tag size
// the file gives (OutputSize, or Ctrl = size:N); the others are counted, not run.
void check_blake2_evp_data() {
    std::size_t blake2b_run = 0;
    std::size_t blake2s_run = 0;
    std::size_t skipped = 0;
    for (auto const& lines : read_stanzas(WEBCPP_TEST_OPENSSL_EVP_DATA "/evpmac_blake.txt")) {
        auto const name = value_of(lines, "MAC");
        if (!name || (*name != "BLAKE2BMAC" && *name != "BLAKE2SMAC")) {
            continue;
        }
        auto const output = value_of(lines, "Output");
        if (value_of(lines, "Salt") || value_of(lines, "Custom") || value_of(lines, "Result") ||
            !output) {
            ++skipped;
            continue;
        }
        auto const key = value_bytes(*value_of(lines, "Key"));
        auto const input = value_bytes(value_of(lines, "Input").value_or(""));
        bytes tag(output->size() / 2);
        bool const computed =
            *name == "BLAKE2BMAC"
                ? hash::mac<macs::blake2b_mac, openssl>(tag, key, input).has_value()
                : hash::mac<macs::blake2s_mac, openssl>(tag, key, input).has_value();
        if (!BOOST_TEST(computed) ||
            !BOOST_TEST_EQ(test::to_hex(tag), test::to_hex(test::from_hex(*output)))) {
            std::cerr << "  evpmac_blake.txt, " << *name << ", key " << key.size() << ", tag "
                      << tag.size() << '\n';
        }
        ++(*name == "BLAKE2BMAC" ? blake2b_run : blake2s_run);
    }
    // At OpenSSL 3.5.9's pin.
    evp::count_is("evpmac_blake.txt", "BLAKE2BMAC stanzas computed", blake2b_run, 14);
    evp::count_is("evpmac_blake.txt", "BLAKE2SMAC stanzas computed", blake2s_run, 13);
    evp::count_is("evpmac_blake.txt", "stanzas left out", skipped, 14);
}

// Keyed BLAKE2b on OpenSSL against digests::blake2b keyed on backends::sodium at every tag size
// from 1 to 64 bytes, random keys of 1 to 64 bytes; keyed BLAKE2s against Boost.Hash2's keyed
// blake2s_256 (backends::hash2's cell, 32-byte tags), random keys of 1 to 32 bytes.
void agree_blake2() {
    test::random_source rnd(test::agreement_seed);
    for (std::size_t index = 0; index < cases; ++index) {
        auto const key = rnd.bytes(rnd.between(1, 64));
        auto const input = next_input(rnd, index);
        std::size_t const tag_size = 1 + (index % 64);
        bytes tag(tag_size);
        bytes expected(tag_size);
        bool const computed = hash::mac<macs::blake2b_mac, openssl>(tag, key, input).has_value();
        bool const oracle = hash::digest_of<digests::blake2b, hash::backends::sodium>(
                                expected, input, {.key = key, .output_size = tag_size})
                                .has_value();
        if (!BOOST_TEST(computed && oracle) ||
            !BOOST_TEST_EQ(test::to_hex(tag), test::to_hex(expected))) {
            std::cerr << "  blake2b_mac, case " << index << ", key " << key.size() << ", tag "
                      << tag_size << '\n';
        }
    }
    for (std::size_t index = 0; index < cases; ++index) {
        auto const key = rnd.bytes(rnd.between(1, 32));
        auto const input = next_input(rnd, index);
        bytes tag(32);
        bytes expected(32);
        bool const computed = hash::mac<macs::blake2s_mac, openssl>(tag, key, input).has_value();
        bool const oracle =
            hash::mac<macs::blake2s_mac, hash::backends::hash2>(expected, key, input).has_value();
        if (!BOOST_TEST(computed && oracle) ||
            !BOOST_TEST_EQ(test::to_hex(tag), test::to_hex(expected))) {
            std::cerr << "  blake2s_mac, case " << index << ", key " << key.size() << '\n';
        }
    }

    // The family's guards: an empty key, which OpenSSL's BLAKE2 MACs refuse too, and a key or a
    // tag past the hash's, are invalid on every backend.
    std::array<std::uint8_t, 3> const input{0x61, 0x62, 0x63};
    bytes tag(32, 0x5A);
    BOOST_TEST(failed_with(hash::mac<macs::blake2b_mac, openssl>(tag, {}, input),
                           hash::error::invalid_key_size));
    BOOST_TEST(failed_with(hash::mac<macs::blake2s_mac, openssl>(tag, {}, input),
                           hash::error::invalid_key_size));
    bytes const key33(33, 0x0b);
    BOOST_TEST(failed_with(hash::mac<macs::blake2s_mac, openssl>(tag, key33, input),
                           hash::error::invalid_key_size));
    bytes long_tag(65, 0x5A);
    BOOST_TEST(failed_with(hash::mac<macs::blake2b_mac, openssl>(long_tag, key33, input),
                           hash::error::invalid_output_size));
    BOOST_TEST(all_of(tag, 0x5A));
    BOOST_TEST(all_of(long_tag, 0x5A));
}

void check_blake2() {
    check_blake2b_kat();
    check_blake2s_kat();
    check_blake2_evp_data();
    agree_blake2();
}

// ---- SipHash ----

// The tag size of a SipHash stanza of evpmac_siphash.txt when it is SipHash-2-4 that mac computes:
// 16 by default (Ctrl = size:0 too), or 8; 0 for other rounds, another size or an expected
// failure.
std::size_t siphash_2_4_size(stanza const& lines) {
    if (value_of(lines, "Result")) {
        return 0;
    }
    std::size_t tag_size = 16;
    for (auto const& control : values_of(lines, "Ctrl")) {
        if (control.starts_with("size:")) {
            auto const size = std::stoul(control.substr(5));
            tag_size = size == 0 ? 16 : size;
        } else if (control != "c-rounds:2" && control != "d-rounds:4") {
            return 0;
        }
    }
    return tag_size == 8 || tag_size == 16 ? tag_size : 0;
}

// The SipHash cases of OpenSSL's evpmac_siphash.txt that are SipHash-2-4: a 16-byte tag by
// default (macs::siphash_2_4x), an 8-byte one with Ctrl = size:8 (macs::siphash_2_4); other
// rounds, sizes and the EVP_PKEY cases are counted, not run.
void check_siphash_evp_data() {
    std::size_t run_8 = 0;
    std::size_t run_16 = 0;
    std::size_t skipped = 0;
    for (auto const& lines : read_stanzas(WEBCPP_TEST_OPENSSL_EVP_DATA "/evpmac_siphash.txt")) {
        if (value_of(lines, "MAC") != "SipHash") {
            continue;
        }
        std::size_t const tag_size = siphash_2_4_size(lines);
        if (tag_size == 0) {
            ++skipped;
            continue;
        }
        auto const key = value_bytes(*value_of(lines, "Key"));
        auto const input = value_bytes(value_of(lines, "Input").value_or(""));
        auto const expected = test::to_hex(test::from_hex(*value_of(lines, "Output")));
        bytes tag(tag_size);
        bool const computed =
            tag_size == 8 ? hash::mac<macs::siphash_2_4, openssl>(tag, key, input).has_value()
                          : hash::mac<macs::siphash_2_4x, openssl>(tag, key, input).has_value();
        if (!BOOST_TEST(computed) || !BOOST_TEST_EQ(test::to_hex(tag), expected)) {
            std::cerr << "  evpmac_siphash.txt, tag " << tag_size << ", input " << input.size()
                      << '\n';
        }
        ++(tag_size == 8 ? run_8 : run_16);
    }
    // At OpenSSL 3.5.9's pin.
    evp::count_is("evpmac_siphash.txt", "SipHash-2-4 stanzas computed", run_8, 1);
    evp::count_is("evpmac_siphash.txt", "SipHash-2-4x stanzas computed", run_16, 24);
    evp::count_is("evpmac_siphash.txt", "stanzas left out", skipped, 2);
}

// SipHash-2-4 on OpenSSL against backends::hash2 and backends::sodium, SipHash-2-4x against
// backends::sodium, on random keys and inputs.
void agree_siphash() {
    test::random_source rnd(test::agreement_seed);
    for (std::size_t index = 0; index < cases; ++index) {
        auto const key = rnd.bytes(16);
        auto const input = next_input(rnd, index);
        bytes tag(8);
        bytes by_hash2(8);
        bytes by_sodium(8);
        bool const computed =
            hash::mac<macs::siphash_2_4, openssl>(tag, key, input).has_value() &&
            hash::mac<macs::siphash_2_4, hash::backends::hash2>(by_hash2, key, input) &&
            hash::mac<macs::siphash_2_4, hash::backends::sodium>(by_sodium, key, input);
        if (!BOOST_TEST(computed) || !BOOST_TEST_EQ(test::to_hex(tag), test::to_hex(by_hash2)) ||
            !BOOST_TEST_EQ(test::to_hex(tag), test::to_hex(by_sodium))) {
            std::cerr << "  siphash_2_4, case " << index << '\n';
        }
        bytes wide(16);
        bytes wide_sodium(16);
        bool const wide_computed =
            hash::mac<macs::siphash_2_4x, openssl>(wide, key, input).has_value() &&
            hash::mac<macs::siphash_2_4x, hash::backends::sodium>(wide_sodium, key, input);
        if (!BOOST_TEST(wide_computed) ||
            !BOOST_TEST_EQ(test::to_hex(wide), test::to_hex(wide_sodium))) {
            std::cerr << "  siphash_2_4x, case " << index << '\n';
        }
    }
}

void check_siphash() {
    check_wycheproof<macs::siphash_2_4>("siphash_2_4_test.json");
    check_wycheproof<macs::siphash_2_4x>("siphashx_2_4_test.json");
    check_siphash_evp_data();
    agree_siphash();
}

// Every tag of this test is a cell of backends::openssl, and never its default (design D34).
template <class Mac>
constexpr bool in_openssl_never_default =
    hash::backend_has_v<openssl, Mac, void> && !std::is_same_v<hash::default_backend<Mac>, openssl>;

static_assert(in_openssl_never_default<macs::hmac<digests::md5>> &&
              in_openssl_never_default<macs::hmac<digests::sha1>> &&
              in_openssl_never_default<macs::hmac<digests::sha2_224>> &&
              in_openssl_never_default<macs::hmac<digests::sha2_256>> &&
              in_openssl_never_default<macs::hmac<digests::sha2_384>> &&
              in_openssl_never_default<macs::hmac<digests::sha2_512>> &&
              in_openssl_never_default<macs::hmac<digests::sha2_512_224>> &&
              in_openssl_never_default<macs::hmac<digests::sha2_512_256>> &&
              in_openssl_never_default<macs::hmac<digests::sha3_224>> &&
              in_openssl_never_default<macs::hmac<digests::sha3_256>> &&
              in_openssl_never_default<macs::hmac<digests::sha3_384>> &&
              in_openssl_never_default<macs::hmac<digests::sha3_512>> &&
              in_openssl_never_default<macs::hmac<digests::keccak_224>> &&
              in_openssl_never_default<macs::hmac<digests::keccak_256>> &&
              in_openssl_never_default<macs::hmac<digests::keccak_384>> &&
              in_openssl_never_default<macs::hmac<digests::keccak_512>> &&
              in_openssl_never_default<macs::hmac<digests::ripemd_160>> &&
              in_openssl_never_default<macs::hmac<digests::blake2b>> &&
              in_openssl_never_default<macs::hmac<digests::blake2s_256>> &&
              in_openssl_never_default<macs::hmac<digests::sm3>> &&
              in_openssl_never_default<macs::kmac_128> &&
              in_openssl_never_default<macs::kmac_256> &&
              in_openssl_never_default<macs::siphash_2_4> &&
              in_openssl_never_default<macs::siphash_2_4x> &&
              in_openssl_never_default<macs::blake2b_mac> &&
              in_openssl_never_default<macs::blake2s_mac>);
// No HMAC over an extendable-output function, none over a digest OpenSSL lacks, and none over
// MD5-SHA1, which OpenSSL has as a digest but no standard defines an HMAC over.
static_assert(!hash::backend_has_v<openssl, macs::hmac<digests::shake_128>, void>);
static_assert(!hash::backend_has_v<openssl, macs::hmac<digests::whirlpool>, void>);
static_assert(!hash::backend_has_v<openssl, macs::hmac<digests::md5_sha1>, void>);
// The HMACs Boost.Hash2 lacks have no default.
static_assert(std::is_same_v<hash::default_backend<macs::hmac<digests::keccak_256>>,
                             hash::detail::no_default>);
static_assert(
    std::is_same_v<hash::default_backend<macs::hmac<digests::sm3>>, hash::detail::no_default>);
static_assert(
    std::is_same_v<hash::default_backend<macs::hmac<digests::md5_sha1>>, hash::detail::no_default>);

}  // namespace

int main() {
    check_hmac();
    check_kmac();
    check_blake2();
    check_siphash();
    return webcpp::test::exit_status(boost::report_errors());
}
