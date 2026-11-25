// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// HKDF on backends::openssl (OpenSSL 3.5.9's EVP_KDF "HKDF"): RFC 5869's seven cases and the three
// cases of hkdf_hash2_test.cpp over SHA3-256, BLAKE2b and RIPEMD-160 through hkdf_extract,
// hkdf_expand and hkdf; every hmac of spec 3.2's OpenSSL column against backends::hash2, the empty
// inputs and the longest output among the shapes; the info of 32,768 bytes through OpenSSL and of
// 32,769 refused before it; and the default backend. It includes hkdf.hpp alone, which brings
// backends/openssl.hpp in when the program links OpenSSL.

#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>

#include <boost/core/lightweight_test.hpp>

#include <webcpp/test/exit_status.hpp>

#include "support/defaults.hpp"
#include "support/hex.hpp"
#include "support/rfc5869.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

namespace hash = webcpp::hash;
using webcpp::test::from_hex;
using webcpp::test::rfc5869_case;
using webcpp::test::to_hex;

namespace {

using hash::backends::hash2;
using hash::backends::openssl;

template <class Hmac>
constexpr std::size_t digest_size = typename Hmac::result_type().size();

std::span<std::uint8_t const> view(const typename hash::hmac_sha2_256::result_type& d) {
    return {d.data(), d.size()};
}

// The three functions on one case, over Hmac on OpenSSL; `salt` is the case's own or another
// spelling of it.
template <class Hmac>
void check(const rfc5869_case& c, std::span<std::uint8_t const> salt) {
    const auto ikm = from_hex(c.ikm);
    const auto info = from_hex(c.info);

    auto prk = hash::hkdf_extract<Hmac, openssl>(salt, ikm);
    if (!BOOST_TEST(prk.has_value())) {
        return;
    }
    const std::span<std::uint8_t const> key(prk->data(), prk->size());
    BOOST_TEST_EQ(to_hex(key), std::string(c.prk));

    std::vector<std::uint8_t> okm(c.length);
    BOOST_TEST((hash::hkdf_expand<Hmac, openssl>(okm, key, info).has_value()));
    BOOST_TEST_EQ(to_hex(okm), std::string(c.okm));

    std::vector<std::uint8_t> together(c.length);
    BOOST_TEST((hash::hkdf<Hmac, openssl>(together, salt, ikm, info).has_value()));
    BOOST_TEST_EQ(to_hex(together), std::string(c.okm));
}

template <class Hmac>
void check(const rfc5869_case& c) {
    const auto salt = from_hex(c.salt);
    check<Hmac>(c, salt);
}

// The three cases of hkdf_hash2_test.cpp over hmacs RFC 5869 has none for, computed there by
// Python's hmac over hashlib (Task 9's report records the script); the values are that file's.
constexpr rfc5869_case sha3_256_case{
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

constexpr rfc5869_case blake2b_512_case{
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

constexpr rfc5869_case ripemd_160_case{
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

// Bytes of a fixed pattern, different for each `seed`.
std::vector<std::uint8_t> pattern(std::size_t size, unsigned seed) {
    std::vector<std::uint8_t> bytes(size);
    for (std::size_t i = 0; i < size; ++i) {
        bytes[i] = static_cast<std::uint8_t>((i * 131U) + (std::size_t{seed} * 29U) + 7U);
    }
    return bytes;
}

// One shape of inputs: the sizes of salt, IKM and info, and the output in bytes, or (0) the
// longest, 255 digests.
struct shape {
    std::size_t salt;
    std::size_t ikm;
    std::size_t info;
    std::size_t output;
};

// OpenSSL and backends::hash2 agree on the three functions over Hmac, for every shape.
template <class Hmac>
void agree() {
    constexpr std::size_t size = digest_size<Hmac>;
    for (const shape s : {
             shape{.salt = 0, .ikm = 0, .info = 0, .output = 1},
             shape{.salt = 13, .ikm = 22, .info = 10, .output = 42},
             shape{.salt = 0, .ikm = 1, .info = 0, .output = size},
             shape{.salt = 200, .ikm = 80, .info = 300, .output = (3 * size) + 5},
             shape{.salt = 1, .ikm = 300, .info = 255, .output = 0},
         }) {
        const auto salt = pattern(s.salt, 1);
        const auto ikm = pattern(s.ikm, 2);
        const auto info = pattern(s.info, 3);
        const std::size_t length = s.output != 0 ? s.output : 255 * size;

        auto ours = hash::hkdf_extract<Hmac, openssl>(salt, ikm);
        auto theirs = hash::hkdf_extract<Hmac, hash2>(salt, ikm);
        if (!BOOST_TEST(ours.has_value() && theirs.has_value())) {
            return;
        }
        BOOST_TEST(*ours == *theirs);
        const std::span<std::uint8_t const> prk(theirs->data(), theirs->size());

        std::vector<std::uint8_t> expected(length);
        BOOST_TEST((hash::hkdf_expand<Hmac, hash2>(expected, prk, info).has_value()));
        std::vector<std::uint8_t> expanded(length);
        BOOST_TEST((hash::hkdf_expand<Hmac, openssl>(expanded, prk, info).has_value()));
        BOOST_TEST(expanded == expected);
        std::vector<std::uint8_t> together(length);
        BOOST_TEST((hash::hkdf<Hmac, openssl>(together, salt, ikm, info).has_value()));
        BOOST_TEST(together == expected);
    }
}

template <class... Hmacs>
void agree_on() {
    (agree<Hmacs>(), ...);
}

constexpr std::uint8_t untouched = 0xaa;

bool is_untouched(std::span<std::uint8_t const> bytes) {
    return std::ranges::all_of(bytes, [](std::uint8_t b) { return b == untouched; });
}

// The info of hkdf_max_application_info_size bytes reaches OpenSSL and agrees with backends::hash2.
void longest_info() {
    using hmac = hash::hmac_sha2_256;
    const auto ikm = pattern(22, 2);
    const auto prk = pattern(32, 4);
    const auto info = pattern(hash::hkdf_max_application_info_size, 3);
    std::vector<std::uint8_t> expected(42);
    BOOST_TEST((hash::hkdf_expand<hmac, hash2>(expected, prk, info).has_value()));
    std::vector<std::uint8_t> expanded(42, untouched);
    BOOST_TEST((hash::hkdf_expand<hmac, openssl>(expanded, prk, info).has_value()));
    BOOST_TEST(expanded == expected);

    std::vector<std::uint8_t> theirs(42);
    BOOST_TEST((hash::hkdf<hmac, hash2>(theirs, prk, ikm, info).has_value()));
    std::vector<std::uint8_t> together(42, untouched);
    BOOST_TEST((hash::hkdf<hmac, openssl>(together, prk, ikm, info).has_value()));
    BOOST_TEST(together == theirs);
}

// One byte more is refused by the guard, before OpenSSL, the output untouched.
void info_too_long() {
    using hmac = hash::hmac_sha2_256;
    const auto ikm = pattern(22, 2);
    const auto prk = pattern(32, 4);
    const auto info = pattern(hash::hkdf_max_application_info_size + 1, 3);
    std::vector<std::uint8_t> output(42, untouched);
    auto refused = hash::hkdf_expand<hmac, openssl>(output, prk, info);
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::input_too_long);
    BOOST_TEST(is_untouched(output));
    refused = hash::hkdf<hmac, openssl>(output, prk, ikm, info);
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::input_too_long);
    BOOST_TEST(is_untouched(output));
}

}  // namespace

int main() {
    using webcpp::test::a1;
    using webcpp::test::a2;
    using webcpp::test::a3;
    using webcpp::test::a4;
    using webcpp::test::a5;
    using webcpp::test::a6;
    using webcpp::test::a7;

    check<hash::hmac_sha2_256>(a1);
    check<hash::hmac_sha2_256>(a2);
    check<hash::hmac_sha2_256>(a3);
    check<hash::hmac_sha1_160>(a4);
    check<hash::hmac_sha1_160>(a5);
    check<hash::hmac_sha1_160>(a6);
    check<hash::hmac_sha1_160>(a7);
    // A.7's salt not provided, spelled as RFC 5869 2.2 defines it: HashLen (20) zero octets.
    const std::vector<std::uint8_t> zeros(20, 0);
    check<hash::hmac_sha1_160>(a7, zeros);

    check<hash::hmac_sha3_256>(sha3_256_case);
    check<hash::hmac_blake2b_512>(blake2b_512_case);
    check<hash::hmac_ripemd_160>(ripemd_160_case);

    agree_on<hash::hmac_md5_128, hash::hmac_sha1_160, hash::hmac_sha2_224, hash::hmac_sha2_256,
             hash::hmac_sha2_384, hash::hmac_sha2_512, hash::hmac_sha2_512_224,
             hash::hmac_sha2_512_256, hash::hmac_sha3_224, hash::hmac_sha3_256, hash::hmac_sha3_384,
             hash::hmac_sha3_512, hash::hmac_ripemd_160, hash::hmac_blake2b_512,
             hash::hmac_blake2s_256>();
    longest_info();
    info_too_long();

    // The default backend of a program that links OpenSSL is still backends::hash2 for each
    // operation: OpenSSL is reached only by naming it (spec 4.1).
    webcpp::test::for_each_kdf_cell([]<class Operation, class Hmac> {
        webcpp::test::expect_default<Operation, Hmac>("hash2");
    });
    // hmac_ripemd_128, which OpenSSL lacks, defaults to backends::hash2 on every target.
    static_assert(std::is_same_v<hash::default_kdf_backend<hash::hmac_ripemd_128>, hash2>);
    auto prk = hash::hkdf_extract<hash::hmac_sha2_256>(from_hex(a1.salt), from_hex(a1.ikm));
    if (BOOST_TEST(prk.has_value())) {
        BOOST_TEST_EQ(to_hex(view(*prk)), std::string(a1.prk));
    }

    return webcpp::test::exit_status(boost::report_errors());
}
