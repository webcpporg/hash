// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// HKDF on backends::hash2: RFC 5869's seven cases through hkdf_extract, hkdf_expand and hkdf, and
// three cases over hmacs the RFC does not cover (SHA3-256, BLAKE2b, RIPEMD-160), computed by an
// independent implementation, Python's hmac over hashlib (spec section 1.3, the first departure).

#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/ripemd.hpp>

#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/rfc5869.hpp"

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

// The three functions on one case, over Hmac on Backend; `salt` is the case's own or another
// spelling of it.
template <class Hmac, class Backend>
void check(const rfc5869_case& c, std::span<std::uint8_t const> salt) {
    const auto ikm = from_hex(c.ikm);
    const auto info = from_hex(c.info);

    auto prk = hash::hkdf_extract<Hmac, Backend>(salt, ikm);
    if (!BOOST_TEST(prk.has_value())) {
        return;
    }
    BOOST_TEST_EQ(to_hex(std::span<std::uint8_t const>(prk->data(), prk->size())),
                  std::string(c.prk));

    std::vector<std::uint8_t> okm(c.length);
    const auto expanded = hash::hkdf_expand<Hmac, Backend>(
        okm, std::span<std::uint8_t const>(prk->data(), prk->size()), info);
    BOOST_TEST(expanded.has_value());
    BOOST_TEST_EQ(to_hex(okm), std::string(c.okm));

    std::vector<std::uint8_t> together(c.length);
    const auto derived = hash::hkdf<Hmac, Backend>(together, salt, ikm, info);
    BOOST_TEST(derived.has_value());
    BOOST_TEST_EQ(to_hex(together), std::string(c.okm));
}

template <class Hmac>
void check(const rfc5869_case& c) {
    const auto salt = from_hex(c.salt);
    check<Hmac, hash::backends::hash2>(c, salt);
}

// Three cases over hmacs RFC 5869 has none for, written by tools outside webcpp and Boost.Hash2:
// Python 3.15.2's hmac over hashlib.sha3_256, hashlib.blake2b and hashlib.new('ripemd160')
// (OpenSSL 4.1.0's), RFC 5869's two steps over hmac.new; the script and its output are in the
// stream's report. SHA3-256's salt is longer than its block (136 bytes), so the hmac hashes it;
// BLAKE2b's is empty; each output ends inside a block.
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
    check<hash::hmac_sha1_160, hash::backends::hash2>(a7, zeros);

    check<hash::hmac_sha3_256>(sha3_256_case);
    check<hash::hmac_blake2b_512>(blake2b_512_case);
    check<boost::hash2::hmac<boost::hash2::ripemd_160>>(ripemd_160_case);

    // The default backend of a program that links no other backend is backends::hash2.
    static_assert(
        std::is_same_v<hash::default_kdf_backend<hash::hmac_sha2_256>, hash::backends::hash2>);
    const auto salt = from_hex(a1.salt);
    const auto ikm = from_hex(a1.ikm);
    const auto info = from_hex(a1.info);
    std::vector<std::uint8_t> okm(a1.length);
    BOOST_TEST(hash::hkdf<hash::hmac_sha2_256>(okm, salt, ikm, info).has_value());
    BOOST_TEST_EQ(to_hex(okm), std::string(a1.okm));

    return webcpp::test::exit_status(boost::report_errors());
}
