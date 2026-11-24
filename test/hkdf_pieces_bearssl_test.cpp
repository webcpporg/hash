// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// HKDF over pieces on backends::bearssl (design D2, D4, D8 of the change hkdf-pieces), over
// BearSSL's br_hmac_key_init, br_hmac_init, br_hmac_update and br_hmac_out: hkdf_extract,
// hkdf_expand and hkdf over byte_pieces give the bytes of backends::hash2's single-buffer forms on
// the concatenation (and of BearSSL's own hkdf), with RFC 5869's cases, random splits, empty pieces
// and lists, many pieces and long inputs, and refuse only RFC 5869's sizes
// (support/hkdf_pieces.hpp), over BearSSL's six hmacs, MD5, SHA-1 and SHA-224 to SHA-512. BearSSL
// gains Extract and Expand over pieces, while its single-buffer hkdf_extract and hkdf_expand stay
// refused (test/messages/extract_on_bearssl and expand_on_bearssl): the spec's scenario
// hkdf_extract<hmac_sha2_256, backends::bearssl>(salt, {a, b}). Each step wipes BearSSL's HMAC
// contexts, its key contexts, every block T(i) and the pseudorandom key between the steps,
// reported through the seam WEBCPP_HASH_DETAIL_TEST_WIPE_RECORD; a guard's refusal wipes nothing.
// Built again as hkdf_pieces_bearssl_sliced with the test seam
// WEBCPP_HASH_DETAIL_TEST_HKDF_PIECES_SLICE, which makes the engine feed every piece to BearSSL in
// slices of a few bytes (Review Focus 4), over hmac_sha2_256: the bytes are the same, 1 MiB pieces
// included.

#include "support/hkdf_pieces.hpp"

#include <webcpp/hash/backends/bearssl.hpp>
#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/byte_pieces.hpp>
#include <webcpp/hash/config.hpp>
#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/kdf.hpp>

#include <boost/core/lightweight_test.hpp>

#include <webcpp/test/exit_status.hpp>

#include <bearssl_hmac.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <vector>

#ifndef WEBCPP_HASH_DETAIL_TEST_WIPE_RECORD
#error "hkdf_pieces_bearssl_test is built with WEBCPP_HASH_DETAIL_TEST_WIPE_RECORD (test/Jamfile)"
#endif

namespace hash = webcpp::hash;
namespace test = webcpp::test;

namespace {

using hash::backends::bearssl;

// The pieces cells are BearSSL's HMAC cells, its six hmacs, for all three forms: Extract and
// Expand over pieces included, while the single-buffer Extract and Expand stay refused.
template <class Hmac>
constexpr bool has_pieces = hash::backend_has_v<bearssl, hash::kdfs::hkdf_pieces, Hmac> &&
                            hash::backend_has_v<bearssl, hash::kdfs::hkdf_extract_pieces, Hmac> &&
                            hash::backend_has_v<bearssl, hash::kdfs::hkdf_expand_pieces, Hmac>;
static_assert(has_pieces<hash::hmac_md5_128>);
static_assert(has_pieces<hash::hmac_sha1_160>);
static_assert(has_pieces<hash::hmac_sha2_224>);
static_assert(has_pieces<hash::hmac_sha2_256>);
static_assert(has_pieces<hash::hmac_sha2_384>);
static_assert(has_pieces<hash::hmac_sha2_512>);
static_assert(!hash::backend_has_v<bearssl, hash::kdfs::hkdf_pieces, hash::hmac_sha2_512_256>);
static_assert(!hash::backend_has_v<bearssl, hash::kdfs::hkdf_extract_pieces, hash::hmac_sha3_256>);
static_assert(!hash::backend_has_v<bearssl, hash::kdfs::hkdf_expand_pieces, hash::hmac_ripemd_160>);
static_assert(!hash::backend_has_v<bearssl, hash::kdfs::hkdf_extract, hash::hmac_sha2_256>);
static_assert(!hash::backend_has_v<bearssl, hash::kdfs::hkdf_expand, hash::hmac_sha2_256>);

// The wipes since the last clear: their sizes in order (the first ones), how many, and how many
// found a byte that was not zero. Fixed storage: the seam is noexcept and allocates nothing.
struct record {
    std::array<std::size_t, 16> sizes{};
    std::size_t count = 0;
    std::size_t not_zero = 0;
};

// The seam's record, which detail::wipe reaches through a function of this test.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the seam's record
record wipes;

// The sizes of the wipes since the last call, which clears the record.
std::vector<std::size_t> taken() {
    std::vector<std::size_t> const sizes(
        wipes.sizes.begin(), wipes.sizes.begin() + static_cast<std::ptrdiff_t>(
                                                       std::min(wipes.count, wipes.sizes.size())));
    BOOST_TEST_EQ(wipes.not_zero, 0U);
    wipes = {};
    return sizes;
}

// The spec's scenario "BearSSL's Extract over pieces": hkdf_extract over {a, b} on BearSSL compiles
// and gives backends::hash2's pseudorandom key of a's and b's bytes.
void check_extract_scenario() {
    std::vector<std::uint8_t> const salt{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    std::vector<std::uint8_t> const a{0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    std::vector<std::uint8_t> const b{0x0c, 0x0c, 0x0c};
    auto const by_bearssl = hash::hkdf_extract<hash::hmac_sha2_256, bearssl>(salt, {a, b});
    std::vector<std::uint8_t> joined = a;
    joined.insert(joined.end(), b.begin(), b.end());
    auto const by_hash2 =
        hash::hkdf_extract<hash::hmac_sha2_256, hash::backends::hash2>(salt, joined);
    BOOST_TEST(by_bearssl.has_value());
    BOOST_TEST(by_hash2.has_value());
    if (by_bearssl && by_hash2) {
        BOOST_TEST(std::ranges::equal(*by_bearssl, *by_hash2));
    }
    static_cast<void>(taken());
}

// The wipes of the three steps over Hmac, with an output of two blocks: Extract wipes its HMAC
// context and its key context; Expand each block's HMAC context, then T and the key context of the
// PRK; hkdf both, then the PRK. A guard's refusal wipes nothing.
template <class Hmac>
void check_wipes() {
    constexpr std::size_t mac = sizeof(br_hmac_context);
    constexpr std::size_t key = sizeof(br_hmac_key_context);
    constexpr std::size_t digest = typename Hmac::result_type().size();
    using piece = std::span<std::uint8_t const>;
    std::vector<std::uint8_t> const salt(13, 0x01);
    std::vector<std::uint8_t> const ikm(22, 0x0b);
    std::vector<std::uint8_t> const info(10, 0xf0);
    std::array<piece, 3> const ikm_pieces{piece(ikm).first(5), piece{}, piece(ikm).subspan(5)};
    std::array<piece, 2> const info_pieces{piece(info).first(3), piece(info).subspan(3)};
    std::vector<std::uint8_t> output(digest + 10);
    static_cast<void>(taken());

    auto const prk = hash::hkdf_extract<Hmac, bearssl>(salt, ikm_pieces);
    BOOST_TEST(prk.has_value());
    BOOST_TEST((taken() == std::vector<std::size_t>{mac, key}));

    std::vector<std::uint8_t> const pseudorandom_key(prk->begin(), prk->end());
    BOOST_TEST(
        (hash::hkdf_expand<Hmac, bearssl>(output, pseudorandom_key, info_pieces).has_value()));
    BOOST_TEST((taken() == std::vector<std::size_t>{mac, mac, digest, key}));

    BOOST_TEST((hash::hkdf<Hmac, bearssl>(output, salt, ikm_pieces, info_pieces).has_value()));
    BOOST_TEST((taken() == std::vector<std::size_t>{mac, key, mac, mac, digest, key, digest}));

    BOOST_TEST((hash::hkdf_expand<Hmac, bearssl>(output, salt, info_pieces).has_error()));
    BOOST_TEST((hash::hkdf<Hmac, bearssl>(std::span<std::uint8_t>{}, salt, ikm_pieces, info_pieces)
                    .has_error()));
    BOOST_TEST(taken().empty());
}

}  // namespace

void webcpp::hash::detail::test::wipe_record(void const* wiped_data,
                                             std::size_t byte_count) noexcept {
    auto const* const bytes = static_cast<unsigned char const*>(wiped_data);
    if (wipes.count < wipes.sizes.size()) {
        wipes.sizes.at(wipes.count) = byte_count;
    }
    ++wipes.count;
    if (!std::all_of(bytes, bytes + byte_count, [](unsigned char b) { return b == 0; })) {
        ++wipes.not_zero;
    }
}

int main() {
    std::cout << "backends::bearssl feeds its HMAC slices of at most "
              << hash::detail::hkdf_pieces_slice<bearssl> << " bytes\n";
    check_extract_scenario();
#ifdef WEBCPP_HASH_DETAIL_TEST_HKDF_PIECES_SLICE
    // The slicing is the engine's, whatever the hmac.
    BOOST_TEST_EQ(hash::detail::hkdf_pieces_slice<bearssl>,
                  std::uint64_t{WEBCPP_HASH_DETAIL_TEST_HKDF_PIECES_SLICE});
    test::check_hkdf_pieces<hash::hmac_sha2_256, bearssl>("bearssl");
#else
    test::check_hkdf_pieces<hash::hmac_md5_128, bearssl>("bearssl");
    test::check_hkdf_pieces<hash::hmac_sha1_160, bearssl>("bearssl");
    test::check_hkdf_pieces<hash::hmac_sha2_224, bearssl>("bearssl");
    test::check_hkdf_pieces<hash::hmac_sha2_256, bearssl>("bearssl");
    test::check_hkdf_pieces<hash::hmac_sha2_384, bearssl>("bearssl");
    test::check_hkdf_pieces<hash::hmac_sha2_512, bearssl>("bearssl");
#endif
    check_wipes<hash::hmac_md5_128>();
    check_wipes<hash::hmac_sha2_256>();
    check_wipes<hash::hmac_sha2_512>();
    return webcpp::test::exit_status(boost::report_errors());
}
