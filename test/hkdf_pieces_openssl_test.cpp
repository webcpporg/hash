// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// HKDF over pieces on backends::openssl (design D2, D4, D8 of the change hkdf-pieces), over
// OpenSSL's EVP_MAC "HMAC" (EVP_MAC_init with the digest's name, EVP_MAC_update, EVP_MAC_final,
// the context keyed by the pseudorandom key duplicated by EVP_MAC_CTX_dup for each block):
// hkdf_extract, hkdf_expand and hkdf over byte_pieces give the bytes of the single-buffer forms on
// the concatenation, those of backends::hash2 and of OpenSSL's own EVP_KDF "HKDF", with RFC 5869's
// cases, random splits, empty pieces and lists, many pieces and long inputs, and refuse only RFC
// 5869's sizes (support/hkdf_pieces.hpp), over the 15 hmacs of OpenSSL's HMAC cells, every hmac of
// hmac.hpp but hmac_ripemd_128. The cells equal those of kdfs::hkdf. OpenSSL's contexts are its
// own, freed by EVP_MAC_CTX_free; hash wipes each block T(i) and the pseudorandom key between the
// steps, reported through the seam WEBCPP_HASH_DETAIL_TEST_WIPE_RECORD; a guard's refusal wipes
// nothing; the thread's error queue is left empty. Built again as hkdf_pieces_openssl_sliced with
// the test seam WEBCPP_HASH_DETAIL_TEST_HKDF_PIECES_SLICE, which makes the engine feed every piece
// to OpenSSL in slices of a few bytes (Review Focus 4), over hmac_sha2_256: the bytes are the same,
// 1 MiB pieces included.

#include "support/hkdf_pieces.hpp"

#include <webcpp/hash/backends/openssl.hpp>
#include <webcpp/hash/byte_pieces.hpp>
#include <webcpp/hash/config.hpp>
#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/kdf.hpp>

#include <boost/core/lightweight_test.hpp>

#include <webcpp/test/exit_status.hpp>

#include <openssl/err.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <vector>

#ifndef WEBCPP_HASH_DETAIL_TEST_WIPE_RECORD
#error "hkdf_pieces_openssl_test is built with WEBCPP_HASH_DETAIL_TEST_WIPE_RECORD (test/Jamfile)"
#endif

namespace hash = webcpp::hash;
namespace test = webcpp::test;

namespace {

using hash::backends::openssl;

// The pieces cells are OpenSSL's HMAC cells, those of kdfs::hkdf: every hmac of hmac.hpp but
// hmac_ripemd_128, for all three forms.
template <class Hmac>
constexpr bool has_pieces = hash::backend_has_v<openssl, hash::kdfs::hkdf_pieces, Hmac> &&
                            hash::backend_has_v<openssl, hash::kdfs::hkdf_extract_pieces, Hmac> &&
                            hash::backend_has_v<openssl, hash::kdfs::hkdf_expand_pieces, Hmac>;
static_assert(has_pieces<hash::hmac_md5_128>);
static_assert(has_pieces<hash::hmac_sha1_160>);
static_assert(has_pieces<hash::hmac_sha2_224>);
static_assert(has_pieces<hash::hmac_sha2_256>);
static_assert(has_pieces<hash::hmac_sha2_384>);
static_assert(has_pieces<hash::hmac_sha2_512>);
static_assert(has_pieces<hash::hmac_sha2_512_224>);
static_assert(has_pieces<hash::hmac_sha2_512_256>);
static_assert(has_pieces<hash::hmac_sha3_224>);
static_assert(has_pieces<hash::hmac_sha3_256>);
static_assert(has_pieces<hash::hmac_sha3_384>);
static_assert(has_pieces<hash::hmac_sha3_512>);
static_assert(has_pieces<hash::hmac_ripemd_160>);
static_assert(has_pieces<hash::hmac_blake2b_512>);
static_assert(has_pieces<hash::hmac_blake2s_256>);
static_assert(!hash::backend_has_v<openssl, hash::kdfs::hkdf_pieces, hash::hmac_ripemd_128>);
static_assert(
    !hash::backend_has_v<openssl, hash::kdfs::hkdf_extract_pieces, hash::hmac_ripemd_128>);
static_assert(!hash::backend_has_v<openssl, hash::kdfs::hkdf_expand_pieces, hash::hmac_ripemd_128>);

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

// The wipes of the three steps over Hmac, with an output of two blocks: Extract writes the PRK
// into its result and wipes nothing of hash's (OpenSSL's context is freed by EVP_MAC_CTX_free);
// Expand wipes T after its blocks; hkdf wipes T, then the PRK. A guard's refusal wipes nothing.
// The thread's error queue stays empty.
template <class Hmac>
void check_wipes() {
    constexpr std::size_t digest = typename Hmac::result_type().size();
    using piece = std::span<std::uint8_t const>;
    std::vector<std::uint8_t> const salt(13, 0x01);
    std::vector<std::uint8_t> const ikm(22, 0x0b);
    std::vector<std::uint8_t> const info(10, 0xf0);
    std::array<piece, 3> const ikm_pieces{piece(ikm).first(5), piece{}, piece(ikm).subspan(5)};
    std::array<piece, 2> const info_pieces{piece(info).first(3), piece(info).subspan(3)};
    std::vector<std::uint8_t> output(digest + 10);
    static_cast<void>(taken());

    auto const prk = hash::hkdf_extract<Hmac, openssl>(salt, ikm_pieces);
    BOOST_TEST(prk.has_value());
    BOOST_TEST(taken().empty());

    std::vector<std::uint8_t> const pseudorandom_key(prk->begin(), prk->end());
    BOOST_TEST(
        (hash::hkdf_expand<Hmac, openssl>(output, pseudorandom_key, info_pieces).has_value()));
    BOOST_TEST((taken() == std::vector<std::size_t>{digest}));

    BOOST_TEST((hash::hkdf<Hmac, openssl>(output, salt, ikm_pieces, info_pieces).has_value()));
    BOOST_TEST((taken() == std::vector<std::size_t>{digest, digest}));

    BOOST_TEST((hash::hkdf_expand<Hmac, openssl>(output, salt, info_pieces).has_error()));
    BOOST_TEST((hash::hkdf<Hmac, openssl>(std::span<std::uint8_t>{}, salt, ikm_pieces, info_pieces)
                    .has_error()));
    BOOST_TEST(taken().empty());
    BOOST_TEST_EQ(ERR_peek_error(), 0UL);
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
    std::cout << "backends::openssl feeds its HMAC slices of at most "
              << hash::detail::hkdf_pieces_slice<openssl> << " bytes\n";
#ifdef WEBCPP_HASH_DETAIL_TEST_HKDF_PIECES_SLICE
    // The slicing is the engine's, whatever the hmac.
    BOOST_TEST_EQ(hash::detail::hkdf_pieces_slice<openssl>,
                  std::uint64_t{WEBCPP_HASH_DETAIL_TEST_HKDF_PIECES_SLICE});
    test::check_hkdf_pieces<hash::hmac_sha2_256, openssl>("openssl");
#else
    test::check_hkdf_pieces<hash::hmac_md5_128, openssl>("openssl");
    test::check_hkdf_pieces<hash::hmac_sha1_160, openssl>("openssl");
    test::check_hkdf_pieces<hash::hmac_sha2_224, openssl>("openssl");
    test::check_hkdf_pieces<hash::hmac_sha2_256, openssl>("openssl");
    test::check_hkdf_pieces<hash::hmac_sha2_384, openssl>("openssl");
    test::check_hkdf_pieces<hash::hmac_sha2_512, openssl>("openssl");
    test::check_hkdf_pieces<hash::hmac_sha2_512_224, openssl>("openssl");
    test::check_hkdf_pieces<hash::hmac_sha2_512_256, openssl>("openssl");
    test::check_hkdf_pieces<hash::hmac_sha3_224, openssl>("openssl");
    test::check_hkdf_pieces<hash::hmac_sha3_256, openssl>("openssl");
    test::check_hkdf_pieces<hash::hmac_sha3_384, openssl>("openssl");
    test::check_hkdf_pieces<hash::hmac_sha3_512, openssl>("openssl");
    test::check_hkdf_pieces<hash::hmac_ripemd_160, openssl>("openssl");
    test::check_hkdf_pieces<hash::hmac_blake2b_512, openssl>("openssl");
    test::check_hkdf_pieces<hash::hmac_blake2s_256, openssl>("openssl");
#endif
    check_wipes<hash::hmac_md5_128>();
    check_wipes<hash::hmac_sha2_256>();
    check_wipes<hash::hmac_sha3_512>();
    BOOST_TEST_EQ(ERR_peek_error(), 0UL);
    return webcpp::test::exit_status(boost::report_errors());
}
