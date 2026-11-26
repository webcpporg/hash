// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// HKDF over pieces on backends::botan (design D2, D4, D8 of the change hkdf-pieces), over Botan's
// MessageAuthenticationCode "HMAC(<hash>)" (set_key, update, final, re-keyed for each block by
// clear and set_key): hkdf_extract, hkdf_expand and hkdf over byte_pieces give the bytes of the
// single-buffer forms on the concatenation, those of backends::hash2 and of Botan's own HKDF, with
// RFC 5869's cases, random splits, empty pieces and lists, many pieces and long inputs, and refuse
// only RFC 5869's sizes (support/hkdf_pieces.hpp), over the 14 hmacs of Botan's HMAC cells, every
// hmac of hmac.hpp but hmac_ripemd_128 and hmac_sha2_512_224. The cells equal those of kdfs::hkdf.
// A salt longer than the 8,192 bytes Botan's HMAC takes as a key is hashed first, as RFC 2104 does,
// and gives the same pseudorandom key. Botan's HMAC object is cleared (its clear()) and freed; hash
// wipes the digest room of a long salt, each block T(i) and the pseudorandom key between the steps,
// reported through the seam WEBCPP_SECURE_TEST_WIPE_RECORD; a guard's refusal wipes nothing.
// Built again as hkdf_pieces_botan_sliced with the test seam
// WEBCPP_HASH_DETAIL_TEST_HKDF_PIECES_SLICE, which makes the engine feed every piece to Botan in
// slices of a few bytes (Review Focus 4), over hmac_sha2_256: the bytes are the same, 1 MiB pieces
// included.

#include "support/hkdf_pieces.hpp"
#include "support/wipe_record.hpp"

#include <webcpp/hash/backends/botan.hpp>
#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/byte_pieces.hpp>
#include <webcpp/hash/config.hpp>
#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/kdf.hpp>

#include <boost/core/lightweight_test.hpp>

#include <webcpp/test/exit_status.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <vector>

#ifndef WEBCPP_SECURE_TEST_WIPE_RECORD
#error "hkdf_pieces_botan_test is built with WEBCPP_SECURE_TEST_WIPE_RECORD (test/Jamfile)"
#endif

namespace hash = webcpp::hash;
namespace test = webcpp::test;

namespace {

using hash::backends::botan;

// The pieces cells are Botan's HMAC cells, those of kdfs::hkdf: every hmac of hmac.hpp but
// hmac_ripemd_128 and hmac_sha2_512_224, for all three forms.
template <class Hmac>
constexpr bool has_pieces = hash::backend_has_v<botan, hash::kdfs::hkdf_pieces, Hmac> &&
                            hash::backend_has_v<botan, hash::kdfs::hkdf_extract_pieces, Hmac> &&
                            hash::backend_has_v<botan, hash::kdfs::hkdf_expand_pieces, Hmac>;
static_assert(has_pieces<hash::hmac_md5_128>);
static_assert(has_pieces<hash::hmac_sha1_160>);
static_assert(has_pieces<hash::hmac_sha2_224>);
static_assert(has_pieces<hash::hmac_sha2_256>);
static_assert(has_pieces<hash::hmac_sha2_384>);
static_assert(has_pieces<hash::hmac_sha2_512>);
static_assert(has_pieces<hash::hmac_sha2_512_256>);
static_assert(has_pieces<hash::hmac_sha3_224>);
static_assert(has_pieces<hash::hmac_sha3_256>);
static_assert(has_pieces<hash::hmac_sha3_384>);
static_assert(has_pieces<hash::hmac_sha3_512>);
static_assert(has_pieces<hash::hmac_ripemd_160>);
static_assert(has_pieces<hash::hmac_blake2b_512>);
static_assert(has_pieces<hash::hmac_blake2s_256>);
static_assert(!hash::backend_has_v<botan, hash::kdfs::hkdf_pieces, hash::hmac_ripemd_128>);
static_assert(
    !hash::backend_has_v<botan, hash::kdfs::hkdf_extract_pieces, hash::hmac_sha2_512_224>);
static_assert(!hash::backend_has_v<botan, hash::kdfs::hkdf_expand_pieces, hash::hmac_ripemd_128>);

// The room of a long salt's digest (detail::botan_keyed), wiped by every Extract.
constexpr std::size_t hashed_room = 64;

// The wipes of the three steps over Hmac, with an output of two blocks: Extract wipes the room of a
// long salt's digest, which it always has, and writes the PRK into its result; Expand wipes T after
// its blocks; hkdf both, then the PRK. A guard's refusal wipes nothing.
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
    test::clear_wipes();

    auto const prk = hash::hkdf_extract<Hmac, botan>(salt, ikm_pieces);
    BOOST_TEST(prk.has_value());
    BOOST_TEST((test::wiped_sizes() == std::vector<std::size_t>{hashed_room}));

    std::vector<std::uint8_t> const pseudorandom_key(prk->begin(), prk->end());
    BOOST_TEST((hash::hkdf_expand<Hmac, botan>(output, pseudorandom_key, info_pieces).has_value()));
    BOOST_TEST((test::wiped_sizes() == std::vector<std::size_t>{digest}));

    BOOST_TEST((hash::hkdf<Hmac, botan>(output, salt, ikm_pieces, info_pieces).has_value()));
    BOOST_TEST((test::wiped_sizes() == std::vector<std::size_t>{hashed_room, digest, digest}));

    BOOST_TEST((hash::hkdf_expand<Hmac, botan>(output, salt, info_pieces).has_error()));
    BOOST_TEST((hash::hkdf<Hmac, botan>(std::span<std::uint8_t>{}, salt, ikm_pieces, info_pieces)
                    .has_error()));
    BOOST_TEST(test::wiped_sizes().empty());
}

// A salt longer than Botan's HMAC takes as a key (8,192 bytes) is hashed first, as HMAC hashes
// every key longer than its block: the bytes of backends::hash2, through Extract and hkdf.
template <class Hmac>
void check_long_salt() {
    using piece = std::span<std::uint8_t const>;
    std::vector<std::uint8_t> const salt(8193, 0x5a);
    std::vector<std::uint8_t> const ikm(22, 0x0b);
    std::vector<std::uint8_t> const info(10, 0xf0);
    std::array<piece, 2> const ikm_pieces{piece(ikm).first(7), piece(ikm).subspan(7)};
    std::array<piece, 2> const info_pieces{piece(info).first(4), piece(info).subspan(4)};
    auto const by_botan = hash::hkdf_extract<Hmac, botan>(salt, ikm_pieces);
    auto const by_hash2 = hash::hkdf_extract<Hmac, hash::backends::hash2>(salt, ikm);
    BOOST_TEST(by_botan.has_value() && by_hash2.has_value());
    if (by_botan && by_hash2) {
        BOOST_TEST(std::ranges::equal(*by_botan, *by_hash2));
    }
    std::vector<std::uint8_t> whole_by_botan(100);
    std::vector<std::uint8_t> whole_by_hash2(100);
    BOOST_TEST((hash::hkdf<Hmac, botan>(whole_by_botan, salt, ikm_pieces, info_pieces)));
    BOOST_TEST((hash::hkdf<Hmac, hash::backends::hash2>(whole_by_hash2, salt, ikm, info)));
    BOOST_TEST(whole_by_botan == whole_by_hash2);
    test::clear_wipes();
}

}  // namespace

int main() {
    std::cout << "backends::botan feeds its HMAC slices of at most "
              << hash::detail::hkdf_pieces_slice<botan> << " bytes\n";
#ifdef WEBCPP_HASH_DETAIL_TEST_HKDF_PIECES_SLICE
    // The slicing is the engine's, whatever the hmac.
    BOOST_TEST_EQ(hash::detail::hkdf_pieces_slice<botan>,
                  std::uint64_t{WEBCPP_HASH_DETAIL_TEST_HKDF_PIECES_SLICE});
    test::check_hkdf_pieces<hash::hmac_sha2_256, botan>("botan");
#else
    test::check_hkdf_pieces<hash::hmac_md5_128, botan>("botan");
    test::check_hkdf_pieces<hash::hmac_sha1_160, botan>("botan");
    test::check_hkdf_pieces<hash::hmac_sha2_224, botan>("botan");
    test::check_hkdf_pieces<hash::hmac_sha2_256, botan>("botan");
    test::check_hkdf_pieces<hash::hmac_sha2_384, botan>("botan");
    test::check_hkdf_pieces<hash::hmac_sha2_512, botan>("botan");
    test::check_hkdf_pieces<hash::hmac_sha2_512_256, botan>("botan");
    test::check_hkdf_pieces<hash::hmac_sha3_224, botan>("botan");
    test::check_hkdf_pieces<hash::hmac_sha3_256, botan>("botan");
    test::check_hkdf_pieces<hash::hmac_sha3_384, botan>("botan");
    test::check_hkdf_pieces<hash::hmac_sha3_512, botan>("botan");
    test::check_hkdf_pieces<hash::hmac_ripemd_160, botan>("botan");
    test::check_hkdf_pieces<hash::hmac_blake2b_512, botan>("botan");
    test::check_hkdf_pieces<hash::hmac_blake2s_256, botan>("botan");
#endif
    check_long_salt<hash::hmac_sha2_256>();
    check_long_salt<hash::hmac_sha3_512>();
    check_wipes<hash::hmac_md5_128>();
    check_wipes<hash::hmac_sha2_256>();
    check_wipes<hash::hmac_sha3_512>();
    return webcpp::test::exit_status(boost::report_errors());
}
