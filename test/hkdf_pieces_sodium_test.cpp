// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// HKDF over pieces on backends::sodium (design D2, D4, D8 of the change hkdf-pieces), over
// libsodium's crypto_auth_hmacsha256_* and crypto_auth_hmacsha512_*: hkdf_extract, hkdf_expand and
// hkdf over byte_pieces give the bytes of the single-buffer forms on the concatenation, those of
// backends::hash2 and of libsodium's own HKDF, with RFC 5869's cases, random splits, empty pieces
// and lists, many pieces and long inputs, and refuse only RFC 5869's sizes
// (support/hkdf_pieces.hpp), over hmac_sha2_256 and hmac_sha2_512, the hmacs of libsodium's HMAC
// cells. The cells equal those of kdfs::hkdf. Each step wipes libsodium's HMAC states, every
// block T(i) and the pseudorandom key between the steps, reported through the seam
// WEBCPP_HASH_DETAIL_TEST_WIPE_RECORD; a guard's refusal wipes nothing. Built again as
// hkdf_pieces_sodium_sliced with the test seam WEBCPP_HASH_DETAIL_TEST_HKDF_PIECES_SLICE, which
// makes the engine feed every piece to libsodium in slices of a few bytes (Review Focus 4), over
// hmac_sha2_256: the bytes are the same, 1 MiB pieces included.

#include "support/hkdf_pieces.hpp"

#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/backends/sodium.hpp>
#include <webcpp/hash/byte_pieces.hpp>
#include <webcpp/hash/config.hpp>
#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/kdf.hpp>

#include <boost/core/lightweight_test.hpp>

#include <webcpp/test/exit_status.hpp>

#include <sodium/crypto_auth_hmacsha256.h>
#include <sodium/crypto_auth_hmacsha512.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <vector>

#ifndef WEBCPP_HASH_DETAIL_TEST_WIPE_RECORD
#error "hkdf_pieces_sodium_test is built with WEBCPP_HASH_DETAIL_TEST_WIPE_RECORD (test/Jamfile)"
#endif

namespace hash = webcpp::hash;
namespace test = webcpp::test;

namespace {

using hash::backends::sodium;

// The pieces cells are libsodium's HMAC cells, those of kdfs::hkdf: SHA-256 and SHA-512 alone.
template <class Hmac>
constexpr bool has_pieces = hash::backend_has_v<sodium, hash::kdfs::hkdf_pieces, Hmac> &&
                            hash::backend_has_v<sodium, hash::kdfs::hkdf_extract_pieces, Hmac> &&
                            hash::backend_has_v<sodium, hash::kdfs::hkdf_expand_pieces, Hmac>;
static_assert(has_pieces<hash::hmac_sha2_256>);
static_assert(has_pieces<hash::hmac_sha2_512>);
static_assert(!hash::backend_has_v<sodium, hash::kdfs::hkdf_pieces, hash::hmac_sha1_160>);
static_assert(!hash::backend_has_v<sodium, hash::kdfs::hkdf_extract_pieces, hash::hmac_sha2_384>);
static_assert(!hash::backend_has_v<sodium, hash::kdfs::hkdf_expand_pieces, hash::hmac_sha2_224>);

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

// The wipes of the three steps, over Hmac and libsodium's State, with an output of two blocks:
// Extract wipes its HMAC state; Expand each block's state, then T and the state keyed by the PRK;
// hkdf both, then the PRK. A guard's refusal wipes nothing.
template <class Hmac, class State>
void check_wipes() {
    constexpr std::size_t state = sizeof(State);
    constexpr std::size_t digest = typename Hmac::result_type().size();
    using piece = std::span<std::uint8_t const>;
    std::vector<std::uint8_t> const salt(13, 0x01);
    std::vector<std::uint8_t> const ikm(22, 0x0b);
    std::vector<std::uint8_t> const info(10, 0xf0);
    std::array<piece, 3> const ikm_pieces{piece(ikm).first(5), piece{}, piece(ikm).subspan(5)};
    std::array<piece, 2> const info_pieces{piece(info).first(3), piece(info).subspan(3)};
    std::vector<std::uint8_t> output(digest + 10);
    static_cast<void>(taken());

    auto const prk = hash::hkdf_extract<Hmac, sodium>(salt, ikm_pieces);
    BOOST_TEST(prk.has_value());
    BOOST_TEST((taken() == std::vector<std::size_t>{state}));

    std::vector<std::uint8_t> const pseudorandom_key(prk->begin(), prk->end());
    BOOST_TEST(
        (hash::hkdf_expand<Hmac, sodium>(output, pseudorandom_key, info_pieces).has_value()));
    BOOST_TEST((taken() == std::vector<std::size_t>{state, state, digest, state}));

    BOOST_TEST((hash::hkdf<Hmac, sodium>(output, salt, ikm_pieces, info_pieces).has_value()));
    BOOST_TEST((taken() == std::vector<std::size_t>{state, state, state, digest, state, digest}));

    BOOST_TEST((hash::hkdf_expand<Hmac, sodium>(output, salt, info_pieces).has_error()));
    BOOST_TEST((hash::hkdf<Hmac, sodium>(std::span<std::uint8_t>{}, salt, ikm_pieces, info_pieces)
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
    std::cout << "backends::sodium feeds its HMAC slices of at most "
              << hash::detail::hkdf_pieces_slice<sodium> << " bytes\n";
#ifdef WEBCPP_HASH_DETAIL_TEST_HKDF_PIECES_SLICE
    // The slicing is the engine's, whatever the hmac.
    BOOST_TEST_EQ(hash::detail::hkdf_pieces_slice<sodium>,
                  std::uint64_t{WEBCPP_HASH_DETAIL_TEST_HKDF_PIECES_SLICE});
    test::check_hkdf_pieces<hash::hmac_sha2_256, sodium>("sodium");
#else
    test::check_hkdf_pieces<hash::hmac_sha2_256, sodium>("sodium");
    test::check_hkdf_pieces<hash::hmac_sha2_512, sodium>("sodium");
#endif
    check_wipes<hash::hmac_sha2_256, crypto_auth_hmacsha256_state>();
    check_wipes<hash::hmac_sha2_512, crypto_auth_hmacsha512_state>();
    return webcpp::test::exit_status(boost::report_errors());
}
