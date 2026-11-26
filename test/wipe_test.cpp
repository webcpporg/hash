// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// secure::erase_secret, as hash's wipes call it (a span of bytes, a part of a buffer, an object's
// bytes), zeroes every byte it is given and none around it; detail::exceeds compares in 64 bits on
// every target. Built with WEBCPP_SECURE_TEST_WIPE_RECORD, every wipe is reported to this test
// once its bytes are zero, so that the test checks the whole sequence of wipes HKDF's
// (also over pieces) and PBKDF2's engines on backends::hash2 do (spec section 6.1): each one's
// size, in order, its bytes zero, and the addresses of objects alive at once told apart.

#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/detail/limits.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/pbkdf2.hpp>
#include <webcpp/secure/erase_secret.hpp>

#include <boost/core/lightweight_test.hpp>

#include <webcpp/test/exit_status.hpp>

#include "require.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <span>
#include <vector>

#ifndef WEBCPP_SECURE_TEST_WIPE_RECORD
#error "wipe_test is built with WEBCPP_SECURE_TEST_WIPE_RECORD (test/Jamfile)"
#endif

namespace detail = webcpp::hash::detail;
namespace hash = webcpp::hash;
namespace secure = webcpp::secure;

namespace {

// One wipe: where, and how many bytes.
struct wipe_entry {
    void const* at = nullptr;
    std::size_t size = 0;
};

// The wipes reported since the last clear, and how many of them found a byte that was not zero.
struct record {
    std::array<wipe_entry, 512> entries{};
    std::size_t count = 0;
    std::size_t not_zero = 0;
};

// The seam's record, which secure::detail::wipe reaches through a function of this test.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the seam's record
record wipes;

// The wipes since the last call, which clears them; each found its bytes zero.
std::vector<wipe_entry> taken_entries() {
    std::vector<wipe_entry> entries(
        wipes.entries.begin(), wipes.entries.begin() + static_cast<std::ptrdiff_t>(wipes.count));
    BOOST_TEST_EQ(wipes.not_zero, 0U);
    wipes = record{};
    return entries;
}

std::vector<std::size_t> sizes_of(const std::vector<wipe_entry>& entries) {
    std::vector<std::size_t> sizes;
    sizes.reserve(entries.size());
    for (const wipe_entry& entry : entries) {
        sizes.push_back(entry.size);
    }
    return sizes;
}

// The sizes of the wipes since the last call, which clears them.
std::vector<std::size_t> taken() {
    return sizes_of(taken_entries());
}

// Whether the wipe at `index` is at an address none of the wipes at `others` used: two objects
// alive at once (the keyed hmac and a block's copy, T and the PRK, U and T) are told apart.
bool apart(const std::vector<wipe_entry>& entries, std::size_t index,
           std::initializer_list<std::size_t> others) {
    return std::ranges::none_of(
        others, [&](std::size_t other) { return entries[other].at == entries[index].at; });
}

}  // namespace

void webcpp::secure::test::wipe_record(void const* wiped_data, std::size_t byte_count) noexcept {
    const auto* const bytes = static_cast<unsigned char const*>(wiped_data);
    for (std::size_t i = 0; i < byte_count; ++i) {
        if (bytes[i] != 0) {
            ++wipes.not_zero;
            break;
        }
    }
    if (wipes.count < wipes.entries.size()) {
        wipes.entries[wipes.count] = wipe_entry{.at = wiped_data, .size = byte_count};
    }
    ++wipes.count;
}

namespace {

void test_wipe() {
    std::array<std::uint8_t, 34> bytes{};
    bytes.fill(0xa5);
    secure::erase_secret(std::span<std::uint8_t>(bytes.data() + 1, 32));
    BOOST_TEST_EQ(bytes.front(), 0xa5);
    BOOST_TEST_EQ(bytes.back(), 0xa5);
    for (std::size_t i = 1; i < 33; ++i) {
        BOOST_TEST_EQ(bytes[i], 0);
    }
    bytes.fill(0xa5);
    secure::erase_secret(std::span(bytes).subspan(2, 30));
    BOOST_TEST_EQ(bytes[1], 0xa5);
    BOOST_TEST_EQ(bytes[2], 0);
    BOOST_TEST_EQ(bytes[31], 0);
    BOOST_TEST_EQ(bytes[32], 0xa5);

    struct schedule {
        std::array<std::uint32_t, 4> words;
    } object{{{1, 2, 3, 4}}};

    secure::erase_secret(std::span(&object, 1));
    BOOST_TEST_EQ(object.words[0] | object.words[1] | object.words[2] | object.words[3], 0U);
    secure::erase_secret(std::span<std::uint8_t>());
    secure::erase_secret(std::span<char>());

    BOOST_TEST((taken() == std::vector<std::size_t>{32, 30, sizeof(schedule), 0, 0}));
}

void test_exceeds() {
    BOOST_TEST(detail::exceeds((std::uint64_t{1} << 36U) - 31, (std::uint64_t{1} << 36U) - 32));
    BOOST_TEST(!detail::exceeds((std::uint64_t{1} << 36U) - 32, (std::uint64_t{1} << 36U) - 32));
    BOOST_TEST(!detail::exceeds(0, 0));
}

// HKDF over hmac_sha2_256 with an output of two blocks (42 bytes): extract wipes its mac; expand
// wipes each block's mac, then T, then the keyed hmac; hkdf then wipes the PRK.
void test_hkdf() {
    using hmac = hash::hmac_sha2_256;
    using backend = hash::backends::hash2;
    constexpr std::size_t mac = sizeof(hmac);
    constexpr std::size_t digest = 32;
    const std::vector<std::uint8_t> salt(13, 0x01);
    const std::vector<std::uint8_t> ikm(22, 0x0b);
    const std::vector<std::uint8_t> info(10, 0xf0);
    std::vector<std::uint8_t> output(42);
    static_cast<void>(taken());

    auto prk = hash::hkdf_extract<hmac, backend>(salt, ikm);
    webcpp::test::require(BOOST_TEST(prk.has_value()));
    BOOST_TEST((taken() == std::vector<std::size_t>{mac}));

    // Each block's mac, T, the keyed hmac (apart from the blocks' macs).
    const std::vector<std::uint8_t> pseudorandom_key(prk->begin(), prk->end());
    BOOST_TEST((hash::hkdf_expand<hmac, backend>(output, pseudorandom_key, info).has_value()));
    auto entries = taken_entries();
    BOOST_TEST((sizes_of(entries) == std::vector<std::size_t>{mac, mac, digest, mac}));
    if (entries.size() == 4) {
        BOOST_TEST(apart(entries, 3, {0, 1}));
    }

    // Extract's mac, each block's mac, T, the keyed hmac, the PRK (apart from T).
    BOOST_TEST((hash::hkdf<hmac, backend>(output, salt, ikm, info).has_value()));
    entries = taken_entries();
    BOOST_TEST((sizes_of(entries) == std::vector<std::size_t>{mac, mac, mac, digest, mac, digest}));
    if (entries.size() == 6) {
        BOOST_TEST(apart(entries, 4, {1, 2}));
        BOOST_TEST(apart(entries, 5, {3}));
    }

    // The longest output, 255 blocks: one mac per block, then T and the keyed hmac.
    std::vector<std::uint8_t> longest(255 * digest);
    BOOST_TEST((hash::hkdf_expand<hmac, backend>(longest, pseudorandom_key, info).has_value()));
    std::vector<std::size_t> expected(255, mac);
    expected.push_back(digest);
    expected.push_back(mac);
    entries = taken_entries();
    BOOST_TEST((sizes_of(entries) == expected));
    if (entries.size() == expected.size()) {
        for (std::size_t block = 0; block < 255; ++block) {
            BOOST_TEST(apart(entries, 256, {block}));
        }
    }

    // A guard's refusal wipes nothing: no work has started.
    BOOST_TEST((hash::hkdf_expand<hmac, backend>(output, salt, info).has_error()));
    BOOST_TEST(taken().empty());
}

// HKDF over pieces, hmac_sha2_256, an output of two blocks: the same wipes as the single-buffer
// forms, whatever the pieces (design D2 of the change hkdf-pieces); a guard's refusal wipes
// nothing.
void test_hkdf_pieces() {
    using hmac = hash::hmac_sha2_256;
    using backend = hash::backends::hash2;
    using piece = std::span<std::uint8_t const>;
    constexpr std::size_t mac = sizeof(hmac);
    constexpr std::size_t digest = 32;
    const std::vector<std::uint8_t> salt(13, 0x01);
    const std::vector<std::uint8_t> ikm(22, 0x0b);
    const std::vector<std::uint8_t> info(10, 0xf0);
    std::array<piece, 3> const ikm_pieces{piece(ikm).first(5), piece{}, piece(ikm).subspan(5)};
    std::array<piece, 2> const info_pieces{piece(info).first(3), piece(info).subspan(3)};
    std::vector<std::uint8_t> output(42);
    static_cast<void>(taken());

    auto prk = hash::hkdf_extract<hmac, backend>(salt, ikm_pieces);
    webcpp::test::require(BOOST_TEST(prk.has_value()));
    BOOST_TEST((taken() == std::vector<std::size_t>{mac}));

    const std::vector<std::uint8_t> pseudorandom_key(prk->begin(), prk->end());
    BOOST_TEST(
        (hash::hkdf_expand<hmac, backend>(output, pseudorandom_key, info_pieces).has_value()));
    auto entries = taken_entries();
    BOOST_TEST((sizes_of(entries) == std::vector<std::size_t>{mac, mac, digest, mac}));
    if (entries.size() == 4) {
        BOOST_TEST(apart(entries, 3, {0, 1}));
    }

    BOOST_TEST((hash::hkdf<hmac, backend>(output, salt, ikm_pieces, info_pieces).has_value()));
    entries = taken_entries();
    BOOST_TEST((sizes_of(entries) == std::vector<std::size_t>{mac, mac, mac, digest, mac, digest}));
    if (entries.size() == 6) {
        BOOST_TEST(apart(entries, 4, {1, 2}));
        BOOST_TEST(apart(entries, 5, {3}));
    }

    BOOST_TEST((hash::hkdf_expand<hmac, backend>(output, salt, info_pieces).has_error()));
    BOOST_TEST((hash::hkdf<hmac, backend>(std::span<std::uint8_t>{}, salt, ikm_pieces, info_pieces)
                    .has_error()));
    BOOST_TEST(taken().empty());
}

// PBKDF2 over hmac_sha2_256 with an output of two blocks (64 bytes) and three iterations: each
// block's mac, then U, T and the keyed hmac.
void test_pbkdf2() {
    using hmac = hash::hmac_sha2_256;
    using backend = hash::backends::hash2;
    constexpr std::size_t mac = sizeof(hmac);
    constexpr std::size_t digest = 32;
    const std::vector<std::uint8_t> password(8, 0x70);
    const std::vector<std::uint8_t> salt(4, 0x73);
    std::vector<std::uint8_t> output(64);
    static_cast<void>(taken());

    BOOST_TEST((hash::pbkdf2<hmac, backend>(output, password, salt, 3).has_value()));
    const auto entries = taken_entries();
    BOOST_TEST((sizes_of(entries) == std::vector<std::size_t>{mac, mac, digest, digest, mac}));
    if (entries.size() == 5) {
        BOOST_TEST(apart(entries, 4, {0, 1}));  // the keyed hmac, not a block's mac
        BOOST_TEST(apart(entries, 3, {2}));     // T, not U
    }

    // A guard's refusal wipes nothing.
    BOOST_TEST((hash::pbkdf2<hmac, backend>(output, password, salt, 0).has_error()));
    BOOST_TEST(taken().empty());
}

}  // namespace

int main() {
    test_wipe();
    test_exceeds();
    test_hkdf();
    test_hkdf_pieces();
    test_pbkdf2();
    return webcpp::test::exit_status(boost::report_errors());
}
