// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// detail::wipe zeroes every byte it is given and none around it; detail::exceeds compares in 64
// bits on every target. Built with WEBCPP_HASH_DETAIL_TEST_WIPE_RECORD, every wipe is reported
// to this test once its bytes are zero, so that the test checks the whole sequence of wipes HKDF's
// engine on backends::hash2 does (spec section 6.1): each one's size, in order, its bytes zero.

#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/detail/limits.hpp>
#include <webcpp/hash/detail/wipe.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>

#include <boost/core/lightweight_test.hpp>

#include <webcpp/test/exit_status.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#ifndef WEBCPP_HASH_DETAIL_TEST_WIPE_RECORD
#error "wipe_test is built with WEBCPP_HASH_DETAIL_TEST_WIPE_RECORD (test/Jamfile)"
#endif

namespace detail = webcpp::hash::detail;
namespace hash = webcpp::hash;

namespace {

// The sizes of the wipes reported since the last clear, and how many of them found a byte that
// was not zero.
struct record {
    std::array<std::size_t, 512> sizes{};
    std::size_t count = 0;
    std::size_t not_zero = 0;
};

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the seam's record, which
// detail::wipe reaches through a function of this test.
record wipes;

std::vector<std::size_t> taken() {
    std::vector<std::size_t> sizes(wipes.sizes.begin(),
                                   wipes.sizes.begin() + static_cast<std::ptrdiff_t>(wipes.count));
    BOOST_TEST_EQ(wipes.not_zero, 0U);
    wipes = record{};
    return sizes;
}

}  // namespace

void webcpp::hash::detail::test::wipe_record(void const* data, std::size_t size) noexcept {
    const auto* const bytes = static_cast<unsigned char const*>(data);
    for (std::size_t i = 0; i < size; ++i) {
        if (bytes[i] != 0) {
            ++wipes.not_zero;
            break;
        }
    }
    if (wipes.count < wipes.sizes.size()) {
        wipes.sizes[wipes.count] = size;
    }
    ++wipes.count;
}

namespace {

void test_wipe() {
    std::array<std::uint8_t, 34> bytes{};
    bytes.fill(0xa5);
    detail::wipe(std::span<std::uint8_t>(bytes.data() + 1, 32));
    BOOST_TEST_EQ(bytes.front(), 0xa5);
    BOOST_TEST_EQ(bytes.back(), 0xa5);
    for (std::size_t i = 1; i < 33; ++i) {
        BOOST_TEST_EQ(bytes[i], 0);
    }
    bytes.fill(0xa5);
    detail::wipe(bytes.data() + 2, 30);
    BOOST_TEST_EQ(bytes[1], 0xa5);
    BOOST_TEST_EQ(bytes[2], 0);
    BOOST_TEST_EQ(bytes[31], 0);
    BOOST_TEST_EQ(bytes[32], 0xa5);

    struct schedule {
        std::array<std::uint32_t, 4> words;
    } object{{{1, 2, 3, 4}}};

    detail::wipe_object(object);
    BOOST_TEST_EQ(object.words[0] | object.words[1] | object.words[2] | object.words[3], 0U);
    detail::wipe(nullptr, 0);
    detail::wipe(std::span<std::uint8_t>());

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
    BOOST_TEST(prk.has_value());
    BOOST_TEST((taken() == std::vector<std::size_t>{mac}));

    const std::vector<std::uint8_t> prk_bytes(prk->begin(), prk->end());
    BOOST_TEST((hash::hkdf_expand<hmac, backend>(output, prk_bytes, info).has_value()));
    BOOST_TEST((taken() == std::vector<std::size_t>{mac, mac, digest, mac}));

    BOOST_TEST((hash::hkdf<hmac, backend>(output, salt, ikm, info).has_value()));
    BOOST_TEST((taken() == std::vector<std::size_t>{mac, mac, mac, digest, mac, digest}));

    // The longest output, 255 blocks: one mac per block, then T and the keyed hmac.
    std::vector<std::uint8_t> longest(255 * digest);
    BOOST_TEST((hash::hkdf_expand<hmac, backend>(longest, prk_bytes, info).has_value()));
    std::vector<std::size_t> expected(255, mac);
    expected.push_back(digest);
    expected.push_back(mac);
    BOOST_TEST((taken() == expected));

    // A guard's refusal wipes nothing: no work has started.
    BOOST_TEST((hash::hkdf_expand<hmac, backend>(output, salt, info).has_error()));
    BOOST_TEST(taken().empty());
}

}  // namespace

int main() {
    test_wipe();
    test_exceeds();
    test_hkdf();
    return webcpp::test::exit_status(boost::report_errors());
}
