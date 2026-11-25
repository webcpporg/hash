// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The test seam of detail::wipe, recorded: a program built with
// WEBCPP_HASH_DETAIL_TEST_WIPE_RECORD includes this header once, which defines the seam's function
// detail::test::wipe_record. Each wipe is recorded in wipes, and wiped_sizes() returns the sizes
// of the wipes since its last call, checking that each wipe left only zero bytes; clear_wipes()
// discards them, however many.

#ifndef WEBCPP_TEST_HASH_SUPPORT_WIPE_RECORD_HPP
#define WEBCPP_TEST_HASH_SUPPORT_WIPE_RECORD_HPP

#ifndef WEBCPP_HASH_DETAIL_TEST_WIPE_RECORD
#error "support/wipe_record.hpp is for a program built with WEBCPP_HASH_DETAIL_TEST_WIPE_RECORD"
#endif

#include <webcpp/hash/detail/wipe.hpp>

#include <boost/core/lightweight_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <vector>

namespace webcpp::test {

/**
 * The wipes since the last clear: their sizes in order (the first ones), how many, and how many
 * found a byte that was not zero. Fixed storage: the seam is noexcept and allocates nothing, so a
 * wipe past the storage is counted but its size is not kept, and wiped_sizes() reports it.
 */
struct wipe_log {
    std::array<std::size_t, 16> sizes{};
    std::size_t count = 0;
    std::size_t not_zero = 0;
};

/** The seam's record, which detail::wipe reaches through detail::test::wipe_record. */
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the seam's record
inline wipe_log wipes;

/**
 * The sizes of the wipes since the last call, which clears the record; every wipe must have left
 * only zero bytes, and every size must have fit the record's storage.
 */
inline std::vector<std::size_t> wiped_sizes() {
    BOOST_TEST_LE(wipes.count, wipes.sizes.size());
    std::vector<std::size_t> const sizes(
        wipes.sizes.begin(), wipes.sizes.begin() + static_cast<std::ptrdiff_t>(
                                                       std::min(wipes.count, wipes.sizes.size())));
    BOOST_TEST_EQ(wipes.not_zero, 0U);
    wipes = {};
    return sizes;
}

/**
 * Clears the record without reading the sizes, however many wipes it counted (the work before a
 * checked step, which may wipe more often than the record keeps); every wipe must still have left
 * only zero bytes.
 */
inline void clear_wipes() {
    BOOST_TEST_EQ(wipes.not_zero, 0U);
    wipes = {};
}

}  // namespace webcpp::test

// The seam's function, declared by detail/wipe.hpp, defined once by the program that includes
// this header.
// NOLINTBEGIN(misc-definitions-in-headers)
void webcpp::hash::detail::test::wipe_record(void const* wiped_data,
                                             std::size_t byte_count) noexcept {
    auto& log = ::webcpp::test::wipes;
    auto const* const bytes = static_cast<unsigned char const*>(wiped_data);
    // Checked here, so that the store cannot throw: the seam is noexcept. A wipe past the storage
    // is only counted, and wiped_sizes() fails the test on it.
    if (log.count < log.sizes.size()) {
        log.sizes[log.count] = byte_count;
    }
    ++log.count;
    if (!std::all_of(bytes, bytes + byte_count, [](unsigned char b) { return b == 0; })) {
        ++log.not_zero;
    }
}

// NOLINTEND(misc-definitions-in-headers)

#endif  // WEBCPP_TEST_HASH_SUPPORT_WIPE_RECORD_HPP
