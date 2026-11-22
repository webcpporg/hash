// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The seam of detail::timing_guard (support/timing_seam.hpp) and a test's control of the thread's
// DIT: force_dit sets or clears it, as a program can, so that a test starts from a known state.
// Like the seam, a test includes this header before any hash header.

#ifndef WEBCPP_TEST_HASH_SUPPORT_TIMING_DIT_HPP
#define WEBCPP_TEST_HASH_SUPPORT_TIMING_DIT_HPP

#include "timing_seam.hpp"

#include <webcpp/hash/detail/timing.hpp>

namespace webcpp::test {

/**
 * Sets or clears DIT for this thread, as a program can; only where the CPU has DIT, since the
 * instruction traps on a CPU without it.
 *
 * @param set Whether to set DIT.
 */
inline void force_dit([[maybe_unused]] bool set) noexcept {
#ifdef WEBCPP_HASH_DETAIL_TIMING_COVERED
    if (!webcpp::hash::detail::cpu_has_dit()) {
        return;
    }
    webcpp::hash::detail::write_dit(set ? webcpp::hash::detail::dit_bit : 0);
#endif
}

}  // namespace webcpp::test

#endif  // WEBCPP_TEST_HASH_SUPPORT_TIMING_DIT_HPP
