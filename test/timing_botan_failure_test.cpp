// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A failure of Botan inside a guard (design D1, ruling H10): through the seam
// WEBCPP_HASH_DETAIL_TEST_BOTAN_NAME, which the test's Jamfile defines to "NO-SUCH-HASH", Botan's
// create_or_throw throws Lookup_Error inside detail::botan_boundary, after the public function's
// detail::timing_guard is entered; the boundary answers backend_failure, and the guard's scope
// ends by that return. Each of mac, hkdf_extract, hkdf_expand, hkdf and pbkdf2 enters its own
// guard first and leaves the thread's DIT as it found it, from a thread with DIT clear and from
// one that set DIT itself (where the CPU has DIT).

#include "support/timing_dit.hpp"

#include <webcpp/hash/backends/botan.hpp>
#include <webcpp/hash/detail/timing.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/hash/pbkdf2.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/system/result.hpp>

#include <array>
#include <cstdint>
#include <string>

#ifndef WEBCPP_HASH_DETAIL_TEST_BOTAN_NAME
#error "the test's Jamfile defines WEBCPP_HASH_DETAIL_TEST_BOTAN_NAME"
#endif

namespace {

namespace hash = webcpp::hash;
namespace test = webcpp::test;
using hash::backends::botan;
using hmac = hash::hmac_sha2_256;

std::array<std::uint8_t, 3> const abc{0x61, 0x62, 0x63};
std::array<std::uint8_t, 16> const salt{1};
std::array<std::uint8_t, 32> const key{2};

bool backend_failed(boost::system::result<void> const& outcome) {
    return outcome.has_error() && outcome.error() == hash::error::backend_failure;
}

// Each call, from DIT set as `set` says: its own guard first, backend_failure, DIT as found.
void fails_inside_guard(bool set) {
    test::force_dit(set);
    bool const before = hash::detail::dit_is_set();
    std::string const from = set ? " from DIT set" : " from DIT clear";
    auto const restored = [&](std::string const& name) {
        if (hash::detail::dit_is_set() != before) {
            BOOST_ERROR((name + from + " left DIT other than it found it").c_str());
        }
    };
    std::array<std::uint8_t, 32> output{};
    test::require_enters("hash::mac of hmac_sha2_256 on botan", [&] {
        BOOST_TEST(backend_failed(
            hash::mac<hash::macs::hmac<hash::digests::sha2_256>, botan>(output, key, abc)));
    });
    restored("mac");
    test::require_enters("hash::hkdf_extract on botan", [&] {
        auto const prk = hash::hkdf_extract<hmac, botan>(salt, abc);
        BOOST_TEST(prk.has_error() && prk.error() == hash::error::backend_failure);
    });
    restored("hkdf_extract");
    test::require_enters("hash::hkdf_expand on botan", [&] {
        BOOST_TEST(backend_failed(hash::hkdf_expand<hmac, botan>(output, key, abc)));
    });
    restored("hkdf_expand");
    test::require_enters("hash::hkdf on botan", [&] {
        BOOST_TEST(backend_failed(hash::hkdf<hmac, botan>(output, salt, abc, abc)));
    });
    restored("hkdf");
    test::require_enters("hash::pbkdf2 on botan", [&] {
        BOOST_TEST(backend_failed(hash::pbkdf2<hmac, botan>(output, abc, salt, 2)));
    });
    restored("pbkdf2");
    test::force_dit(false);
}

}  // namespace

int main() {
    fails_inside_guard(false);
    fails_inside_guard(true);
    BOOST_TEST(!hash::detail::dit_is_set());
    return webcpp::test::exit_status(boost::report_errors());
}
