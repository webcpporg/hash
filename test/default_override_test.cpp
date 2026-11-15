// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// WEBCPP_HASH_DEFAULT_BACKEND_HKDF_SODIUM beside WEBCPP_HASH_PROFILE_FASTEST (spec 4.1), with
// every library the target has: HKDF's three functions are libsodium's over every hmac,
// whatever the profile says, while PBKDF2 keeps the profile's choice.

#include <webcpp/hash/kdf.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/defaults.hpp"

#include <boost/core/lightweight_test.hpp>

#include <type_traits>

int main() {
    namespace hash = webcpp::hash;
    namespace test = webcpp::test;
    BOOST_TEST((std::is_same_v<hash::detail::profile, hash::detail::profiles::fastest>));
    BOOST_TEST((std::is_same_v<hash::detail::override_choice<hash::kdfs::hkdf>::type,
                               hash::backends::sodium>));
    BOOST_TEST((std::is_void_v<hash::detail::override_choice<hash::kdfs::pbkdf2>::type>));
    test::for_each_kdf_cell([]<class Operation, class Hmac> {
        if constexpr (std::is_same_v<Operation, hash::kdfs::pbkdf2>) {
            using ranking = hash::detail::ranking<hash::kdfs::pbkdf2, Hmac>;
            test::expect_default<Operation, Hmac>(
                test::first_serving<Operation, Hmac>(typename ranking::by_throughput{}));
        } else {
            test::expect_default<Operation, Hmac>("sodium");
        }
    });
    test::check_invariants<true>();
    test::check_calls();
    return webcpp::test::exit_status(boost::report_errors());
}
