// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// WEBCPP_HASH_PROFILE_FASTEST (spec 4.1), with every library the target has: on every target the
// throughput order's first linked backend that has each operation over each hmac.

#include <webcpp/hash/kdf.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/defaults.hpp"

#include <boost/core/lightweight_test.hpp>

#include <type_traits>

int main() {
    namespace hash = webcpp::hash;
    namespace test = webcpp::test;
    BOOST_TEST((std::is_same_v<hash::detail::profile, hash::detail::profiles::fastest>));
    test::for_each_kdf_cell([]<class Operation, class Hmac> {
        using ranking = hash::detail::ranking<Operation, Hmac>;
        test::expect_default<Operation, Hmac>(
            test::first_serving<Operation, Hmac>(typename ranking::by_throughput{}));
    });
    test::check_invariants();
    test::check_calls();
    return webcpp::test::exit_status(boost::report_errors());
}
