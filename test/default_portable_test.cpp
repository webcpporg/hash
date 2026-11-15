// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// WEBCPP_HASH_PROFILE_PORTABLE (spec 4.1), with every library the target has: the first of
// hash2, sodium, bearssl (ruling R3) that has each operation over each hmac, never OpenSSL,
// which is absent from Emscripten.

#include <webcpp/hash/kdf.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/defaults.hpp"

#include <boost/core/lightweight_test.hpp>

#include <type_traits>

int main() {
    namespace hash = webcpp::hash;
    namespace test = webcpp::test;
    using hash::backends::bearssl;
    using hash::backends::hash2;
    using hash::backends::sodium;
    BOOST_TEST((std::is_same_v<hash::detail::profile, hash::detail::profiles::portable>));
    BOOST_TEST((std::is_same_v<hash::detail::portable_order,
                               hash::detail::backend_list<hash2, sodium, bearssl>>));
    test::for_each_kdf_cell([]<class Operation, class Hmac> {
        test::expect_default<Operation, Hmac>(
            test::first_serving<Operation, Hmac>(hash::detail::portable_order{}));
        BOOST_TEST(
            !(std::is_same_v<hash::default_kdf_backend<Hmac, Operation>, hash::backends::openssl>));
    });
    test::check_invariants();
    test::check_calls();
    return webcpp::test::exit_status(boost::report_errors());
}
