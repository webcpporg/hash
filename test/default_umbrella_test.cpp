// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// webcpp's umbrella profile (spec 4.1), with every library the target has, built three times:
// WEBCPP_PROFILE_SMALLEST alone follows the size order; with WEBCPP_HASH_PROFILE_PORTABLE too the
// library's profile wins; with WEBCPP_HASH_DEFAULT_BACKEND_HKDF_OPENSSL as well the override
// wins for HKDF (native, wasip2 and wasip3). The precedence: override, library profile,
// umbrella profile, auto.

#include <webcpp/hash/kdf.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/defaults.hpp"

#include <boost/core/lightweight_test.hpp>

#include <type_traits>

namespace {

// The default a cell has when no override names its backend: the library's profile, else the
// umbrella's size order.
template <class Operation, class Hmac>
void expect_profile_default() {
    namespace test = webcpp::test;
#ifdef WEBCPP_HASH_PROFILE_PORTABLE
    test::expect_default<Operation, Hmac>(
        test::first_serving<Operation, Hmac>(webcpp::hash::detail::portable_order{}));
#else
    using ranking = webcpp::hash::detail::ranking<Operation, Hmac>;
    test::expect_default<Operation, Hmac>(
        test::first_serving<Operation, Hmac>(typename ranking::by_size{}));
#endif
}

}  // namespace

int main() {
    namespace hash = webcpp::hash;
    namespace test = webcpp::test;
#ifndef WEBCPP_PROFILE_SMALLEST
#error "default_umbrella_test: define WEBCPP_PROFILE_SMALLEST"
#endif
#ifdef WEBCPP_HASH_PROFILE_PORTABLE
    BOOST_TEST((std::is_same_v<hash::detail::profile, hash::detail::profiles::portable>));
#else
    BOOST_TEST((std::is_same_v<hash::detail::profile, hash::detail::profiles::smallest>));
#endif
    test::for_each_kdf_cell([]<class Operation, class Hmac> {
#ifdef WEBCPP_HASH_DEFAULT_BACKEND_HKDF_OPENSSL
        // The override's cells, then the profile's in the else branch: code after a return in
        // an if constexpr is unreachable for MSVC (C4702) in the cells the branch takes.
        if constexpr (!std::is_same_v<Operation, hash::kdfs::pbkdf2>) {
            test::expect_default<Operation, Hmac>("openssl");
        } else {
            expect_profile_default<Operation, Hmac>();
        }
#else
        expect_profile_default<Operation, Hmac>();
#endif
    });
#ifdef WEBCPP_HASH_DEFAULT_BACKEND_HKDF_OPENSSL
    test::check_invariants<true>();
#else
    test::check_invariants();
#endif
    test::check_calls();
    return webcpp::test::exit_status(boost::report_errors());
}
