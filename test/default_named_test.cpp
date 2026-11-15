// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// WEBCPP_HASH_PROFILE_BACKEND_<NAME> (spec 4.1), with every library the target has, built once
// with BEARSSL and once with SODIUM: the named backend for every operation and hmac it has, and
// auto's choice for the others. With BearSSL named, hkdf over SHA-256 is BearSSL's while its two
// steps alone keep auto's choice, since BearSSL has them only together.

#include <webcpp/hash/kdf.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/defaults.hpp"

#include <boost/core/lightweight_test.hpp>

#include <type_traits>

namespace {

namespace hash = webcpp::hash;
namespace test = webcpp::test;

#ifdef WEBCPP_HASH_PROFILE_BACKEND_BEARSSL
using named = hash::backends::bearssl;
#elif defined(WEBCPP_HASH_PROFILE_BACKEND_SODIUM)
using named = hash::backends::sodium;
#else
#error "default_named_test: define WEBCPP_HASH_PROFILE_BACKEND_BEARSSL or _SODIUM"
#endif

}  // namespace

int main() {
    BOOST_TEST((std::is_same_v<hash::detail::profile, hash::detail::profiles::named<named>>));
    test::for_each_kdf_cell([]<class Operation, class Hmac> {
        constexpr bool serves =
            test::linked<named>() && hash::backend_has_v<named, Operation, Hmac>;
        test::expect_default<Operation, Hmac>(serves ? test::name_of<named>()
                                                     : test::auto_choice<Operation, Hmac>());
    });
    using hmac = hash::hmac_sha2_256;
    BOOST_TEST((std::is_same_v<hash::default_kdf_backend<hmac>, named>));
#ifdef WEBCPP_HASH_PROFILE_BACKEND_BEARSSL
    // BearSSL has hkdf alone: its steps keep auto's choice.
    BOOST_TEST_EQ((test::name_of<hash::default_kdf_backend<hmac, hash::kdfs::hkdf_extract>>()),
                  (test::auto_choice<hash::kdfs::hkdf_extract, hmac>()));
#endif
    test::check_invariants();
    test::check_calls();
    return webcpp::test::exit_status(boost::report_errors());
}
