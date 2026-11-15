// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The default backends without a profile (`auto`, spec 4.1), built once per target with every
// library the target has and once with none: natively the throughput order's first linked
// backend that has each operation over each hmac, on WebAssembly the size order's; the
// invariants of support/defaults.hpp, each operation's default its own; the selection over an order
// that puts BearSSL first; the selection's fallbacks, with and without libsodium; and each default
// called, agreeing with backends::hash2 on RFC 5869's A.1.

#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/hash/pbkdf2.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/defaults.hpp"

#include <boost/core/lightweight_test.hpp>

#include <type_traits>

namespace {

namespace hash = webcpp::hash;
namespace test = webcpp::test;
using hash::backends::bearssl;
using hash::backends::hash2;
using hash::detail::backend_list;

void check_auto() {
    BOOST_TEST((std::is_same_v<hash::detail::profile, hash::detail::profiles::automatic>));
    test::for_each_kdf_cell([]<class Operation, class Hmac> {
        test::expect_default<Operation, Hmac>(test::auto_choice<Operation, Hmac>());
    });
    test::check_invariants();
}

// Per operation, the first backend of an order that is linked and has the operation, so an order
// that puts BearSSL first gives BearSSL's hkdf and never its two steps alone.
void check_bearssl_first() {
    using order = backend_list<bearssl, hash2>;
    using whole = hash::detail::first_serving<hash::kdfs::hkdf, hash::hmac_sha2_256, order>::type;
    using extract =
        hash::detail::first_serving<hash::kdfs::hkdf_extract, hash::hmac_sha2_256, order>::type;
    using expand =
        hash::detail::first_serving<hash::kdfs::hkdf_expand, hash::hmac_sha2_256, order>::type;
    using derive =
        hash::detail::first_serving<hash::kdfs::pbkdf2, hash::hmac_sha2_256, order>::type;
#ifdef WEBCPP_HASH_HAS_BEARSSL
    BOOST_TEST((std::is_same_v<whole, bearssl>));
#else
    BOOST_TEST((std::is_same_v<whole, hash2>));
#endif
    BOOST_TEST((std::is_same_v<extract, hash2>));
    BOOST_TEST((std::is_same_v<expand, hash2>));
    BOOST_TEST((std::is_same_v<derive, hash2>));
}

// first_serving's fallbacks (built once with libsodium linked and once without): when no linked
// backend of the order serves, the first that serves, linked or not, whose engine then refuses
// with the Jamfile's line; when none serves at all, backends::hash2. Argon2id and scrypt are
// libsodium's either way.
void check_fallbacks() {
    using hash::backends::sodium;
    using unlinked = hash::detail::first_serving<hash::kdfs::hkdf, hash::hmac_sha2_256,
                                                 backend_list<sodium>>::type;
    using none = hash::detail::first_serving<hash::kdfs::pbkdf2, hash::hmac_sha2_256,
                                             backend_list<sodium, bearssl>>::type;
#ifndef WEBCPP_HASH_HAS_SODIUM
    BOOST_TEST(!hash::detail::linked_v<sodium>);
#endif
    BOOST_TEST((std::is_same_v<unlinked, sodium>));
    BOOST_TEST((std::is_same_v<none, hash2>));
    BOOST_TEST((std::is_same_v<hash::default_backend<hash::kdfs::argon2id>, sodium>));
    BOOST_TEST((std::is_same_v<hash::default_backend<hash::kdfs::scrypt>, sodium>));
}

}  // namespace

int main() {
    check_auto();
    check_bearssl_first();
    check_fallbacks();
    test::check_calls();
    return webcpp::test::exit_status(boost::report_errors());
}
