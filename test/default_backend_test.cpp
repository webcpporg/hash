// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The default backends (spec 4.1), built once per target with every library the target has, once
// with none, and once with the defines that chose a default before 2026-11-16: backends::hash2 for
// every key derivation over every hmac, whatever the program links and defines, and
// backends::sodium for argon2id and scrypt, the only backend that has them; each default called,
// agreeing with RFC 5869's A.1 and backends::hash2's PBKDF2.

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

void check_key_derivations() {
    test::for_each_kdf_cell(
        []<class Operation, class Hmac> { test::expect_default<Operation, Hmac>("hash2"); });
    // An hmac the library does not take still names backends::hash2, whose refusal is then the
    // only error a call gives (spec 3.3).
    BOOST_TEST((std::is_same_v<hash::default_kdf_backend<int>, hash::backends::hash2>));
    BOOST_TEST((std::is_same_v<hash::default_backend<hash::kdfs::hkdf>, hash::backends::hash2>));
}

void check_password_hashing() {
    BOOST_TEST(
        (std::is_same_v<hash::default_backend<hash::kdfs::argon2id>, hash::backends::sodium>));
    BOOST_TEST((std::is_same_v<hash::default_backend<hash::kdfs::scrypt>, hash::backends::sodium>));
}

}  // namespace

int main() {
    check_key_derivations();
    check_password_hashing();
    test::check_calls();
    return webcpp::test::exit_status(boost::report_errors());
}
