// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Every keyed cell of backends::sodium enters its own webcpp::secure::timing_guard first and leaves
// the thread's DIT as it found it, on every target of the backend, also where DIT does not apply,
// each with valid input and with input refused before the backend; every digest cell, called
// without a key, enters none (support/timing_coverage.hpp).
//
// What it covers, by family; the list is doc/capabilities.json's, read at run time. A new cell of
// a family the support knows gets its call from backend_has_v, which capabilities_test keeps equal
// to the table; a cell of a family or function the support does not know fails here until its
// call is written:
// - mac over siphash_2_4, siphash_2_4x, blake2b_mac, hmac<sha2_256> and hmac<sha2_512>.
// - hkdf_extract, hkdf_expand and hkdf, each also over pieces, over hmac_sha2_256 and
//   hmac_sha2_512; blake2b_subkey.
// - argon2id; argon2 of argon2i and argon2id; scrypt.
// - BLAKE2b with a key: digest_of and a hasher round (design D1).
// - Not guarded: each digest cell without a key, through digest_of and a hasher round.

#include "support/timing_coverage.hpp"

#include <webcpp/hash/backends/sodium.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

int main() {
    namespace test = webcpp::test;
    using webcpp::hash::backends::sodium;
    test::check_and_run("sodium", test::keyed_calls<sodium>());
    test::uncover_digests<sodium>();
    return webcpp::test::exit_status(boost::report_errors());
}
