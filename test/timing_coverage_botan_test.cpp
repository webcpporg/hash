// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Every keyed cell of backends::botan enters its own detail::timing_guard first and leaves the
// thread's DIT as it found it, on every target of the backend, also where DIT does not apply,
// each with valid input and with input refused before the backend; every digest cell, called
// without a key, enters none (support/timing_coverage.hpp).
//
// What it covers, by family; the list is doc/capabilities.json's, read at run time. A new cell of
// a family the support knows gets its call from backend_has_v, which capabilities_test keeps equal
// to the table; a cell of a family or function the support does not know fails here until its
// call is written:
// - mac over siphash_2_4, kmac_128, kmac_256, blake2b_mac and hmac<D> for the 23 digests of
//   the backend's cells.
// - hkdf_extract, hkdf_expand, hkdf (each also over pieces), pbkdf2 and kbkdf over each of the 14
//   hmacs the cells list; sskdf and x963kdf.
// - argon2id; argon2 of argon2d, argon2i and argon2id; scrypt; bcrypt and bcrypt_pbkdf.
// - bcrypt_verify (ruling H12) and BLAKE2b with a key, digest_of and a hasher round (design D1),
//   which the table holds no cell of.
// - Not guarded: each digest cell without a key, through digest_of and a hasher round.
// Botan reports its errors by throwing: the test runs with exceptions on, natively and on
// Emscripten, Botan's targets.

#include "support/timing_coverage.hpp"

#include <webcpp/hash/backends/botan.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

int main() {
    namespace test = webcpp::test;
    using webcpp::hash::backends::botan;
    test::check_and_run("botan", test::keyed_calls<botan>());
    test::uncover_digests<botan>();
    return webcpp::test::exit_status(boost::report_errors());
}
