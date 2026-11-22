// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Every keyed cell of backends::openssl enters its own detail::timing_guard first and leaves the
// thread's DIT as it found it, on every target of the backend, also where DIT does not apply,
// each with valid input and with input refused before the backend; every digest cell, called
// without a key, enters none (support/timing_coverage.hpp).
//
// What it covers, by family; the list is doc/capabilities.json's, read at run time. A new cell of
// a family the support knows gets its call from backend_has_v, which capabilities_test keeps equal
// to the table; a cell of a family or function the support does not know fails here until its
// call is written:
// - mac over siphash_2_4, siphash_2_4x, kmac_128, kmac_256, blake2b_mac, blake2s_mac and
//   hmac<D> for each digest of the backend's cells.
// - hkdf_extract, hkdf_expand, hkdf, pbkdf2 and kbkdf over each hmac of hmac.hpp the cells list
//   (all but hmac_ripemd_128); sskdf and x963kdf.
// - argon2id; argon2 of argon2d, argon2i and argon2id; scrypt.
// - BLAKE2b with a key (design D1): digest_of and hasher::make, which the cell refuses
//   (unsupported_by_backend) inside the guard.
// - Not guarded: each digest cell without a key, through digest_of and a hasher round.

#include "support/timing_coverage.hpp"

#include <webcpp/hash/backends/openssl.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

int main() {
    namespace test = webcpp::test;
    using webcpp::hash::backends::openssl;
    test::check_and_run("openssl", test::keyed_calls<openssl>());
    test::uncover_digests<openssl>();
    return webcpp::test::exit_status(boost::report_errors());
}
