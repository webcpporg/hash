// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Every keyed cell of backends::bearssl enters its own webcpp::secure::timing_guard first and
// leaves the thread's DIT as it found it, on every target of the backend, also where DIT does not
// apply, each with valid input and with input refused before the backend; every digest cell, called
// without a key, enters none (support/timing_coverage.hpp).
//
// What it covers, by family; the list is doc/capabilities.json's, read at run time. A new cell of
// a family the support knows gets its call from backend_has_v, which capabilities_test keeps equal
// to the table; a cell of a family or function the support does not know fails here until its
// call is written:
// - mac over hmac<D> for MD5, SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512.
// - hkdf, and hkdf_extract, hkdf_expand and hkdf over pieces, over the six hmacs of those
//   digests.
// - Not guarded: each digest cell, through digest_of and a hasher round.

#include "support/timing_coverage.hpp"

#include <webcpp/hash/backends/bearssl.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

int main() {
    namespace test = webcpp::test;
    using webcpp::hash::backends::bearssl;
    test::check_and_run("bearssl", test::keyed_calls<bearssl>());
    test::uncover_digests<bearssl>();
    return webcpp::test::exit_status(boost::report_errors());
}
