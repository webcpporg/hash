// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Every keyed cell of backends::xkcp enters its own webcpp::secure::timing_guard first and leaves
// the thread's DIT as it found it, on every target, also where DIT does not apply, each with valid
// input and with input refused before the backend; every digest cell, called without a key,
// enters none; and so does the keccak_256 type, seeded or not (design D3)
// (support/timing_coverage.hpp).
//
// What it covers, by family; the list is doc/capabilities.json's, read at run time. A new cell of
// a family the support knows gets its call from backend_has_v, which capabilities_test keeps equal
// to the table; a cell of a family or function the support does not know fails here until its
// call is written:
// - mac over kmac_128 and kmac_256.
// - Not guarded: each digest cell without a key (SHA-3, SHAKE, TurboSHAKE, Keccak, cSHAKE,
//   TupleHash, ParallelHash, KangarooTwelve), through digest_of and a hasher round; keccak_256.

#include "support/timing_coverage.hpp"

#include <webcpp/hash/backends/xkcp.hpp>
#include <webcpp/hash/keccak.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

int main() {
    namespace test = webcpp::test;
    using webcpp::hash::backends::xkcp;
    test::check_and_run("xkcp", test::keyed_calls<xkcp>());
    test::uncover_digests<xkcp>();
    test::coverage_calls types;
    types.emplace("keccak_256",
                  [] { test::uncover_type<webcpp::hash::keccak_256>("keccak_256 on xkcp", true); });
    test::uncover_types("xkcp", types);
    return webcpp::test::exit_status(boost::report_errors());
}
