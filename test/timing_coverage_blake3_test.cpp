// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The keyed modes of the blake3 type, the one keyed function of backends::blake3, enter their own
// detail::timing_guard first and leave the thread's DIT as it found it, on every target, also
// where DIT does not apply; its digest cell, called through digest_of and a hasher round, and the
// blake3 type in its plain mode enter none (support/timing_coverage.hpp).
//
// What it covers, by family; the list is doc/capabilities.json's, read at run time, and a cell
// the table gains fails here until the support has its call:
// - The blake3 type keyed (design D1), which the table holds no keyed cell of: keyed and
//   derive_key, and the seeds that key (a non-zero integer, bytes), then update (both
//   overloads), result, squeeze and reset of a keyed object (ruling H4, H5).
// - Not guarded: digests::blake3, through digest_of and a hasher round; the blake3 type made by
//   its default constructor, fed, read, squeezed and reset (design D2, D3).

#include "support/timing_coverage.hpp"

#include <webcpp/hash/backends/blake3.hpp>
#include <webcpp/hash/blake3.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace {

namespace test = webcpp::test;
using webcpp::hash::blake3;

// The member functions of a keyed object, each entering its own guard first; `what` says how the
// object was keyed.
void cover_keyed_members(blake3& keyed, std::string const& what) {
    auto const& bytes = test::coverage_input;
    test::covered("blake3::update(void const*) of " + what,
                  [&] { keyed.update(static_cast<void const*>(bytes.data()), bytes.size()); });
    test::covered("blake3::update(unsigned char const*) of " + what, [&] {
        keyed.update(static_cast<unsigned char const*>(bytes.data()), bytes.size());
    });
    test::covered("blake3::result of " + what, [&] { BOOST_TEST(keyed.result().size() == 32); });
    test::covered("blake3::squeeze of " + what, [&] {
        std::array<std::uint8_t, 70> out{};
        keyed.squeeze(out, 3);
    });
    test::covered("blake3::reset of " + what, [&] { keyed.reset(); });
}

// The keyed modes: each factory and each seed that keys, then the members of the object each
// leaves.
void cover_keyed_blake3() {
    auto const& bytes = test::coverage_input;
    std::optional<blake3> keyed;
    test::covered("blake3::keyed on blake3",
                  [&] { keyed.emplace(blake3::keyed(test::coverage_key)); });
    if (keyed) {
        cover_keyed_members(*keyed, "a keyed object on blake3");
    }
    std::optional<blake3> derived;
    test::covered("blake3::derive_key on blake3",
                  [&] { derived.emplace(blake3::derive_key("webcpp coverage")); });
    if (derived) {
        cover_keyed_members(*derived, "a derived object on blake3");
    }
    std::optional<blake3> seeded;
    test::covered("blake3::blake3 of a non-zero integer seed on blake3",
                  [&] { seeded.emplace(std::uint64_t{7}); });
    if (seeded) {
        cover_keyed_members(*seeded, "an object of an integer seed on blake3");
    }
    std::optional<blake3> of_bytes;
    test::covered("blake3::blake3(unsigned char const*) of a seed of bytes on blake3", [&] {
        of_bytes.emplace(static_cast<unsigned char const*>(bytes.data()), bytes.size());
    });
    // The delegating constructor of void const* holds none: the one it delegates to runs first.
    test::covered(
        "blake3::blake3(unsigned char const*) of a seed of bytes, through void const*, on blake3",
        [&] { blake3 const through{static_cast<void const*>(bytes.data()), bytes.size()}; });
    if (of_bytes) {
        cover_keyed_members(*of_bytes, "an object of a seed of bytes on blake3");
    }
}

// The plain mode, on public data: no step enters a guard.
void uncover_plain_blake3() {
    auto const& bytes = test::coverage_input;
    test::uncover_type<blake3>("blake3 on blake3", false);
    blake3 plain;
    test::uncovered("blake3::squeeze of a plain object on blake3", [&] {
        std::array<std::uint8_t, 70> out{};
        plain.squeeze(out, 3);
    });
    test::uncovered("blake3::reset of a plain object on blake3", [&] { plain.reset(); });
    test::uncovered("blake3::blake3 of a zero integer seed on blake3",
                    [&] { blake3 const zero{std::uint64_t{0}}; });
    test::uncovered("blake3::blake3 of a seed of no bytes on blake3", [&] {
        blake3 const empty{static_cast<unsigned char const*>(bytes.data()), std::size_t{0}};
    });
}

}  // namespace

int main() {
    using webcpp::hash::backends::blake3;
    auto calls = test::keyed_calls<blake3>();
    calls.emplace(test::keyed_blake3_cell, cover_keyed_blake3);
    test::check_and_run("blake3", calls);
    test::uncover_digests<blake3>();
    test::coverage_calls types;
    types.emplace("blake3", uncover_plain_blake3);
    test::uncover_types("blake3", types);
    return webcpp::test::exit_status(boost::report_errors());
}
