// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// RFC 9861's functions on backends::xkcp: KT128 and KT256 with their customisation string C, and
// TurboSHAKE128 and TurboSHAKE256 with their domain byte D, through digest_of and hasher.
//
// - Every test vector of RFC 9861, section 5 (36 of KangarooTwelve, 31 of TurboSHAKE, counted),
//   each in one call and through a hasher fed in two pieces at three splits, and those of up to
//   17^3 bytes also in pieces of 7 bytes, across KangarooTwelve's 8,192-byte chunks. The messages
//   of 17^6 bytes (24 MB, more than Emscripten's fixed memory) are fed to a hasher from a buffer
//   of whole periods of the pattern, never held at once.
// - The default backend of each tag is backends::xkcp, and gives the same bytes.
// - A hasher of KT128 reads C at finish, from the span make took (ruling R33): the caller keeps
//   it alive until then.
// - TurboSHAKE's domain byte outside 0x01..0x7F is invalid_parameters, before any engine
//   (ruling R25): XKCP itself would answer 0x00 with an error and compute a value for 0x80 and
//   above; the output is untouched.
// - A longer output starts with the shorter one, an empty output is invalid_output_size, and the
//   options' defaults (D = 0x1F, C empty) are the RFC's.
// - kangarootwelve_max_bytes, the guard of XKCP's count of chunks, is no limit where a size_t has
//   64 bits; its seam test is xkcp_kangarootwelve_limits_test.cpp.
//
// Agreement with libsodium's TurboSHAKE, on random inputs, outputs and domain bytes, is in
// agreement_families_test.cpp (the task "Agreement across increments", ruling R6).

#include <webcpp/hash/backends/xkcp.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/test/exit_status.hpp>

#include "require.hpp"
#include "support/hex.hpp"
#include "support/rfc9861_kangarootwelve.hpp"
#include "support/rfc9861_turboshake.hpp"

#include <boost/core/lightweight_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace {

namespace hash = webcpp::hash;
namespace digests = webcpp::hash::digests;
namespace test = webcpp::test;
using webcpp::hash::backends::xkcp;
using bytes = std::vector<std::uint8_t>;

static_assert(std::is_same_v<hash::default_backend<digests::kt128>, xkcp>);
static_assert(std::is_same_v<hash::default_backend<digests::kt256>, xkcp>);
static_assert(std::is_same_v<hash::default_backend<digests::turboshake_128>, xkcp>);
static_assert(std::is_same_v<hash::default_backend<digests::turboshake_256>, xkcp>);
static_assert(hash::backend_has_v<xkcp, digests::kt128, void>);
static_assert(hash::backend_has_v<xkcp, digests::kt256, void>);
static_assert(hash::backend_has_v<xkcp, digests::turboshake_128, void>);
static_assert(hash::backend_has_v<xkcp, digests::turboshake_256, void>);

// XKCP counts KangarooTwelve's chunks of 8,192 bytes in a size_t: the guard is needed only where
// a size_t is narrower than 64 bits.
static_assert(sizeof(std::size_t) < sizeof(std::uint64_t)
                  ? hash::detail::kangarootwelve_max_bytes ==
                        (std::uint64_t{std::numeric_limits<std::size_t>::max()} * 8192) -
                            (sizeof(std::size_t) + 1)
                  : hash::detail::kangarootwelve_max_bytes ==
                        std::numeric_limits<std::uint64_t>::max());

bool failed_with(boost::system::result<void> const& outcome, hash::error expected) {
    return outcome.has_error() && outcome.error() == expected;
}

bool started_with(auto const& started, hash::error expected) {
    return started.has_error() && started.error() == expected;
}

// ptn(n) of RFC 9861, section 5.
bytes pattern(std::size_t size) {
    bytes out(size);
    for (std::size_t i = 0; i != size; ++i) {
        out[i] = static_cast<std::uint8_t>(i % 251);
    }
    return out;
}

// The output from `offset` on, in hex, as the RFC prints it.
std::string tail_hex(bytes const& output, std::size_t offset) {
    return test::to_hex(std::span<std::uint8_t const>(output).subspan(offset));
}

// The digest of `message` in one call, then through hashers fed in two pieces (split at 0, a
// third and the whole) and, for a message of up to 17^3 bytes, in pieces of 7 bytes: each equal
// to the RFC's bytes from `offset` on.
template <class Digest>
bool agrees(bytes const& message, hash::digest_options<Digest> const& options, std::size_t length,
            std::size_t offset, std::string_view expected) {
    bool fine = true;
    bytes output(length);
    fine = hash::digest_of<Digest, xkcp>(output, message, options).has_value() &&
           tail_hex(output, offset) == expected;
    std::span<std::uint8_t const> const all(message);
    std::array<std::size_t, 3> const cuts{0, message.size() / 3, message.size()};
    for (std::size_t const cut : cuts) {
        auto hashing = hash::hasher<Digest, xkcp>::make(options);
        bytes piecewise(length);
        fine = fine && hashing.has_value() && hashing->update(all.first(cut)).has_value() &&
               hashing->update(all.subspan(cut)).has_value() &&
               hashing->finish(piecewise).has_value() && tail_hex(piecewise, offset) == expected;
    }
    if (message.size() <= 4913) {
        auto hashing = hash::hasher<Digest, xkcp>::make(options);
        fine = fine && hashing.has_value();
        for (std::size_t at = 0; fine && at < message.size(); at += 7) {
            fine = hashing->update(all.subspan(at, std::min<std::size_t>(7, message.size() - at)))
                       .has_value();
        }
        bytes piecewise(length);
        fine = fine && hashing->finish(piecewise).has_value() &&
               tail_hex(piecewise, offset) == expected;
    }
    return fine;
}

// The messages longer than this are fed to a hasher from a buffer of whole periods of ptn, the
// only way through which a 24 MB message fits Emscripten's 16 MB of fixed memory.
constexpr std::size_t streamed_from = std::size_t{4} * 1024 * 1024;

// The digest of ptn(size), fed to a hasher in pieces of 64 periods of the pattern (16,064 bytes,
// a size that is not a multiple of KangarooTwelve's chunks): equal to the RFC's bytes.
template <class Digest>
bool agrees_streamed(std::size_t size, hash::digest_options<Digest> const& options,
                     std::size_t length, std::size_t offset, std::string_view expected) {
    bytes const periods = pattern(std::size_t{251} * 64);
    auto hashing = hash::hasher<Digest, xkcp>::make(options);
    bool fine = hashing.has_value();
    for (std::size_t at = 0; fine && at < size; at += periods.size()) {
        auto const piece =
            std::span<std::uint8_t const>(periods).first(std::min(periods.size(), size - at));
        fine = hashing->update(piece).has_value();
    }
    bytes output(length);
    return fine && hashing->finish(output).has_value() && tail_hex(output, offset) == expected;
}

// One vector: its message written or ptn(n), the latter streamed when it is long.
template <class Digest, class Vector>
bool agrees_with(Vector const& vector, hash::digest_options<Digest> const& options) {
    if (vector.pattern && vector.pattern_length > streamed_from) {
        return agrees_streamed<Digest>(vector.pattern_length, options, vector.length, vector.offset,
                                       vector.expected);
    }
    bytes const message =
        vector.pattern ? pattern(vector.pattern_length) : test::from_hex(vector.message);
    return agrees<Digest>(message, options, vector.length, vector.offset, vector.expected);
}

void check_kangarootwelve_vectors() {
    std::size_t counted = 0;
    for (auto const& vector : test::rfc9861_kangarootwelve) {
        bytes const customisation = pattern(vector.customisation_length);
        bool const fine =
            vector.variant == 128
                ? agrees_with<digests::kt128>(vector, {.customisation = customisation})
                : agrees_with<digests::kt256>(vector, {.customisation = customisation});
        if (!BOOST_TEST(fine)) {
            std::cerr << "  KT" << vector.variant << " vector " << counted << '\n';
        }
        ++counted;
    }
    BOOST_TEST_EQ(counted, 36U);
}

void check_turboshake_vectors() {
    std::size_t counted = 0;
    for (auto const& vector : test::rfc9861_turboshake) {
        bool const fine =
            vector.variant == 128
                ? agrees_with<digests::turboshake_128>(vector, {.domain = vector.domain})
                : agrees_with<digests::turboshake_256>(vector, {.domain = vector.domain});
        if (!BOOST_TEST(fine)) {
            std::cerr << "  TurboSHAKE" << vector.variant << " vector " << counted << '\n';
        }
        ++counted;
    }
    BOOST_TEST_EQ(counted, 31U);
}

// The default backend gives the same bytes; the options' defaults are the RFC's: C empty, D 0x1F.
void check_defaults() {
    bytes const message = pattern(300);
    bytes named(48);
    bytes defaulted(48);
    BOOST_TEST((hash::digest_of<digests::kt128, xkcp>(named, message).has_value()));
    BOOST_TEST(
        (hash::digest_of<digests::kt128>(defaulted, message, {.customisation = {}}).has_value()));
    BOOST_TEST(named == defaulted);
    BOOST_TEST((hash::digest_of<digests::kt256, xkcp>(named, message).has_value()));
    BOOST_TEST((hash::digest_of<digests::kt256>(defaulted, message).has_value()));
    BOOST_TEST(named == defaulted);
    BOOST_TEST((hash::digest_of<digests::turboshake_128, xkcp>(named, message).has_value()));
    BOOST_TEST((hash::digest_of<digests::turboshake_128>(defaulted, message, {.domain = 0x1F})
                    .has_value()));
    BOOST_TEST(named == defaulted);
    BOOST_TEST((hash::digest_of<digests::turboshake_256, xkcp>(named, message).has_value()));
    BOOST_TEST((hash::digest_of<digests::turboshake_256>(defaulted, message).has_value()));
    BOOST_TEST(named == defaulted);
    BOOST_TEST_EQ(hash::digest_options<digests::turboshake_128>{}.domain, 0x1F);
    BOOST_TEST_EQ(hash::digest_options<digests::turboshake_256>{}.domain, 0x1F);
    BOOST_TEST(hash::digest_options<digests::kt128>{}.customisation.empty());
    BOOST_TEST(hash::digest_options<digests::kt256>{}.customisation.empty());
}

// The hasher keeps the span of C and reads it at finish (ruling R33).
void check_customisation_read_at_finish() {
    bytes const message = pattern(100);
    bytes customisation = pattern(41);
    auto hashing = hash::hasher<digests::kt128, xkcp>::make({.customisation = customisation});
    test::require(BOOST_TEST(hashing.has_value()));
    BOOST_TEST(hashing->update(message).has_value());
    customisation.assign(customisation.size(), 0xFF);
    bytes read_late(32);
    BOOST_TEST(hashing->finish(read_late).has_value());
    bytes expected(32);
    BOOST_TEST(
        (hash::digest_of<digests::kt128, xkcp>(expected, message, {.customisation = customisation})
             .has_value()));
    BOOST_TEST(read_late == expected);
}

// RFC 9861 allows D from 0x01 to 0x7F; the family refuses another before any engine, the output
// untouched, and XKCP never sees it.
template <class Digest>
void check_domain() {
    bytes const message{1, 2, 3};
    for (unsigned const domain : {0x00U, 0x80U, 0x9FU, 0xFFU}) {
        bytes output(32, 0xAA);
        auto const options =
            hash::digest_options<Digest>{.domain = static_cast<std::uint8_t>(domain)};
        BOOST_TEST(failed_with(hash::digest_of<Digest, xkcp>(output, message, options),
                               hash::error::invalid_parameters));
        BOOST_TEST(output == bytes(32, 0xAA));
        BOOST_TEST(started_with(hash::hasher<Digest, xkcp>::make(options),
                                hash::error::invalid_parameters));
    }
    for (unsigned const domain : {0x01U, 0x06U, 0x7FU}) {
        bytes output(32);
        auto const options =
            hash::digest_options<Digest>{.domain = static_cast<std::uint8_t>(domain)};
        BOOST_TEST((hash::digest_of<Digest, xkcp>(output, message, options).has_value()));
        BOOST_TEST((hash::hasher<Digest, xkcp>::make(options).has_value()));
    }
}

// An extendable output: any size from 1 byte, the shorter the start of the longer; 0 is refused.
template <class Digest>
void check_outputs(hash::digest_options<Digest> const& options) {
    bytes const message = pattern(9000);
    bytes longest(500);
    BOOST_TEST((hash::digest_of<Digest, xkcp>(longest, message, options).has_value()));
    for (std::size_t const size :
         {std::size_t{1}, std::size_t{31}, std::size_t{168}, std::size_t{169}, std::size_t{499}}) {
        bytes output(size);
        BOOST_TEST((hash::digest_of<Digest, xkcp>(output, message, options).has_value()));
        BOOST_TEST(std::equal(output.begin(), output.end(), longest.begin()));
    }
    bytes none;
    BOOST_TEST(failed_with(hash::digest_of<Digest, xkcp>(none, message, options),
                           hash::error::invalid_output_size));
    auto hashing = hash::hasher<Digest, xkcp>::make(options);
    test::require(BOOST_TEST(hashing.has_value()));
    BOOST_TEST(hashing->update(message).has_value());
    BOOST_TEST(failed_with(hashing->finish(none), hash::error::invalid_output_size));
    bytes output(500);
    BOOST_TEST(hashing->finish(output).has_value());
    BOOST_TEST(output == longest);
    BOOST_TEST(failed_with(hashing->finish(output), hash::error::invalid_state));
    BOOST_TEST(failed_with(hashing->update(message), hash::error::invalid_state));
}

}  // namespace

int main() {
    check_kangarootwelve_vectors();
    check_turboshake_vectors();
    check_defaults();
    check_customisation_read_at_finish();
    check_domain<digests::turboshake_128>();
    check_domain<digests::turboshake_256>();
    bytes const customisation = pattern(41);
    check_outputs<digests::kt128>({.customisation = customisation});
    check_outputs<digests::kt256>({});
    check_outputs<digests::turboshake_128>({.domain = 0x0B});
    check_outputs<digests::turboshake_256>({});
    return webcpp::test::exit_status(boost::report_errors());
}
