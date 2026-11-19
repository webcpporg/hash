// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// XKCP counts KangarooTwelve's chunks of 8,192 bytes in a size_t (`blockNumber`), which on wasm32
// would wrap past 32 TiB into a wrong digest: webcpp counts the message and the customisation
// string together in 64 bits and refuses the call that would take them past
// kangarootwelve_max_bytes with input_too_long, before XKCP sees the bytes. This program lowers
// that limit to 16 bytes through the seam WEBCPP_HASH_DETAIL_TEST_KANGAROOTWELVE_MAX_BYTES (its
// Jamfile line), so that the guard is reached with small inputs on every target: 16 bytes pass,
// 17 are refused. TurboSHAKE keeps no count and has no such limit.

#include <webcpp/hash/backends/xkcp.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/test/exit_status.hpp>

#include "require.hpp"

#include <boost/core/lightweight_test.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace {

namespace hash = webcpp::hash;
namespace digests = webcpp::hash::digests;
namespace test = webcpp::test;
using webcpp::hash::backends::xkcp;
using bytes = std::vector<std::uint8_t>;

constexpr std::size_t limit = 16;
static_assert(hash::detail::kangarootwelve_max_bytes == limit);

bool failed_with(boost::system::result<void> const& outcome, hash::error expected) {
    return outcome.has_error() && outcome.error() == expected;
}

bool started_with(auto const& started, hash::error expected) {
    return started.has_error() && started.error() == expected;
}

// The customisation alone: 16 bytes pass, 17 are input_too_long from digest_of (its output
// zeroed, an engine's refusal) and from hasher::make.
template <class Digest>
void check_customisation() {
    bytes const at(limit, 0x61);
    bytes const over(limit + 1, 0x61);
    bytes output(32, 0xAA);
    BOOST_TEST((hash::digest_of<Digest, xkcp>(output, {}, {.customisation = at}).has_value()));
    output.assign(32, 0xAA);
    BOOST_TEST(failed_with(hash::digest_of<Digest, xkcp>(output, {}, {.customisation = over}),
                           hash::error::input_too_long));
    BOOST_TEST(output == bytes(32, 0));
    BOOST_TEST((hash::hasher<Digest, xkcp>::make({.customisation = at}).has_value()));
    BOOST_TEST(started_with(hash::hasher<Digest, xkcp>::make({.customisation = over}),
                            hash::error::input_too_long));
}

// The message and the customisation together, in one call and across a hasher's updates.
template <class Digest>
void check_total() {
    bytes const customisation(6, 0x63);
    bytes const message(limit - customisation.size(), 0x61);
    bytes const longer(message.size() + 1, 0x61);
    std::span<std::uint8_t const> const half(message.data(), message.size() / 2);
    bytes once(32);
    bytes output(32, 0xAA);
    BOOST_TEST((hash::digest_of<Digest, xkcp>(once, message, {.customisation = customisation})
                    .has_value()));
    BOOST_TEST(
        failed_with(hash::digest_of<Digest, xkcp>(output, longer, {.customisation = customisation}),
                    hash::error::input_too_long));
    BOOST_TEST(output == bytes(32, 0));

    auto hashing = hash::hasher<Digest, xkcp>::make({.customisation = customisation});
    test::require(BOOST_TEST(hashing.has_value()));
    BOOST_TEST(hashing->update(half).has_value());
    BOOST_TEST(hashing->update(half).has_value());
    BOOST_TEST(hashing->finish(output).has_value());
    BOOST_TEST(output == once);

    auto crossing = hash::hasher<Digest, xkcp>::make({.customisation = customisation});
    test::require(BOOST_TEST(crossing.has_value()));
    BOOST_TEST(crossing->update(message).has_value());
    BOOST_TEST(crossing->update(bytes{}).has_value());
    BOOST_TEST(failed_with(crossing->update(bytes{0x61}), hash::error::input_too_long));
    BOOST_TEST(failed_with(crossing->finish(output), hash::error::invalid_state));

    bytes const whole(limit + 1, 0x61);
    BOOST_TEST(
        failed_with(hash::digest_of<Digest, xkcp>(output, whole), hash::error::input_too_long));
}

// TurboSHAKE counts nothing: more than the lowered limit passes.
template <class Digest>
void check_turboshake_unlimited() {
    bytes const message(4 * limit, 0x61);
    bytes output(32);
    BOOST_TEST((hash::digest_of<Digest, xkcp>(output, message).has_value()));
}

}  // namespace

int main() {
    check_customisation<digests::kt128>();
    check_customisation<digests::kt256>();
    check_total<digests::kt128>();
    check_total<digests::kt256>();
    check_turboshake_unlimited<digests::turboshake_128>();
    check_turboshake_unlimited<digests::turboshake_256>();
    return webcpp::test::exit_status(boost::report_errors());
}
