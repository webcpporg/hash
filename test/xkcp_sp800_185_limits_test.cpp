// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// SP 800-185's lengths are bits, which XKCP holds in a size_t: a function name, customisation,
// KMAC key, TupleHash element or fixed-length output is at most SIZE_MAX / 8 bytes (512 MiB on
// wasm32), and webcpp refuses a longer one before XKCP sees it (preflight-b.md M7). This program
// lowers that limit to 16 bytes through the seam WEBCPP_HASH_DETAIL_TEST_SP800_185_MAX_BYTES
// (its Jamfile line), so that each guard is reached with small inputs on every target: 16 bytes
// pass, 17 are refused, the output untouched by a guard.

#include <webcpp/hash/backends/xkcp.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/mac.hpp>
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
namespace macs = webcpp::hash::macs;
namespace test = webcpp::test;
using webcpp::hash::backends::xkcp;
using bytes = std::vector<std::uint8_t>;

constexpr std::size_t limit = 16;
static_assert(hash::detail::sp800_185_max_bytes == limit);

bool failed_with(boost::system::result<void> const& outcome, hash::error expected) {
    return outcome.has_error() && outcome.error() == expected;
}

bool started_with(auto const& started, hash::error expected) {
    return started.has_error() && started.error() == expected;
}

// A function name or a customisation over the limit: input_too_long, from digest_of (output
// untouched), hasher::make and mac. The fixed-length outputs are within the limit.
void check_strings() {
    bytes const at(limit, 0x61);
    bytes const over(limit + 1, 0x61);
    bytes const input{1, 2, 3};
    bytes output(32, 0xAA);

    BOOST_TEST((hash::digest_of<digests::cshake_128, xkcp>(output, input, {.function_name = at})
                    .has_value()));
    output.assign(32, 0xAA);
    BOOST_TEST(failed_with(
        hash::digest_of<digests::cshake_128, xkcp>(output, input, {.function_name = over}),
        hash::error::input_too_long));
    BOOST_TEST(output == bytes(32, 0xAA));
    BOOST_TEST(failed_with(
        hash::digest_of<digests::cshake_256, xkcp>(output, input, {.customisation = over}),
        hash::error::input_too_long));
    BOOST_TEST(started_with(hash::hasher<digests::cshake_256, xkcp>::make({.customisation = over}),
                            hash::error::input_too_long));

    output.assign(limit, 0xAA);
    BOOST_TEST((hash::digest_of<digests::tuplehash_128, xkcp>(output, input, {.customisation = at})
                    .has_value()));
    BOOST_TEST(failed_with(
        hash::digest_of<digests::tuplehash_128, xkcp>(output, input, {.customisation = over}),
        hash::error::input_too_long));
    BOOST_TEST(
        started_with(hash::hasher<digests::tuplehash_256, xkcp>::make({.customisation = over}),
                     hash::error::input_too_long));

    BOOST_TEST((hash::digest_of<digests::parallelhash_128, xkcp>(
                    output, input, {.block_size = 8, .customisation = at})
                    .has_value()));
    BOOST_TEST(failed_with(hash::digest_of<digests::parallelhash_128, xkcp>(
                               output, input, {.block_size = 8, .customisation = over}),
                           hash::error::input_too_long));
    BOOST_TEST(started_with(hash::hasher<digests::parallelhash_256, xkcp>::make(
                                {.block_size = 8, .customisation = over}),
                            hash::error::input_too_long));

    output.assign(16, 0xAA);
    BOOST_TEST(
        (hash::mac<macs::kmac_128, xkcp>(output, at, input, {.customisation = at}).has_value()));
    output.assign(16, 0xAA);
    BOOST_TEST(
        failed_with(hash::mac<macs::kmac_256, xkcp>(output, at, input, {.customisation = over}),
                    hash::error::input_too_long));
    BOOST_TEST(output == bytes(16, 0xAA));
}

// A KMAC key over the limit is invalid_key_size; a KMAC tag over it invalid_output_size, in
// both forms; a fixed-length TupleHash or ParallelHash output over it invalid_output_size, from
// digest_of and hasher::finish (the hasher still hashing), while their XOF forms, squeezed in
// pieces, take any length.
void check_key_and_outputs() {
    bytes const input{1, 2, 3};
    bytes const at(limit, 0x0b);
    bytes const over(limit + 1, 0x0b);
    bytes tag(limit, 0xAA);
    BOOST_TEST((hash::mac<macs::kmac_128, xkcp>(tag, at, input).has_value()));
    BOOST_TEST(failed_with(hash::mac<macs::kmac_128, xkcp>(tag, over, input),
                           hash::error::invalid_key_size));
    bytes long_tag(limit + 1, 0xAA);
    BOOST_TEST(failed_with(hash::mac<macs::kmac_128, xkcp>(long_tag, at, input),
                           hash::error::invalid_output_size));
    BOOST_TEST(failed_with(hash::mac<macs::kmac_256, xkcp>(long_tag, at, input, {.xof = true}),
                           hash::error::invalid_output_size));
    BOOST_TEST(long_tag == bytes(limit + 1, 0xAA));

    bytes fixed(limit);
    bytes past(limit + 1, 0xAA);
    BOOST_TEST((hash::digest_of<digests::tuplehash_128, xkcp>(fixed, input).has_value()));
    BOOST_TEST(failed_with(hash::digest_of<digests::tuplehash_128, xkcp>(past, input),
                           hash::error::invalid_output_size));
    BOOST_TEST(failed_with(
        hash::digest_of<digests::parallelhash_256, xkcp>(past, input, {.block_size = 8}),
        hash::error::invalid_output_size));
    BOOST_TEST(past == bytes(limit + 1, 0xAA));
    BOOST_TEST(
        (hash::digest_of<digests::tuplehash_256, xkcp>(past, input, {.xof = true}).has_value()));
    BOOST_TEST((hash::digest_of<digests::parallelhash_128, xkcp>(past, input,
                                                                 {.block_size = 8, .xof = true})
                    .has_value()));
    bytes long_output(1000);
    BOOST_TEST((hash::digest_of<digests::cshake_128, xkcp>(long_output, input).has_value()));

    auto hashing = hash::hasher<digests::parallelhash_128, xkcp>::make({.block_size = 8});
    test::require(BOOST_TEST(hashing.has_value()));
    BOOST_TEST(hashing->update(input).has_value());
    BOOST_TEST(failed_with(hashing->finish(past), hash::error::invalid_output_size));
    BOOST_TEST(hashing->finish(fixed).has_value());
}

// A TupleHash element over the limit: input_too_long, from hasher::update (the hasher then
// spent) and from digest_of, whose input is the tuple's one element; cSHAKE takes any input, fed
// to XKCP in pieces.
void check_elements() {
    bytes const at(limit, 0x61);
    bytes const over(limit + 1, 0x61);
    bytes output(limit);
    BOOST_TEST((hash::digest_of<digests::tuplehash_128, xkcp>(output, at).has_value()));
    BOOST_TEST(failed_with(hash::digest_of<digests::tuplehash_128, xkcp>(output, over),
                           hash::error::input_too_long));
    auto hashing = hash::hasher<digests::tuplehash_256, xkcp>::make();
    test::require(BOOST_TEST(hashing.has_value()));
    BOOST_TEST(hashing->update(at).has_value());
    BOOST_TEST(failed_with(hashing->update(over), hash::error::input_too_long));
    BOOST_TEST(failed_with(hashing->finish(output), hash::error::invalid_state));
    BOOST_TEST((hash::digest_of<digests::cshake_256, xkcp>(output, over).has_value()));
}

// ParallelHash's whole input over the limit: XKCP counts it in bits in a size_t, across calls,
// and on wasm32 that count wraps past 512 MiB into a wrong digest. The engine counts the bytes
// itself and refuses the call that would pass the limit with input_too_long, before XKCP sees
// it: from digest_of, and from the update that crosses it in a hasher (then spent), however the
// input is cut; up to the limit, in pieces, the digest is digest_of's.
void check_parallel_total() {
    bytes const at(limit, 0x61);
    bytes const over(limit + 1, 0x61);
    std::span<std::uint8_t const> const half(at.data(), limit / 2);
    bytes output(limit);
    bytes once(limit);
    BOOST_TEST((
        hash::digest_of<digests::parallelhash_128, xkcp>(once, at, {.block_size = 8}).has_value()));
    BOOST_TEST(failed_with(
        hash::digest_of<digests::parallelhash_128, xkcp>(output, over, {.block_size = 8}),
        hash::error::input_too_long));
    BOOST_TEST(failed_with(hash::digest_of<digests::parallelhash_256, xkcp>(
                               output, over, {.block_size = 8, .xof = true}),
                           hash::error::input_too_long));

    auto hashing = hash::hasher<digests::parallelhash_128, xkcp>::make({.block_size = 8});
    test::require(BOOST_TEST(hashing.has_value()));
    BOOST_TEST(hashing->update(half).has_value());
    BOOST_TEST(hashing->update(half).has_value());
    BOOST_TEST(hashing->finish(output).has_value());
    BOOST_TEST(output == once);

    auto crossing = hash::hasher<digests::parallelhash_256, xkcp>::make({.block_size = 8});
    test::require(BOOST_TEST(crossing.has_value()));
    BOOST_TEST(crossing->update(at).has_value());
    BOOST_TEST(crossing->update(bytes{}).has_value());
    BOOST_TEST(failed_with(crossing->update(bytes{0x61}), hash::error::input_too_long));
    BOOST_TEST(failed_with(crossing->finish(output), hash::error::invalid_state));
}

}  // namespace

int main() {
    check_strings();
    check_key_and_outputs();
    check_elements();
    check_parallel_total();
    return webcpp::test::exit_status(boost::report_errors());
}
