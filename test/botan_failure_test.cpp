// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A failure of Botan (spec sections 2.8 and 7.5), provoked through the seam
// WEBCPP_HASH_DETAIL_TEST_BOTAN_NAME, which the test's Jamfile defines to "NO-SUCH-HASH", a name
// Botan does not know: its create_or_throw throws Lookup_Error, which the boundary catches, so
// that digest_of, a hasher's make and mac answer backend_failure, digest_of and mac with their
// output zeroed, and no exception leaves webcpp::hash. A guard's refusal still comes first.

#include <webcpp/hash/backends/botan.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#ifndef WEBCPP_HASH_DETAIL_TEST_BOTAN_NAME
#error "the test's Jamfile defines WEBCPP_HASH_DETAIL_TEST_BOTAN_NAME"
#endif

namespace {

namespace hash = webcpp::hash;
namespace digests = webcpp::hash::digests;
namespace macs = webcpp::hash::macs;
using hash::backends::botan;

bool failed_with(boost::system::result<void> const& outcome, hash::error expected) {
    return outcome.has_error() && outcome.error() == expected;
}

bool zeroed(std::span<std::uint8_t const> output) {
    return std::ranges::all_of(output, [](std::uint8_t b) { return b == 0; });
}

std::array<std::uint8_t, 3> const abc{0x61, 0x62, 0x63};

// A digest of each kind: a HashFunction, an XOF, BLAKE2b unkeyed and keyed.
template <class Tag>
void digest_fails(std::size_t size, hash::digest_options<Tag> const& options = {}) {
    std::array<std::uint8_t, 64> output{};
    output.fill(0x55);
    auto const out = std::span(output).first(size);
    BOOST_TEST(
        failed_with(hash::digest_of<Tag, botan>(out, abc, options), hash::error::backend_failure));
    BOOST_TEST(zeroed(out));
    auto const made = hash::hasher<Tag, botan>::make(options);
    BOOST_TEST(made.has_error() && made.error() == hash::error::backend_failure);
}

// A MAC of each kind: HMAC (with a key Botan's HMAC would refuse, hashed first), KMAC, SipHash,
// keyed BLAKE2b.
template <class Tag>
void mac_fails(std::size_t size, std::size_t key_size) {
    std::array<std::uint8_t, 64> output{};
    output.fill(0x55);
    auto const out = std::span(output).first(size);
    std::vector<std::uint8_t> const key(key_size, 0x0b);
    BOOST_TEST(failed_with(hash::mac<Tag, botan>(out, key, abc), hash::error::backend_failure));
    BOOST_TEST(zeroed(out));
}

}  // namespace

int main() {
    digest_fails<digests::sha2_256>(32);
    digest_fails<digests::whirlpool>(64);
    digest_fails<digests::shake_128>(64);
    digest_fails<digests::blake2b>(32, {.output_size = 32});
    std::array<std::uint8_t, 16> const key{};
    digest_fails<digests::blake2b>(64, {.key = key});

    mac_fails<macs::hmac<digests::sha2_256>>(32, 32);
    mac_fails<macs::hmac<digests::sha2_256>>(32, 9000);
    mac_fails<macs::kmac_128>(32, 32);
    mac_fails<macs::siphash_2_4>(8, 16);
    mac_fails<macs::blake2b_mac>(64, 64);

    // A guard's refusal comes before Botan: the output untouched.
    std::array<std::uint8_t, 31> short_output{};
    short_output.fill(0x55);
    BOOST_TEST(failed_with(hash::digest_of<digests::sha2_256, botan>(short_output, abc),
                           hash::error::invalid_output_size));
    BOOST_TEST(std::ranges::all_of(short_output, [](std::uint8_t b) { return b == 0x55; }));
    return webcpp::test::exit_status(boost::report_errors());
}
