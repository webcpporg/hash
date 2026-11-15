// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// PBKDF2's guards (spec section 2.9), for hmac_sha2_256: an output of 1 to (2^32 - 1) times 32
// bytes, at least one iteration. A refusal leaves the output as it was; a backend's failure
// zeroes it (a backend of this test's own).

#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/detail/limits.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/pbkdf2.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/system/result.hpp>

#include <webcpp/test/exit_status.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <vector>

namespace hash = webcpp::hash;

namespace test_backends {
namespace {

// A backend whose engine writes into the output, then fails: the public function zeroes it.
struct failing {};

}  // namespace
}  // namespace test_backends

template <>
struct webcpp::hash::detail::pbkdf2_engine<test_backends::failing, webcpp::hash::hmac_sha2_256> {
    static boost::system::result<void> derive(std::span<std::uint8_t> output,
                                              std::span<std::uint8_t const> /*password*/,
                                              std::span<std::uint8_t const> /*salt*/,
                                              std::uint64_t /*iterations*/) noexcept {
        std::ranges::fill(output, std::uint8_t{0x55});
        return webcpp::hash::error::backend_failure;
    }
};

namespace {

using hmac = hash::hmac_sha2_256;
using backend = hash::backends::hash2;

constexpr std::uint8_t untouched = 0xaa;

// The longest output for hmac_sha2_256: (2^32 - 1) blocks of 32 bytes, wider than size_t on wasm32.
constexpr std::uint64_t longest = ((std::uint64_t{1} << 32U) - 1) * 32;

bool all_of(std::span<std::uint8_t const> bytes, std::uint8_t value) {
    return std::ranges::all_of(bytes, [value](std::uint8_t b) { return b == value; });
}

const std::array<std::uint8_t, 8> password{'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
const std::array<std::uint8_t, 4> salt{'s', 'a', 'l', 't'};

void test_output_size() {
    std::array<std::uint8_t, 33> buffer{};
    buffer.fill(untouched);
    auto refused =
        hash::pbkdf2<hmac, backend>(std::span<std::uint8_t>(buffer.data(), 0), password, salt, 1);
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::invalid_output_size);
    BOOST_TEST(all_of(buffer, untouched));

    BOOST_TEST(hash::detail::exceeds(longest + 1, longest));
    BOOST_TEST(!hash::detail::exceeds(longest, longest));

    // The guard against an output past the limit, natively: a span of limit + 1 bytes over one
    // byte, which the guard refuses before anything reads or writes it. On wasm32 no span is that
    // long (the limit exceeds SIZE_MAX), so the guard is unreachable there.
    if constexpr (std::numeric_limits<std::size_t>::max() > longest) {
        const auto past = static_cast<std::size_t>(longest + 1);
        refused = hash::pbkdf2<hmac, backend>(std::span<std::uint8_t>(buffer.data(), past),
                                              password, salt, 1);
        BOOST_TEST(refused.has_error() && refused.error() == hash::error::invalid_output_size);
        BOOST_TEST(all_of(buffer, untouched));
    }

    // One block and a byte: the second block is cut to one byte, the byte past it untouched.
    BOOST_TEST(
        (hash::pbkdf2<hmac, backend>(std::span<std::uint8_t>(buffer.data(), 33), password, salt, 1)
             .has_value()));
    BOOST_TEST(!all_of(std::span<std::uint8_t const>(buffer.data(), 32), untouched));
}

void test_iterations() {
    std::array<std::uint8_t, 32> buffer{};
    buffer.fill(untouched);
    auto refused = hash::pbkdf2<hmac, backend>(buffer, password, salt, 0);
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::invalid_iterations);
    BOOST_TEST(all_of(buffer, untouched));

    // The output's guard comes first.
    refused =
        hash::pbkdf2<hmac, backend>(std::span<std::uint8_t>(buffer.data(), 0), password, salt, 0);
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::invalid_output_size);
}

// An empty password and an empty salt are valid inputs.
void test_empty_inputs() {
    std::array<std::uint8_t, 32> buffer{};
    buffer.fill(untouched);
    BOOST_TEST((hash::pbkdf2<hmac, backend>(buffer, {}, {}, 2).has_value()));
    BOOST_TEST(!all_of(buffer, untouched));
}

void test_backend_failure() {
    std::array<std::uint8_t, 32> buffer{};
    buffer.fill(untouched);
    auto failed = hash::pbkdf2<hmac, test_backends::failing>(buffer, password, salt, 1);
    BOOST_TEST(failed.has_error() && failed.error() == hash::error::backend_failure);
    BOOST_TEST(all_of(buffer, 0));

    // A guard's refusal reaches no backend: the failing one does not touch the output.
    buffer.fill(untouched);
    failed = hash::pbkdf2<hmac, test_backends::failing>(buffer, password, salt, 0);
    BOOST_TEST(failed.has_error() && failed.error() == hash::error::invalid_iterations);
    BOOST_TEST(all_of(buffer, untouched));
}

}  // namespace

int main() {
    test_output_size();
    test_iterations();
    test_empty_inputs();
    test_backend_failure();
    return webcpp::test::exit_status(boost::report_errors());
}
