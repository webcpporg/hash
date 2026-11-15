// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// HKDF's guards (spec section 2.8) at their limits, for hmac_sha2_256: the output of 1 to 8,160
// bytes (255 times 32), the PRK of exactly 32 bytes, the info of at most 32,768 bytes. A refusal
// leaves the output as it was; a backend's failure zeroes it (a backend of this test's own).

#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/system/result.hpp>

#include <webcpp/test/exit_status.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
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
struct webcpp::hash::detail::hkdf_engine<test_backends::failing, webcpp::hash::hmac_sha2_256> {
    using digest_type = webcpp::hash::hmac_sha2_256::result_type;

    static boost::system::result<digest_type> extract(
        std::span<std::uint8_t const> /*salt*/, std::span<std::uint8_t const> /*ikm*/) noexcept {
        return webcpp::hash::error::backend_failure;
    }

    static boost::system::result<void> expand(std::span<std::uint8_t> output,
                                              std::span<std::uint8_t const> /*prk*/,
                                              std::span<std::uint8_t const> /*info*/) noexcept {
        std::ranges::fill(output, std::uint8_t{0x55});
        return webcpp::hash::error::backend_failure;
    }

    static boost::system::result<void> extract_and_expand(
        std::span<std::uint8_t> output, std::span<std::uint8_t const> /*salt*/,
        std::span<std::uint8_t const> /*ikm*/, std::span<std::uint8_t const> /*info*/) noexcept {
        std::ranges::fill(output, std::uint8_t{0x55});
        return webcpp::hash::error::backend_failure;
    }
};

namespace {

using hmac = hash::hmac_sha2_256;
using backend = hash::backends::hash2;

constexpr std::uint8_t untouched = 0xaa;

std::vector<std::uint8_t> filled(std::size_t size, std::uint8_t value) {
    std::vector<std::uint8_t> bytes(size, value);
    return bytes;
}

bool all_of(std::span<std::uint8_t const> bytes, std::uint8_t value) {
    return std::ranges::all_of(bytes, [value](std::uint8_t b) { return b == value; });
}

// hkdf_expand on an output of `size` bytes from a buffer of 0xaa with one byte more, past its
// end, which no call may write.
boost::system::result<void> expand_into(std::vector<std::uint8_t>& buffer, std::size_t size,
                                        std::size_t prk_size, std::size_t info_size) {
    buffer = filled(size + 1, untouched);
    const auto prk = filled(prk_size, 0x0b);
    const auto info = filled(info_size, 0xf0);
    return hash::hkdf_expand<hmac, backend>(std::span<std::uint8_t>(buffer.data(), size), prk,
                                            info);
}

boost::system::result<void> hkdf_into(std::vector<std::uint8_t>& buffer, std::size_t size,
                                      std::size_t info_size) {
    buffer = filled(size + 1, untouched);
    const auto salt = filled(13, 0x01);
    const auto ikm = filled(22, 0x0b);
    const auto info = filled(info_size, 0xf0);
    return hash::hkdf<hmac, backend>(std::span<std::uint8_t>(buffer.data(), size), salt, ikm, info);
}

// hkdf_expand (with a valid PRK and info), or hkdf, on an output of `size` bytes.
boost::system::result<void> derive_into(bool together, std::vector<std::uint8_t>& buffer,
                                        std::size_t size) {
    return together ? hkdf_into(buffer, size, 10) : expand_into(buffer, size, 32, 10);
}

void test_output_size() {
    std::vector<std::uint8_t> buffer;
    for (const bool together : {false, true}) {
        const auto empty = derive_into(together, buffer, 0);
        BOOST_TEST(empty.has_error() && empty.error() == hash::error::invalid_output_size);
        BOOST_TEST(all_of(buffer, untouched));

        const auto longest = derive_into(together, buffer, 8160);
        BOOST_TEST(longest.has_value());
        BOOST_TEST(!all_of(std::span<std::uint8_t const>(buffer.data() + 8128, 32), untouched));
        BOOST_TEST_EQ(buffer.back(), untouched);

        const auto one_more = derive_into(together, buffer, 8161);
        BOOST_TEST(one_more.has_error() && one_more.error() == hash::error::invalid_output_size);
        BOOST_TEST(all_of(buffer, untouched));
    }
}

void test_prk_size() {
    std::vector<std::uint8_t> buffer;
    for (const std::size_t size : {std::size_t{0}, std::size_t{31}, std::size_t{33}}) {
        const auto refused = expand_into(buffer, 42, size, 10);
        BOOST_TEST(refused.has_error() && refused.error() == hash::error::invalid_key_size);
        BOOST_TEST(all_of(buffer, untouched));
    }
    BOOST_TEST(expand_into(buffer, 42, 32, 10).has_value());
    BOOST_TEST(!all_of(std::span<std::uint8_t const>(buffer.data(), 42), untouched));
}

void test_info_size() {
    std::vector<std::uint8_t> buffer;
    BOOST_TEST(expand_into(buffer, 42, 32, 32768).has_value());
    BOOST_TEST(!all_of(std::span<std::uint8_t const>(buffer.data(), 42), untouched));
    BOOST_TEST(hkdf_into(buffer, 42, 32768).has_value());
    BOOST_TEST(!all_of(std::span<std::uint8_t const>(buffer.data(), 42), untouched));

    auto refused = expand_into(buffer, 42, 32, 32769);
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::input_too_long);
    BOOST_TEST(all_of(buffer, untouched));
    refused = hkdf_into(buffer, 42, 32769);
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::input_too_long);
    BOOST_TEST(all_of(buffer, untouched));
}

// The guards run in spec 2.8's order: the output, then the PRK, then the info.
void test_order() {
    std::vector<std::uint8_t> buffer;
    auto refused = expand_into(buffer, 0, 31, 32769);
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::invalid_output_size);
    refused = expand_into(buffer, 42, 31, 32769);
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::invalid_key_size);
    refused = hkdf_into(buffer, 8161, 32769);
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::invalid_output_size);
}

// Empty salt, IKM and info are valid, and agree with their spelled-out forms where RFC 5869
// defines one (an empty salt is HashLen zeros).
void test_empty_inputs() {
    const std::vector<std::uint8_t> nothing;
    const auto zeros = filled(32, 0);
    auto empty_salt = hash::hkdf_extract<hmac, backend>(nothing, nothing);
    auto zero_salt = hash::hkdf_extract<hmac, backend>(zeros, nothing);
    if (!BOOST_TEST(empty_salt.has_value() && zero_salt.has_value())) {
        return;
    }
    BOOST_TEST(*empty_salt == *zero_salt);

    std::vector<std::uint8_t> output(32, untouched);
    BOOST_TEST((hash::hkdf<hmac, backend>(output, nothing, nothing, nothing).has_value()));
    BOOST_TEST(!all_of(output, untouched));
}

void test_backend_failure() {
    using test_backends::failing;
    std::vector<std::uint8_t> output(42, untouched);
    const auto prk = filled(32, 0x0b);
    const auto info = filled(10, 0xf0);

    auto failed = hash::hkdf_expand<hmac, failing>(output, prk, info);
    BOOST_TEST(failed.has_error() && failed.error() == hash::error::backend_failure);
    BOOST_TEST(all_of(output, 0));

    output.assign(42, untouched);
    failed = hash::hkdf<hmac, failing>(output, info, prk, info);
    BOOST_TEST(failed.has_error() && failed.error() == hash::error::backend_failure);
    BOOST_TEST(all_of(output, 0));

    const auto no_prk = hash::hkdf_extract<hmac, failing>(info, prk);
    BOOST_TEST(no_prk.has_error() && no_prk.error() == hash::error::backend_failure);

    // A guard's refusal reaches no backend: the failing one does not touch the output.
    output.assign(42, untouched);
    failed = hash::hkdf_expand<hmac, failing>(output, info, info);
    BOOST_TEST(failed.has_error() && failed.error() == hash::error::invalid_key_size);
    BOOST_TEST(all_of(output, untouched));
}

}  // namespace

int main() {
    test_output_size();
    test_prk_size();
    test_info_size();
    test_order();
    test_empty_inputs();
    test_backend_failure();
    return webcpp::test::exit_status(boost::report_errors());
}
