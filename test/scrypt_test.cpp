// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// scrypt on backends::sodium: RFC 7914's first three cases, the first also with a password and a
// salt that are empty spans whose data() is null (libsodium declares both pointers nonnull); the
// guards of spec 2.11 at their limits, each one also
// passed through to a recording backend of this test's own where a real run would take too much
// memory; libsodium's own limit on N; a backend's failure. The test includes scrypt.hpp alone: a
// program that links libsodium and includes only the function's header gets the backend's engine.

#include <webcpp/hash/error.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/hash/scrypt.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/system/result.hpp>

#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/rfc7914.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace hash = webcpp::hash;
using webcpp::test::to_hex;

namespace test_backends {
namespace {

// A backend whose engine writes into the output, then fails: the public function zeroes it.
struct failing {};

// A backend whose engine counts its calls and succeeds: a call past the guards, with no work.
struct recording {};

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the recording engine's count
int recorded_calls = 0;

}  // namespace
}  // namespace test_backends

template <>
struct webcpp::hash::detail::scrypt_engine<test_backends::failing> {
    static constexpr scrypt_limits limits{.n = 0xffffffffULL};

    static boost::system::result<void> derive(std::span<std::uint8_t> output,
                                              std::span<std::uint8_t const> /*password*/,
                                              std::span<std::uint8_t const> /*salt*/,
                                              std::uint64_t /*n*/, std::uint32_t /*r*/,
                                              std::uint32_t /*p*/) noexcept {
        std::ranges::fill(output, std::uint8_t{0x55});
        return webcpp::hash::error::backend_failure;
    }
};

template <>
struct webcpp::hash::detail::scrypt_engine<test_backends::recording> {
    static constexpr scrypt_limits limits{.n = std::numeric_limits<std::uint64_t>::max()};

    static boost::system::result<void> derive(std::span<std::uint8_t> /*output*/,
                                              std::span<std::uint8_t const> /*password*/,
                                              std::span<std::uint8_t const> /*salt*/,
                                              std::uint64_t /*n*/, std::uint32_t /*r*/,
                                              std::uint32_t /*p*/) noexcept {
        ++test_backends::recorded_calls;
        return {};
    }
};

namespace {

constexpr std::uint8_t untouched = 0xaa;

bool all_of(std::span<std::uint8_t const> bytes, std::uint8_t value) {
    return std::ranges::all_of(bytes, [value](std::uint8_t b) { return b == value; });
}

void test_rfc7914() {
    for (auto const& c : webcpp::test::rfc7914_cases) {
        std::array<std::uint8_t, 64> output{};
        auto const done =
            hash::scrypt(output, webcpp::test::bytes_of(c.password), webcpp::test::bytes_of(c.salt),
                         {.n = c.n, .r = c.r, .p = c.p});
        BOOST_TEST(done.has_value());
        BOOST_TEST_EQ(to_hex(output), std::string(c.output));
    }

    // The first case's empty password and salt as default spans, whose data() is null: scrypt
    // passes libsodium a pointer that is not.
    auto const& first = webcpp::test::rfc7914_cases[0];
    std::span<std::uint8_t const> const nothing{};
    BOOST_TEST(nothing.data() == nullptr);
    std::array<std::uint8_t, 64> output{};
    auto const done =
        hash::scrypt(output, nothing, nothing, {.n = first.n, .r = first.r, .p = first.p});
    BOOST_TEST(done.has_value());
    BOOST_TEST_EQ(to_hex(output), std::string(first.output));
}

const std::array<std::uint8_t, 8> password{'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
const std::array<std::uint8_t, 4> salt{'N', 'a', 'C', 'l'};

// Whether scrypt refuses `parameters` with `expected` on Backend, the output untouched.
template <class Backend = hash::backends::sodium>
bool refuses(hash::scrypt_parameters const& parameters, hash::error expected) {
    std::array<std::uint8_t, 32> buffer{};
    buffer.fill(untouched);
    auto const refused = hash::scrypt<Backend>(buffer, password, salt, parameters);
    return refused.has_error() && refused.error() == expected && all_of(buffer, untouched);
}

// Whether `parameters` pass every guard: the recording backend is called.
bool passes(hash::scrypt_parameters const& parameters) {
    std::array<std::uint8_t, 32> buffer{};
    int const before = test_backends::recorded_calls;
    auto const done = hash::scrypt<test_backends::recording>(buffer, password, salt, parameters);
    return done.has_value() && test_backends::recorded_calls == before + 1;
}

void test_output_guard() {
    std::array<std::uint8_t, 33> buffer{};
    buffer.fill(untouched);
    constexpr hash::scrypt_parameters cheap{.n = 16, .r = 1, .p = 1};
    auto refused = hash::scrypt(std::span<std::uint8_t>(buffer.data(), 0), password, salt, cheap);
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::invalid_output_size);
    // Natively a span of (2^32 - 1) 32 + 1 bytes over 33, refused before anything touches it; on
    // wasm32 no span is that long.
    constexpr std::uint64_t longest = 0xffffffffULL * 32;
    if constexpr (std::numeric_limits<std::size_t>::max() > longest) {
        refused = hash::scrypt(
            std::span<std::uint8_t>(buffer.data(), static_cast<std::size_t>(longest + 1)), password,
            salt, cheap);
        BOOST_TEST(refused.has_error() && refused.error() == hash::error::invalid_output_size);
    }
    BOOST_TEST(all_of(buffer, untouched));
    // One byte, the shortest, then 33, past one block of PBKDF2.
    BOOST_TEST(
        hash::scrypt(std::span<std::uint8_t>(buffer.data(), 1), password, salt, cheap).has_value());
    BOOST_TEST(buffer[1] == untouched);
    BOOST_TEST(hash::scrypt(buffer, password, salt, cheap).has_value());
}

void test_parameters_guard_n() {
    using enum hash::error;
    // N: a power of two, above 1, below 2^(16 r).
    for (std::uint64_t const n : {0ULL, 1ULL, 3ULL, 48ULL, 65535ULL, 65536ULL}) {
        BOOST_TEST(refuses({.n = n, .r = 1, .p = 1}, invalid_parameters));
    }
    BOOST_TEST(refuses({.n = std::uint64_t{1} << 32U, .r = 2, .p = 1}, invalid_parameters));
    BOOST_TEST(refuses({.n = std::uint64_t{1} << 48U, .r = 3, .p = 1}, invalid_parameters));
    BOOST_TEST(passes({.n = std::uint64_t{1} << 15U, .r = 1, .p = 1}));
    // The largest N for r = 2, 2^31, takes 512 GiB: past size_t on wasm32, where the size refuses.
    if constexpr (std::numeric_limits<std::size_t>::max() > 0xffffffffU) {
        BOOST_TEST(passes({.n = std::uint64_t{1} << 31U, .r = 2, .p = 1}));
    } else {
        BOOST_TEST(refuses({.n = std::uint64_t{1} << 31U, .r = 2, .p = 1}, invalid_parameters));
    }
    BOOST_TEST(passes({.n = 2, .r = 1, .p = 1}));
}

void test_parameters_guard_r_and_p() {
    using enum hash::error;
    // r and p at least 1.
    BOOST_TEST(refuses({.n = 16, .r = 0, .p = 1}, invalid_parameters));
    BOOST_TEST(refuses({.n = 16, .r = 1, .p = 0}, invalid_parameters));
    // r p below 2^30.
    BOOST_TEST(refuses({.n = 16, .r = 1U << 15U, .p = 1U << 15U}, invalid_parameters));
    BOOST_TEST(refuses({.n = 16, .r = 1, .p = 1U << 30U}, invalid_parameters));
    BOOST_TEST(refuses<test_backends::recording>({.n = 16, .r = 1U << 15U, .p = 1U << 15U},
                                                 invalid_parameters));
}

void test_parameters_guard_size() {
    using enum hash::error;
    // 128 r (N + p) past size_t: on wasm32 4 GiB and a KiB, which passes natively; everywhere
    // 2^67 bytes.
    constexpr hash::scrypt_parameters four_gib{.n = std::uint64_t{1} << 22U, .r = 8, .p = 1};
    if constexpr (std::numeric_limits<std::size_t>::max() == 0xffffffffU) {
        BOOST_TEST(refuses(four_gib, invalid_parameters));
        BOOST_TEST(refuses<test_backends::recording>(four_gib, invalid_parameters));
        BOOST_TEST(passes({.n = std::uint64_t{1} << 21U, .r = 8, .p = 1}));
    } else {
        BOOST_TEST(passes(four_gib));
    }
    constexpr hash::scrypt_parameters huge{.n = std::uint64_t{1} << 31U, .r = 1U << 29U, .p = 1};
    BOOST_TEST(refuses<test_backends::recording>(huge, invalid_parameters));
    // libsodium's N is at most UINT32_MAX, its uint32_t: 2^32 with r = 3 is RFC 7914's, and
    // refused before the call (natively 1.5 TiB fit size_t; on wasm32 the size refuses first).
    BOOST_TEST(refuses({.n = std::uint64_t{1} << 32U, .r = 3, .p = 1}, invalid_parameters));
    BOOST_TEST_EQ(hash::detail::scrypt_engine<hash::backends::sodium>::limits.n, 0xffffffffULL);
    if constexpr (std::numeric_limits<std::size_t>::max() > 0xffffffffU) {
        BOOST_TEST(passes({.n = std::uint64_t{1} << 32U, .r = 3, .p = 1}));
    }
    // The output's guard comes first.
    std::array<std::uint8_t, 1> buffer{};
    auto const refused = hash::scrypt(std::span<std::uint8_t>(buffer.data(), 0), password, salt,
                                      {.n = 0, .r = 0, .p = 0});
    BOOST_TEST(refused.has_error() && refused.error() == invalid_output_size);
}

void test_backend_failure() {
    std::array<std::uint8_t, 32> buffer{};
    buffer.fill(untouched);
    auto const failed =
        hash::scrypt<test_backends::failing>(buffer, password, salt, {.n = 16, .r = 1, .p = 1});
    BOOST_TEST(failed.has_error() && failed.error() == hash::error::backend_failure);
    BOOST_TEST(all_of(buffer, 0));

    // A guard's refusal reaches no backend.
    BOOST_TEST(
        refuses<test_backends::failing>({.n = 3, .r = 1, .p = 1}, hash::error::invalid_parameters));
}

// scrypt's default backend is default_backend's choice for kdfs::scrypt: backends::sodium, the one
// backend that has it.
static_assert(std::is_same_v<hash::default_backend<hash::kdfs::scrypt>, hash::backends::sodium>);
static_assert(&hash::scrypt<> == &hash::scrypt<hash::backends::sodium>);

}  // namespace

int main() {
    test_rfc7914();
    test_output_guard();
    test_parameters_guard_n();
    test_parameters_guard_r_and_p();
    test_parameters_guard_size();
    test_backend_failure();
    return webcpp::test::exit_status(boost::report_errors());
}
