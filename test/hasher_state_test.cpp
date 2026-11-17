// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// hasher's state machine (spec 2.15): make, update, finish once; invalid_state after finish, after
// a backend's failure and once moved from; a guard's refusal at finish leaves it hashing;
// move-only. On the mock backend, every engine call is counted and every init is matched by one
// destroy, in every path; on backends::hash2, built with WEBCPP_HASH_DETAIL_TEST_WIPE_RECORD, the
// state's bytes inside the hasher are wiped by finish, by the destructor and in the hasher moved
// from.

#include <webcpp/hash/digest.hpp>
#include <webcpp/test/exit_status.hpp>

#include "require.hpp"
#include "support/mock_backend.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/sha2.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <new>
#include <span>
#include <type_traits>
#include <utility>

#ifndef WEBCPP_HASH_DETAIL_TEST_WIPE_RECORD
#error "hasher_state_test is built with WEBCPP_HASH_DETAIL_TEST_WIPE_RECORD (test/Jamfile)"
#endif

namespace {

namespace hash = webcpp::hash;
namespace digests = webcpp::hash::digests;
namespace test = webcpp::test;
using test::mock;
using mock_hasher = hash::hasher<digests::sha2_256, mock>;
using sha256_hasher = hash::hasher<digests::sha2_256, hash::backends::hash2>;

// The wipes the seam reported since the last clear: where and how many bytes, and whether each
// found its bytes zero. A fixed array: the seam is noexcept and allocates nothing.
struct wipe_entry {
    void const* at = nullptr;
    std::size_t size = 0;
    bool zero = false;
};

struct wipe_log {
    std::array<wipe_entry, 64> entries{};
    std::size_t count = 0;

    void clear() noexcept { count = 0; }
};

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the seam's record
wipe_log wipes;

}  // namespace

namespace webcpp::hash::detail::test {

void wipe_record(void const* wiped_data, std::size_t byte_count) noexcept {
    auto const* const bytes = static_cast<unsigned char const*>(wiped_data);
    bool zero = true;
    for (std::size_t index = 0; index < byte_count; ++index) {
        zero = zero && bytes[index] == 0;
    }
    if (wipes.count < wipes.entries.size()) {
        wipes.entries[wipes.count] = {.at = wiped_data, .size = byte_count, .zero = zero};
        ++wipes.count;
    }
}

}  // namespace webcpp::hash::detail::test

namespace {

static_assert(!std::is_copy_constructible_v<mock_hasher>);
static_assert(!std::is_copy_assignable_v<mock_hasher>);
static_assert(std::is_nothrow_move_constructible_v<mock_hasher>);
static_assert(std::is_nothrow_move_assignable_v<mock_hasher>);
static_assert(!std::is_default_constructible_v<mock_hasher>);

bool failed_with(boost::system::result<void> const& outcome, hash::error expected) {
    return outcome.has_error() && outcome.error() == expected;
}

// Every init was matched by one destroy, and the engine saw no breach of its contract.
void expect_balanced() {
    BOOST_TEST_EQ(test::mock_control.live, 0);
    BOOST_TEST_EQ(test::mock_control.violations, 0);
}

void check_finish_once() {
    test::mock_reset();
    {
        auto hashing = mock_hasher::make();
        test::require(BOOST_TEST(hashing.has_value()));
        std::array<std::uint8_t, 2> const piece{1, 2};
        BOOST_TEST(hashing->update(piece).has_value());
        BOOST_TEST(hashing->update({}).has_value());
        BOOST_TEST(hashing->update(piece).has_value());
        std::array<std::uint8_t, 32> digest{};
        BOOST_TEST(hashing->finish(digest).has_value());
        BOOST_TEST_EQ(digest[0], 6U);
        BOOST_TEST_EQ(test::mock_control.ends, 1);  // finish wipes the state at once

        // The result is final: no second finish, no update after it.
        std::array<std::uint8_t, 32> again{};
        BOOST_TEST(failed_with(hashing->finish(again), hash::error::invalid_state));
        BOOST_TEST(failed_with(hashing->update(piece), hash::error::invalid_state));
        BOOST_TEST_EQ(again[0], 0U);
    }
    BOOST_TEST_EQ(test::mock_control.ends, 1);  // a spent hasher's destructor has nothing left
    BOOST_TEST_EQ(test::mock_control.finishes, 1);
    expect_balanced();
}

void check_guard_keeps_hashing() {
    test::mock_reset();
    auto hashing = mock_hasher::make();
    test::require(BOOST_TEST(hashing.has_value()));
    std::array<std::uint8_t, 31> short_digest{};
    BOOST_TEST(failed_with(hashing->finish(short_digest), hash::error::invalid_output_size));
    std::array<std::uint8_t, 32> digest{};
    BOOST_TEST(hashing->finish(digest).has_value());

    // An extendable output: past the engine's 100 bytes is the backend's refusal, not the family's.
    auto xof = hash::hasher<digests::shake_128, mock>::make();
    test::require(BOOST_TEST(xof.has_value()));
    std::array<std::uint8_t, 101> past{};
    BOOST_TEST(failed_with(xof->finish(past), hash::error::unsupported_by_backend));
    std::array<std::uint8_t, 0> none{};
    BOOST_TEST(failed_with(xof->finish(none), hash::error::invalid_output_size));
    BOOST_TEST(xof->finish(std::span(past).first(100)).has_value());
    auto one_byte = hash::hasher<digests::shake_128, mock>::make();
    test::require(BOOST_TEST(one_byte.has_value()));
    BOOST_TEST(one_byte->finish(std::span(past).first(1)).has_value());
}

void check_moves() {
    test::mock_reset();
    {
        auto made = mock_hasher::make();
        test::require(BOOST_TEST(made.has_value()));
        std::array<std::uint8_t, 1> const piece{5};
        BOOST_TEST(made->update(piece).has_value());

        mock_hasher moved(std::move(*made));
        // NOLINTNEXTLINE(bugprone-use-after-move): a hasher moved from is what is tested
        BOOST_TEST(failed_with(made->update(piece), hash::error::invalid_state));
        std::array<std::uint8_t, 32> digest{};
        BOOST_TEST(failed_with(made->finish(digest), hash::error::invalid_state));
        BOOST_TEST(moved.update(piece).has_value());

        // Assignment ends the target's own hash and takes the other's.
        auto other = mock_hasher::make();
        test::require(BOOST_TEST(other.has_value()));
        BOOST_TEST_EQ(test::mock_control.live, 2);
        *other = std::move(moved);
        BOOST_TEST_EQ(test::mock_control.live, 1);
        // NOLINTNEXTLINE(bugprone-use-after-move): a hasher moved from is what is tested
        BOOST_TEST(failed_with(moved.update(piece), hash::error::invalid_state));
        BOOST_TEST(other->finish(digest).has_value());
        BOOST_TEST_EQ(digest[0], 10U);

        // A self-assignment keeps the hash; a spent hasher moves as spent.
        auto self = mock_hasher::make();
        test::require(BOOST_TEST(self.has_value()));
        auto& alias = *self;
        *self = std::move(alias);
        BOOST_TEST(self->update(piece).has_value());
        mock_hasher spent(std::move(*other));
        BOOST_TEST(failed_with(spent.update(piece), hash::error::invalid_state));
    }
    expect_balanced();
}

void check_failures() {
    test::mock_reset();
    test::mock_control.init = hash::error::backend_failure;
    auto const refused = mock_hasher::make();
    BOOST_TEST(refused.has_error() && refused.error() == hash::error::backend_failure);
    BOOST_TEST_EQ(test::mock_control.ends, 1);  // a failed init's state is destroyed too
    expect_balanced();

    test::mock_reset();
    test::mock_control.accepts = false;
    auto const unsupported = mock_hasher::make();
    BOOST_TEST(unsupported.has_error() &&
               unsupported.error() == hash::error::unsupported_by_backend);
    BOOST_TEST_EQ(test::mock_control.inits, 0);

    test::mock_reset();
    {
        auto hashing = mock_hasher::make();
        test::require(BOOST_TEST(hashing.has_value()));
        test::mock_control.update = hash::error::backend_failure;
        std::array<std::uint8_t, 1> const piece{1};
        BOOST_TEST(failed_with(hashing->update(piece), hash::error::backend_failure));
        test::mock_control.update = {};
        BOOST_TEST(failed_with(hashing->update(piece), hash::error::invalid_state));
    }
    expect_balanced();

    test::mock_reset();
    {
        auto hashing = mock_hasher::make();
        test::require(BOOST_TEST(hashing.has_value()));
        test::mock_control.finish = hash::error::backend_failure;
        std::array<std::uint8_t, 32> digest{};
        BOOST_TEST(failed_with(hashing->finish(digest), hash::error::backend_failure));
        BOOST_TEST_EQ(digest[0], 0U);  // zeroed over what the backend left
        BOOST_TEST_EQ(digest[31], 0U);
        BOOST_TEST(failed_with(hashing->finish(digest), hash::error::invalid_state));
    }
    expect_balanced();

    // A hasher dropped while hashing destroys its state.
    test::mock_reset();
    {
        auto const hashing = mock_hasher::make();
        test::require(BOOST_TEST(hashing.has_value()));
    }
    BOOST_TEST_EQ(test::mock_control.ends, 1);
    expect_balanced();
}

// Whether a wipe of the state's whole size was reported inside [object, object + size), its bytes
// zero.
bool wiped_inside(void const* object, std::size_t object_size) {
    auto const* const first = static_cast<unsigned char const*>(object);
    auto const reported = std::span(wipes.entries).first(wipes.count);
    return std::ranges::any_of(reported, [&](wipe_entry const& entry) {
        auto const* const at = static_cast<unsigned char const*>(entry.at);
        return entry.size == sizeof(boost::hash2::sha2_256) && entry.zero && at >= first &&
               at + entry.size <= first + object_size;
    });
}

void check_wipes() {
    std::array<std::uint8_t, 3> const piece{0x61, 0x62, 0x63};
    std::array<std::uint8_t, 32> digest{};

    // finish wipes the state at once.
    auto hashing = sha256_hasher::make();
    test::require(BOOST_TEST(hashing.has_value()));
    BOOST_TEST(hashing->update(piece).has_value());
    wipes.clear();
    BOOST_TEST(hashing->finish(digest).has_value());
    BOOST_TEST(wiped_inside(&*hashing, sizeof(sha256_hasher)));

    // The destructor of a hasher still hashing wipes its state.
    alignas(sha256_hasher) std::array<unsigned char, sizeof(sha256_hasher)> storage{};
    auto made = sha256_hasher::make();
    test::require(BOOST_TEST(made.has_value()));
    auto* const placed = new (storage.data()) sha256_hasher(std::move(*made));
    BOOST_TEST(placed->update(piece).has_value());
    wipes.clear();
    placed->~sha256_hasher();
    BOOST_TEST(wiped_inside(storage.data(), storage.size()));

    // A move wipes the state left in the hasher moved from.
    auto source = sha256_hasher::make();
    test::require(BOOST_TEST(source.has_value()));
    BOOST_TEST(source->update(piece).has_value());
    wipes.clear();
    sha256_hasher target(std::move(*source));
    BOOST_TEST(wiped_inside(&*source, sizeof(sha256_hasher)));
    BOOST_TEST(target.finish(digest).has_value());
    std::array<std::uint8_t, 32> once{};
    BOOST_TEST(hash::digest_of<digests::sha2_256>(once, piece).has_value());
    BOOST_TEST(digest == once);  // the hash went with the move
}

}  // namespace

int main() {
    check_finish_once();
    check_guard_keeps_hashing();
    check_moves();
    check_failures();
    check_wipes();
    return webcpp::test::exit_status(boost::report_errors());
}
