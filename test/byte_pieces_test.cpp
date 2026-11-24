// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// byte_pieces and the call of HKDF over pieces, on every target and with each lane's compiler (the
// record of design B2): `{a, b, c}` binds to byte_pieces; a braced list of one span picks the
// single-buffer overload (design D1, B1, ruling R1), and `byte_pieces{x}` the pieces one, which
// has no cap (Review Focus 3); a std::array and a std::vector of spans pass through the range
// constructor (Review Focus 1). And the slicing of a piece for a backend whose HMAC update takes
// a narrower length than a span (detail::for_each_slice, Review Focus 4), with a small maximum.

#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/byte_pieces.hpp>
#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/system/result.hpp>

#include <webcpp/test/exit_status.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <type_traits>
#include <vector>

namespace hash = webcpp::hash;
namespace detail = webcpp::hash::detail;

namespace {

using piece = std::span<std::uint8_t const>;

// The overloads a braced list picks, the counts and sizes of a list, the range constructor.
void binding() {
    std::array<std::uint8_t, 3> const x{1, 2, 3};
    piece const a{x};
    piece const b{x};
    piece const c{x};
    static_assert(std::is_same_v<decltype(hash::hkdf_extract<hash::hmac_sha2_256>(a, {a, b, c})),
                                 boost::system::result<hash::hmac_sha2_256::result_type>>);
    BOOST_TEST_EQ(hash::byte_pieces({a, b, c}).size(), 3U);
    BOOST_TEST_EQ(hash::byte_pieces({a, b, c}).total_size(), 9U);
    BOOST_TEST(!hash::byte_pieces({a, b, c}).empty());
    std::array<piece, 2> const named{a, b};
    std::vector<piece> const listed{a, b, c};
    BOOST_TEST_EQ(hash::byte_pieces(named).size(), 2U);
    BOOST_TEST_EQ(hash::byte_pieces(listed).size(), 3U);
    BOOST_TEST_EQ(hash::byte_pieces(listed).total_size(), 9U);
    BOOST_TEST(hash::byte_pieces(named).begin() == named.data());
    BOOST_TEST(hash::byte_pieces(named).end() == named.data() + named.size());

    hash::byte_pieces const none;
    BOOST_TEST(none.empty());
    BOOST_TEST_EQ(none.size(), 0U);
    BOOST_TEST_EQ(none.total_size(), 0U);
    BOOST_TEST(none.begin() == none.end());

    // A list of empty pieces holds pieces and no byte.
    piece const empty;
    BOOST_TEST_EQ(hash::byte_pieces({empty, empty}).size(), 2U);
    BOOST_TEST_EQ(hash::byte_pieces({empty, empty}).total_size(), 0U);
    BOOST_TEST_EQ(hash::byte_pieces({empty, a, empty}).total_size(), 3U);

    // A constant list: the type is a literal one.
    static constexpr std::array<std::uint8_t, 4> constant_bytes{1, 2, 3, 4};
    static constexpr std::array<piece, 2> constant_pieces{piece(constant_bytes),
                                                          piece(constant_bytes).first(1)};
    static_assert(hash::byte_pieces(constant_pieces).total_size() == 5U);
}

// {x} is the single-buffer form and its cap; byte_pieces{x} the pieces form, uncapped.
void lone_span() {
    std::vector<std::uint8_t> const long_info(hash::hkdf_max_application_info_size + 1, 0x5a);
    std::array<std::uint8_t, 32> prk{};
    std::array<std::uint8_t, 42> out{};
    BOOST_TEST(hash::hkdf_expand<hash::hmac_sha2_256>(out, prk, {std::span(long_info)}).error() ==
               hash::error::input_too_long);
    BOOST_TEST(
        hash::hkdf_expand<hash::hmac_sha2_256>(out, prk, hash::byte_pieces{std::span(long_info)}));
}

// The slices for_each_slice hands over, as (offset into the concatenation, size).
std::vector<std::array<std::size_t, 2>> slices_of(hash::byte_pieces pieces, std::uint64_t slice_max,
                                                  std::uint8_t const* origin) {
    std::vector<std::array<std::size_t, 2>> slices;
    detail::for_each_slice(pieces, slice_max, [&](piece slice) {
        slices.push_back({static_cast<std::size_t>(slice.data() - origin), slice.size()});
    });
    return slices;
}

// Each piece in slices of at most the maximum, in order, every byte once; an empty piece in none.
void slicing() {
    std::array<std::uint8_t, 10> bytes{};
    piece const all(bytes);
    using pairs = std::vector<std::array<std::size_t, 2>>;
    BOOST_TEST((slices_of({all}, 3, bytes.data()) == pairs{{0, 3}, {3, 3}, {6, 3}, {9, 1}}));
    BOOST_TEST((slices_of({all}, 10, bytes.data()) == pairs{{0, 10}}));
    BOOST_TEST((slices_of({all}, 11, bytes.data()) == pairs{{0, 10}}));
    BOOST_TEST((slices_of({all.first(4), piece{}, all.subspan(4)}, 4, bytes.data()) ==
                pairs{{0, 4}, {4, 4}, {8, 2}}));
    BOOST_TEST((slices_of({all.first(2), all.subspan(2, 1)}, 1, bytes.data()) ==
                pairs{{0, 1}, {1, 1}, {2, 1}}));
    BOOST_TEST((slices_of({piece{}, piece{}}, 1, bytes.data()).empty()));
    BOOST_TEST((slices_of({}, 1, bytes.data()).empty()));
    BOOST_TEST((slices_of({all}, std::numeric_limits<std::uint64_t>::max(), bytes.data()) ==
                pairs{{0, 10}}));

    // backends::hash2's HMAC takes a size_t: its slice is a span's whole length (the test seam,
    // which lowers it, is hkdf_pieces_sliced's).
    BOOST_TEST_EQ(detail::hkdf_pieces_slice<hash::backends::hash2>,
                  std::uint64_t{std::numeric_limits<std::size_t>::max()});
}

}  // namespace

int main() {
    binding();
    lone_span();
    slicing();
    return webcpp::test::exit_status(boost::report_errors());
}
