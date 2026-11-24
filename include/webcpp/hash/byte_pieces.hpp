// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `byte_pieces`: byte sequences a function reads one after another, as if concatenated, so that an
 input made of parts (a label, a prefix and a secret) needs no buffer to join them: HKDF over pieces
 (`hkdf.hpp`) takes its input keying material and its application info so. `<webcpp/hash/hkdf.hpp>`
 includes it; `backends/hash2.hpp` and the engines include it for their parameters.

 @code
 // label, suite_id and secret: std::span<std::uint8_t const>
 auto prk = webcpp::hash::hkdf_extract<webcpp::hash::hmac_sha2_256>(salt,
                                                                    {label, suite_id, secret});
 @endcode

 @see "Key derivation", in the guide.
*/
#ifndef WEBCPP_HASH_BYTE_PIECES_HPP
#define WEBCPP_HASH_BYTE_PIECES_HPP

#include <webcpp/hash/config.hpp>

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <iterator>
#include <ranges>
#include <span>
#include <type_traits>

namespace webcpp::hash {

/**
 Byte sequences read one after another, as if concatenated: `{a, b, c}` at the call.

 A view: it holds a pointer to a contiguous list of spans and their count, and the spans point to
 the caller's bytes; neither is copied. Write the braced list at the call, where its array lives
 until the end of the full expression, which outlasts the call; or name a `std::array` (or a
 `std::vector`) of spans and pass it. A `byte_pieces` variable initialised from a braced list
 points to an array that dies at the end of its declaration: its constructors carry
 `WEBCPP_HASH_LIFETIMEBOUND`, which makes that a warning where the compiler has the attribute.

 A braced list of one span, `{x}`, is that span (the language's rule): a function with a
 single-buffer overload takes it there. `byte_pieces{x}` is the list of one piece. A lone `{}` where
 both overloads take braces is ambiguous: write `byte_pieces{}` for no piece, or an empty
 `std::span<std::uint8_t const>` for an empty input (the same bytes).

 @code
 std::array<std::span<std::uint8_t const>, 3> const parts{prefix, label, secret};
 auto prk = webcpp::hash::hkdf_extract<webcpp::hash::hmac_sha2_256>(salt, parts);
 @endcode
*/
class byte_pieces {
public:
    /** A piece: a span of bytes. */
    using value_type = std::span<std::uint8_t const>;

    /** No piece: the empty input. */
    constexpr byte_pieces() noexcept = default;

    /**
     The pieces of a braced list, `{a, b, c}`, each element converted to a span of bytes.

     @param pieces The list; its array must outlive this object (it does, written at the call).
    */
    constexpr byte_pieces(
        std::initializer_list<value_type> pieces WEBCPP_HASH_LIFETIMEBOUND) noexcept
        : first_(std::data(pieces)), count_(pieces.size()) {}

    /**
     The pieces of a contiguous range of spans of bytes: a `std::array`, a `std::vector`, a
     `std::span` of them.

     @tparam Range A contiguous, sized range whose value type is `std::span<std::uint8_t const>`.
     @param pieces The range; it must outlive this object.
    */
    template <std::ranges::contiguous_range Range>
        requires std::ranges::sized_range<Range> &&
                     std::same_as<std::ranges::range_value_t<Range>, value_type> &&
                     (!std::same_as<std::remove_cvref_t<Range>, byte_pieces>)
    // NOLINTNEXTLINE(misc-explicit-constructor): a range of spans is its pieces, as {a, b} is
    constexpr byte_pieces(Range const& pieces WEBCPP_HASH_LIFETIMEBOUND) noexcept
        : first_(std::ranges::data(pieces)), count_(std::ranges::size(pieces)) {}

    /** @return The first piece. */
    [[nodiscard]] constexpr value_type const* begin() const noexcept { return first_; }

    /** @return Past the last piece. */
    [[nodiscard]] constexpr value_type const* end() const noexcept { return first_ + count_; }

    /** @return The number of pieces, empty ones included. */
    [[nodiscard]] constexpr std::size_t size() const noexcept { return count_; }

    /** @return Whether there is no piece. */
    [[nodiscard]] constexpr bool empty() const noexcept { return count_ == 0; }

    /** @return The bytes of all pieces, summed. */
    [[nodiscard]] constexpr std::uint64_t total_size() const noexcept {
        std::uint64_t total = 0;
        for (value_type const piece : *this) {
            total += piece.size();
        }
        return total;
    }

private:
    value_type const* first_ = nullptr;
    std::size_t count_ = 0;
};

}  // namespace webcpp::hash

#endif  // WEBCPP_HASH_BYTE_PIECES_HPP
