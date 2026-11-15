// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// What every example of the guide shares: bytes written as hexadecimal, and text or hexadecimal
// read as bytes.

#ifndef WEBCPP_HASH_EXAMPLE_HEX_HPP
#define WEBCPP_HASH_EXAMPLE_HEX_HPP

// tag::hex[]
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace example {

/** The bytes of `data`, two lowercase hexadecimal digits each. */
inline std::string hex(std::span<std::uint8_t const> data) {
    constexpr std::string_view digits = "0123456789abcdef";
    std::string out;
    out.reserve(2 * data.size());
    for (std::uint8_t const byte : data) {
        out += digits[byte >> 4U];
        out += digits[byte & 0x0fU];
    }
    return out;
}

/** The bytes of `text`, as they are: a password, a label, a message. */
inline std::span<std::uint8_t const> bytes(std::string_view text) {
    // A char and a std::uint8_t share their object representation.
    return {reinterpret_cast<std::uint8_t const*>(text.data()), text.size()};
}

/** The bytes `text` writes in hexadecimal, two digits each. */
inline std::vector<std::uint8_t> from_hex(std::string_view text) {
    auto const digit = [](char c) {
        auto const u = static_cast<unsigned char>(c);
        return u <= '9' ? u - unsigned{'0'} : (u | 0x20U) - unsigned{'a'} + 10U;
    };
    std::vector<std::uint8_t> out(text.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::uint8_t>((digit(text[2 * i]) << 4U) | digit(text[(2 * i) + 1]));
    }
    return out;
}

}  // namespace example

// end::hex[]

#endif  // WEBCPP_HASH_EXAMPLE_HEX_HPP
