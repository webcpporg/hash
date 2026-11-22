// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// bcrypt and bcrypt_verify on their default, which kdfs::bcrypt has none of, stop (design D34).

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so the
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/hash/detail/engines.hpp:* {{webcpp::hash: kdfs::bcrypt has no default backend. Name one of: backends::botan.}}
// clang-format on
#include <webcpp/hash/bcrypt.hpp>

#include <array>
#include <cstdint>
#include <string_view>

int main() {
    std::array<char, webcpp::hash::bcrypt_hash_size> output{};
    std::array<std::uint8_t, webcpp::hash::bcrypt_salt_size> const salt{};
    auto const made = webcpp::hash::bcrypt(output, {}, salt);
    auto const same =
        webcpp::hash::bcrypt_verify({}, std::string_view(output.data(), output.size()));
    return made && same ? 0 : 1;
}
