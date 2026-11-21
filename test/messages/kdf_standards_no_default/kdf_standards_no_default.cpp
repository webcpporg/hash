// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// kbkdf, sskdf and x963kdf on their default, which none of them has, stop (design D34).

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so the
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/hash/detail/engines.hpp:* {{webcpp::hash: kdfs::kbkdf_hmac has no default backend. Name one of: backends::openssl, backends::botan.}}
// expected-error@webcpp/hash/detail/engines.hpp:* {{webcpp::hash: kdfs::sskdf has no default backend. Name one of: backends::openssl, backends::botan.}}
// expected-error@webcpp/hash/detail/engines.hpp:* {{webcpp::hash: kdfs::x963kdf has no default backend. Name one of: backends::openssl, backends::botan.}}
// clang-format on
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/kdf_standards.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace hash = webcpp::hash;
    std::array<std::uint8_t, 32> output{};
    std::array<std::uint8_t, 16> const key{1};
    auto const kbkdf = hash::kbkdf<hash::hmac_sha2_256>(output, key);
    auto const sskdf = hash::sskdf<hash::digests::sha2_256>(output, key);
    auto const x963kdf = hash::x963kdf<hash::digests::sha2_256>(output, key);
    return kbkdf && sskdf && x963kdf ? 0 : 1;
}
