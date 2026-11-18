// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// sskdf over a digest SP 800-56C does not approve (MD5) and x963kdf over one outside FIPS 180-4
// (SHA3-256) stop, whatever the backend.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so the
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/hash/kdf_standards.hpp:* {{webcpp::hash: sskdf takes a digest of SP 800-56C: digests::sha1, digests::sha2_224, sha2_256, sha2_384, sha2_512, sha2_512_224, sha2_512_256, sha3_224, sha3_256, sha3_384 or sha3_512.}}
// expected-error@webcpp/hash/kdf_standards.hpp:* {{webcpp::hash: x963kdf takes a digest of FIPS 180-4: digests::sha1, digests::sha2_224, sha2_256, sha2_384, sha2_512, sha2_512_224 or sha2_512_256.}}
// clang-format on
#include <webcpp/hash/kdf_standards.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace hash = webcpp::hash;
    std::array<std::uint8_t, 32> output{};
    std::array<std::uint8_t, 16> const secret{1};
    auto const sskdf = hash::sskdf<hash::digests::md5>(output, secret);
    auto const x963kdf = hash::x963kdf<hash::digests::sha3_256>(output, secret);
    return sskdf && x963kdf ? 0 : 1;
}
