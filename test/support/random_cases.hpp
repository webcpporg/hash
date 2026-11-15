// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The random cases of the agreement tests: a seeded std::mt19937 whose draws do not depend on the
// standard library (no std::*_distribution), so that every target sees the same cases, and a
// generator that puts the empty inputs first.

#ifndef WEBCPP_TEST_HASH_SUPPORT_RANDOM_CASES_HPP
#define WEBCPP_TEST_HASH_SUPPORT_RANDOM_CASES_HPP

#include <cstddef>
#include <cstdint>
#include <random>
#include <vector>

namespace webcpp::test {

// The seed of every agreement test, printed with a failing case.
inline constexpr std::uint32_t agreement_seed = 0x5eed17U;

// The number of cases of each agreement test and hmac, the empty ones among them.
inline constexpr std::size_t agreement_cases = 1000;

// A random source with draws that are the same on every standard library.
class random_source {
public:
    explicit random_source(std::uint32_t seed) : engine_(seed) {}

    // A value in [low, high]; the modulo bias is irrelevant to a test of agreement.
    std::size_t between(std::size_t low, std::size_t high) {
        return low + (static_cast<std::size_t>(engine_()) % (high - low + 1));
    }

    // `size` random bytes.
    std::vector<std::uint8_t> bytes(std::size_t size) {
        std::vector<std::uint8_t> out(size);
        for (auto& b : out) {
            b = static_cast<std::uint8_t>(engine_() >> 8U);
        }
        return out;
    }

private:
    std::mt19937 engine_;
};

// One HKDF case: the three inputs and the output size.
struct random_hkdf_case {
    std::vector<std::uint8_t> salt;
    std::vector<std::uint8_t> ikm;
    std::vector<std::uint8_t> info;
    std::size_t output;
};

// Case `index` of HKDF over a digest of `digest` bytes: the first four are the empty inputs (every
// input empty with the shortest and the longest output, then each of salt and ikm alone empty),
// the others random sizes, up to 300 bytes for an input and up to 255 digests for the output
// (the longest 1 time in 16).
inline random_hkdf_case next_hkdf_case(random_source& rnd, std::size_t index, std::size_t digest) {
    const std::size_t longest = 255 * digest;
    switch (index) {
        case 0: return {{}, {}, {}, 1};
        case 1: return {{}, {}, {}, longest};
        case 2: return {{}, rnd.bytes(rnd.between(1, 64)), rnd.bytes(rnd.between(0, 64)), digest};
        case 3: return {rnd.bytes(rnd.between(1, 64)), {}, rnd.bytes(rnd.between(0, 64)), digest};
        default: break;
    }
    const std::size_t output =
        rnd.between(0, 15) == 0 ? longest : rnd.between(1, std::size_t{4} * digest);
    // The sizes are drawn one after the other, so that their order of evaluation is fixed.
    const std::size_t salt = rnd.between(0, 300);
    const std::size_t ikm = rnd.between(0, 300);
    const std::size_t info = rnd.between(0, 300);
    random_hkdf_case c;
    c.salt = rnd.bytes(salt);
    c.ikm = rnd.bytes(ikm);
    c.info = rnd.bytes(info);
    c.output = output;
    return c;
}

// One PBKDF2 case: password, salt, iterations and the output size.
struct random_pbkdf2_case {
    std::vector<std::uint8_t> password;
    std::vector<std::uint8_t> salt;
    std::uint64_t iterations;
    std::size_t output;
};

// Case `index` of PBKDF2 over a digest of `digest` bytes: the first three are the empty inputs
// (both empty, then each alone), the others random sizes, up to 300 bytes for an input, 1 to 40
// iterations and up to 3 digests of output.
inline random_pbkdf2_case next_pbkdf2_case(random_source& rnd, std::size_t index,
                                           std::size_t digest) {
    switch (index) {
        case 0: return {{}, {}, 1, digest};
        case 1: return {{}, rnd.bytes(rnd.between(1, 64)), 2, rnd.between(1, 2 * digest)};
        case 2: return {rnd.bytes(rnd.between(1, 64)), {}, 2, rnd.between(1, 2 * digest)};
        default: break;
    }
    const std::size_t password = rnd.between(0, 300);
    const std::size_t salt = rnd.between(0, 300);
    const std::size_t iterations = rnd.between(1, 40);
    const std::size_t output = rnd.between(1, std::size_t{3} * digest);
    random_pbkdf2_case c;
    c.password = rnd.bytes(password);
    c.salt = rnd.bytes(salt);
    c.iterations = iterations;
    c.output = output;
    return c;
}

}  // namespace webcpp::test

#endif  // WEBCPP_TEST_HASH_SUPPORT_RANDOM_CASES_HPP
