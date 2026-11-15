// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// keccak_256: the published digests, EIP-55's checksums, and Boost.Hash2's own Keccak-256 as the
// oracle of every length and of random sequences of updates and results (spec section 1.3).

#include <webcpp/hash/keccak.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/sha3.hpp>

#include <webcpp/test/exit_status.hpp>

#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <random>
#include <string>
#include <vector>

namespace hash = webcpp::hash;

namespace {

// Boost.Hash2's own Keccak-256, under detail: the oracle of every call sequence (spec 1.3).
using oracle = boost::hash2::detail::keccak_base<0x01, 512, 256>;

// The oracle seeded as Hash2's sha3_256(std::uint64_t) seeds its base: nothing when the seed is
// zero, else its eight bytes little-endian, a result, and an empty update.
oracle seeded_oracle(std::uint64_t seed) {
    oracle seeded;
    if (seed != 0) {
        std::array<unsigned char, 8> tmp{};
        boost::hash2::detail::write64le(tmp.data(), seed);
        seeded.update(tmp.data(), tmp.size());
        static_cast<void>(seeded.result());
        seeded.update(tmp.data(), 0);
    }
    return seeded;
}

// The oracle seeded as Hash2's sha3_256(unsigned char const*, std::size_t) seeds its base.
oracle seeded_oracle(unsigned char const* p, std::size_t n) {
    oracle seeded;
    if (n != 0) {
        seeded.update(p, n);
        static_cast<void>(seeded.result());
        seeded.update(p, 0);
    }
    return seeded;
}

std::string hex(const hash::keccak_256::result_type& digest) {
    return boost::hash2::to_string(digest);
}

void check_published() {
    hash::keccak_256 empty;
    BOOST_TEST_EQ(hex(empty.result()),
                  "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    hash::keccak_256 abc;
    abc.update("abc", 3);
    BOOST_TEST_EQ(hex(abc.result()),
                  "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
}

// EIP-55: a hex digit of an address is upper case where the same position of Keccak-256 of the
// lowercase hex address is 8 or more. The four examples of EIP-55 ("All caps", "All lower",
// "Normal").
void check_eip55() {
    const std::array<std::string, 4> addresses{
        "52908400098527886E0F7030069857D2E4169EE7",
        "8617E340B3D01FA5F11F306F4090FD50E238070D",
        "de709f2102306220921060314715629080e2fb77",
        "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    };
    for (const auto& address : addresses) {
        std::string lower = address;
        for (auto& c : lower) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        hash::keccak_256 hasher;
        hasher.update(lower.data(), lower.size());
        const std::string digest = hex(hasher.result());
        std::string checksummed = lower;
        for (std::size_t i = 0; i < checksummed.size(); ++i) {
            const int nibble = std::stoi(digest.substr(i, 1), nullptr, 16);
            if (std::isalpha(static_cast<unsigned char>(checksummed[i])) != 0 && nibble >= 8) {
                checksummed[i] =
                    static_cast<char>(std::toupper(static_cast<unsigned char>(checksummed[i])));
            }
        }
        BOOST_TEST_EQ(checksummed, address);
    }
}

// Every length 0 to 1,000 in one update, then random sequences of updates and results.
void check_oracle() {
    std::vector<unsigned char> data(1000);
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<unsigned char>((i * 7) + 3);
    }
    for (std::size_t n = 0; n <= data.size(); ++n) {
        hash::keccak_256 ours;
        oracle theirs;
        ours.update(data.data(), n);
        theirs.update(data.data(), n);
        BOOST_TEST(ours.result() == theirs.result());
    }
    constexpr std::uint32_t seed = 20261114;
    // A fixed seed, so that a failing sequence is found again from the seed it prints.
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp)
    std::mt19937 random(seed);
    for (int sequence = 0; sequence < 200; ++sequence) {
        hash::keccak_256 ours(static_cast<std::uint64_t>(sequence));
        oracle theirs = seeded_oracle(static_cast<std::uint64_t>(sequence));
        for (int call = 0; call < 20; ++call) {
            if (random() % 3 == 0) {
                BOOST_TEST(ours.result() == theirs.result());
            } else {
                const std::size_t n = random() % 300;
                ours.update(data.data(), n);
                theirs.update(data.data(), n);
            }
        }
        if (!BOOST_TEST(ours.result() == theirs.result())) {
            std::printf("keccak oracle: seed %u, sequence %d\n", seed, sequence);
        }
    }
}

// The edges a random sequence reaches rarely: an empty update after a result (which pads again
// at the block's start), results in a row (each the next permutation's), updates that end
// exactly at, one short of and one past a block, the seeds of every constructor, and update's
// void const* overload.
void check_edges() {
    std::vector<unsigned char> data((3 * hash::keccak_256::block_size) + 1);
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<unsigned char>(255 - i);
    }
    const std::array<std::size_t, 9> lengths{
        0,
        1,
        hash::keccak_256::block_size - 1,
        hash::keccak_256::block_size,
        hash::keccak_256::block_size + 1,
        (2 * hash::keccak_256::block_size) - 1,
        2 * hash::keccak_256::block_size,
        (2 * hash::keccak_256::block_size) + 1,
        (3 * hash::keccak_256::block_size) + 1,
    };
    for (const std::size_t first : lengths) {
        for (const std::size_t second : lengths) {
            hash::keccak_256 ours;
            oracle theirs;
            ours.update(data.data(), first);
            theirs.update(data.data(), first);
            BOOST_TEST(ours.result() == theirs.result());
            BOOST_TEST(ours.result() == theirs.result());
            ours.update(data.data(), 0);
            theirs.update(data.data(), 0);
            BOOST_TEST(ours.result() == theirs.result());
            ours.update(static_cast<void const*>(data.data()), second);
            theirs.update(static_cast<void const*>(data.data()), second);
            BOOST_TEST(ours.result() == theirs.result());
        }
        hash::keccak_256 bytes(data.data(), first);
        oracle theirs = seeded_oracle(data.data(), first);
        BOOST_TEST(bytes.result() == theirs.result());
        hash::keccak_256 untyped(static_cast<void const*>(data.data()), first);
        BOOST_TEST(untyped.result() == seeded_oracle(data.data(), first).result());
    }
    hash::keccak_256 unseeded(std::uint64_t{0});
    BOOST_TEST(unseeded.result() == oracle().result());
    hash::keccak_256 large(UINT64_C(0x0123456789abcdef));
    BOOST_TEST(large.result() == seeded_oracle(UINT64_C(0x0123456789abcdef)).result());
}

}  // namespace

int main() {
    check_published();
    check_eip55();
    check_oracle();
    check_edges();
    return webcpp::test::exit_status(boost::report_errors());
}
