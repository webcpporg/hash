// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// blake3 in Hash2's HashAlgorithm form: the digest of nothing; the seeds, an integer one and
// byte ones of every length class, against BLAKE3's C functions called directly; Hash2's
// contract on result(), whose values never repeat for one history and continue the extendable
// output; derive_key's context taken as bytes, a zero byte among them; and reset().

#include <webcpp/hash/blake3.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/digest.hpp>

#include <blake3.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <type_traits>

namespace {

using webcpp::hash::blake3;

// Hash2 requires a copyable hash algorithm with these members.
static_assert(std::is_copy_constructible_v<blake3>);
static_assert(std::is_copy_assignable_v<blake3>);
static_assert(blake3::block_size == 64);
static_assert(blake3::key_size == 32);
static_assert(std::is_same_v<blake3::result_type, boost::hash2::digest<32>>);

// n bytes of BLAKE3's keyed hash under key, of message, from position on, through the C API.
template <std::size_t N>
std::array<std::uint8_t, N> c_keyed(std::array<std::uint8_t, 32> const& key,
                                    std::span<std::uint8_t const> message,
                                    std::uint64_t position = 0) {
    blake3_hasher hasher;
    blake3_hasher_init_keyed(&hasher, key.data());
    blake3_hasher_update(&hasher, message.data(), message.size());
    std::array<std::uint8_t, N> output{};
    blake3_hasher_finalize_seek(&hasher, position, output.data(), output.size());
    return output;
}

bool same(boost::hash2::digest<32> const& digest, std::span<std::uint8_t const> bytes) {
    return bytes.size() == digest.size() && std::equal(digest.begin(), digest.end(), bytes.begin());
}

void check_empty() {
    webcpp::hash::blake3 hasher;
    BOOST_TEST_EQ(boost::hash2::to_string(hasher.result()),
                  "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
}

// A bytes seed of exactly 32 bytes is BLAKE3's keyed mode with that key.
void check_seed_is_key() {
    std::array<std::uint8_t, 32> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>(i);
    }
    webcpp::hash::blake3 seeded(key.data(), key.size());
    auto keyed = webcpp::hash::blake3::keyed(key);
    seeded.update("x", 1);
    keyed.update("x", 1);
    BOOST_TEST(seeded.result() == keyed.result());
}

// Hash2's contract: results never repeat for one history; update after result continues.
void check_result_sequence() {
    webcpp::hash::blake3 a;
    a.update("abc", 3);
    const auto first = a.result();
    const auto second = a.result();
    BOOST_TEST(first != second);
    std::array<std::uint8_t, 64> stream{};
    a.squeeze(stream);
    BOOST_TEST(std::equal(first.begin(), first.end(), stream.begin()));
    BOOST_TEST(std::equal(second.begin(), second.end(), stream.begin() + 32));
    a.update("d", 1);
    webcpp::hash::blake3 b;
    b.update("abcd", 4);
    BOOST_TEST(a.result() == b.result());
}

// An update of no bytes is no input: the output goes on where it was.
void check_empty_update_continues() {
    blake3 a;
    a.update("abc", 3);
    a.result();
    a.update("", 0);
    std::array<std::uint8_t, 64> stream{};
    a.squeeze(stream);
    BOOST_TEST(same(a.result(), std::span<std::uint8_t const>(stream).subspan(32)));
}

// The integer seed: 0 is the plain hash; another is the bytes seed of its 8 little-endian bytes.
void check_integer_seeds() {
    blake3 zero(std::uint64_t{0});
    blake3 plain;
    zero.update("x", 1);
    plain.update("x", 1);
    BOOST_TEST(zero.result() == plain.result());

    std::array<std::uint8_t, 8> const one_bytes{1, 0, 0, 0, 0, 0, 0, 0};
    blake3 one(std::uint64_t{1});
    blake3 from_bytes(one_bytes.data(), one_bytes.size());
    one.update("x", 1);
    from_bytes.update("x", 1);
    auto const result = one.result();
    BOOST_TEST(result == from_bytes.result());

    // And that is the keyed hash under the 8 bytes, zero-padded to the key's 32.
    std::array<std::uint8_t, 32> key{};
    key[0] = 1;
    std::array<std::uint8_t, 1> const x{'x'};
    BOOST_TEST(same(result, c_keyed<32>(key, x)));
}

// A bytes seed of no bytes is the plain hash; a shorter one is a zero-padded key.
void check_short_seeds() {
    blake3 none(static_cast<void const*>(nullptr), 0);
    blake3 plain;
    none.update("x", 1);
    plain.update("x", 1);
    BOOST_TEST(none.result() == plain.result());

    std::array<unsigned char, 5> const seed{9, 8, 7, 6, 5};
    blake3 seeded(seed.data(), seed.size());
    seeded.update("x", 1);
    std::array<std::uint8_t, 32> key{};
    std::ranges::copy(seed, key.begin());
    std::array<std::uint8_t, 1> const x{'x'};
    BOOST_TEST(same(seeded.result(), c_keyed<32>(key, x)));
}

// A 41-byte seed: keyed by its first 32 bytes, the other 9 absorbed, then a result taken, as
// Hash2's blake2b_512 is seeded. The next update starts the output again; without one, the
// first result is the output's second 32 bytes.
void check_long_seed() {
    std::array<std::uint8_t, 41> seed{};
    for (std::size_t i = 0; i < seed.size(); ++i) {
        seed[i] = static_cast<std::uint8_t>(200 - i);
    }
    std::array<std::uint8_t, 32> key{};
    std::copy_n(seed.begin(), key.size(), key.begin());
    auto const rest = std::span<std::uint8_t const>(seed).subspan(32);

    blake3 untouched(seed.data(), seed.size());
    BOOST_TEST(same(untouched.result(), c_keyed<32>(key, rest, 32)));

    blake3 seeded(seed.data(), seed.size());
    seeded.update("x", 1);
    std::array<std::uint8_t, 10> message{};
    std::ranges::copy(rest, message.begin());
    message[9] = 'x';
    BOOST_TEST(same(seeded.result(), c_keyed<32>(key, message)));
}

// derive_key takes its context as bytes: one with a zero byte is all of it, not its prefix.
void check_derive_key_context_with_zero() {
    std::string_view const context("ab\0cd", 5);
    auto derived = blake3::derive_key(context);
    derived.update("x", 1);

    blake3_hasher hasher;
    blake3_hasher_init_derive_key_raw(&hasher, context.data(), context.size());
    blake3_hasher_update(&hasher, "x", 1);
    std::array<std::uint8_t, 32> expected{};
    blake3_hasher_finalize(&hasher, expected.data(), expected.size());
    auto const result = derived.result();
    BOOST_TEST(same(result, expected));

    auto prefix = blake3::derive_key(std::string_view("ab", 2));
    prefix.update("x", 1);
    BOOST_TEST(result != prefix.result());
}

// reset() forgets the input and the output taken, and keeps the mode with its key or context.
void check_reset() {
    std::array<std::uint8_t, 32> key{};
    key.fill(0x5a);
    auto keyed = blake3::keyed(key);
    keyed.update("first", 5);
    keyed.result();
    keyed.reset();
    keyed.update("second", 6);
    auto fresh = blake3::keyed(key);
    fresh.update("second", 6);
    BOOST_TEST(keyed.result() == fresh.result());

    auto derived = blake3::derive_key("context");
    derived.update("first", 5);
    derived.reset();
    BOOST_TEST(derived.result() == blake3::derive_key("context").result());

    blake3 plain;
    plain.update("first", 5);
    plain.result();
    plain.reset();
    BOOST_TEST_EQ(boost::hash2::to_string(plain.result()),
                  "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
}

// squeeze() reads any part of the output without changing the hash.
void check_squeeze_position() {
    blake3 a;
    a.update("abc", 3);
    std::array<std::uint8_t, 96> whole{};
    a.squeeze(whole);
    std::array<std::uint8_t, 7> part{};
    a.squeeze(part, 61);
    BOOST_TEST(std::equal(part.begin(), part.end(), whole.begin() + 61));
    BOOST_TEST(same(a.result(), std::span<std::uint8_t const>(whole).first(32)));
}

}  // namespace

int main() {
    check_empty();
    check_seed_is_key();
    check_result_sequence();
    check_empty_update_continues();
    check_integer_seeds();
    check_short_seeds();
    check_long_seed();
    check_derive_key_context_with_zero();
    check_reset();
    check_squeeze_position();
    return webcpp::test::exit_status(boost::report_errors());
}
