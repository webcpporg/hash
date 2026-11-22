// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// mac, and the keyed modes of BLAKE2b (digest_of, hasher) and of BLAKE3 (the blake3 class), hold
// detail::timing_guard (design D1, D4): each enters its own guard first, on every target, through
// the seam; a call that is not keyed enters none (D2); a guard changes no byte of any output.
// Where the CPU has DIT, mac leaves the thread's state as it found it.

#include "support/timing_seam.hpp"

#include <webcpp/hash/algorithms.hpp>
#include <webcpp/hash/backends/sodium.hpp>
#include <webcpp/hash/blake3.hpp>
#include <webcpp/hash/detail/timing.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/test/exit_status.hpp>

#include "require.hpp"
#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/json.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

namespace detail = webcpp::hash::detail;
namespace hash = webcpp::hash;
namespace test = webcpp::test;
namespace digests = webcpp::hash::digests;
namespace macs = webcpp::hash::macs;
namespace backends = webcpp::hash::backends;
using webcpp::hash::blake3;

using hmac_sha256 = macs::hmac<digests::sha2_256>;
using blake2b_options = hash::digest_options<digests::blake2b>;

/**
 * Sets or clears DIT for this thread, as a program can, so that a test starts from a known state;
 * only where the CPU has DIT, since the instruction traps on a CPU without it.
 */
void force_dit([[maybe_unused]] bool set) {
#ifdef WEBCPP_HASH_DETAIL_TIMING_COVERED
    if (!detail::cpu_has_dit()) {
        return;
    }
    detail::write_dit(set ? detail::dit_bit : 0);
#endif
}

std::array<std::uint8_t, 32> const key = [] {
    std::array<std::uint8_t, 32> bytes{};
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<std::uint8_t>(i + 1);
    }
    return bytes;
}();
std::array<std::uint8_t, 24> const input{9, 8, 7, 6, 5, 4, 3, 2, 1};

// mac enters its own guard on the default backend and on sodium, and still does when the output's
// size is wrong, since the guard precedes the checks.
void mac_enters() {
    std::array<std::uint8_t, 32> tag{};
    test::require_enters("hash::mac of hmac_sha256 on hash2", [&] {
        auto const done = hash::mac<hmac_sha256, backends::hash2>(tag, key, input);
        BOOST_TEST(done.has_value());
    });
    test::require_enters("hash::mac of blake2b_mac on sodium", [&] {
        auto const done = hash::mac<macs::blake2b_mac, backends::sodium>(tag, key, input);
        BOOST_TEST(done.has_value());
    });
    std::array<std::uint8_t, 1> wrong{};
    test::require_enters("hash::mac with a tag of the wrong size on hash2", [&] {
        auto const done = hash::mac<hmac_sha256, backends::hash2>(wrong, key, input);
        BOOST_TEST(!done.has_value());
    });
    test::require_enters("hash::mac with a key of the wrong size on sodium", [&] {
        auto const done = hash::mac<macs::blake2b_mac, backends::sodium>(
            tag, std::span<std::uint8_t const>{}, input);
        BOOST_TEST(!done.has_value());
    });
}

// Where the CPU has DIT: mac leaves it set when the program set it, and clear when it was clear.
void mac_leaves_set_state() {
    std::array<std::uint8_t, 32> tag{};
    force_dit(true);
    BOOST_TEST_EQ(detail::dit_is_set(), detail::cpu_has_dit());
    BOOST_TEST((hash::mac<hmac_sha256, backends::hash2>(tag, key, input)).has_value());
    BOOST_TEST_EQ(detail::dit_is_set(), detail::cpu_has_dit());
    force_dit(false);
    BOOST_TEST(!detail::dit_is_set());
    BOOST_TEST((hash::mac<hmac_sha256, backends::hash2>(tag, key, input)).has_value());
    BOOST_TEST(!detail::dit_is_set());
}

// digest_of with a key, and hasher's make, update and finish of a keyed hasher, each enter their
// own guard; the output is the one of the unguarded computation, the same on the unkeyed call.
void keyed_blake2b() {
    blake2b_options const keyed{.key = key};
    std::array<std::uint8_t, 64> once{};
    test::require_enters("hash::digest_of with a key on sodium", [&] {
        BOOST_TEST((hash::digest_of<digests::blake2b>(once, input, keyed)).has_value());
    });
    // The same tag by mac, and by hasher.
    std::array<std::uint8_t, 64> by_mac{};
    BOOST_TEST((hash::mac<macs::blake2b_mac, backends::sodium>(by_mac, key, input)).has_value());
    BOOST_TEST(once == by_mac);

    std::optional<hash::hasher<digests::blake2b>> hashing;
    test::require_enters("hash::hasher::make with a key", [&] {
        auto made = hash::hasher<digests::blake2b>::make(keyed);
        if (BOOST_TEST(made.has_value())) {
            hashing.emplace(std::move(*made));
        }
    });
    if (!hashing) {
        return;
    }
    test::require_enters("hash::hasher::update of a keyed hasher",
                         [&] { BOOST_TEST(hashing->update(input).has_value()); });
    std::array<std::uint8_t, 64> pieces{};
    test::require_enters("hash::hasher::finish of a keyed hasher",
                         [&] { BOOST_TEST(hashing->finish(pieces).has_value()); });
    BOOST_TEST(pieces == once);
}

// Without a key, BLAKE2b and every other digest compute on public data: no guard.
void unkeyed_blake2b_enters_none() {
    std::array<std::uint8_t, 64> out{};
    test::uncovered("hash::digest_of of blake2b without a key", [&] {
        BOOST_TEST((hash::digest_of<digests::blake2b>(out, input)).has_value());
    });
    std::optional<hash::hasher<digests::blake2b>> hashing;
    test::uncovered("hash::hasher::make of blake2b without a key", [&] {
        auto made = hash::hasher<digests::blake2b>::make();
        if (BOOST_TEST(made.has_value())) {
            hashing.emplace(std::move(*made));
        }
    });
    if (!hashing) {
        return;
    }
    test::uncovered("hash::hasher::update of blake2b without a key",
                    [&] { BOOST_TEST(hashing->update(input).has_value()); });
    test::uncovered("hash::hasher::finish of blake2b without a key",
                    [&] { BOOST_TEST(hashing->finish(out).has_value()); });
    std::array<std::uint8_t, 32> id{};
    test::uncovered("hash::digest_of of sha2_256 on hash2", [&] {
        BOOST_TEST((hash::digest_of<digests::sha2_256, backends::hash2>(id, input)).has_value());
    });
}

// A keyed hasher moved into another still holds its guards, and so does one assigned to; an
// unkeyed one moved holds none. Moving enters no guard of its own.
void moved_keyed_hasher() {
    blake2b_options const keyed{.key = key};
    auto made = hash::hasher<digests::blake2b>::make(keyed);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    std::optional<hash::hasher<digests::blake2b>> moved;
    test::uncovered("moving a keyed hasher", [&] { moved.emplace(std::move(*made)); });
    test::require_enters("hash::hasher::update of a moved keyed hasher",
                         [&] { BOOST_TEST(moved->update(input).has_value()); });
    auto other = hash::hasher<digests::blake2b>::make();
    if (!BOOST_TEST(other.has_value())) {
        return;
    }
    test::uncovered("assigning a keyed hasher", [&] { *other = std::move(*moved); });
    test::require_enters("hash::hasher::finish of an assigned keyed hasher", [&] {
        std::array<std::uint8_t, 64> out{};
        BOOST_TEST(other->finish(out).has_value());
    });

    auto plain = hash::hasher<digests::blake2b>::make();
    if (!BOOST_TEST(plain.has_value())) {
        return;
    }
    std::optional<hash::hasher<digests::blake2b>> plain_moved;
    plain_moved.emplace(std::move(*plain));
    test::uncovered("hash::hasher::update of a moved unkeyed hasher",
                    [&] { BOOST_TEST(plain_moved->update(input).has_value()); });
    // The destructor of a keyed hasher wipes and holds no guard.
    auto dying = hash::hasher<digests::blake2b>::make(keyed);
    if (BOOST_TEST(dying.has_value())) {
        std::optional<hash::hasher<digests::blake2b>> held;
        held.emplace(std::move(*dying));
        test::uncovered("destroying a keyed hasher", [&] { held.reset(); });
    }
}

// The whole file at path; one that cannot be opened ends the test, by name.
std::string read_text(std::string const& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cerr << "cannot open test data: " << path << '\n';
        std::abort();
    }
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

// BLAKE3's official vectors, keyed and derive-key entries, through objects whose every call
// enters a guard: the guard changes no byte.
void blake3_vectors_unchanged() {
    namespace json = boost::json;
    auto const text = read_text(WEBCPP_TEST_BLAKE3_VECTORS "/test_vectors.json");
    boost::system::error_code ec;
    auto const doc = json::parse(text, ec);
    test::require(BOOST_TEST(!ec));
    std::string_view const key_text = doc.at("key").as_string();
    test::require(BOOST_TEST_EQ(key_text.size(), std::size_t{32}));
    std::array<std::uint8_t, 32> vector_key{};
    for (std::size_t i = 0; i < vector_key.size(); ++i) {
        vector_key[i] = static_cast<std::uint8_t>(key_text[i]);
    }
    std::string_view const context = doc.at("context_string").as_string();
    int cases = 0;
    for (auto const& entry : doc.at("cases").as_array()) {
        auto const length = static_cast<std::size_t>(entry.at("input_len").as_int64());
        std::vector<std::uint8_t> data(length);
        for (std::size_t i = 0; i < length; ++i) {
            data[i] = static_cast<std::uint8_t>(i % 251);
        }
        auto const expect = [&](blake3 hasher, std::string_view name) {
            std::string_view const hex = entry.at(name).as_string();
            std::vector<std::uint8_t> squeezed(hex.size() / 2);
            hasher.squeeze(squeezed);
            BOOST_TEST_EQ(test::to_hex(squeezed), std::string(hex));
        };
        auto keyed = blake3::keyed(vector_key);
        keyed.update(data.data(), data.size());
        expect(keyed, "keyed_hash");
        auto derived = blake3::derive_key(context);
        derived.update(data.data(), data.size());
        expect(derived, "derive_key");
        ++cases;
    }
    BOOST_TEST_EQ(cases, 35);
}

// The keyed modes and the seeds that key enter their own guard; the plain mode, and the seeds that
// do not key, enter none.
void blake3_modes() {
    std::array<std::uint8_t, 40> const bytes{1, 2, 3, 4, 5, 6, 7, 8, 9};
    std::optional<blake3> keyed;
    test::require_enters("blake3::keyed", [&] { keyed.emplace(blake3::keyed(key)); });
    test::require_enters("blake3::update(void of a keyed object", [&] {
        keyed->update(static_cast<void const*>(bytes.data()), bytes.size());
    });
    test::require_enters("blake3::update(unsigned of a keyed object", [&] {
        keyed->update(static_cast<unsigned char const*>(bytes.data()), bytes.size());
    });
    test::require_enters("blake3::result of a keyed object",
                         [&] { BOOST_TEST(keyed->result().size() == 32); });
    test::require_enters("blake3::squeeze of a keyed object", [&] {
        std::array<std::uint8_t, 70> out{};
        keyed->squeeze(out, 3);
    });
    test::require_enters("blake3::reset of a keyed object", [&] { keyed->reset(); });

    std::optional<blake3> derived;
    test::require_enters("blake3::derive_key", [&] { derived.emplace(blake3::derive_key("ctx")); });
    test::require_enters("blake3::update(void of a derived object", [&] {
        derived->update(static_cast<void const*>(bytes.data()), bytes.size());
    });
    test::require_enters("blake3::result of a derived object",
                         [&] { BOOST_TEST(derived->result().size() == 32); });
    test::require_enters("blake3::reset of a derived object", [&] { derived->reset(); });

    // A copy and a move of a keyed object are keyed as it is.
    blake3 copy{*keyed};
    test::require_enters("blake3::update(void of a copy of a keyed object",
                         [&] { copy.update(static_cast<void const*>(bytes.data()), 1); });
    blake3 moved{std::move(copy)};
    test::require_enters("blake3::update(void of a moved keyed object",
                         [&] { moved.update(static_cast<void const*>(bytes.data()), 1); });

    // The seeds that key: a non-zero integer, and bytes.
    test::require_enters("blake3::blake3 of a non-zero integer seed", [&] {
        blake3 seeded{std::uint64_t{7}};
        BOOST_TEST(seeded.result().size() == 32);
    });
    test::require_enters("blake3::blake3(char of 16 bytes", [&] {
        blake3 seeded{static_cast<unsigned char const*>(bytes.data()), std::size_t{16}};
        BOOST_TEST(seeded.result().size() == 32);
    });
    test::require_enters("blake3::blake3(char of 40 bytes", [&] {
        blake3 seeded{static_cast<unsigned char const*>(bytes.data()), std::size_t{40}};
        BOOST_TEST(seeded.result().size() == 32);
    });
    // The delegating constructor of void const* holds none: the one it delegates to runs first.
    test::require_enters("blake3::blake3(char of 16 bytes through void", [&] {
        blake3 seeded{static_cast<void const*>(bytes.data()), std::size_t{16}};
        BOOST_TEST(seeded.result().size() == 32);
    });
    // The seed that keys leaves a keyed object.
    blake3 seeded{std::uint64_t{7}};
    test::require_enters("blake3::update(void of a seeded object",
                         [&] { seeded.update(static_cast<void const*>(bytes.data()), 3); });

    // The plain mode, and the seeds that are plain, compute on public data.
    test::uncovered("blake3::blake3()", [&] { blake3 plain; });
    blake3 plain;
    test::uncovered("blake3::update(void of a plain object",
                    [&] { plain.update(static_cast<void const*>(bytes.data()), bytes.size()); });
    test::uncovered("blake3::update(unsigned of a plain object", [&] {
        plain.update(static_cast<unsigned char const*>(bytes.data()), bytes.size());
    });
    test::uncovered("blake3::result of a plain object",
                    [&] { BOOST_TEST(plain.result().size() == 32); });
    test::uncovered("blake3::squeeze of a plain object", [&] {
        std::array<std::uint8_t, 70> out{};
        plain.squeeze(out);
    });
    test::uncovered("blake3::reset of a plain object", [&] { plain.reset(); });
    test::uncovered("blake3 of a zero integer seed", [&] {
        blake3 zero{std::uint64_t{0}};
        zero.update(static_cast<void const*>(bytes.data()), 3);
        BOOST_TEST(zero.result().size() == 32);
    });
    test::uncovered("blake3 of a seed of no bytes", [&] {
        blake3 empty{static_cast<unsigned char const*>(bytes.data()), std::size_t{0}};
        empty.update(static_cast<void const*>(bytes.data()), 3);
        BOOST_TEST(empty.result().size() == 32);
    });
    test::uncovered("blake3 of a seed of no bytes through void", [&] {
        blake3 empty{static_cast<void const*>(bytes.data()), std::size_t{0}};
        BOOST_TEST(empty.result().size() == 32);
    });
}

}  // namespace

int main() {
    mac_enters();
    mac_leaves_set_state();
    keyed_blake2b();
    unkeyed_blake2b_enters_none();
    moved_keyed_hasher();
    blake3_vectors_unchanged();
    blake3_modes();
    return webcpp::test::exit_status(boost::report_errors());
}
