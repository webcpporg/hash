// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// mac, the keyed modes of BLAKE2b (digest_of, hasher) and of BLAKE3 (the blake3 class), and the
// key derivations and password hashes of the default backends (hkdf_extract, hkdf_expand, hkdf,
// pbkdf2, blake2b_subkey, argon2id, argon2, scrypt), hold detail::timing_guard (design D1, D4):
// each enters its own guard first, on every target, through the seam, also for a call that a
// guard refuses before the backend; a call that is not keyed enters none (D2); a guard changes no
// byte of any output. Where the CPU has DIT, mac leaves the thread's state as it found it.

#include "support/timing_coverage.hpp"

#include <webcpp/hash/algorithms.hpp>
#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/backends/sodium.hpp>
#include <webcpp/hash/blake2b_subkey.hpp>
#include <webcpp/hash/blake3.hpp>
#include <webcpp/hash/detail/timing.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/hash/pbkdf2.hpp>
#include <webcpp/hash/scrypt.hpp>
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
#include <memory>
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

constexpr std::array<std::uint8_t, 32> key = [] {
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
    test::force_dit(true);
    BOOST_TEST_EQ(detail::dit_is_set(), detail::cpu_has_dit());
    BOOST_TEST((hash::mac<hmac_sha256, backends::hash2>(tag, key, input)).has_value());
    BOOST_TEST_EQ(detail::dit_is_set(), detail::cpu_has_dit());
    test::force_dit(false);
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
        // Held by a unique_ptr, not a std::optional, whose reset GCC 15 at -O2 reads as a use of
        // an uninitialized phase (-Wmaybe-uninitialized).
        auto held = std::make_unique<hash::hasher<digests::blake2b>>(std::move(*dying));
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
    test::require_enters("blake3::update(void const*) of a keyed object", [&] {
        keyed->update(static_cast<void const*>(bytes.data()), bytes.size());
    });
    test::require_enters("blake3::update(unsigned char const*) of a keyed object", [&] {
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
    test::require_enters("blake3::update(void const*) of a derived object", [&] {
        derived->update(static_cast<void const*>(bytes.data()), bytes.size());
    });
    test::require_enters("blake3::result of a derived object",
                         [&] { BOOST_TEST(derived->result().size() == 32); });
    test::require_enters("blake3::reset of a derived object", [&] { derived->reset(); });

    // A copy and a move of a keyed object are keyed as it is.
    blake3 copy{*keyed};
    test::require_enters("blake3::update(void const*) of a copy of a keyed object",
                         [&] { copy.update(static_cast<void const*>(bytes.data()), 1); });
    // blake3 is trivially copyable: its move is its copy, which the check names as a move.
    blake3 moved{std::move(copy)};  // NOLINT(performance-move-const-arg)
    test::require_enters("blake3::update(void const*) of a moved keyed object",
                         [&] { moved.update(static_cast<void const*>(bytes.data()), 1); });

    // The seeds that key: a non-zero integer, and bytes.
    test::require_enters("blake3::blake3 of a non-zero integer seed", [&] {
        blake3 seeded{std::uint64_t{7}};
        BOOST_TEST(seeded.result().size() == 32);
    });
    test::require_enters("blake3::blake3(unsigned char const*) of 16 bytes", [&] {
        blake3 seeded{static_cast<unsigned char const*>(bytes.data()), std::size_t{16}};
        BOOST_TEST(seeded.result().size() == 32);
    });
    test::require_enters("blake3::blake3(unsigned char const*) of 40 bytes", [&] {
        blake3 seeded{static_cast<unsigned char const*>(bytes.data()), std::size_t{40}};
        BOOST_TEST(seeded.result().size() == 32);
    });
    // The delegating constructor of void const* holds none: the one it delegates to runs first.
    test::require_enters(
        "blake3::blake3(unsigned char const*) of 16 bytes, through the void const* overload", [&] {
            blake3 seeded{static_cast<void const*>(bytes.data()), std::size_t{16}};
            BOOST_TEST(seeded.result().size() == 32);
        });
    // The seed that keys leaves a keyed object.
    blake3 seeded{std::uint64_t{7}};
    test::require_enters("blake3::update(void const*) of a seeded object",
                         [&] { seeded.update(static_cast<void const*>(bytes.data()), 3); });

    // The plain mode, and the seeds that are plain, compute on public data.
    test::uncovered("blake3::blake3()", [&] { blake3 plain; });
    blake3 plain;
    test::uncovered("blake3::update(void const*) of a plain object",
                    [&] { plain.update(static_cast<void const*>(bytes.data()), bytes.size()); });
    test::uncovered("blake3::update(unsigned char const*) of a plain object", [&] {
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

using hmac_sha2_256 = hash::hmac_sha2_256;

std::array<std::uint8_t, 16> const salt16{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};

// hkdf_extract and hkdf_expand enter their own guards, and hkdf its own first though it computes
// what the other two do; a call refused by a guard (an output of no byte) enters its guard too.
void hkdf_enters() {
    using prk_type = hmac_sha2_256::result_type;
    std::optional<prk_type> prk;
    test::require_enters("hash::hkdf_extract of a salt on hash2", [&] {
        auto const made = hash::hkdf_extract<hmac_sha2_256, backends::hash2>(salt16, key);
        if (BOOST_TEST(made.has_value())) {
            prk.emplace(*made);
        }
    });
    if (!prk) {
        return;
    }
    std::array<std::uint8_t, 42> okm{};
    test::require_enters("hash::hkdf_expand of a prk on hash2", [&] {
        BOOST_TEST(
            (hash::hkdf_expand<hmac_sha2_256, backends::hash2>(okm, *prk, input)).has_value());
    });
    test::require_enters("hash::hkdf_expand with a prk of the wrong size on hash2", [&] {
        BOOST_TEST(!(hash::hkdf_expand<hmac_sha2_256, backends::hash2>(
                         okm, std::span<std::uint8_t const>{key}.first(5), input))
                        .has_value());
    });
    std::array<std::uint8_t, 42> whole{};
    test::require_enters("hash::hkdf of a salt on hash2", [&] {
        BOOST_TEST(
            (hash::hkdf<hmac_sha2_256, backends::hash2>(whole, salt16, key, input)).has_value());
    });
    // The two steps give what hkdf gives: the guards change no byte.
    std::array<std::uint8_t, 42> stepped{};
    auto const extracted = hash::hkdf_extract<hmac_sha2_256, backends::hash2>(salt16, key);
    if (BOOST_TEST(extracted.has_value())) {
        BOOST_TEST((hash::hkdf_expand<hmac_sha2_256, backends::hash2>(stepped, *extracted, input))
                       .has_value());
        BOOST_TEST(stepped == whole);
    }
    std::array<std::uint8_t, 0> none{};
    test::require_enters("hash::hkdf with an output of no byte on hash2", [&] {
        BOOST_TEST(
            !(hash::hkdf<hmac_sha2_256, backends::hash2>(none, salt16, key, input)).has_value());
    });
}

// pbkdf2 enters its guard, also for an iteration count of 0, and derives the same bytes.
void pbkdf2_enters() {
    std::array<std::uint8_t, 32> derived{};
    test::require_enters("hash::pbkdf2 of 1000 iterations on hash2", [&] {
        BOOST_TEST(
            (hash::pbkdf2<hmac_sha2_256, backends::hash2>(derived, key, salt16, 1000)).has_value());
    });
    std::array<std::uint8_t, 32> again{};
    test::require_enters("hash::pbkdf2 with the same arguments on hash2", [&] {
        BOOST_TEST(
            (hash::pbkdf2<hmac_sha2_256, backends::hash2>(again, key, salt16, 1000)).has_value());
    });
    BOOST_TEST(derived == again);
    test::require_enters("hash::pbkdf2 of 0 iterations on hash2", [&] {
        BOOST_TEST(
            !(hash::pbkdf2<hmac_sha2_256, backends::hash2>(derived, key, salt16, 0)).has_value());
    });
}

// blake2b_subkey, argon2id, argon2 and scrypt on sodium, each also with a parameter refused
// before the backend.
void sodium_derivations_enter() {
    std::array<std::uint8_t, 8> const context{'c', 't', 'x', '_', 't', 'e', 's', 't'};
    std::array<std::uint8_t, 32> subkey{};
    test::require_enters("hash::blake2b_subkey on sodium", [&] {
        BOOST_TEST((hash::blake2b_subkey<backends::sodium>(subkey, key, 7, context)).has_value());
    });
    std::array<std::uint8_t, 8> tiny{};
    test::require_enters("hash::blake2b_subkey with an output too small on sodium", [&] {
        BOOST_TEST(!(hash::blake2b_subkey<backends::sodium>(tiny, key, 7, context)).has_value());
    });

    std::array<std::uint8_t, 32> derived{};
    hash::argon2id_parameters const cheapest{.passes = 1, .memory = 8192};
    test::require_enters("hash::argon2id of the minimum parameters on sodium", [&] {
        BOOST_TEST((hash::argon2id<backends::sodium>(derived, key, salt16, cheapest)).has_value());
    });
    std::array<std::uint8_t, 4> const short_salt{1, 2, 3, 4};
    test::require_enters("hash::argon2id with a salt of the wrong size on sodium", [&] {
        BOOST_TEST(
            !(hash::argon2id<backends::sodium>(derived, key, short_salt, cheapest)).has_value());
    });

    hash::argon2_parameters const family{.passes = 3, .memory_kib = 8};
    test::require_enters("hash::argon2 of argon2id on sodium", [&] {
        BOOST_TEST(
            (hash::argon2<hash::kdfs::argon2id, backends::sodium>(derived, key, salt16, family))
                .has_value());
    });
    test::require_enters("hash::argon2 of argon2i on sodium", [&] {
        BOOST_TEST(
            (hash::argon2<hash::kdfs::argon2i, backends::sodium>(derived, key, salt16, family))
                .has_value());
    });
    test::require_enters("hash::argon2 with a salt too short on sodium", [&] {
        BOOST_TEST(!(hash::argon2<hash::kdfs::argon2id, backends::sodium>(derived, key, short_salt,
                                                                          family))
                        .has_value());
    });

    hash::scrypt_parameters const small{.n = 16, .r = 1, .p = 1};
    test::require_enters("hash::scrypt of N = 16 on sodium", [&] {
        BOOST_TEST((hash::scrypt<backends::sodium>(derived, key, salt16, small)).has_value());
    });
    test::require_enters("hash::scrypt of N = 1 on sodium", [&] {
        BOOST_TEST(!(hash::scrypt<backends::sodium>(
                         derived, key, salt16, hash::scrypt_parameters{.n = 1, .r = 1, .p = 1}))
                        .has_value());
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
    hkdf_enters();
    pbkdf2_enters();
    sodium_derivations_enter();
    return webcpp::test::exit_status(boost::report_errors());
}
