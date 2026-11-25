// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The coverage of detail::timing_guard, driven by the capability table: every keyed cell of a
// backend in doc/capabilities.json enters its own guard first and leaves the thread's DIT as it
// found it, and every digest cell of the backend, called without a key, enters none (design D1,
// D2). Each backend's timing_coverage_<backend>_test.cpp builds its calls from the helpers here
// and hands them to check_and_run, which fails on a keyed cell of the table with no call and on a
// call that names no keyed cell; then it walks the backend's digest cells through
// uncover_digests. A test includes this header before any hash header.
//
// covered, and the support's shape, are a copy of libs/crypto/test/support/timing_coverage.hpp
// with hash's guard: the duplication is accepted for the reason of detail/timing.hpp's own (hash
// includes nothing of crypto). The keyed cells are the table's (ruling H6): every function of
// the chapters macs, kdfs and password_hashing whose kind is not "type", each backend's cell, one
// per hmac where the cell lists hmacs ("other": a Hash2 hmac the list does not name); plus three
// keyed functions the table holds no cell of, named here with design D1 as the reason: BLAKE2b
// with a key (digest_of and a hasher round) wherever the backend has digests::blake2b, the blake3
// type's keyed modes on backends::blake3, and bcrypt_verify wherever the backend has bcrypt
// (H12). backends::webcrypto has no coverage test (D6).

#ifndef WEBCPP_TEST_HASH_SUPPORT_TIMING_COVERAGE_HPP
#define WEBCPP_TEST_HASH_SUPPORT_TIMING_COVERAGE_HPP

#include "timing_dit.hpp"

#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/bcrypt.hpp>
#include <webcpp/hash/blake2b_subkey.hpp>
#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/detail/timing.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/hash/kdf_standards.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/hash/pbkdf2.hpp>
#include <webcpp/hash/scrypt.hpp>

#include "data_file.hpp"
#include "defaults.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/json.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

namespace webcpp::test {

/**
 * Runs `call` and reports an error when it entered no detail::timing_guard, when the first guard
 * it entered is not the one of `function` (support/timing_seam.hpp), or when it left the thread's
 * DIT other than it found it.
 *
 * @param name What the call is, `<qualifiers>::<function>[ how] on <backend>`, as an error names
 * it.
 * @param function The function whose guard the call must enter first, `<scope>::<identifier>`,
 * where the name cannot say it (a member of a class template, overloads).
 * @param call The call, with its arguments bound.
 */
template <class Call>
void covered(std::string const& name, std::string const& function, Call&& call) {
    bool const before = webcpp::hash::detail::dit_is_set();
    require_enters(name, function, std::forward<Call>(call));
    if (webcpp::hash::detail::dit_is_set() != before) {
        std::string const message = name + (before ? " left DIT clear, though it found it set"
                                                   : " left DIT set, though it found it clear");
        BOOST_ERROR(message.c_str());
    }
}

/**
 * `covered`, for a call whose name begins with the function whose guard it must enter first,
 * `<qualifiers>::<scope>::<identifier>`.
 *
 * @param name What the call is, `<qualifiers>::<function>[ how] on <backend>`, as an error names
 * it.
 * @param call The call, with its arguments bound.
 */
template <class Call>
void covered(std::string const& name, Call&& call) {
    covered(name, name, std::forward<Call>(call));
}

/**
 * Runs `call` and reports an error when it entered a detail::timing_guard: a public function that
 * computes on public data alone (a digest without a key, a Hash2 type) holds none (design D2,
 * D3). A guard added to one by mistake costs every call, and makes the rule "a guard where a key
 * is" harder to check.
 *
 * @param name What the call is, `<qualifiers>::<function>[ how] on <backend>`, as an error names
 * it.
 * @param call The call, with its arguments bound.
 */
template <class Call>
void uncovered(std::string_view name, Call&& call) {
    std::size_t const before = timing_entries;
    std::forward<Call>(call)();
    if (timing_entries != before) {
        std::string const message =
            std::string(name) + " entered a detail::timing_guard it should not hold";
        BOOST_ERROR(message.c_str());
    }
}

/** A backend's coverage calls, by the name of the keyed cell each covers. */
using coverage_calls = std::map<std::string, std::function<void()>, std::less<>>;

/**
 * The capability table, doc/capabilities.json, read from the directory the define
 * `WEBCPP_TEST_HASH_DOC` gives; a file that cannot be read or parsed ends the test, by name.
 *
 * @return The table.
 */
inline boost::json::value capability_table() {
    std::string const path = WEBCPP_TEST_HASH_DOC "/capabilities.json";
    boost::system::error_code ec;
    boost::json::value parsed = boost::json::parse(read_text(path), ec);
    if (ec || !parsed.is_object()) {
        std::cerr << "cannot parse " << path << ": " << ec.message() << '\n';
        std::abort();
    }
    return parsed;
}

/**
 * A function's cell on `backend`, or null.
 *
 * @param function A function of the table, an element of an algorithm's "functions".
 * @param backend The backend's name.
 * @return The cell, or null where the function has none on the backend.
 */
inline boost::json::value const* cell_of(boost::json::value const& function,
                                         std::string_view backend) {
    auto const& backends = function.at("backends").as_object();
    return backends.if_contains(backend);
}

/**
 * Whether the table has a cell of the function or tag `row` on `backend`, in any chapter.
 *
 * @param table The capability table.
 * @param row The function's name as the table spells it (`digests::blake2b`, `bcrypt`).
 * @param backend The backend's name.
 * @return Whether the cell exists.
 */
inline bool table_has_cell(boost::json::value const& table, std::string_view row,
                           std::string_view backend) {
    for (auto const& algorithm : table.at("algorithms").as_array()) {
        for (auto const& function : algorithm.at("functions").as_array()) {
            if (function.at("name").as_string() == row && cell_of(function, backend) != nullptr) {
                return true;
            }
        }
    }
    return false;
}

/**
 * Whether the table's cell of `digests::blake2b` on `backend` takes a key: the cell exists, and its
 * "partial", when it has one, does not list "a key" among what the backend refuses.
 *
 * @param backend The backend's name.
 * @return Whether the table says the backend takes a key.
 */
inline bool table_blake2b_takes_key(std::string_view backend) {
    auto const table = capability_table();
    for (auto const& algorithm : table.at("algorithms").as_array()) {
        for (auto const& function : algorithm.at("functions").as_array()) {
            if (function.at("name").as_string() != "digests::blake2b") {
                continue;
            }
            auto const* const cell = cell_of(function, backend);
            if (cell == nullptr) {
                return false;
            }
            auto const* const partial = cell->as_object().if_contains("partial");
            return partial == nullptr || !partial->is_string() ||
                   std::string_view(partial->as_string()).find("a key") == std::string_view::npos;
        }
    }
    return false;
}

/** The name of the keyed cell of BLAKE2b with a key, a keyed function of design D1. */
inline constexpr std::string_view keyed_blake2b_cell = "digests::blake2b keyed";
/** The name of the keyed cell of the blake3 type's keyed modes, a keyed function of design D1. */
inline constexpr std::string_view keyed_blake3_cell = "blake3 keyed";
/** The name of the keyed cell of bcrypt_verify, a keyed function of design D1 (ruling H12). */
inline constexpr std::string_view bcrypt_verify_cell = "bcrypt_verify";

/**
 * The keyed cells of `backend` (ruling H6), in the table's order, then the keyed functions this
 * support names with design D1 as the reason.
 *
 * A cell is named as the table names its function: `<function>` (`scrypt`), `<function><<hmac>>`
 * for each hmac the cell lists (`hkdf<hmac_sha2_256>`, `hkdf<other>`), `mac<<tag>>` for a tag of
 * `mac` (`mac<macs::siphash_2_4>`), `<function><<tag>>` for a variant (`argon2<kdfs::argon2d>`);
 * a row of a form of its function adds ` over <form>` (`hkdf<hmac_sha2_256> over pieces`).
 * The keyed functions: `digests::blake2b keyed` (digest_of and a hasher round with a key)
 * wherever the table has a cell of digests::blake2b; `blake3 keyed` (the blake3 type's keyed
 * modes) wherever it has the blake3 type; `bcrypt_verify` wherever it has bcrypt.
 *
 * @param backend The backend's name, as the table spells it.
 * @return The names.
 */
inline std::vector<std::string> keyed_cells(std::string_view backend) {
    constexpr std::array<std::string_view, 3> keyed_chapters{"macs", "kdfs", "password_hashing"};
    auto const table = capability_table();
    std::vector<std::string> cells;
    for (auto const& algorithm_value : table.at("algorithms").as_array()) {
        auto const& algorithm = algorithm_value.as_object();
        std::string_view const chapter = algorithm.at("chapter").as_string();
        if (std::ranges::find(keyed_chapters, chapter) == keyed_chapters.end()) {
            continue;
        }
        for (auto const& function_value : algorithm.at("functions").as_array()) {
            auto const& function = function_value.as_object();
            std::string_view const kind = function.at("kind").as_string();
            auto const* const cell = cell_of(function_value, backend);
            if (kind == "type" || cell == nullptr) {
                continue;
            }
            std::string const name(function.at("name").as_string());
            auto const* const form_value = function.if_contains("form");
            std::string const form =
                form_value == nullptr ? "" : " over " + std::string(form_value->as_string());
            std::string base = name;
            if (kind == "mac") {
                base = "mac<" + name + ">";
            } else if (kind == "kdf") {
                base = std::string(algorithm.at("name").as_string()) + "<" + name + ">";
            }
            auto const& hmacs = cell->as_object().at("hmacs");
            if (hmacs.is_null()) {
                cells.push_back(base.append(form));
                continue;
            }
            for (auto const& hmac : hmacs.as_array()) {
                std::string named = base;
                named.append("<").append(hmac.as_string()).append(">").append(form);
                cells.push_back(std::move(named));
            }
        }
    }
    if (table_has_cell(table, "digests::blake2b", backend)) {
        cells.emplace_back(keyed_blake2b_cell);
    }
    if (table_has_cell(table, "blake3", backend)) {
        cells.emplace_back(keyed_blake3_cell);
    }
    if (table_has_cell(table, "bcrypt", backend)) {
        cells.emplace_back(bcrypt_verify_cell);
    }
    return cells;
}

/**
 * Reports each keyed cell of `backend` that `calls` does not cover and each call that names no
 * keyed cell of it, then runs every call from a thread with DIT clear, and again from one that set
 * DIT itself (where the CPU has DIT), as a program can: `covered` checks that each call leaves the
 * thread's DIT as it found it, clear and set. The thread's DIT is clear after.
 *
 * @param backend The backend's name, as the table spells it.
 * @param calls The backend's coverage calls.
 */
inline void check_and_run(std::string_view backend, coverage_calls const& calls) {
    auto const cells = keyed_cells(backend);
    BOOST_TEST(!cells.empty());
    for (auto const& cell : cells) {
        if (!calls.contains(cell)) {
            std::string const message =
                cell + " on " + std::string(backend) + " is a keyed cell with no coverage call";
            BOOST_ERROR(message.c_str());
        }
    }
    for (auto const& entry : calls) {
        if (std::ranges::find(cells, entry.first) == cells.end()) {
            std::string const message =
                entry.first + " on " + std::string(backend) + " names no keyed cell";
            BOOST_ERROR(message.c_str());
        }
    }
    force_dit(false);
    for (auto const& entry : calls) {
        entry.second();
    }
    force_dit(true);
    for (auto const& entry : calls) {
        entry.second();
    }
    force_dit(false);
}

/**
 * The digest cells of `backend` (the functions of kind "digest"), in the table's order.
 *
 * @param backend The backend's name, as the table spells it.
 * @return The names of the tags, as `digests::sha2_256`.
 */
inline std::vector<std::string> digest_cells(std::string_view backend) {
    auto const table = capability_table();
    std::vector<std::string> cells;
    for (auto const& algorithm : table.at("algorithms").as_array()) {
        for (auto const& function_value : algorithm.at("functions").as_array()) {
            auto const& function = function_value.as_object();
            if (function.at("kind").as_string() == "digest" &&
                cell_of(function_value, backend) != nullptr) {
                cells.emplace_back(function.at("name").as_string());
            }
        }
    }
    return cells;
}

/** Every tag of `digests`, which the dispatch from a digest cell's name to its call reads. */
using coverage_digest_tags =
    std::tuple<hash::digests::md5, hash::digests::sha1, hash::digests::sha2_224,
               hash::digests::sha2_256, hash::digests::sha2_384, hash::digests::sha2_512,
               hash::digests::sha2_512_224, hash::digests::sha2_512_256, hash::digests::sha3_224,
               hash::digests::sha3_256, hash::digests::sha3_384, hash::digests::sha3_512,
               hash::digests::shake_128, hash::digests::shake_256, hash::digests::keccak_224,
               hash::digests::keccak_256, hash::digests::keccak_384, hash::digests::keccak_512,
               hash::digests::cshake_128, hash::digests::cshake_256, hash::digests::kt128,
               hash::digests::kt256, hash::digests::turboshake_128, hash::digests::turboshake_256,
               hash::digests::tuplehash_128, hash::digests::tuplehash_256,
               hash::digests::parallelhash_128, hash::digests::parallelhash_256,
               hash::digests::blake2b, hash::digests::blake2s_256, hash::digests::blake3,
               hash::digests::ripemd_160, hash::digests::md5_sha1, hash::digests::sm3,
               hash::digests::streebog_256, hash::digests::streebog_512, hash::digests::whirlpool,
               hash::digests::skein_512>;
/** The names of `coverage_digest_tags`, in its order, as the table spells them. */
inline constexpr std::array<std::string_view, 38> coverage_digest_names{
    "digests::md5",
    "digests::sha1",
    "digests::sha2_224",
    "digests::sha2_256",
    "digests::sha2_384",
    "digests::sha2_512",
    "digests::sha2_512_224",
    "digests::sha2_512_256",
    "digests::sha3_224",
    "digests::sha3_256",
    "digests::sha3_384",
    "digests::sha3_512",
    "digests::shake_128",
    "digests::shake_256",
    "digests::keccak_224",
    "digests::keccak_256",
    "digests::keccak_384",
    "digests::keccak_512",
    "digests::cshake_128",
    "digests::cshake_256",
    "digests::kt128",
    "digests::kt256",
    "digests::turboshake_128",
    "digests::turboshake_256",
    "digests::tuplehash_128",
    "digests::tuplehash_256",
    "digests::parallelhash_128",
    "digests::parallelhash_256",
    "digests::blake2b",
    "digests::blake2s_256",
    "digests::blake3",
    "digests::ripemd_160",
    "digests::md5_sha1",
    "digests::sm3",
    "digests::streebog_256",
    "digests::streebog_512",
    "digests::whirlpool",
    "digests::skein_512",
};

/** Every tag of `mac`, which add_keyed_calls walks. */
using coverage_mac_tags = std::tuple<
    hash::macs::hmac<hash::digests::md5>, hash::macs::hmac<hash::digests::sha1>,
    hash::macs::hmac<hash::digests::sha2_224>, hash::macs::hmac<hash::digests::sha2_256>,
    hash::macs::hmac<hash::digests::sha2_384>, hash::macs::hmac<hash::digests::sha2_512>,
    hash::macs::hmac<hash::digests::sha2_512_224>, hash::macs::hmac<hash::digests::sha2_512_256>,
    hash::macs::hmac<hash::digests::sha3_224>, hash::macs::hmac<hash::digests::sha3_256>,
    hash::macs::hmac<hash::digests::sha3_384>, hash::macs::hmac<hash::digests::sha3_512>,
    hash::macs::hmac<hash::digests::ripemd_160>, hash::macs::hmac<hash::digests::blake2b>,
    hash::macs::hmac<hash::digests::blake2s_256>, hash::macs::hmac<hash::digests::keccak_224>,
    hash::macs::hmac<hash::digests::keccak_256>, hash::macs::hmac<hash::digests::keccak_384>,
    hash::macs::hmac<hash::digests::keccak_512>, hash::macs::hmac<hash::digests::md5_sha1>,
    hash::macs::hmac<hash::digests::sm3>, hash::macs::hmac<hash::digests::streebog_256>,
    hash::macs::hmac<hash::digests::streebog_512>, hash::macs::hmac<hash::digests::whirlpool>,
    hash::macs::hmac<hash::digests::skein_512>, hash::macs::kmac_128, hash::macs::kmac_256,
    hash::macs::siphash_2_4, hash::macs::siphash_2_4x, hash::macs::blake2b_mac,
    hash::macs::blake2s_mac>;
/** The names of `coverage_mac_tags`, in its order, as the table spells them. */
inline constexpr std::array<std::string_view, 31> coverage_mac_names{
    "macs::hmac<digests::md5>",
    "macs::hmac<digests::sha1>",
    "macs::hmac<digests::sha2_224>",
    "macs::hmac<digests::sha2_256>",
    "macs::hmac<digests::sha2_384>",
    "macs::hmac<digests::sha2_512>",
    "macs::hmac<digests::sha2_512_224>",
    "macs::hmac<digests::sha2_512_256>",
    "macs::hmac<digests::sha3_224>",
    "macs::hmac<digests::sha3_256>",
    "macs::hmac<digests::sha3_384>",
    "macs::hmac<digests::sha3_512>",
    "macs::hmac<digests::ripemd_160>",
    "macs::hmac<digests::blake2b>",
    "macs::hmac<digests::blake2s_256>",
    "macs::hmac<digests::keccak_224>",
    "macs::hmac<digests::keccak_256>",
    "macs::hmac<digests::keccak_384>",
    "macs::hmac<digests::keccak_512>",
    "macs::hmac<digests::md5_sha1>",
    "macs::hmac<digests::sm3>",
    "macs::hmac<digests::streebog_256>",
    "macs::hmac<digests::streebog_512>",
    "macs::hmac<digests::whirlpool>",
    "macs::hmac<digests::skein_512>",
    "macs::kmac_128",
    "macs::kmac_256",
    "macs::siphash_2_4",
    "macs::siphash_2_4x",
    "macs::blake2b_mac",
    "macs::blake2s_mac",
};

/** The variants of `argon2`, which add_keyed_calls walks. */
using coverage_argon2_tags =
    std::tuple<hash::kdfs::argon2d, hash::kdfs::argon2i, hash::kdfs::argon2id>;
/** The names of `coverage_argon2_tags`, in its order, as the table spells them. */
inline constexpr std::array<std::string_view, 3> coverage_argon2_names{
    "kdfs::argon2d",
    "kdfs::argon2i",
    "kdfs::argon2id",
};

/**
 * Calls `each.template operator()<Tag>(name)` for each tag of `Tags`, with its name.
 *
 * @tparam Tags A tuple of tags.
 * @param names The tags' names, in the tuple's order.
 * @param each The visitor.
 */
template <class Tags, std::size_t Size, class Each>
void for_each_coverage_tag(std::array<std::string_view, Size> const& names, Each&& each) {
    static_assert(std::tuple_size_v<Tags> == Size);
    [&]<std::size_t... Index>(std::index_sequence<Index...>) {
        (each.template operator()<std::tuple_element_t<Index, Tags>>(names[Index]), ...);
    }(std::make_index_sequence<Size>{});
}

/** Whether the program has `Tag` on `Backend` (over `Key`, as backend_has_v reads it) and links it.
 */
template <class Backend, class Tag, class Key = void>
inline constexpr bool coverage_has_v =
    hash::backend_has_v<Backend, Tag, Key> && hash::detail::linked_v<Backend>;

/** A key of 32 bytes whose bytes differ from one another. */
inline constexpr std::array<std::uint8_t, 32> coverage_key = [] {
    std::array<std::uint8_t, 32> bytes{};
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<std::uint8_t>((i * 29) + 3);
    }
    return bytes;
}();
/** A salt of 16 bytes, the size every key derivation and password hash takes. */
inline constexpr std::array<std::uint8_t, 16> coverage_salt = [] {
    std::array<std::uint8_t, 16> bytes{};
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<std::uint8_t>(bytes.size() - i);
    }
    return bytes;
}();
/** The data, or the info of a key derivation. */
inline constexpr std::array<std::uint8_t, 24> coverage_input{9, 8, 7, 6, 5, 4, 3, 2, 1};

/** ` on <backend>`, which ends each check's name. */
template <class Backend>
std::string coverage_on() {
    return " on " + std::string(name_of<Backend>());
}

/** ` over <hmac> on <backend>`, which ends the name of each check of a function over `Hmac`. */
template <class Hmac, class Backend>
std::string coverage_over() {
    return " over " + std::string(name_of_hmac<Hmac>()) + coverage_on<Backend>();
}

/**
 * `mac` of `Mac` on `Backend`: a tag of the longest size (at most 64 bytes) under the shortest
 * key the backend takes, then a tag of no byte, which the guards refuse before the backend.
 *
 * @param tag The tag's name, as the table spells it.
 */
template <class Mac, class Backend>
void cover_mac(std::string_view tag) {
    using traits = hash::detail::mac_traits<Mac>;
    using engine = hash::detail::mac_engine<Backend, Mac>;
    std::string const on = " of " + std::string(tag) + coverage_on<Backend>();
    std::vector<std::uint8_t> output(std::min(traits::max_output, std::uint64_t{64}));
    auto key_size = static_cast<std::size_t>(traits::min_key);
    while (!engine::accepts(hash::mac_options<Mac>{}, key_size, output.size()) && key_size < 64) {
        ++key_size;
    }
    std::vector<std::uint8_t> const key(key_size, 0x0b);
    covered("hash::mac" + on, [&] {
        BOOST_TEST((hash::mac<Mac, Backend>(output, key, coverage_input)).has_value());
    });
    covered("hash::mac with a tag of no byte" + on, [&] {
        BOOST_TEST(
            (hash::mac<Mac, Backend>(std::span<std::uint8_t>{}, key, coverage_input)).error() ==
            hash::error::invalid_output_size);
    });
}

/**
 * `hkdf_extract` over `Hmac` on `Backend`. No call of it is refused before the backend but one
 * past a backend's own limits, which no backend has small enough to reach here.
 */
template <class Hmac, class Backend>
void cover_hkdf_extract() {
    std::string const on = coverage_over<Hmac, Backend>();
    covered("hash::hkdf_extract" + on, [&] {
        BOOST_TEST((hash::hkdf_extract<Hmac, Backend>(coverage_salt, coverage_key)).has_value());
    });
}

/**
 * `hkdf_expand` over `Hmac` on `Backend`, then with a pseudorandom key of the wrong size.
 */
template <class Hmac, class Backend>
void cover_hkdf_expand() {
    std::string const on = coverage_over<Hmac, Backend>();
    std::vector<std::uint8_t> const prk(typename Hmac::result_type().size(), 0x0b);
    std::array<std::uint8_t, 42> output{};
    covered("hash::hkdf_expand" + on, [&] {
        BOOST_TEST((hash::hkdf_expand<Hmac, Backend>(output, prk, coverage_input)).has_value());
    });
    covered("hash::hkdf_expand with a prk of the wrong size" + on, [&] {
        BOOST_TEST((hash::hkdf_expand<Hmac, Backend>(output, std::span(prk).first(prk.size() - 1),
                                                     coverage_input))
                       .error() == hash::error::invalid_key_size);
    });
}

/**
 * `hkdf` over `Hmac` on `Backend`, then with an output of no byte.
 */
template <class Hmac, class Backend>
void cover_hkdf() {
    std::string const on = coverage_over<Hmac, Backend>();
    std::array<std::uint8_t, 42> output{};
    covered("hash::hkdf" + on, [&] {
        BOOST_TEST((hash::hkdf<Hmac, Backend>(output, coverage_salt, coverage_key, coverage_input))
                       .has_value());
    });
    covered("hash::hkdf with an output of no byte" + on, [&] {
        BOOST_TEST((hash::hkdf<Hmac, Backend>(std::span<std::uint8_t>{}, coverage_salt,
                                              coverage_key, coverage_input))
                       .error() == hash::error::invalid_output_size);
    });
}

/** Two pieces of coverage_input, and an empty one between them: HKDF's input over pieces. */
inline std::array<std::span<std::uint8_t const>, 3> coverage_pieces() {
    std::span<std::uint8_t const> const input(coverage_input);
    return {input.first(5), std::span<std::uint8_t const>{}, input.subspan(5)};
}

/**
 * `hkdf_extract` over pieces, over `Hmac` on `Backend`. No call of it is refused before the
 * backend but one past a backend's own key limit, which no backend has small enough to reach here.
 */
template <class Hmac, class Backend>
void cover_hkdf_extract_pieces() {
    std::string const on = coverage_over<Hmac, Backend>();
    auto const pieces = coverage_pieces();
    covered("hash::hkdf_extract over pieces" + on, "hash::hkdf_extract(byte_pieces", [&] {
        BOOST_TEST((hash::hkdf_extract<Hmac, Backend>(coverage_salt, pieces)).has_value());
    });
}

/**
 * `hkdf_expand` over pieces, over `Hmac` on `Backend`, then with an output of no byte.
 */
template <class Hmac, class Backend>
void cover_hkdf_expand_pieces() {
    std::string const on = coverage_over<Hmac, Backend>();
    std::vector<std::uint8_t> const prk(typename Hmac::result_type().size(), 0x0b);
    std::array<std::uint8_t, 42> output{};
    auto const pieces = coverage_pieces();
    covered("hash::hkdf_expand over pieces" + on, "hash::hkdf_expand(byte_pieces", [&] {
        BOOST_TEST((hash::hkdf_expand<Hmac, Backend>(output, prk, pieces)).has_value());
    });
    covered(
        "hash::hkdf_expand over pieces with an output of no byte" + on,
        "hash::hkdf_expand(byte_pieces", [&] {
            BOOST_TEST((hash::hkdf_expand<Hmac, Backend>(std::span<std::uint8_t>{}, prk, pieces))
                           .error() == hash::error::invalid_output_size);
        });
}

/**
 * `hkdf` over pieces, over `Hmac` on `Backend`, then with an output of no byte.
 */
template <class Hmac, class Backend>
void cover_hkdf_pieces() {
    std::string const on = coverage_over<Hmac, Backend>();
    std::array<std::uint8_t, 42> output{};
    auto const pieces = coverage_pieces();
    covered("hash::hkdf over pieces" + on, "hash::hkdf(byte_pieces", [&] {
        BOOST_TEST((hash::hkdf<Hmac, Backend>(output, coverage_salt, pieces, pieces)).has_value());
    });
    covered("hash::hkdf over pieces with an output of no byte" + on, "hash::hkdf(byte_pieces", [&] {
        BOOST_TEST(
            (hash::hkdf<Hmac, Backend>(std::span<std::uint8_t>{}, coverage_salt, pieces, pieces))
                .error() == hash::error::invalid_output_size);
    });
}

/**
 * `pbkdf2` over `Hmac` on `Backend`, of one iteration, then of none.
 */
template <class Hmac, class Backend>
void cover_pbkdf2() {
    std::string const on = coverage_over<Hmac, Backend>();
    std::array<std::uint8_t, 32> output{};
    covered("hash::pbkdf2 of 1 iteration" + on, [&] {
        BOOST_TEST(
            (hash::pbkdf2<Hmac, Backend>(output, coverage_key, coverage_salt, 1)).has_value());
    });
    covered("hash::pbkdf2 of 0 iterations" + on, [&] {
        BOOST_TEST((hash::pbkdf2<Hmac, Backend>(output, coverage_key, coverage_salt, 0)).error() ==
                   hash::error::invalid_iterations);
    });
}

/**
 * `kbkdf` over `Hmac` on `Backend`, then with a counter of 7 bits.
 */
template <class Hmac, class Backend>
void cover_kbkdf() {
    std::string const on = coverage_over<Hmac, Backend>();
    std::array<std::uint8_t, 40> output{};
    covered("hash::kbkdf" + on, [&] {
        BOOST_TEST((hash::kbkdf<Hmac, Backend>(output, coverage_key,
                                               {.label = coverage_input, .context = coverage_salt}))
                       .has_value());
    });
    covered("hash::kbkdf with a counter of 7 bits" + on, [&] {
        BOOST_TEST(
            (hash::kbkdf<Hmac, Backend>(output, coverage_key, {.counter_bits = 7})).error() ==
            hash::error::invalid_parameters);
    });
}

/**
 * The calls of the functions over an hmac that `Backend` has over `Hmac`: hkdf_extract,
 * hkdf_expand, hkdf, each also over pieces, pbkdf2 and kbkdf, each by the name of its cell.
 *
 * @param calls Where the calls go.
 */
template <class Backend, class Hmac>
void add_hmac_calls(coverage_calls& calls) {
    namespace kdfs = hash::kdfs;
    std::string const column = "<" + std::string(name_of_hmac<Hmac>()) + ">";
    if constexpr (coverage_has_v<Backend, kdfs::hkdf_extract, Hmac>) {
        calls.emplace("hkdf_extract" + column, [] { cover_hkdf_extract<Hmac, Backend>(); });
    }
    if constexpr (coverage_has_v<Backend, kdfs::hkdf_expand, Hmac>) {
        calls.emplace("hkdf_expand" + column, [] { cover_hkdf_expand<Hmac, Backend>(); });
    }
    if constexpr (coverage_has_v<Backend, kdfs::hkdf, Hmac>) {
        calls.emplace("hkdf" + column, [] { cover_hkdf<Hmac, Backend>(); });
    }
    if constexpr (coverage_has_v<Backend, kdfs::hkdf_extract_pieces, Hmac>) {
        calls.emplace("hkdf_extract" + column + " over pieces",
                      [] { cover_hkdf_extract_pieces<Hmac, Backend>(); });
    }
    if constexpr (coverage_has_v<Backend, kdfs::hkdf_expand_pieces, Hmac>) {
        calls.emplace("hkdf_expand" + column + " over pieces",
                      [] { cover_hkdf_expand_pieces<Hmac, Backend>(); });
    }
    if constexpr (coverage_has_v<Backend, kdfs::hkdf_pieces, Hmac>) {
        calls.emplace("hkdf" + column + " over pieces", [] { cover_hkdf_pieces<Hmac, Backend>(); });
    }
    if constexpr (coverage_has_v<Backend, kdfs::pbkdf2, Hmac>) {
        calls.emplace("pbkdf2" + column, [] { cover_pbkdf2<Hmac, Backend>(); });
    }
    if constexpr (coverage_has_v<Backend, kdfs::kbkdf_hmac, Hmac>) {
        calls.emplace("kbkdf" + column, [] { cover_kbkdf<Hmac, Backend>(); });
    }
}

/** `sskdf` over SHA-256 on `Backend`, then with an output of no byte. */
template <class Backend>
void cover_sskdf() {
    std::string const on = " of sha2_256" + coverage_on<Backend>();
    std::array<std::uint8_t, 40> output{};
    covered("hash::sskdf" + on, [&] {
        BOOST_TEST(
            (hash::sskdf<hash::digests::sha2_256, Backend>(output, coverage_key, coverage_input))
                .has_value());
    });
    covered("hash::sskdf with an output of no byte" + on, [&] {
        BOOST_TEST((hash::sskdf<hash::digests::sha2_256, Backend>(std::span<std::uint8_t>{},
                                                                  coverage_key, coverage_input))
                       .error() == hash::error::invalid_output_size);
    });
}

/** `x963kdf` over SHA-256 on `Backend`, then with an output of no byte. */
template <class Backend>
void cover_x963kdf() {
    std::string const on = " of sha2_256" + coverage_on<Backend>();
    std::array<std::uint8_t, 40> output{};
    covered("hash::x963kdf" + on, [&] {
        BOOST_TEST(
            (hash::x963kdf<hash::digests::sha2_256, Backend>(output, coverage_key, coverage_input))
                .has_value());
    });
    covered("hash::x963kdf with an output of no byte" + on, [&] {
        BOOST_TEST((hash::x963kdf<hash::digests::sha2_256, Backend>(std::span<std::uint8_t>{},
                                                                    coverage_key, coverage_input))
                       .error() == hash::error::invalid_output_size);
    });
}

/** `blake2b_subkey` on `Backend`, then with an output shorter than the shortest subkey. */
template <class Backend>
void cover_blake2b_subkey() {
    std::string const on = coverage_on<Backend>();
    std::array<std::uint8_t, 8> const context{'c', 't', 'x', '_', 't', 'e', 's', 't'};
    std::array<std::uint8_t, 32> output{};
    covered("hash::blake2b_subkey" + on, [&] {
        BOOST_TEST((hash::blake2b_subkey<Backend>(output, coverage_key, 7, context)).has_value());
    });
    std::array<std::uint8_t, 8> tiny{};
    covered("hash::blake2b_subkey with an output too small" + on, [&] {
        BOOST_TEST((hash::blake2b_subkey<Backend>(tiny, coverage_key, 7, context)).error() ==
                   hash::error::invalid_output_size);
    });
}

/** `argon2id` on `Backend`, of its least parameters, then with a salt of 4 bytes. */
template <class Backend>
void cover_argon2id() {
    std::string const on = coverage_on<Backend>();
    hash::argon2id_parameters const cheapest{.passes = 1, .memory = 8192};
    std::array<std::uint8_t, 32> output{};
    covered("hash::argon2id" + on, [&] {
        BOOST_TEST(
            (hash::argon2id<Backend>(output, coverage_key, coverage_salt, cheapest)).has_value());
    });
    covered("hash::argon2id with a salt of 4 bytes" + on, [&] {
        BOOST_TEST((hash::argon2id<Backend>(output, coverage_key, std::span(coverage_salt).first(4),
                                            cheapest))
                       .error() == hash::error::invalid_salt_size);
    });
}

/**
 * `argon2` of `Variant` on `Backend`, of three passes over 8 KiB, then with a salt of 4 bytes.
 *
 * @param variant The variant's name, as the table spells it.
 */
template <class Variant, class Backend>
void cover_argon2(std::string_view variant) {
    std::string const on = " of " + std::string(variant) + coverage_on<Backend>();
    hash::argon2_parameters const family{.passes = 3, .memory_kibibytes = 8};
    std::array<std::uint8_t, 32> output{};
    covered("hash::argon2" + on, [&] {
        BOOST_TEST((hash::argon2<Variant, Backend>(output, coverage_key, coverage_salt, family))
                       .has_value());
    });
    covered("hash::argon2 with a salt of 4 bytes" + on, [&] {
        BOOST_TEST((hash::argon2<Variant, Backend>(output, coverage_key,
                                                   std::span(coverage_salt).first(4), family))
                       .error() == hash::error::invalid_salt_size);
    });
}

/** `scrypt` on `Backend`, of N = 16, then of N = 1, which is no power of two above 1. */
template <class Backend>
void cover_scrypt() {
    std::string const on = coverage_on<Backend>();
    std::array<std::uint8_t, 32> output{};
    covered("hash::scrypt of N = 16" + on, [&] {
        BOOST_TEST((hash::scrypt<Backend>(output, coverage_key, coverage_salt,
                                          {.cost = 16, .block_size = 1, .parallelism = 1}))
                       .has_value());
    });
    covered("hash::scrypt of N = 1" + on, [&] {
        BOOST_TEST((hash::scrypt<Backend>(output, coverage_key, coverage_salt,
                                          {.cost = 1, .block_size = 1, .parallelism = 1}))
                       .error() == hash::error::invalid_parameters);
    });
}

/** `bcrypt` on `Backend`, of cost 4, then with a salt of 8 bytes. */
template <class Backend>
void cover_bcrypt() {
    std::string const on = coverage_on<Backend>();
    std::array<char, hash::bcrypt_hash_size> output{};
    covered("hash::bcrypt of cost 4" + on, [&] {
        BOOST_TEST(
            (hash::bcrypt<Backend>(output, coverage_key, coverage_salt, {.cost = 4})).has_value());
    });
    covered("hash::bcrypt with a salt of 8 bytes" + on, [&] {
        BOOST_TEST((hash::bcrypt<Backend>(output, coverage_key, std::span(coverage_salt).first(8),
                                          {.cost = 4}))
                       .error() == hash::error::invalid_salt_size);
    });
}

/**
 * `bcrypt_verify` on `Backend` (ruling H12): of the right password, of a wrong one, and of a
 * string of the wrong form, which the guards refuse before the backend.
 */
template <class Backend>
void cover_bcrypt_verify() {
    std::string const on = coverage_on<Backend>();
    std::array<char, hash::bcrypt_hash_size> made{};
    if (!BOOST_TEST(
            (hash::bcrypt<Backend>(made, coverage_key, coverage_salt, {.cost = 4})).has_value())) {
        return;
    }
    std::string_view const text{made.data(), made.size()};
    covered("hash::bcrypt_verify of the right password" + on, [&] {
        auto const checked = hash::bcrypt_verify<Backend>(coverage_key, text);
        BOOST_TEST(checked.has_value() && *checked);
    });
    covered("hash::bcrypt_verify of a wrong password" + on, [&] {
        auto const checked = hash::bcrypt_verify<Backend>(coverage_salt, text);
        BOOST_TEST(checked.has_value() && !*checked);
    });
    covered("hash::bcrypt_verify of a string of the wrong form" + on, [&] {
        BOOST_TEST(hash::bcrypt_verify<Backend>(coverage_key, "not a bcrypt string").error() ==
                   hash::error::invalid_parameters);
    });
}

/** `bcrypt_pbkdf` on `Backend`, of one round, then of none. */
template <class Backend>
void cover_bcrypt_pbkdf() {
    std::string const on = coverage_on<Backend>();
    std::array<std::uint8_t, 32> output{};
    covered("hash::bcrypt_pbkdf of 1 round" + on, [&] {
        BOOST_TEST(
            (hash::bcrypt_pbkdf<Backend>(output, coverage_key, coverage_salt, 1)).has_value());
    });
    covered("hash::bcrypt_pbkdf of 0 rounds" + on, [&] {
        BOOST_TEST((hash::bcrypt_pbkdf<Backend>(output, coverage_key, coverage_salt, 0)).error() ==
                   hash::error::invalid_iterations);
    });
}

/**
 * A hasher round of BLAKE2b with a key on `Backend`: `make`, `update` and `finish`, each entering
 * its own guard; on a backend whose cell refuses a key, `make` answers `unsupported_by_backend`.
 *
 * @param on ` of blake2b with a key on <backend>`, which ends each name.
 * @param keyed The options, with the key.
 * @param takes_key Whether the backend takes a key.
 * @return The round's digest, or none when the backend refuses the key or the round failed.
 */
template <class Backend>
std::optional<std::array<std::uint8_t, 64>> cover_keyed_blake2b_round(
    std::string const& on, hash::digest_options<hash::digests::blake2b> const& keyed,
    bool takes_key) {
    using hash::digests::blake2b;
    std::optional<hash::hasher<blake2b, Backend>> hashing;
    covered("hash::hasher::make" + on, [&] {
        auto made = hash::hasher<blake2b, Backend>::make(keyed);
        if (!takes_key) {
            BOOST_TEST(made.error() == hash::error::unsupported_by_backend);
        } else if (BOOST_TEST(made.has_value())) {
            hashing.emplace(std::move(*made));
        }
    });
    if (!hashing) {
        return std::nullopt;
    }
    covered("hash::hasher::update" + on,
            [&] { BOOST_TEST(hashing->update(coverage_input).has_value()); });
    std::array<std::uint8_t, 64> pieces{};
    bool finished = false;
    covered("hash::hasher::finish" + on,
            [&] { finished = BOOST_TEST(hashing->finish(pieces).has_value()); });
    return finished ? std::optional(pieces) : std::nullopt;
}

/**
 * BLAKE2b with a key on `Backend` (design D1): `digest_of`, then a hasher round, `make`, `update`
 * and `finish`, the round's digest the one of `digest_of`; on a backend whose cell refuses a key
 * (its "partial" lists "a key": `backends::hash2`, `backends::openssl`; the engine must agree),
 * `digest_of` and `make` answer `unsupported_by_backend` and still enter the guard, which precedes
 * every check. Then `digest_of` and `make` with a key of 65 bytes, which the guards refuse before
 * the backend.
 */
template <class Backend>
void cover_keyed_blake2b() {
    using hash::digests::blake2b;
    std::string const on = " of blake2b with a key" + coverage_on<Backend>();
    hash::digest_options<blake2b> const keyed{.key = coverage_key};
    // The table says whether the backend takes a key; the engine must agree, so that a backend
    // that stopped taking one fails here rather than passing through the refusal's branch.
    bool const takes_key = table_blake2b_takes_key(name_of<Backend>());
    bool const engine_takes_key = hash::detail::digest_engine<Backend, blake2b>::accepts(keyed);
    BOOST_TEST_EQ(engine_takes_key, takes_key);
    std::array<std::uint8_t, 64> once{};
    covered("hash::digest_of" + on, [&] {
        auto const done = hash::digest_of<blake2b, Backend>(once, coverage_input, keyed);
        BOOST_TEST(takes_key ? done.has_value()
                             : done.error() == hash::error::unsupported_by_backend);
    });
    auto const pieces = cover_keyed_blake2b_round<Backend>(on, keyed, takes_key);
    BOOST_TEST(pieces.has_value() == takes_key);
    if (pieces) {
        BOOST_TEST(*pieces == once);
    }
    std::array<std::uint8_t, 65> const long_key{};
    hash::digest_options<blake2b> const too_long{.key = long_key};
    covered("hash::digest_of with a key of 65 bytes" + on, [&] {
        BOOST_TEST((hash::digest_of<blake2b, Backend>(once, coverage_input, too_long)).error() ==
                   hash::error::invalid_key_size);
    });
    covered("hash::hasher::make with a key of 65 bytes" + on, [&] {
        BOOST_TEST((hash::hasher<blake2b, Backend>::make(too_long)).error() ==
                   hash::error::invalid_key_size);
    });
}

/**
 * The calls of every keyed cell this support knows that `Backend` has, each by the name of its
 * cell (keyed_cells): mac over each tag, the functions over each hmac of the table's columns,
 * those over none, argon2's variants, and the keyed functions of design D1 but the blake3 type's,
 * which its backend's test adds. A new cell of a family this support knows gets its call here
 * from backend_has_v, which capabilities_test keeps equal to the table; a cell of a family or
 * function this support does not know stays without a call, which check_and_run reports until its
 * call is written.
 *
 * @return The calls.
 */
template <class Backend>
coverage_calls keyed_calls() {
    namespace kdfs = hash::kdfs;
    coverage_calls calls;
    for_each_coverage_tag<coverage_mac_tags>(coverage_mac_names, [&calls]<class Mac>(
                                                                     std::string_view tag) {
        if constexpr (coverage_has_v<Backend, Mac>) {
            calls.emplace("mac<" + std::string(tag) + ">", [tag] { cover_mac<Mac, Backend>(tag); });
        }
    });
    [&calls]<class... Hmac>(std::tuple<Hmac...>*) {
        (add_hmac_calls<Backend, Hmac>(calls), ...);
    }(static_cast<kdf_hmacs*>(nullptr));
    if constexpr (coverage_has_v<Backend, kdfs::blake2b_subkey>) {
        calls.emplace("blake2b_subkey", [] { cover_blake2b_subkey<Backend>(); });
    }
    if constexpr (coverage_has_v<Backend, kdfs::sskdf>) {
        calls.emplace("sskdf", [] { cover_sskdf<Backend>(); });
    }
    if constexpr (coverage_has_v<Backend, kdfs::x963kdf>) {
        calls.emplace("x963kdf", [] { cover_x963kdf<Backend>(); });
    }
    if constexpr (coverage_has_v<Backend, kdfs::argon2id>) {
        calls.emplace("argon2id", [] { cover_argon2id<Backend>(); });
    }
    for_each_coverage_tag<coverage_argon2_tags>(
        coverage_argon2_names, [&calls]<class Variant>(std::string_view variant) {
            if constexpr (coverage_has_v<Backend, Variant, hash::argon2_parameters>) {
                calls.emplace("argon2<" + std::string(variant) + ">",
                              [variant] { cover_argon2<Variant, Backend>(variant); });
            }
        });
    if constexpr (coverage_has_v<Backend, kdfs::scrypt>) {
        calls.emplace("scrypt", [] { cover_scrypt<Backend>(); });
    }
    if constexpr (coverage_has_v<Backend, kdfs::bcrypt>) {
        calls.emplace("bcrypt", [] { cover_bcrypt<Backend>(); });
        calls.emplace(bcrypt_verify_cell, [] { cover_bcrypt_verify<Backend>(); });
    }
    if constexpr (coverage_has_v<Backend, kdfs::bcrypt_pbkdf>) {
        calls.emplace("bcrypt_pbkdf", [] { cover_bcrypt_pbkdf<Backend>(); });
    }
    if constexpr (coverage_has_v<Backend, hash::digests::blake2b>) {
        calls.emplace(keyed_blake2b_cell, [] { cover_keyed_blake2b<Backend>(); });
    }
    return calls;
}

/**
 * `Digest` on `Backend` without a key: `digest_of`, then a hasher round, `make`, `update` and
 * `finish`, none of which may enter a guard; each succeeds, over an output of the digest's size,
 * or of 64 bytes (at most the backend's longest) for a function whose output may be longer.
 *
 * @param tag The tag's name, as the table spells it.
 */
template <class Digest, class Backend>
void uncover_digest(std::string_view tag) {
    using traits = hash::detail::digest_traits<Digest>;
    std::string const on = " of " + std::string(tag) + coverage_on<Backend>();
    // The default options, but for ParallelHash's block size, which has no default.
    auto const options = [] {
        hash::digest_options<Digest> chosen{};
        if constexpr (requires { chosen.block_size; }) {
            chosen.block_size = 8;
        }
        return chosen;
    }();
    std::vector<std::uint8_t> output(std::min({
        traits::max_output(options),
        hash::detail::digest_engine<Backend, Digest>::max_output,
        std::uint64_t{64},
    }));
    uncovered("hash::digest_of" + on, [&] {
        BOOST_TEST((hash::digest_of<Digest, Backend>(output, coverage_input, options)).has_value());
    });
    std::optional<hash::hasher<Digest, Backend>> hashing;
    uncovered("hash::hasher::make" + on, [&] {
        auto made = hash::hasher<Digest, Backend>::make(options);
        if (BOOST_TEST(made.has_value())) {
            hashing.emplace(std::move(*made));
        }
    });
    if (!hashing) {
        return;
    }
    uncovered("hash::hasher::update" + on,
              [&] { BOOST_TEST(hashing->update(coverage_input).has_value()); });
    uncovered("hash::hasher::finish" + on,
              [&] { BOOST_TEST(hashing->finish(output).has_value()); });
}

/**
 * The unkeyed boundary of `Backend`: every digest cell of the backend in the table, called
 * without a key through `digest_of` and a hasher round (uncover_digest), none of which may enter
 * a guard. Reports a digest cell this support cannot call, and a digest the backend has that the
 * table does not list.
 */
template <class Backend>
void uncover_digests() {
    std::string const backend(name_of<Backend>());
    std::map<std::string, std::function<void()>, std::less<>> calls;
    for_each_coverage_tag<coverage_digest_tags>(
        coverage_digest_names, [&calls]<class Digest>(std::string_view tag) {
            if constexpr (coverage_has_v<Backend, Digest>) {
                calls.emplace(tag, [tag] { uncover_digest<Digest, Backend>(tag); });
            }
        });
    auto const cells = digest_cells(backend);
    BOOST_TEST(!cells.empty());
    for (auto const& cell : cells) {
        auto const found = calls.find(cell);
        if (found == calls.end()) {
            std::string message = cell;
            message += " on ";
            message += backend;
            message += " is a digest cell with no unkeyed call";
            BOOST_ERROR(message.c_str());
            continue;
        }
        found->second();
    }
    for (auto const& [name, call] : calls) {
        if (std::ranges::find(cells, name) == cells.end()) {
            std::string message = name;
            message += " on ";
            message += backend;
            message += " names no digest cell";
            BOOST_ERROR(message.c_str());
        }
    }
}

/**
 * The type cells of `backend` (the Boost.Hash2-form types of kind "type", design D3), in the
 * table's order.
 *
 * @param backend The backend's name, as the table spells it.
 * @return The names of the types, as `sha2_256` or `hmac`.
 */
inline std::vector<std::string> type_cells(std::string_view backend) {
    auto const table = capability_table();
    std::vector<std::string> cells;
    for (auto const& algorithm : table.at("algorithms").as_array()) {
        for (auto const& function_value : algorithm.at("functions").as_array()) {
            auto const& function = function_value.as_object();
            if (function.at("kind").as_string() == "type" &&
                cell_of(function_value, backend) != nullptr) {
                cells.emplace_back(function.at("name").as_string());
            }
        }
    }
    return cells;
}

/**
 * A Boost.Hash2-form type `H` (design D3), which holds no guard however it is seeded: made by its
 * default constructor, fed and read, and, where `seeded`, made from a seed of bytes (HMAC's key)
 * and from an integer seed, fed and read; no step may enter a guard.
 *
 * @param name The type's name, as the table spells it, and its backend: `<type> on <backend>`.
 * @param seeded Whether to make it from seeds too (not the blake3 type, whose seeds key it).
 */
template <class H>
void uncover_type(std::string const& name, bool seeded) {
    uncovered(name + ", made, fed and read", [] {
        H plain;
        plain.update(coverage_input.data(), coverage_input.size());
        static_cast<void>(plain.result());
    });
    if (!seeded) {
        return;
    }
    uncovered(name + ", seeded with bytes, fed and read", [] {
        H keyed(coverage_key.data(), coverage_key.size());
        keyed.update(coverage_input.data(), coverage_input.size());
        static_cast<void>(keyed.result());
    });
    uncovered(name + ", seeded with an integer, fed and read", [] {
        H keyed(std::uint64_t{7});
        keyed.update(coverage_input.data(), coverage_input.size());
        static_cast<void>(keyed.result());
    });
}

/**
 * Runs each of `calls`, a backend's unguarded types by name, after reporting each type cell of
 * `backend` without a call and each call that names no type cell of it.
 *
 * @param backend The backend's name, as the table spells it.
 * @param calls The calls, by the type's name.
 */
inline void uncover_types(std::string_view backend, coverage_calls const& calls) {
    auto const cells = type_cells(backend);
    for (auto const& cell : cells) {
        if (!calls.contains(cell)) {
            std::string const message =
                cell + " on " + std::string(backend) + " is a type cell with no unkeyed call";
            BOOST_ERROR(message.c_str());
        }
    }
    for (auto const& [name, call] : calls) {
        if (std::ranges::find(cells, name) == cells.end()) {
            std::string const message =
                name + " on " + std::string(backend) + " names no type cell";
            BOOST_ERROR(message.c_str());
        }
        call();
    }
}

}  // namespace webcpp::test

#endif  // WEBCPP_TEST_HASH_SUPPORT_TIMING_COVERAGE_HPP
