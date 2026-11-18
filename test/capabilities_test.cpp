// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The capability table is one fact in two places, which must never drift: doc/capabilities.json and
// backend_has_v agree on every cell, a function over an hmac (or over no hmac), or a family's tag,
// for a backend; the file names exactly the backends, hmacs and functions this test knows, and a
// row for each family tag that a backend has. Each default is default_backend's (null for a tag
// with none). And each refusal text of the headers (spec 3.3) names exactly the backends of its
// row: those that have the function it refuses, over the hmacs it is about, besides the refusing
// backend itself; a family tag's text, read from the tag it names, those of the tag's row. Every
// family tag has its refusal, and a "no default backend" text exactly when it has no default; where
// a backend has a tag and the program links it, digest_of, hasher and mac compile and run on it.

#include <webcpp/hash/algorithms.hpp>
#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/blake3.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/hash/keccak.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/test/exit_status.hpp>

#include "require.hpp"
#include "support/defaults.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/json.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <vector>

namespace {

namespace hash = webcpp::hash;
namespace json = boost::json;
namespace test = webcpp::test;
namespace kdfs = webcpp::hash::kdfs;
namespace digests = webcpp::hash::digests;
namespace macs = webcpp::hash::macs;
using names = std::set<std::string, std::less<>>;

// The whole file at path; one that cannot be opened ends the test, by name.
std::string read_text(std::string const& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cerr << "cannot open test data: " << path << '\n';
        std::abort();
    }
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

using backend_tags =
    std::tuple<hash::backends::hash2, hash::backends::xkcp, hash::backends::blake3,
               hash::backends::sodium, hash::backends::bearssl, hash::backends::openssl>;

// The functions with a Backend parameter: those over an hmac (increment 1's and kbkdf), and those
// over none (sskdf and x963kdf take a digest, which no column of the table names).
template <class First, class Second>
struct joined;

template <class... First, class... Second>
struct joined<std::tuple<First...>, std::tuple<Second...>> {
    using type = std::tuple<First..., Second...>;
};

using hmac_functions = joined<test::kdf_operations, std::tuple<kdfs::kbkdf_hmac>>::type;
using plain_functions =
    std::tuple<kdfs::argon2id, kdfs::scrypt, kdfs::blake2b_subkey, kdfs::sskdf, kdfs::x963kdf>;

template <class Function>
constexpr std::string_view function_name() {
    if constexpr (std::is_same_v<Function, kdfs::argon2id>) {
        return "argon2id";
    } else if constexpr (std::is_same_v<Function, kdfs::scrypt>) {
        return "scrypt";
    } else if constexpr (std::is_same_v<Function, kdfs::blake2b_subkey>) {
        return "blake2b_subkey";
    } else if constexpr (std::is_same_v<Function, kdfs::kbkdf_hmac>) {
        return "kbkdf";
    } else if constexpr (std::is_same_v<Function, kdfs::sskdf>) {
        return "sskdf";
    } else if constexpr (std::is_same_v<Function, kdfs::x963kdf>) {
        return "x963kdf";
    } else {
        return test::name_of_operation<Function>();
    }
}

// Every function of the file, by name.
std::vector<json::object const*> functions_of(json::object const& table) {
    std::vector<json::object const*> functions;
    for (auto const& algorithm : table.at("algorithms").as_array()) {
        for (auto const& function : algorithm.at("functions").as_array()) {
            functions.push_back(&function.as_object());
        }
    }
    return functions;
}

// The row named `name`, or null when the file has none.
json::object const* find_row(json::object const& table, std::string_view name) {
    for (auto const* function : functions_of(table)) {
        if (function->at("name").as_string() == name) {
            return function;
        }
    }
    return nullptr;
}

json::object const& function_row(json::object const& table, std::string_view name) {
    auto const* const found = find_row(table, name);
    if (found == nullptr) {
        std::cerr << "no row for " << name << " in capabilities.json\n";
        std::abort();
    }
    return *found;
}

// Whether the file's cell holds: the backend has the function over the hmac ("" for none).
bool cell(json::object const& row, std::string_view backend, std::string_view hmac) {
    auto const& backends = row.at("backends").as_object();
    auto const* const found = backends.find(backend);
    if (found == backends.end()) {
        return false;
    }
    auto const& hmacs = found->value().at("hmacs");
    if (hmacs.is_null()) {
        return hmac.empty();
    }
    return std::ranges::any_of(hmacs.as_array(),
                               [hmac](json::value const& h) { return h.as_string() == hmac; });
}

// A type row of the table (spec 3.5: Hash2's algorithms, HMAC, Keccak-256, BLAKE3): its name in
// webcpp::hash and the library behind it, read from the code where the code can tell.
struct type_row {
    std::string_view name;
    std::string_view backend;
};

// "hash2" when webcpp::hash's name is Boost.Hash2's type itself.
template <class Webcpp, class Boost>
constexpr std::string_view hash2_if_alias() {
    return std::is_same_v<Webcpp, Boost> ? "hash2" : "not Boost.Hash2's";
}

// The library of one of webcpp's own classes: its header refuses a program that does not link
// that library (the messages xkcp_not_linked and blake3_not_linked), so naming the class here,
// in a program that links it, is the check that the class exists.
template <class Class>
constexpr std::string_view own_class(std::string_view library) {
    return std::is_class_v<Class> ? library : "not a class";
}

constexpr type_row row(std::string_view name, std::string_view backend) {
    return {.name = name, .backend = backend};
}

std::vector<type_row> const& type_rows() {
    namespace h2 = boost::hash2;
    static std::vector<type_row> const rows{
        row("md5_128", hash2_if_alias<hash::md5_128, h2::md5_128>()),
        row("sha1_160", hash2_if_alias<hash::sha1_160, h2::sha1_160>()),
        row("sha2_224", hash2_if_alias<hash::sha2_224, h2::sha2_224>()),
        row("sha2_256", hash2_if_alias<hash::sha2_256, h2::sha2_256>()),
        row("sha2_384", hash2_if_alias<hash::sha2_384, h2::sha2_384>()),
        row("sha2_512", hash2_if_alias<hash::sha2_512, h2::sha2_512>()),
        row("sha2_512_224", hash2_if_alias<hash::sha2_512_224, h2::sha2_512_224>()),
        row("sha2_512_256", hash2_if_alias<hash::sha2_512_256, h2::sha2_512_256>()),
        row("sha3_224", hash2_if_alias<hash::sha3_224, h2::sha3_224>()),
        row("sha3_256", hash2_if_alias<hash::sha3_256, h2::sha3_256>()),
        row("sha3_384", hash2_if_alias<hash::sha3_384, h2::sha3_384>()),
        row("sha3_512", hash2_if_alias<hash::sha3_512, h2::sha3_512>()),
        row("shake_128", hash2_if_alias<hash::shake_128, h2::shake_128>()),
        row("shake_256", hash2_if_alias<hash::shake_256, h2::shake_256>()),
        row("keccak_256", own_class<hash::keccak_256>("xkcp")),
        row("blake2b_512", hash2_if_alias<hash::blake2b_512, h2::blake2b_512>()),
        row("blake2s_256", hash2_if_alias<hash::blake2s_256, h2::blake2s_256>()),
        row("blake3", own_class<hash::blake3>("blake3")),
        row("ripemd_128", hash2_if_alias<hash::ripemd_128, h2::ripemd_128>()),
        row("ripemd_160", hash2_if_alias<hash::ripemd_160, h2::ripemd_160>()),
        row("siphash_32", hash2_if_alias<hash::siphash_32, h2::siphash_32>()),
        row("siphash_64", hash2_if_alias<hash::siphash_64, h2::siphash_64>()),
        row("hmac", hash2_if_alias<hash::hmac<h2::sha2_256>, h2::hmac<h2::sha2_256>>()),
        row("hmac_md5_128", hash2_if_alias<hash::hmac_md5_128, h2::hmac_md5_128>()),
        row("hmac_sha1_160", hash2_if_alias<hash::hmac_sha1_160, h2::hmac_sha1_160>()),
        row("hmac_sha2_224", hash2_if_alias<hash::hmac_sha2_224, h2::hmac_sha2_224>()),
        row("hmac_sha2_256", hash2_if_alias<hash::hmac_sha2_256, h2::hmac_sha2_256>()),
        row("hmac_sha2_384", hash2_if_alias<hash::hmac_sha2_384, h2::hmac_sha2_384>()),
        row("hmac_sha2_512", hash2_if_alias<hash::hmac_sha2_512, h2::hmac_sha2_512>()),
        row("hmac_sha2_512_224", hash2_if_alias<hash::hmac_sha2_512_224, h2::hmac_sha2_512_224>()),
        row("hmac_sha2_512_256", hash2_if_alias<hash::hmac_sha2_512_256, h2::hmac_sha2_512_256>()),
        row("hmac_sha3_224", hash2_if_alias<hash::hmac_sha3_224, h2::hmac_sha3_224>()),
        row("hmac_sha3_256", hash2_if_alias<hash::hmac_sha3_256, h2::hmac_sha3_256>()),
        row("hmac_sha3_384", hash2_if_alias<hash::hmac_sha3_384, h2::hmac_sha3_384>()),
        row("hmac_sha3_512", hash2_if_alias<hash::hmac_sha3_512, h2::hmac_sha3_512>()),
        row("hmac_ripemd_128", hash2_if_alias<hash::hmac_ripemd_128, h2::hmac_ripemd_128>()),
        row("hmac_ripemd_160", hash2_if_alias<hash::hmac_ripemd_160, h2::hmac_ripemd_160>()),
        row("hmac_blake2b_512", hash2_if_alias<hash::hmac_blake2b_512, h2::hmac_blake2b_512>()),
        row("hmac_blake2s_256", hash2_if_alias<hash::hmac_blake2s_256, h2::hmac_blake2s_256>()),
        row("fnv1a_32", hash2_if_alias<hash::fnv1a_32, h2::fnv1a_32>()),
        row("fnv1a_64", hash2_if_alias<hash::fnv1a_64, h2::fnv1a_64>()),
        row("xxhash_32", hash2_if_alias<hash::xxhash_32, h2::xxhash_32>()),
        row("xxhash_64", hash2_if_alias<hash::xxhash_64, h2::xxhash_64>()),
        row("xxh3_128", hash2_if_alias<hash::xxh3_128, h2::xxh3_128>()),
        row("murmur3_32", hash2_if_alias<hash::murmur3_32, h2::murmur3_32>()),
        row("murmur3_128", hash2_if_alias<hash::murmur3_128, h2::murmur3_128>()),
        row("spooky2_128", hash2_if_alias<hash::spooky2_128, h2::spooky2_128>()),
    };
    return rows;
}

// Each type row of the file: a type, over no hmac, whose one backend is the library the code
// says.
void check_type_rows(json::object const& table) {
    for (auto const* function : functions_of(table)) {
        if (function->at("kind").as_string() != "type") {
            continue;
        }
        json::string const& written = function->at("name").as_string();
        std::string_view const name(written.data(), written.size());
        auto const known = std::ranges::find(type_rows(), name, &type_row::name);
        if (!BOOST_TEST(known != type_rows().end())) {
            std::cerr << "  a type row this test does not know: " << name << '\n';
            continue;
        }
        auto const& backends = function->at("backends").as_object();
        auto const* const entry = backends.if_contains(known->backend);
        if (!BOOST_TEST_EQ(backends.size(), 1U) || !BOOST_TEST(entry != nullptr) ||
            !BOOST_TEST(entry->at("hmacs").is_null())) {
            std::cerr << "  the backend of " << name << ": " << known->backend << '\n';
        }
    }
}

// The target this program runs on, as the table names it.
constexpr std::string_view this_target() {
#ifdef WEBCPP_TARGET_WASIP2
    return "wasip2";
#elif defined(WEBCPP_TARGET_WASIP3)
    return "wasip3";
#elif defined(WEBCPP_TARGET_EMSCRIPTEN)
    return "emscripten";
#else
    return "native";
#endif
}

// Whether this program links a library of the table, by its macro word: the program is built with
// every library its target has, so a backend is linked exactly on its targets.
bool linked_here(std::string_view macro) {
    names linked;
    [&linked]<class... Backend>(std::tuple<Backend...>*) {
        (static_cast<void>(hash::detail::linked_v<Backend> &&
                           linked.emplace(test::name_of_macro<Backend>()).second),
         ...);
    }(static_cast<backend_tags*>(nullptr));
    return linked.contains(macro);
}

void check_cell_fields(json::object const& table, names const& tagged);

// The backends' own fields, where the code can tell: a backend's targets hold this
// target exactly when the program links it here, and every cell is of an increment and states its
// constant time, which the documentation renders.
void check_backend_fields(json::object const& table) {
    names tagged;
    for (auto const& b : table.at("backends").as_array()) {
        std::string const name(b.at("name").as_string());
        bool const on_this_target =
            std::ranges::any_of(b.at("targets").as_array(),
                                [](auto const& t) { return t.as_string() == this_target(); });
        if (!BOOST_TEST_EQ(on_this_target, linked_here(b.at("macro").as_string()))) {
            std::cerr << "  the targets of " << name << " on " << this_target() << '\n';
        }
        if (!b.at("tag").is_null()) {
            tagged.insert(name);
        }
    }
    check_cell_fields(table, tagged);
}

// Each function's default, the backend default_backend names for its tag, null for a function
// without one (detail::no_default); a type row has none.
template <class Function>
void check_default(json::object const& table) {
    auto const& listed = function_row(table, function_name<Function>()).at("default");
    using chosen_backend = hash::default_backend<Function>;
    std::string_view const chosen = test::name_of<chosen_backend>();
    bool const agrees = std::is_same_v<chosen_backend, hash::detail::no_default>
                            ? listed.is_null()
                            : listed.is_string() && listed.as_string() == chosen;
    if (!BOOST_TEST(agrees)) {
        std::cerr << "  default of " << function_name<Function>() << '\n';
    }
}

void check_defaults(json::object const& table) {
    auto const each = [&]<class... Function>(std::tuple<Function...>*) {
        (check_default<Function>(table), ...);
    };
    each(static_cast<hmac_functions*>(nullptr));
    each(static_cast<plain_functions*>(nullptr));
    for (auto const& row : type_rows()) {
        BOOST_TEST(function_row(table, row.name).at("default").is_null());
    }
}

// Every cell is of an increment, 1 to 7, states its constant time, says what it refuses when it is
// partial, and, for a function with a Backend parameter or a family's tag, names a backend with a
// tag.
void check_cell_fields(json::object const& table, names const& tagged) {
    for (auto const* function : functions_of(table)) {
        bool const is_function = function->at("kind").as_string() != "type";
        for (auto const& backend : function->at("backends").as_object()) {
            auto const& c = backend.value().as_object();
            auto const* const ct = c.if_contains("constant_time");
            auto const* const value =
                ct != nullptr && ct->is_object() ? ct->as_object().if_contains("value") : nullptr;
            auto const* const source =
                ct != nullptr && ct->is_object() ? ct->as_object().if_contains("source") : nullptr;
            bool const stated = value != nullptr && value->is_string() &&
                                (value->as_string() == "yes" || value->as_string() == "no" ||
                                 value->as_string() == "not stated");
            auto const* const partial = c.if_contains("partial");
            bool const partial_fine =
                partial == nullptr || (partial->is_string() && !partial->as_string().empty());
            auto const since = c.at("since").as_int64();
            bool const fine = since >= 1 && since <= 7 && stated && source != nullptr &&
                              source->is_string() && !source->as_string().empty() && partial_fine &&
                              (!is_function || tagged.contains(backend.key()));
            if (!BOOST_TEST(fine)) {
                std::cerr << "  the cell " << function->at("name").as_string() << " / "
                          << backend.key() << '\n';
            }
        }
    }
}

// Every tag of the families (spec 2.15), with its qualified name: a row of the file has it as its
// name. `macs::hmac` over whirlpool stands for the hmacs no backend has yet.
using digest_tags =
    std::tuple<digests::md5, digests::sha1, digests::sha2_224, digests::sha2_256, digests::sha2_384,
               digests::sha2_512, digests::sha2_512_224, digests::sha2_512_256, digests::sha3_224,
               digests::sha3_256, digests::sha3_384, digests::sha3_512, digests::shake_128,
               digests::shake_256, digests::keccak_224, digests::keccak_256, digests::keccak_384,
               digests::keccak_512, digests::cshake_128, digests::cshake_256, digests::kt128,
               digests::kt256, digests::turboshake_128, digests::turboshake_256,
               digests::tuplehash_128, digests::tuplehash_256, digests::parallelhash_128,
               digests::parallelhash_256, digests::blake2b, digests::blake2s_256, digests::blake3,
               digests::ripemd_160, digests::md5_sha1, digests::sm3, digests::streebog_256,
               digests::streebog_512, digests::whirlpool, digests::skein_512>;
constexpr std::array<std::string_view, 38> digest_names{
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
using mac_tags = std::tuple<
    macs::hmac<digests::md5>, macs::hmac<digests::sha1>, macs::hmac<digests::sha2_224>,
    macs::hmac<digests::sha2_256>, macs::hmac<digests::sha2_384>, macs::hmac<digests::sha2_512>,
    macs::hmac<digests::sha2_512_224>, macs::hmac<digests::sha2_512_256>,
    macs::hmac<digests::sha3_224>, macs::hmac<digests::sha3_256>, macs::hmac<digests::sha3_384>,
    macs::hmac<digests::sha3_512>, macs::hmac<digests::ripemd_160>, macs::hmac<digests::blake2b>,
    macs::hmac<digests::blake2s_256>, macs::hmac<digests::keccak_224>,
    macs::hmac<digests::keccak_256>, macs::hmac<digests::keccak_384>,
    macs::hmac<digests::keccak_512>, macs::hmac<digests::md5_sha1>, macs::hmac<digests::sm3>,
    macs::hmac<digests::whirlpool>, macs::kmac_128, macs::kmac_256, macs::siphash_2_4,
    macs::siphash_2_4x, macs::blake2b_mac, macs::blake2s_mac>;
constexpr std::array<std::string_view, 28> mac_names{
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
    "macs::hmac<digests::whirlpool>",
    "macs::kmac_128",
    "macs::kmac_256",
    "macs::siphash_2_4",
    "macs::siphash_2_4x",
    "macs::blake2b_mac",
    "macs::blake2s_mac",
};
using argon2_tags = std::tuple<kdfs::argon2d, kdfs::argon2i, kdfs::argon2id>;
constexpr std::array<std::string_view, 3> argon2_names{
    "kdfs::argon2d",
    "kdfs::argon2i",
    "kdfs::argon2id",
};

// Calls check.template operator()<Tag>(name) for each tag of Tags, with its name.
template <class Tags, std::size_t Size, class Check>
void for_each_tag(std::array<std::string_view, Size> const& tag_names, Check check) {
    static_assert(std::tuple_size_v<Tags> == Size);
    [&]<std::size_t... Index>(std::index_sequence<Index...>) {
        (check.template operator()<std::tuple_element_t<Index, Tags>>(tag_names[Index]), ...);
    }(std::make_index_sequence<Size>{});
}

// The third argument of backend_has_v for a family's tag: argon2's variants are told from the
// function argon2id by argon2_parameters.
template <class Tag>
using family_key =
    std::conditional_t<std::is_same_v<Tag, kdfs::argon2d> || std::is_same_v<Tag, kdfs::argon2i> ||
                           std::is_same_v<Tag, kdfs::argon2id>,
                       hash::argon2_parameters, void>;

// Whether some backend has the tag: then the file has its row.
template <class Tag>
bool some_backend_has() {
    return [&]<class... Backend>(std::tuple<Backend...>*) {
        return (hash::backend_has_v<Backend, Tag, family_key<Tag>> || ...);
    }(static_cast<backend_tags*>(nullptr));
}

// The names of the family rows the file must hold: every tag some backend has.
names family_rows() {
    names rows;
    auto const each = [&]<class Tag>(std::string_view name) {
        if (some_backend_has<Tag>()) {
            rows.emplace(name);
        }
    };
    for_each_tag<digest_tags>(digest_names, each);
    for_each_tag<mac_tags>(mac_names, each);
    for_each_tag<argon2_tags>(argon2_names, each);
    return rows;
}

// Where Backend has the digest and the program links it, digest_of and hasher compile and run on
// it, over an output of the digest's size (32 bytes for an extendable output).
template <class Tag, class Backend>
void call_digest(std::string_view name) {
    if constexpr (hash::backend_has_v<Backend, Tag, void> && hash::detail::linked_v<Backend>) {
        using traits = hash::detail::digest_traits<Tag>;
        auto const longest = traits::max_output(hash::digest_options<Tag>{});
        std::vector<std::uint8_t> output(longest == hash::detail::no_limit ? 32 : longest);
        std::array<std::uint8_t, 3> const input{0x61, 0x62, 0x63};
        bool const once = hash::digest_of<Tag, Backend>(output, input).has_value();
        auto hashing = hash::hasher<Tag, Backend>::make();
        bool const pieces =
            hashing && hashing->update(input) && hashing->finish(output).has_value();
        if (!BOOST_TEST(once && pieces)) {
            std::cerr << "  " << name << " on " << test::name_of<Backend>() << '\n';
        }
    }
}

// Where Backend has the MAC and the program links it, mac compiles and runs on it, with its
// longest tag (at most 64 bytes) and its shortest key that the backend takes.
template <class Tag, class Backend>
void call_mac(std::string_view name) {
    if constexpr (hash::backend_has_v<Backend, Tag, void> && hash::detail::linked_v<Backend>) {
        using traits = hash::detail::mac_traits<Tag>;
        using engine = hash::detail::mac_engine<Backend, Tag>;
        std::vector<std::uint8_t> output(std::min(traits::max_output, std::uint64_t{64}));
        auto key_size = static_cast<std::size_t>(traits::min_key);
        while (!engine::accepts(hash::mac_options<Tag>{}, key_size, output.size()) &&
               key_size < 64) {
            ++key_size;
        }
        std::vector<std::uint8_t> const key(key_size, 0x0b);
        std::array<std::uint8_t, 3> const input{0x61, 0x62, 0x63};
        if (!BOOST_TEST((hash::mac<Tag, Backend>(output, key, input).has_value()))) {
            std::cerr << "  " << name << " on " << test::name_of<Backend>() << '\n';
        }
    }
}

// The rows of the file the test does not know, and those it misses.
void report_differences(names const& in_file, names const& known) {
    for (auto const& name : in_file) {
        if (!known.contains(name)) {
            std::cerr << "  a row this test does not know: " << name << '\n';
        }
    }
    for (auto const& name : known) {
        if (!in_file.contains(name)) {
            std::cerr << "  no row for " << name << '\n';
        }
    }
}

// The file's lists against the test's: its backends, its hmacs, its functions.
void check_names(json::object const& table) {
    std::vector<std::string> backends;
    for (auto const& backend : table.at("backends").as_array()) {
        backends.emplace_back(backend.at("name").as_string());
    }
    BOOST_TEST((backends == std::vector<std::string>{"hash2", "xkcp", "blake3", "sodium", "bearssl",
                                                     "openssl"}));

    std::vector<std::string> hmacs;
    for (auto const& hmac : table.at("hmacs").as_array()) {
        hmacs.emplace_back(hmac.as_string());
    }
    std::vector<std::string> known;
    [&known]<class... Hmac>(std::tuple<Hmac...>*) {
        (known.emplace_back(test::name_of_hmac<Hmac>()), ...);
    }(static_cast<test::kdf_hmacs*>(nullptr));
    BOOST_TEST((hmacs == known));

    names functions;
    for (auto const* function : functions_of(table)) {
        functions.emplace(function->at("name").as_string());
        for (auto const& backend : function->at("backends").as_object()) {
            BOOST_TEST((std::ranges::find(backends, std::string(backend.key())) != backends.end()));
            auto const& listed = backend.value().at("hmacs");
            for (auto const& hmac : listed.is_null() ? json::array{} : listed.as_array()) {
                BOOST_TEST(
                    (std::ranges::find(hmacs, std::string(hmac.as_string())) != hmacs.end()));
            }
        }
    }
    names known_functions{
        "hkdf_extract", "hkdf_expand",    "hkdf",  "pbkdf2", "argon2id",
        "scrypt",       "blake2b_subkey", "kbkdf", "sskdf",  "x963kdf",
    };
    for (auto const& row : type_rows()) {
        known_functions.emplace(row.name);
    }
    known_functions.merge(family_rows());
    if (!BOOST_TEST((functions == known_functions))) {
        report_differences(functions, known_functions);
    }
}

template <class Backend, class Function, class Hmac>
void check_cell(json::object const& table) {
    std::string_view const hmac = std::is_void_v<Hmac> ? "" : test::name_of_hmac<Hmac>();
    bool const in_file =
        cell(function_row(table, function_name<Function>()), test::name_of<Backend>(), hmac);
    if (!BOOST_TEST_EQ(in_file, (hash::backend_has_v<Backend, Function, Hmac>))) {
        std::cerr << "  cell " << function_name<Function>() << " / " << test::name_of<Backend>()
                  << " / " << (hmac.empty() ? "(no hmac)" : hmac) << '\n';
    }
}

void check_cells(json::object const& table) {
    [&]<class... Backend>(std::tuple<Backend...>*) {
        (
            [&]<class B>(B*) {
                [&]<class... Function>(std::tuple<Function...>*) {
                    (
                        [&]<class F>(F*) {
                            [&]<class... Hmac>(std::tuple<Hmac...>*) {
                                (check_cell<B, F, Hmac>(table), ...);
                                // No hmac: every function of increment 1 takes one but these.
                                check_cell<B, F, void>(table);
                            }(static_cast<test::kdf_hmacs*>(nullptr));
                        }(static_cast<Function*>(nullptr)),
                        ...);
                }(static_cast<hmac_functions*>(nullptr));
                [&]<class... Function>(std::tuple<Function...>*) {
                    (check_cell<B, Function, void>(table), ...);
                    (check_cell<B, Function, hash::hmac_sha2_256>(table), ...);
                }(static_cast<plain_functions*>(nullptr));
            }(static_cast<Backend*>(nullptr)),
            ...);
    }(static_cast<backend_tags*>(nullptr));
}

// The index of the quote that closes the literal opened at `open`, an escaped character skipped.
std::size_t literal_end(std::string const& source, std::size_t open) {
    std::size_t end = open + 1;
    while (end < source.size() && source[end] != source[open]) {
        end += source[end] == '\\' ? 2 : 1;
    }
    return end;
}

// The texts of the static_asserts of a header that begin "webcpp::hash: ", each the
// concatenation of its string literals; a character literal is skipped, and an escape inside a
// literal is kept as written (the refusal texts hold none).
std::vector<std::string> refusals_in(std::string const& source) {
    std::vector<std::string> texts;
    constexpr std::string_view opening = "static_assert(";
    for (std::size_t at = source.find(opening); at != std::string::npos;
         at = source.find(opening, at + 1)) {
        std::string text;
        int depth = 1;
        for (std::size_t i = at + opening.size(); i < source.size() && depth > 0; ++i) {
            char const c = source[i];
            if (c == '"' || c == '\'') {
                std::size_t const end = literal_end(source, i);
                if (c == '"') {
                    text.append(source, i + 1, end - i - 1);
                }
                i = end;
            } else if (c == '(') {
                ++depth;
            } else if (c == ')') {
                --depth;
            }
        }
        if (text.starts_with("webcpp::hash: ")) {
            texts.push_back(text);
        }
    }
    return texts;
}

// The backends a text names, as backends::<name>.
names named_in(std::string_view text) {
    names found;
    constexpr std::string_view prefix = "backends::";
    for (std::size_t at = text.find(prefix); at != std::string_view::npos;
         at = text.find(prefix, at + 1)) {
        std::size_t end = at + prefix.size();
        while (end < text.size() &&
               ((text[end] >= 'a' && text[end] <= 'z') || (text[end] >= '0' && text[end] <= '9'))) {
            ++end;
        }
        found.emplace(text.substr(at + prefix.size(), end - at - prefix.size()));
    }
    return found;
}

// One refusal of spec 3.3: the header that holds it, the start of its text after
// "webcpp::hash: ", the backend that refuses ("" for a primary template), the functions it
// refuses, and the hmacs it is about: listed, or every hmac of the file ({"*"}), or the hmacs
// the refusing backend lacks for the function ({"lacks"}), or none ({} for a function over no
// hmac).
struct refusal {
    std::string_view header;
    std::string_view start;
    std::string_view backend;
    std::vector<std::string_view> functions;
    std::vector<std::string_view> hmacs;
};

std::vector<refusal> const& refusals() {
    static std::vector<refusal> const all{
        {
            .header = "detail/engines.hpp",
            .start = "this backend has no HKDF.",
            .backend = "",
            .functions = {"hkdf"},
            .hmacs = {"*"},
        },
        {
            .header = "detail/engines.hpp",
            .start = "this backend has no PBKDF2.",
            .backend = "",
            .functions = {"pbkdf2"},
            .hmacs = {"*"},
        },
        // A library's text, as the other backends' below: it names argon2id and scrypt as the
        // functions whose default backend is libsodium's, not as the functions only libsodium has.
        {
            .header = "detail/engines.hpp",
            .start = "backends::sodium, argon2id and scrypt need libsodium.",
            .backend = "sodium",
            .functions = {},
            .hmacs = {},
        },
        {
            .header = "detail/engines.hpp",
            .start = "argon2id is in backends::sodium and backends::openssl alone.",
            .backend = "",
            .functions = {"argon2id"},
            .hmacs = {},
        },
        {
            .header = "detail/engines.hpp",
            .start = "scrypt is in backends::sodium and backends::openssl alone.",
            .backend = "",
            .functions = {"scrypt"},
            .hmacs = {},
        },
        {
            .header = "detail/engines.hpp",
            .start = "blake2b_subkey is in backends::sodium alone.",
            .backend = "",
            .functions = {"blake2b_subkey"},
            .hmacs = {},
        },
        {
            .header = "detail/engines.hpp",
            .start = "digest_of and hasher take a tag of webcpp::hash::digests",
            .backend = "",
            .functions = {},
            .hmacs = {},
        },
        {
            .header = "detail/engines.hpp",
            .start = "mac takes a tag of webcpp::hash::macs",
            .backend = "",
            .functions = {},
            .hmacs = {},
        },
        {
            .header = "detail/engines.hpp",
            .start = "argon2 takes kdfs::argon2d, kdfs::argon2i or kdfs::argon2id.",
            .backend = "",
            .functions = {},
            .hmacs = {},
        },
        {
            .header = "detail/engines.hpp",
            .start = "backends::xkcp needs XKCP.",
            .backend = "xkcp",
            .functions = {},
            .hmacs = {},
        },
        {
            .header = "detail/engines.hpp",
            .start = "backends::blake3 needs BLAKE3's C implementation.",
            .backend = "blake3",
            .functions = {},
            .hmacs = {},
        },
        {
            .header = "detail/engines.hpp",
            .start = "backends::bearssl needs BearSSL.",
            .backend = "bearssl",
            .functions = {},
            .hmacs = {},
        },
        {
            .header = "detail/engines.hpp",
            .start = "backends::openssl needs OpenSSL.",
            .backend = "openssl",
            .functions = {},
            .hmacs = {},
        },
        {
            .header = "kdf.hpp",
            .start = "the key derivations take a Boost.Hash2 hmac",
            .backend = "",
            .functions = {},
            .hmacs = {},
        },
        {
            .header = "backends/bearssl.hpp",
            .start = "backends::bearssl has HKDF over",
            .backend = "bearssl",
            .functions = {"hkdf"},
            .hmacs = {"lacks"},
        },
        {
            .header = "backends/bearssl.hpp",
            .start = "hkdf_extract and hkdf_expand are not in backends::bearssl",
            .backend = "bearssl",
            .functions = {"hkdf_extract", "hkdf_expand"},
            .hmacs = {"*"},
        },
        {
            .header = "backends/bearssl.hpp",
            .start = "pbkdf2 is not in backends::bearssl",
            .backend = "bearssl",
            .functions = {"pbkdf2"},
            .hmacs = {"*"},
        },
        {
            .header = "backends/sodium.hpp",
            .start = "backends::sodium has HKDF over",
            .backend = "sodium",
            .functions = {"hkdf"},
            .hmacs = {"lacks"},
        },
        {
            .header = "backends/sodium.hpp",
            .start = "pbkdf2 is not in backends::sodium",
            .backend = "sodium",
            .functions = {"pbkdf2"},
            .hmacs = {"*"},
        },
        {
            .header = "backends/openssl.hpp",
            .start = "backends::openssl has no hmac_ripemd_128",
            .backend = "openssl",
            .functions = {"hkdf", "pbkdf2"},
            .hmacs = {"hmac_ripemd_128"},
        },
        {
            .header = "backends/openssl.hpp",
            .start = "backends::openssl has HKDF and PBKDF2 over the hmacs of hmac.hpp alone",
            .backend = "openssl",
            .functions = {"hkdf", "pbkdf2"},
            .hmacs = {"other"},
        },
        {
            .header = "backends/openssl.hpp",
            .start = "backends::openssl has kbkdf over the hmacs of hmac.hpp alone",
            .backend = "openssl",
            .functions = {"kbkdf"},
            .hmacs = {"lacks"},
        },
        {
            .header = "kdf_standards.hpp",
            .start = "sskdf takes a digest of SP 800-56C",
            .backend = "",
            .functions = {},
            .hmacs = {},
        },
        {
            .header = "kdf_standards.hpp",
            .start = "x963kdf takes a hash function of SEC 1 v2",
            .backend = "",
            .functions = {},
            .hmacs = {},
        },
    };
    return all;
}

// The backends of a refusal's row: those that have one of its functions over one of its hmacs,
// the refusing backend left out.
names row_of(json::object const& table, refusal const& r) {
    names row;
    std::vector<std::string> all_hmacs;
    for (auto const& hmac : table.at("hmacs").as_array()) {
        all_hmacs.emplace_back(hmac.as_string());
    }
    for (std::string_view const function : r.functions) {
        auto const& line = function_row(table, function);
        std::vector<std::string> hmacs;
        if (r.hmacs.empty()) {
            hmacs.emplace_back();
        } else if (r.hmacs.front() == "*") {
            hmacs = all_hmacs;
        } else if (r.hmacs.front() == "lacks") {
            for (auto const& hmac : all_hmacs) {
                if (!cell(line, r.backend, hmac)) {
                    hmacs.push_back(hmac);
                }
            }
        } else {
            hmacs.assign(r.hmacs.begin(), r.hmacs.end());
        }
        for (auto const& backend : line.at("backends").as_object()) {
            for (auto const& hmac : hmacs) {
                if (backend.key() != r.backend && cell(line, backend.key(), hmac)) {
                    row.emplace(backend.key());
                }
            }
        }
    }
    return row;
}

// The index in refusals() of the refusal of header whose text is text, refusals().size() when
// none is.
std::size_t refusal_of(std::string_view header, std::string_view text) {
    std::string_view const body = text.substr(std::string_view("webcpp::hash: ").size());
    for (std::size_t i = 0; i < refusals().size(); ++i) {
        if (refusals()[i].header == header && body.starts_with(refusals()[i].start)) {
            return i;
        }
    }
    return refusals().size();
}

// The tag a family's refusal names, its first word after "webcpp::hash: " when that is a qualified
// tag of digests, macs or kdfs; "" for any other text.
std::string_view family_tag_of(std::string_view text) {
    std::string_view const body = text.substr(std::string_view("webcpp::hash: ").size());
    std::string_view const tag = body.substr(0, body.find(' '));
    bool const qualified =
        tag.starts_with("digests::") || tag.starts_with("macs::") || tag.starts_with("kdfs::");
    return qualified ? tag : std::string_view{};
}

// The row of a function whose tag is `tag` (kbkdf's is kdfs::kbkdf_hmac), or null when none is.
json::object const* row_of_tag(json::object const& table, std::string_view tag) {
    for (auto const* function : functions_of(table)) {
        auto const* const listed = function->if_contains("tag");
        if (listed != nullptr && listed->is_string() && listed->as_string() == tag) {
            return function;
        }
    }
    return nullptr;
}

// A family tag's refusal names exactly the backends of the tag's row (a family's row, named by
// the tag, or a function's, which names it as its tag), none when it has no row. Returns whether
// the text is a family tag's.
bool check_family_refusal(json::object const& table, std::string const& text) {
    std::string_view const tag = family_tag_of(text);
    if (tag.empty()) {
        return false;
    }
    names row;
    auto const* found = find_row(table, tag);
    if (found == nullptr) {
        found = row_of_tag(table, tag);
    }
    if (found != nullptr) {
        for (auto const& backend : found->at("backends").as_object()) {
            row.emplace(backend.key());
        }
    }
    if (!BOOST_TEST((named_in(text) == row))) {
        std::cerr << "  the backends named by: " << text << '\n';
    }
    return true;
}

void check_refusals(json::object const& table, std::string const& include) {
    names headers;
    for (auto const& r : refusals()) {
        headers.emplace(r.header);
    }
    std::vector<bool> seen(refusals().size(), false);
    for (auto const& header : headers) {
        std::string path = include;
        path.append("/webcpp/hash/").append(header);
        for (auto const& text : refusals_in(read_text(path))) {
            if (check_family_refusal(table, text)) {
                continue;
            }
            std::size_t const matched = refusal_of(header, text);
            if (!BOOST_TEST(matched < refusals().size())) {
                std::cerr << "  a refusal this test does not know, in " << header << ": " << text
                          << '\n';
                continue;
            }
            seen[matched] = true;
            refusal const& r = refusals()[matched];
            names named = named_in(text);
            named.erase(std::string(r.backend));
            if (!BOOST_TEST((named == row_of(table, r)))) {
                std::cerr << "  the backends named by: " << text << '\n';
            }
        }
    }
    for (std::size_t i = 0; i < refusals().size(); ++i) {
        if (!BOOST_TEST(seen[i])) {
            std::cerr << "  no refusal in " << refusals()[i].header << " starts \""
                      << refusals()[i].start << "\"\n";
        }
    }
}

// Design D34's rule, where the table can show it: a family tag's default is null or one of hash2,
// xkcp, blake3 and sodium (never bearssl, openssl or a later backend), and no backend before it in
// that order has the tag whole (a cell without "partial"), since that backend would be the default.
// A default whose cell lands in a later increment is allowed: the rule reads the final table.
bool follows_order(json::object const& row) {
    static constexpr std::array<std::string_view, 4> order{"hash2", "xkcp", "blake3", "sodium"};
    auto const& listed = row.at("default");
    if (listed.is_null()) {
        return true;
    }
    auto const index = static_cast<std::size_t>(
        std::ranges::find(order, std::string_view(listed.as_string())) - order.begin());
    if (index == order.size()) {
        return false;
    }
    auto const& backends = row.at("backends").as_object();
    return std::ranges::none_of(std::span(order).first(index), [&](std::string_view earlier) {
        auto const* const found = backends.find(earlier);
        return found != backends.end() && !found->value().as_object().contains("partial");
    });
}

// Each family tag: its cells against backend_has_v, its default against default_backend (null for
// none), its refusal texts in detail/engines.hpp (a "no default backend" one exactly when it has no
// default), and a call on each backend that has it and is linked here.
template <class Tag>
void check_family_tag(json::object const& table, std::vector<std::string> const& texts,
                      std::string_view name) {
    auto const* const row = find_row(table, name);
    [&]<class... Backend>(std::tuple<Backend...>*) {
        (
            [&] {
                bool const in_file = row != nullptr && cell(*row, test::name_of<Backend>(), "");
                if (!BOOST_TEST_EQ(in_file, (hash::backend_has_v<Backend, Tag, family_key<Tag>>))) {
                    std::cerr << "  cell " << name << " / " << test::name_of<Backend>() << '\n';
                }
            }(),
            ...);
    }(static_cast<backend_tags*>(nullptr));

    bool const no_default = std::is_same_v<hash::default_backend<Tag>, hash::detail::no_default>;
    if (row != nullptr) {
        auto const& listed = row->at("default");
        bool const agrees =
            no_default ? listed.is_null()
                       : listed.is_string() &&
                             listed.as_string() == test::name_of<hash::default_backend<Tag>>();
        if (!BOOST_TEST(agrees)) {
            std::cerr << "  default of " << name << '\n';
        }
        if (!BOOST_TEST(follows_order(*row))) {
            std::cerr << "  default of " << name << " against design D34's order\n";
        }
    }

    // A tag's own texts; an hmac over a digest without them, the text of every such hmac.
    auto const refused_as = [&](std::string const& subject) {
        return std::ranges::any_of(texts, [&](auto const& t) { return t.starts_with(subject); });
    };
    std::string own = std::string("webcpp::hash: ") + std::string(name) + " ";
    if (!refused_as(own) && name.starts_with("macs::hmac<")) {
        own = "webcpp::hash: macs::hmac over this digest ";
    }
    bool const refused = refused_as(own);
    bool const without = refused_as(own + "has no default backend");
    if (!BOOST_TEST(refused) || !BOOST_TEST_EQ(without, no_default)) {
        std::cerr << "  the refusals of " << name << '\n';
    }
}

void check_families(json::object const& table, std::string const& include) {
    auto const texts = refusals_in(read_text(include + "/webcpp/hash/detail/engines.hpp"));
    for_each_tag<digest_tags>(digest_names, [&]<class Tag>(std::string_view name) {
        check_family_tag<Tag>(table, texts, name);
        [&]<class... Backend>(std::tuple<Backend...>*) {
            (call_digest<Tag, Backend>(name), ...);
        }(static_cast<backend_tags*>(nullptr));
    });
    for_each_tag<mac_tags>(mac_names, [&]<class Tag>(std::string_view name) {
        check_family_tag<Tag>(table, texts, name);
        [&]<class... Backend>(std::tuple<Backend...>*) {
            (call_mac<Tag, Backend>(name), ...);
        }(static_cast<backend_tags*>(nullptr));
    });
    for_each_tag<argon2_tags>(argon2_names, [&]<class Tag>(std::string_view name) {
        check_family_tag<Tag>(table, texts, name);
    });
}

}  // namespace

int main() {
    std::string const doc = WEBCPP_TEST_HASH_DOC;
    std::string const include = WEBCPP_TEST_HASH_INCLUDE;
    json::value const parsed = json::parse(read_text(doc + "/capabilities.json"));
    test::require(parsed.is_object());
    json::object const& table = parsed.as_object();

    check_names(table);
    check_type_rows(table);
    check_backend_fields(table);
    check_defaults(table);
    check_cells(table);
    check_refusals(table, include);
    check_families(table, include);
    return webcpp::test::exit_status(boost::report_errors());
}
