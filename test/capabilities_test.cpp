// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The capability table is one fact in two places, which must never drift: doc/capabilities.json and
// backend_has_v agree on every cell, a function over an hmac (or over no hmac) for a backend; the
// file names exactly the backends, hmacs and functions this test knows. And each refusal text of
// the headers (spec 3.3) names exactly the backends of its row: those that have the function it
// refuses, over the hmacs it is about, besides the refusing backend itself.

#include <webcpp/hash/algorithms.hpp>
#include <webcpp/hash/blake3.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/hash/keccak.hpp>
#include <webcpp/test/exit_status.hpp>

#include "require.hpp"
#include "support/defaults.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/json.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <set>
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

using backend_tags = std::tuple<hash::backends::hash2, hash::backends::sodium,
                                hash::backends::bearssl, hash::backends::openssl>;

// The functions of increment 1: those over an hmac, and those over none.
using hmac_functions = test::kdf_operations;
using plain_functions = std::tuple<kdfs::argon2id, kdfs::scrypt>;

template <class Function>
constexpr std::string_view function_name() {
    if constexpr (std::is_same_v<Function, kdfs::argon2id>) {
        return "argon2id";
    } else if constexpr (std::is_same_v<Function, kdfs::scrypt>) {
        return "scrypt";
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

json::object const& function_row(json::object const& table, std::string_view name) {
    for (auto const* function : functions_of(table)) {
        if (function->at("name").as_string() == name) {
            return *function;
        }
    }
    std::cerr << "no row for " << name << " in capabilities.json\n";
    std::abort();
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
        if (!BOOST_TEST_EQ(backends.size(), 1U) || !BOOST_TEST(backends.contains(known->backend)) ||
            !BOOST_TEST(backends.at(known->backend).at("hmacs").is_null())) {
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
    linked.emplace("HASH2");
#ifdef WEBCPP_HASH_HAS_XKCP
    linked.emplace("XKCP");
#endif
#ifdef WEBCPP_HASH_HAS_BLAKE3
    linked.emplace("BLAKE3");
#endif
    [&linked]<class... Backend>(std::tuple<Backend...>*) {
        (static_cast<void>(hash::detail::linked_v<Backend> &&
                           linked.emplace(test::name_of_macro<Backend>()).second),
         ...);
    }(static_cast<backend_tags*>(nullptr));
    return linked.contains(macro);
}

void check_cell_fields(json::object const& table, names const& tagged);

// The backends' own fields, where the code can tell: a backend's targets hold this
// target exactly when the program links it here, `portable` is membership of portable_order for
// a backend with a tag, and every cell is of increment 1 and states its constant time, which the
// documentation renders.
void check_backend_fields(json::object const& table) {
    names portable;
    [&portable]<class... Backend>(hash::detail::backend_list<Backend...>*) {
        (portable.emplace(test::name_of<Backend>()), ...);
    }(static_cast<hash::detail::portable_order*>(nullptr));
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
            if (!BOOST_TEST_EQ(b.at("portable").as_bool(), portable.contains(name))) {
                std::cerr << "  portable, for " << name << '\n';
            }
        }
    }
    check_cell_fields(table, tagged);
}

// Every cell is of increment 1, states its constant time, and, for a function with a
// Backend parameter, names a backend with a tag.
void check_cell_fields(json::object const& table, names const& tagged) {
    for (auto const* function : functions_of(table)) {
        bool const is_function = function->at("kind").as_string() == "function";
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
            bool const fine = c.at("since").as_int64() == 1 && stated && source != nullptr &&
                              source->is_string() && !source->as_string().empty() &&
                              (!is_function || tagged.contains(backend.key()));
            if (!BOOST_TEST(fine)) {
                std::cerr << "  the cell " << function->at("name").as_string() << " / "
                          << backend.key() << '\n';
            }
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
            for (auto const& hmac : backend.value().at("hmacs").is_null()
                                        ? json::array{}
                                        : backend.value().at("hmacs").as_array()) {
                BOOST_TEST(
                    (std::ranges::find(hmacs, std::string(hmac.as_string())) != hmacs.end()));
            }
        }
    }
    names known_functions{"hkdf_extract", "hkdf_expand", "hkdf", "pbkdf2", "argon2id", "scrypt"};
    for (auto const& row : type_rows()) {
        known_functions.emplace(row.name);
    }
    BOOST_TEST((functions == known_functions));
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
        {
            .header = "detail/engines.hpp",
            .start = "argon2id is in backends::sodium alone.",
            .backend = "",
            .functions = {"argon2id"},
            .hmacs = {},
        },
        {
            .header = "detail/engines.hpp",
            .start = "scrypt is in backends::sodium alone.",
            .backend = "",
            .functions = {"scrypt"},
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
    check_cells(table);
    check_refusals(table, include);
    return webcpp::test::exit_status(boost::report_errors());
}
