// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The seam of webcpp::secure::timing_guard, secure's guard, recorded for hash's tests: a test
// includes this header before any webcpp header, so that the seam is defined before
// <webcpp/secure/timing_guard.hpp> is first read and every engaged guard a call enters is
// counted, on every target, also where DIT does not apply. A guard is hash's own when one of
// hash's headers declares it: its source_location's file_name() holds include/webcpp/hash/, with
// `/` or `\` around each word (MSVC writes backslashes, and joins an include directory to a
// header's path with either); the include root keeps a checkout whose own folders read
// webcpp/hash/ from counting a test file's guard. timing_entries counts hash's own guards and
// timing_all_entries every guard: another library's, which a call may enter inside its own, and a
// test's own. require_enters then checks that a call entered a guard of hash's, and that the first
// guard it entered, the outermost since a guard is its function's first statement, is the one of
// the function the check names: a public function that forgot its own guard fails, also when it
// calls another guarded function. The converse, a call that enters no guard of hash's, is
// support/timing_coverage.hpp's uncovered. The recorder is the form of secure's
// (libs/secure/test/support/timing_seam.hpp) in hash's namespace webcpp::test, counting hash's.

#ifndef WEBCPP_TEST_HASH_SUPPORT_TIMING_SEAM_HPP
#define WEBCPP_TEST_HASH_SUPPORT_TIMING_SEAM_HPP

#ifdef WEBCPP_SECURE_TIMING_GUARD_HPP
#error "\"support/timing_seam.hpp\" must be included before any webcpp header"
#endif

#include <boost/core/lightweight_test.hpp>

#include <cstddef>
#include <source_location>
#include <string>
#include <string_view>
#include <utility>

namespace webcpp::test {

/** Every timing guard this thread entered: hash's, another library's, a test's. */
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the seam's counter
inline thread_local std::size_t timing_all_entries = 0;

/** The timing guards of hash's headers this thread has entered. */
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the seam's counter
inline thread_local std::size_t timing_entries = 0;

/**
 * The `function_name()` of the first guard, of any file, this thread entered since it was last
 * reset to null: the function that holds that guard, as the compiler spells it.
 */
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the seam's record
inline thread_local char const* timing_first_entry = nullptr;

/** The `function_name()` of the last guard, of any file, this thread entered. */
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the seam's record
inline thread_local char const* timing_last_entry = nullptr;

/** The library whose guards timing_entries counts. */
inline constexpr std::string_view timing_library = "hash";

/** Whether `character` separates a path's components, on any system webcpp builds on. */
constexpr bool path_separator(char character) noexcept {
    return character == '/' || character == '\\';
}

/**
 * Whether a path names a file under a library's include directory: the components `include`,
 * `webcpp` and `library`, in that order, each followed by a separator, `/` or `\` in any mix, and
 * `include` the path's first component or after a separator.
 *
 * @param path A `file_name()`.
 * @param library The library's directory name.
 * @return Whether the path is under `include/webcpp/<library>/`.
 */
constexpr bool path_in_library(std::string_view path, std::string_view library) noexcept {
    constexpr std::string_view include_root = "include";
    constexpr std::string_view root = "webcpp";
    for (std::size_t at = path.find(include_root); at != std::string_view::npos;
         at = path.find(include_root, at + 1)) {
        std::size_t const root_at = at + include_root.size() + 1;
        std::size_t const library_at = root_at + root.size() + 1;
        std::size_t const after = library_at + library.size();
        if ((at == 0 || path_separator(path[at - 1])) && after < path.size() &&
            path_separator(path[root_at - 1]) && path.substr(root_at, root.size()) == root &&
            path_separator(path[library_at - 1]) &&
            path.substr(library_at, library.size()) == library && path_separator(path[after])) {
            return true;
        }
    }
    return false;
}

/**
 * Records the entry into a webcpp::secure::timing_guard: counts it, as hash's when its file is
 * under include/webcpp/hash/, and keeps its function as the first since timing_first_entry was
 * reset and as the last.
 *
 * @param where Where the guard is declared.
 */
inline void timing_entered(std::source_location const& where) noexcept {
    ++timing_all_entries;
    if (path_in_library(where.file_name(), timing_library)) {
        ++timing_entries;
    }
    if (timing_first_entry == nullptr) {
        timing_first_entry = where.function_name();
    }
    timing_last_entry = where.function_name();
}

}  // namespace webcpp::test

/** Records the entry into a webcpp::secure::timing_guard declared at `where`. */
#define WEBCPP_SECURE_TIMING_ENTERED(where) (::webcpp::test::timing_entered(where))

namespace webcpp::test {

/**
 * A function as a check names it: its identifier, the scope that qualifies it, and optionally a
 * word its parameter list holds, for overloads of one scope and name.
 */
struct named_function {
    /** The class or namespace that qualifies it, unqualified and without template arguments. */
    std::string scope;
    /** Its name: an identifier, or `operator` and its symbol (`operator==`). */
    std::string identifier;
    /** A word its parameter list holds, or empty for any. */
    std::string parameter;
};

/**
 * Reads a function, spelled `<qualifiers>::<scope>::<identifier>`, optionally followed by
 * `(<parameter word>`, or by a space and words that say how it is called.
 *
 * The scope is the component before the identifier, empty when there is none. A check named
 * `hash::hkdf_extract of a salt on hash2` names `hash::hkdf_extract`;
 * `blake3::update(void` names `blake3::update` with a parameter list that holds `void`.
 *
 * @param spelled The function as a check spells it.
 * @return Its scope, identifier and parameter word.
 */
inline named_function function_named(std::string_view spelled) {
    named_function named;
    std::size_t const end = spelled.find_first_of(" (");
    if (end != std::string_view::npos && spelled[end] == '(') {
        std::string_view const rest = spelled.substr(end + 1);
        named.parameter = std::string(rest.substr(0, rest.find_first_of(" ,)")));
    }
    std::string_view const qualified = spelled.substr(0, end);
    std::size_t const separator = qualified.rfind("::");
    if (separator == std::string_view::npos) {
        named.identifier = std::string(qualified);
        return named;
    }
    named.identifier = std::string(qualified.substr(separator + 2));
    std::string_view const qualifiers = qualified.substr(0, separator);
    std::size_t const scope_separator = qualifiers.rfind("::");
    named.scope = std::string(scope_separator == std::string_view::npos
                                  ? qualifiers
                                  : qualifiers.substr(scope_separator + 2));
    return named;
}

/** Whether `character` can be part of an identifier. */
constexpr bool identifier_character(char character) noexcept {
    return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
           (character >= '0' && character <= '9') || character == '_';
}

/**
 * A `function_name()` in one spelling for clang, GCC and MSVC: the template arguments clang and
 * GCC append (` [B = ...]`, ` [with B = ...]`) cut, and the space MSVC puts between `operator`
 * and its symbol (`operator ==`) removed.
 *
 * @param entered A `function_name()`.
 * @return The same function, spelled for the search of `names_function`.
 */
inline std::string normalized_function_name(std::string_view entered) {
    std::string normal(entered.substr(0, entered.find(" [")));
    constexpr std::string_view operator_word = "operator ";
    for (std::size_t found = normal.find(operator_word); found != std::string::npos;
         found = normal.find(operator_word, found + 1)) {
        std::size_t const symbol = found + operator_word.size();
        if (symbol < normal.size() && !identifier_character(normal[symbol])) {
            normal.erase(symbol - 1, 1);
        }
    }
    return normal;
}

/**
 * The component that qualifies a name, read back from the `::` before it at `separator`:
 * `mac_engine` in `detail::mac_engine<hash2, Mac>::compute`, its template arguments skipped.
 *
 * @param text A normalized `function_name()`.
 * @param separator The position of the `::` before the name.
 * @return The qualifying component, unqualified, or empty.
 */
inline std::string_view qualifier_before(std::string_view text, std::size_t separator) {
    std::size_t end = separator;
    if (end > 0 && text[end - 1] == '>') {
        std::size_t depth = 0;
        while (end > 0) {
            --end;
            if (text[end] == '>') {
                ++depth;
            } else if (text[end] == '<' && --depth == 0) {
                break;
            }
        }
    }
    std::size_t begin = end;
    while (begin > 0 && identifier_character(text[begin - 1])) {
        --begin;
    }
    return text.substr(begin, end - begin);
}

/**
 * The position of the `(` that opens a function's own parameter list in a normalized
 * `function_name()`: the one matching its last `)`, so that parentheses and template arguments in
 * the return type and the parameter types are skipped.
 *
 * @param text A normalized `function_name()`.
 * @return The position, or `npos` when there is no parameter list.
 */
inline std::size_t parameter_list_of(std::string_view text) {
    std::size_t position = text.rfind(')');
    if (position == std::string_view::npos) {
        return position;
    }
    std::size_t depth = 0;
    while (true) {
        if (text[position] == ')') {
            ++depth;
        } else if (text[position] == '(' && --depth == 0) {
            return position;
        }
        if (position == 0) {
            return std::string_view::npos;
        }
        --position;
    }
}

/**
 * Whether a `function_name()` is the named function: its own name, the qualified name before its
 * outermost parameter list (and before the template arguments MSVC writes there), ends with
 * `::<scope>::<identifier>`, its scope read without template arguments, and its parameter list
 * holds the named word. A name in the return type or a parameter type never counts, a named
 * function without a scope never matches, and a lambda's (`(lambda)`, `(anonymous class)`,
 * `<lambda()>`, `<lambda_1>`) never is: a guard belongs at the top of the public function, not in
 * a lambda in it.
 *
 * @param entered A `function_name()`, as clang, GCC or MSVC spells it.
 * @param named The function a check names.
 * @return Whether `entered` is `named`.
 */
inline bool names_function(std::string_view entered, named_function const& named) {
    if (named.scope.empty() || entered.find("lambda") != std::string_view::npos ||
        entered.find("anonymous class") != std::string_view::npos) {
        return false;
    }
    std::string const normal = normalized_function_name(entered);
    std::string_view const text = normal;
    std::size_t const open = parameter_list_of(text);
    if (open == std::string_view::npos) {
        return false;
    }
    std::string const needle = "::" + named.identifier;
    std::string_view name = text.substr(0, open);
    if (!name.ends_with(needle) && name.ends_with('>')) {
        // MSVC writes a function template's arguments after its name: armour<struct ...>(.
        std::size_t depth = 0;
        std::size_t end = name.size();
        while (end > 0) {
            --end;
            if (name[end] == '>') {
                ++depth;
            } else if (name[end] == '<' && --depth == 0) {
                break;
            }
        }
        name = name.substr(0, end);
    }
    if (!name.ends_with(needle) ||
        qualifier_before(text, name.size() - needle.size()) != named.scope) {
        return false;
    }
    std::string_view const parameters = text.substr(open, text.rfind(')') - open);
    return named.parameter.empty() || parameters.find(named.parameter) != std::string_view::npos;
}

/**
 * Runs `call` and reports an error when it entered no webcpp::secure::timing_guard of hash's, or
 * when the first guard it entered is not the one of `function`.
 *
 * @param name What the call is, as an error names it.
 * @param function The function whose guard the call must enter first, as `function_named` reads
 * it: `<scope>::<identifier>` where the name cannot say it (an alias of a class template, an
 * operator, a constructor, overloads).
 * @param call The call, with its arguments bound.
 */
template <class Call>
void require_enters(std::string_view name, std::string_view function, Call&& call) {
    std::size_t const before = timing_entries;
    timing_first_entry = nullptr;
    std::forward<Call>(call)();
    if (timing_entries == before) {
        std::string const message =
            std::string(name) + " did not enter a webcpp::secure::timing_guard of hash's";
        BOOST_ERROR(message.c_str());
    } else if (function_named(function).scope.empty()) {
        std::string const message =
            std::string(name) + " names no scope: give the function, <scope>::<identifier>";
        BOOST_ERROR(message.c_str());
    } else if (!names_function(timing_first_entry, function_named(function))) {
        std::string const message = std::string(name) +
                                    " entered first the webcpp::secure::timing_guard of " +
                                    timing_first_entry + ", not its own";
        BOOST_ERROR(message.c_str());
    }
    timing_first_entry = nullptr;
}

/**
 * Runs `call` and reports an error when it entered no webcpp::secure::timing_guard of hash's, or
 * when the first guard it entered is not the one of the function the name begins with.
 *
 * @param name What the call is, `<qualifiers>::<scope>::<function>[ how] on <backend>`, which
 * names the function as `function_named` reads it.
 * @param call The call, with its arguments bound.
 */
template <class Call>
void require_enters(std::string_view name, Call&& call) {
    require_enters(name, name, std::forward<Call>(call));
}

}  // namespace webcpp::test

#endif  // WEBCPP_TEST_HASH_SUPPORT_TIMING_SEAM_HPP
