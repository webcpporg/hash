// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// webcpp::secure::timing_guard, secure's guard, as hash's seam support sees it, with no backend:
// its seam fires once per engaged guard on every target, and never for a disengaged one, and names
// the function that holds the guard, which require_enters reads in the spellings of clang, GCC and
// MSVC; the own-library filter tells hash's guards by their file in the spellings of clang, GCC and
// MSVC and on near misses; where the CPU has DIT, an engaged guard sets it for its scope and clears
// it after when it was clear, leaves it set when it was set, and nests; a disengaged guard touches
// nothing. Built with WEBCPP_TEST_TIMING_THREADS (timing_threads, native, with threads), a guard on
// one thread leaves another's DIT clear.

#include "support/timing_dit.hpp"

#include <webcpp/secure/timing_guard.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <cstddef>
#include <cstdint>
#include <string_view>

#ifdef WEBCPP_TEST_TIMING_THREADS
#include <future>
#include <thread>
#endif

namespace {

namespace secure = webcpp::secure;

namespace seam_probe {

/** Holds a guard, as a public function does, for seam_names_function. */
void guarded_function() {
    secure::timing_guard const guard;
}

/** Calls guarded_function and holds no guard of its own, as a function that forgot its own. */
void forwarding_function() {
    guarded_function();
}

}  // namespace seam_probe

// Constructing a guard raises the seam's count of every guard by exactly one, on every target; the
// guard is this test's own, so hash's count does not move.
void seam_fires() {
    std::size_t const before = webcpp::test::timing_all_entries;
    std::size_t const hash_before = webcpp::test::timing_entries;
    {
        secure::timing_guard const guard;
        BOOST_TEST_EQ(webcpp::test::timing_all_entries, before + 1);
    }
    BOOST_TEST_EQ(webcpp::test::timing_all_entries, before + 1);
    BOOST_TEST_EQ(webcpp::test::timing_entries, hash_before);
}

// The own-library filter reads the paths clang, GCC and MSVC give for hash's headers, and no near
// miss: another library's header, a test file, a directory whose name only begins with hash, and
// webcpp/hash/ under a folder that is not an include root.
void path_in_library_spellings() {
    using webcpp::test::path_in_library;
    constexpr std::string_view library = "hash";
    BOOST_TEST(path_in_library("/w/libs/hash/include/webcpp/hash/mac.hpp", library));
    BOOST_TEST(path_in_library("../include/webcpp/hash/x.hpp", library));
    BOOST_TEST(path_in_library("include/webcpp/hash/x.hpp", library));
    BOOST_TEST(path_in_library(R"(C:\t\a\libs\hash\include\webcpp\hash\x.hpp)", library));
    BOOST_TEST(path_in_library(R"(C:\t\a\include\webcpp/hash\backends\sodium.hpp)", library));
    BOOST_TEST(!path_in_library("/w/libs/hash/test/timing_test.cpp", library));
    BOOST_TEST(!path_in_library("/w/include/webcpp/hashx/x.hpp", library));
    BOOST_TEST(!path_in_library("/w/myinclude/webcpp/hash/x.hpp", library));
    BOOST_TEST(!path_in_library("/w/include/webcpp/secure/timing_guard.hpp", library));
    BOOST_TEST(!path_in_library("/w/include/webcpp/hash", library));
    BOOST_TEST(path_in_library("/w/include/webcpp/secure/timing_guard.hpp", "secure"));
}

// The seam records the function that holds the first guard a call enters, as the compiler spells
// it, and require_enters' reading of it finds that function and no other.
void seam_names_function() {
    webcpp::test::timing_first_entry = nullptr;
    seam_probe::forwarding_function();
    if (BOOST_TEST(webcpp::test::timing_first_entry != nullptr)) {
        std::string_view const entered = webcpp::test::timing_first_entry;
        BOOST_TEST(webcpp::test::names_function(
            entered, webcpp::test::function_named("seam_probe::guarded_function")));
        BOOST_TEST(!webcpp::test::names_function(entered,
                                                 webcpp::test::function_named("guarded_function")));
        BOOST_TEST(!webcpp::test::names_function(
            entered, webcpp::test::function_named("seam_probe::forwarding_function")));
        BOOST_TEST(!webcpp::test::names_function(
            entered, webcpp::test::function_named("other::guarded_function")));
        BOOST_TEST(!webcpp::test::names_function(
            entered, webcpp::test::function_named("seam_probe::guarded")));
    }
    webcpp::test::timing_first_entry = nullptr;
}

// require_enters' reading of a function_name() in the spellings of clang, GCC and MSVC, whatever
// compiles this test: a free forwarder and the member it forwards to, a constructor, operators,
// overloads told apart by a parameter, and lambdas, which are never a public function.
void names_function_spellings() {
    auto const names = [](std::string_view entered, std::string_view spelled) {
        return webcpp::test::names_function(entered, webcpp::test::function_named(spelled));
    };
    BOOST_TEST(names("int ns::pem::armour(int) [with B = int]", "pem::armour"));
    BOOST_TEST(!names("static int ns::pem::algorithm<int>::armour(int) [B = int]", "pem::armour"));
    BOOST_TEST(
        names("static int ns::pem::algorithm<B>::armour(int) [with B = int]", "algorithm::armour"));
    BOOST_TEST(names("int __cdecl ns::pem::armour<struct ns::b>(int)", "pem::armour"));
    BOOST_TEST(!names("int __cdecl ns::pem::algorithm<struct ns::b>::armour(int)", "pem::armour"));
    BOOST_TEST(
        names("struct ns::gcm<int> &__cdecl ns::gcm<int>::operator =(struct ns::gcm<int> &&)",
              "gcm::operator="));
    BOOST_TEST(
        !names("bool __cdecl ns::operator ==(struct ns::pk,struct ns::pk)", "ns::operator="));
    BOOST_TEST(
        names("bool __cdecl ns::operator ==(struct ns::pk,struct ns::pk)", "ns::operator=="));
    BOOST_TEST(names("ns::gcm<C>::gcm(ns::gcm<C>&&) [with C = int]", "gcm::gcm"));
    BOOST_TEST(
        names("bool ns::equal(std::span<const unsigned char>, std::span<const unsigned char>)",
              "ns::equal(span"));
    BOOST_TEST(
        !names("bool ns::equal(std::span<const unsigned char>, std::span<const unsigned char>)",
               "ns::equal(digest"));
    BOOST_TEST(
        names("bool __cdecl ns::equal<16>(const class ns::digest<16> &)", "ns::equal(digest"));
    // A name in the return type or a parameter type is not the function's own.
    BOOST_TEST(!names("int ns::other(ns::pem::armour<int>, int) [with B = int]", "pem::armour"));
    BOOST_TEST(!names("int ns::other(ns::pem::armour(int)) [with B = int]", "pem::armour"));
    BOOST_TEST(!names("ns::pem::armour<int> ns::make(int) [B = int]", "pem::armour"));
    BOOST_TEST(!names("struct ns::pem::armour<int> __cdecl ns::make<int>(int)", "pem::armour"));
    BOOST_TEST(!names("ns::algorithm<ns::pem::armour<int>>::seal(int)", "pem::armour"));
    BOOST_TEST(names("ns::pem::armour<int> ns::pem::armour(ns::pem::armour<int>)", "pem::armour"));
    // A function named without a scope never matches.
    BOOST_TEST(!names("int ns::pem::armour(int) [with B = int]", "armour"));
    BOOST_TEST(names("auto ns::pk::operator<=>(const pk &) const", "pk::operator<=>"));
    BOOST_TEST(
        names("auto __cdecl ns::pk::operator <=>(const struct ns::pk &) const", "pk::operator<=>"));
    BOOST_TEST(!names("auto ns::f()::(anonymous class)::operator()() const", "ns::f"));
    BOOST_TEST(!names("auto ns::f()::(lambda)::operator()() const", "ns::f"));
    BOOST_TEST(!names("ns::f()::<lambda()>", "ns::f"));
    BOOST_TEST(!names("auto __cdecl ns::f::<lambda_1>::operator ()(void) const", "ns::f"));
}

// From clear: set inside a guard, clear after it. Where the guard does not apply, never set.
void guard_sets_and_clears() {
    webcpp::test::force_dit(false);
    BOOST_TEST(!secure::dit_is_set());
    {
        secure::timing_guard const guard;
        BOOST_TEST_EQ(secure::dit_is_set(), secure::cpu_has_dit());
    }
    BOOST_TEST(!secure::dit_is_set());
}

// From set, as a program sets it: still set after a guard.
void guard_leaves_set_bit() {
    webcpp::test::force_dit(true);
    BOOST_TEST_EQ(secure::dit_is_set(), secure::cpu_has_dit());
    {
        secure::timing_guard const guard;
        BOOST_TEST_EQ(secure::dit_is_set(), secure::cpu_has_dit());
    }
    BOOST_TEST_EQ(secure::dit_is_set(), secure::cpu_has_dit());
    webcpp::test::force_dit(false);
    BOOST_TEST(!secure::dit_is_set());
}

// From clear: set inside both guards and after the inner one, clear after the outer one.
void nested_guards() {
    webcpp::test::force_dit(false);
    {
        secure::timing_guard const outer;
        {
            secure::timing_guard const inner;
            BOOST_TEST_EQ(secure::dit_is_set(), secure::cpu_has_dit());
        }
        BOOST_TEST_EQ(secure::dit_is_set(), secure::cpu_has_dit());
        {
            secure::timing_guard const quiet{false};
            BOOST_TEST_EQ(secure::dit_is_set(), secure::cpu_has_dit());
        }
        BOOST_TEST_EQ(secure::dit_is_set(), secure::cpu_has_dit());
    }
    BOOST_TEST(!secure::dit_is_set());
}

// A guard constructed with false fires no seam and touches nothing, whichever state it finds.
void disengaged_does_nothing() {
    std::size_t const before = webcpp::test::timing_all_entries;
    webcpp::test::force_dit(false);
    {
        secure::timing_guard const guard{false};
        BOOST_TEST_EQ(webcpp::test::timing_all_entries, before);
        BOOST_TEST(!secure::dit_is_set());
    }
    BOOST_TEST(!secure::dit_is_set());
    webcpp::test::force_dit(true);
    {
        secure::timing_guard const guard{false};
        BOOST_TEST_EQ(secure::dit_is_set(), secure::cpu_has_dit());
    }
    BOOST_TEST_EQ(secure::dit_is_set(), secure::cpu_has_dit());
    webcpp::test::force_dit(false);
    BOOST_TEST(!secure::dit_is_set());
}

#ifdef WEBCPP_TEST_TIMING_THREADS
// While a guard holds DIT on this thread, another thread reads it clear. The other thread is
// started before the guard, so that it cannot inherit the state at its creation (Linux's clone
// copies PSTATE), and reads it only once the guard is entered.
void other_thread_untouched() {
    webcpp::test::force_dit(false);
    std::promise<void> guard_entered;
    std::promise<bool> other_reading;
    std::thread other([entered = guard_entered.get_future(), &other_reading]() mutable {
        entered.wait();
        other_reading.set_value(secure::dit_is_set());
    });
    {
        secure::timing_guard const guard;
        guard_entered.set_value();
        BOOST_TEST(!other_reading.get_future().get());
        BOOST_TEST_EQ(secure::dit_is_set(), secure::cpu_has_dit());
    }
    other.join();
    BOOST_TEST(!secure::dit_is_set());
}
#endif

}  // namespace

int main() {
    seam_fires();
    path_in_library_spellings();
    seam_names_function();
    names_function_spellings();
    guard_sets_and_clears();
    guard_leaves_set_bit();
    nested_guards();
    disengaged_does_nothing();
#ifdef WEBCPP_TEST_TIMING_THREADS
    other_thread_untouched();
#endif
    return webcpp::test::exit_status(boost::report_errors());
}
