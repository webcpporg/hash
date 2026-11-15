// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// On backends::openssl webcpp's code allocates nothing, and OpenSSL's own allocations are
// measured, printed and not bounded (spec section 7.7): the test sets OpenSSL's allocator with
// CRYPTO_set_mem_functions before anything, counts each call OpenSSL makes through it per
// function (HKDF and PBKDF2 over four hmacs), prints the counts as records (collected by
// bench/allocation_collect.py into doc/measurements.allocation.json and doc/allocation.adoc) and
// asserts only that operator new is never called: the count of OpenSSL's allocator is a
// measurement, never a bound. OpenSSL's allocations are outside the user's allocator (the accepted
// departure); they are measured on OpenSSL 3.5.9 (native with assembly, wasip2 and wasip3 without
// it).

#include <webcpp/hash/backends/openssl.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/pbkdf2.hpp>

#include <boost/core/lightweight_test.hpp>

#include <webcpp/test/exit_status.hpp>

#include "support/counting.hpp"

#include <openssl/crypto.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <span>

namespace hash = webcpp::hash;

namespace {

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): OpenSSL's allocation count
std::atomic<std::size_t> openssl_allocations{0};

#ifdef __GLIBC__
// __libc_malloc, __libc_realloc and __libc_free are declared by support/counting.hpp.
#define WEBCPP_TEST_OPENSSL_C(name) __libc_##name
#else
#define WEBCPP_TEST_OPENSSL_C(name) std::name
#endif

void* counting_malloc(std::size_t size, char const* /*file*/, int /*line*/) {
    ++openssl_allocations;
    return WEBCPP_TEST_OPENSSL_C(malloc)(size);
}

void* counting_realloc(void* p, std::size_t size, char const* /*file*/, int /*line*/) {
    ++openssl_allocations;
    return WEBCPP_TEST_OPENSSL_C(realloc)(p, size);
}

void counting_free(void* p, char const* /*file*/, int /*line*/) {
    WEBCPP_TEST_OPENSSL_C(free)(p);
}

std::array<std::uint8_t, 64> const bytes = [] {
    std::array<std::uint8_t, 64> filled{};
    for (std::size_t i = 0; i != filled.size(); ++i) {
        filled[i] = static_cast<std::uint8_t>(i * 5 + 3);
    }
    return filled;
}();

/** A call's allocations through OpenSSL, as one record; operator new's must stay zero. */
template <class F>
void measured(char const* operation, char const* hmac, int call, F&& call_it) {
    std::size_t const own_before = openssl_allocations.load();
    std::size_t const new_before = webcpp::test::counted_new.load();
    call_it();
    std::size_t const own = openssl_allocations.load() - own_before;
    BOOST_TEST_EQ(webcpp::test::counted_new.load(), new_before);
    std::printf("record operation=%s hmac=%s backend=openssl target=%s call=%d openssl=%zu new=0\n",
                operation, hmac, webcpp::test::target_name, call, own);
}

template <class Hmac>
void measure_one(char const* name) {
    using openssl = hash::backends::openssl;
    if constexpr (!hash::backend_has_v<openssl, hash::kdfs::hkdf, Hmac>) {
        std::printf("record operation=none hmac=%s backend=openssl target=%s\n", name,
                    webcpp::test::target_name);
        return;
    }
    std::array<std::uint8_t, 42> okm{};
    std::array<std::uint8_t, 40> key{};
    std::span<std::uint8_t const> const input(bytes);
    // The first call of each function pays OpenSSL's one-time setup; the second is steady state.
    for (int round = 1; round != 3; ++round) {
        measured("hkdf", name, round, [&] {
            auto const done =
                hash::hkdf<Hmac, openssl>(okm, input.first(20), input, input.last(10));
            BOOST_TEST(done.has_value());
        });
        measured("pbkdf2", name, round, [&] {
            auto const done = hash::pbkdf2<Hmac, openssl>(key, input.first(20), input.last(16), 3);
            BOOST_TEST(done.has_value());
        });
    }
}

}  // namespace

int main() {
    // Before anything: OpenSSL allocates through the test's functions from here on.
    BOOST_TEST(CRYPTO_set_mem_functions(&counting_malloc, &counting_realloc, &counting_free) == 1);
    measure_one<hash::hmac_sha2_256>("hmac_sha2_256");
    measure_one<hash::hmac_sha2_512>("hmac_sha2_512");
    measure_one<hash::hmac_sha3_256>("hmac_sha3_256");
    measure_one<hash::hmac_blake2b_512>("hmac_blake2b_512");
    std::printf("record operation=counter backend=none target=%s c_counted=%d\n",
                webcpp::test::target_name, webcpp::test::c_allocations_counted ? 1 : 0);
    return webcpp::test::exit_status(boost::report_errors());
}
