// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// On backends::openssl webcpp's code allocates nothing, and OpenSSL's own allocations are
// measured, printed and not bounded (spec section 7.7): the test sets OpenSSL's allocator with
// CRYPTO_set_mem_functions before anything, counts each call OpenSSL makes through it per call,
// prints the counts as records and asserts only that operator new is never called: the count of
// OpenSSL's allocator is a measurement, never a bound. The calls are every entry point
// backends::openssl has (increments 1 and 4, ruling R94): HKDF and PBKDF2 over four hmacs (whose
// records bench/allocation_collect.py collects into doc/measurements.allocation.json and
// doc/allocation.adoc), and hkdf_extract, hkdf_expand and hkdf over pieces over the same four,
// whose EVP_MAC_CTX OpenSSL allocates with EVP_MAC_CTX_new, and Expand's for each block with
// EVP_MAC_CTX_dup; digest_of, and a hasher's whole hash, over each of its 23 digests, whose
// EVP_MD_CTX OpenSSL allocates with EVP_MD_CTX_new; mac over each of its 26 MACs, whose
// EVP_MAC_CTX OpenSSL allocates with EVP_MAC_CTX_new; argon2's three variants, argon2id, scrypt,
// kbkdf, sskdf and x963kdf, whose EVP_KDF_CTX OpenSSL allocates (Argon2's and scrypt's memory
// among it). Each entry point's refusal by a guard runs too, and must reach no allocator at all.
// Every call is counted and the totals asserted exactly against the call list written here; a
// tag a wrong trait drops fails the static_assert on backend_has_v instead, and a tag OpenSSL
// gains later is added here by hand. OpenSSL's allocations are outside the user's allocator (the
// accepted departure); they are measured on OpenSSL 3.5.9 (native with assembly, wasip2 and wasip3
// without it).

#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/backends/openssl.hpp>
#include <webcpp/hash/byte_pieces.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/kdf_standards.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/hash/pbkdf2.hpp>
#include <webcpp/hash/scrypt.hpp>

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

constexpr std::array<std::uint8_t, 64> bytes = [] {
    std::array<std::uint8_t, 64> filled{};
    for (std::size_t i = 0; i != filled.size(); ++i) {
        filled[i] = static_cast<std::uint8_t>((i * 5) + 3);
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

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): calls under the counters
std::size_t calls_made = 0;

/**
 One call's allocations through OpenSSL, printed as a record `operation=<operation>
 <key>=<name>`; operator new's must stay zero.
*/
template <class F>
void counted(char const* operation, char const* key, char const* name, int call, F&& call_it) {
    ++calls_made;
    std::size_t const own_before = openssl_allocations.load();
    std::size_t const new_before = webcpp::test::counted_new.load();
    call_it();
    std::size_t const own = openssl_allocations.load() - own_before;
    BOOST_TEST_EQ(webcpp::test::counted_new.load(), new_before);
    std::printf("record operation=%s %s=%s backend=openssl target=%s call=%d openssl=%zu new=0\n",
                operation, key, name, webcpp::test::target_name, call, own);
}

/**
 A refusal by a guard, before OpenSSL is reached: `call_it()` returns the error `expected` and no
 allocation of any kind happened.
*/
template <class F>
void refused_without_allocating(char const* name, hash::error expected, F&& call_it) {
    ++calls_made;
    std::size_t const own_before = openssl_allocations.load();
    std::size_t const new_before = webcpp::test::counted_new.load();
    auto const done = call_it();
    if (!BOOST_TEST(done.has_error()) || !BOOST_TEST(done.error() == expected) ||
        !BOOST_TEST_EQ(openssl_allocations.load(), own_before) ||
        !BOOST_TEST_EQ(webcpp::test::counted_new.load(), new_before)) {
        std::printf("allocated or not refused with error %d: %s (error %d)\n",
                    static_cast<int>(expected), name, done.has_error() ? done.error().value() : 0);
    }
}

/**
 HKDF, PBKDF2 and HKDF's three functions over pieces over `Hmac`, twice each (the first call pays
 OpenSSL's one-time setup); then hkdf over pieces with an empty output, refused.
*/
template <class Hmac>
void measure_one(char const* name) {
    using hash::backends::openssl;
    if constexpr (!hash::backend_has_v<openssl, hash::kdfs::hkdf, Hmac>) {
        std::printf("record operation=none hmac=%s backend=openssl target=%s\n", name,
                    webcpp::test::target_name);
    } else {
        std::array<std::uint8_t, 42> okm{};
        std::array<std::uint8_t, 40> key{};
        std::span<std::uint8_t const> const input(bytes);
        // The first call of each function pays OpenSSL's one-time setup; the second is steady
        // state.
        for (int round = 1; round != 3; ++round) {
            measured("hkdf", name, round, [&] {
                auto const done =
                    hash::hkdf<Hmac, openssl>(okm, input.first(20), input, input.last(10));
                BOOST_TEST(done.has_value());
            });
            measured("pbkdf2", name, round, [&] {
                auto const done =
                    hash::pbkdf2<Hmac, openssl>(key, input.first(20), input.last(16), 3);
                BOOST_TEST(done.has_value());
            });
            measured("hkdf_extract_pieces", name, round, [&] {
                auto const done = hash::hkdf_extract<Hmac, openssl>(
                    input.first(20), {input.first(30), input.last(34)});
                BOOST_TEST(done.has_value());
            });
            measured("hkdf_expand_pieces", name, round, [&] {
                constexpr std::size_t digest_size = typename Hmac::result_type().size();
                auto const done = hash::hkdf_expand<Hmac, openssl>(okm, input.first(digest_size),
                                                                   {input.first(4), input.last(6)});
                BOOST_TEST(done.has_value());
            });
            measured("hkdf_pieces", name, round, [&] {
                auto const done = hash::hkdf<Hmac, openssl>(okm, input.first(20),
                                                            {input.first(30), input.last(34)},
                                                            {input.first(4), input.last(6)});
                BOOST_TEST(done.has_value());
            });
        }
        refused_without_allocating(name, hash::error::invalid_output_size, [&] {
            return hash::hkdf<Hmac, openssl>(std::span<std::uint8_t>{}, input.first(20),
                                             {input.first(30), input.last(34)},
                                             {input.first(4), input.last(6)});
        });
    }
}

/**
 A digest's allocations through OpenSSL: digest_of, and a hasher made, fed and finished, twice (the
 first call pays OpenSSL's fetch); then an empty output, refused.
*/
template <class Digest>
void measure_digest(char const* name) {
    using hash::backends::openssl;
    static_assert(hash::backend_has_v<openssl, Digest, void>);
    constexpr std::uint64_t longest =
        hash::detail::digest_traits<Digest>::max_output(hash::digest_options<Digest>{});
    // The digest's size; 32 bytes of an extendable output.
    std::array<std::uint8_t, longest == hash::detail::no_limit ? 32 : longest> sized{};
    std::span<std::uint8_t const> const input(bytes);
    for (int round = 1; round != 3; ++round) {
        counted("digest_of", "digest", name, round,
                [&] { BOOST_TEST((hash::digest_of<Digest, openssl>(sized, input).has_value())); });
        counted("hasher", "digest", name, round, [&] {
            auto hashing = hash::hasher<Digest, openssl>::make();
            BOOST_TEST(hashing.has_value());
            if (hashing) {
                BOOST_TEST(hashing->update(input).has_value());
                BOOST_TEST(hashing->finish(sized).has_value());
            }
        });
    }
    refused_without_allocating(name, hash::error::invalid_output_size, [&] {
        return hash::digest_of<Digest, openssl>(std::span<std::uint8_t>{}, input);
    });
}

/**
 A MAC's allocations through OpenSSL: mac with a 32-byte key (a 16-byte one for SipHash) and its
 longest tag up to 32 bytes, twice; then an empty tag, refused.
*/
template <class Mac>
void measure_mac(char const* name, hash::mac_options<Mac> const& options = {}) {
    using hash::backends::openssl;
    using traits = hash::detail::mac_traits<Mac>;
    static_assert(hash::backend_has_v<openssl, Mac, void>);
    constexpr std::size_t key_size = traits::max_key < 32 ? traits::max_key : 32;
    constexpr std::size_t tag_size = traits::max_output < 32 ? traits::max_output : 32;
    std::array<std::uint8_t, tag_size> tag{};
    std::span<std::uint8_t const> const input(bytes);
    for (int round = 1; round != 3; ++round) {
        counted("mac", "mac", name, round, [&] {
            BOOST_TEST(
                (hash::mac<Mac, openssl>(tag, input.first(key_size), input, options).has_value()));
        });
    }
    refused_without_allocating(name, hash::error::invalid_output_size, [&] {
        return hash::mac<Mac, openssl>(std::span<std::uint8_t>{}, input.first(key_size), input,
                                       options);
    });
}

// Every digest backends::openssl has: 23 tags, 5 calls each.
void measure_digests() {
    namespace digests = hash::digests;
    std::size_t const before = calls_made;
    measure_digest<digests::md5>("md5");
    measure_digest<digests::sha1>("sha1");
    measure_digest<digests::sha2_224>("sha2_224");
    measure_digest<digests::sha2_256>("sha2_256");
    measure_digest<digests::sha2_384>("sha2_384");
    measure_digest<digests::sha2_512>("sha2_512");
    measure_digest<digests::sha2_512_224>("sha2_512_224");
    measure_digest<digests::sha2_512_256>("sha2_512_256");
    measure_digest<digests::sha3_224>("sha3_224");
    measure_digest<digests::sha3_256>("sha3_256");
    measure_digest<digests::sha3_384>("sha3_384");
    measure_digest<digests::sha3_512>("sha3_512");
    measure_digest<digests::shake_128>("shake_128");
    measure_digest<digests::shake_256>("shake_256");
    measure_digest<digests::keccak_224>("keccak_224");
    measure_digest<digests::keccak_256>("keccak_256");
    measure_digest<digests::keccak_384>("keccak_384");
    measure_digest<digests::keccak_512>("keccak_512");
    measure_digest<digests::blake2b>("blake2b");
    measure_digest<digests::blake2s_256>("blake2s_256");
    measure_digest<digests::ripemd_160>("ripemd_160");
    measure_digest<digests::md5_sha1>("md5_sha1");
    measure_digest<digests::sm3>("sm3");
    BOOST_TEST_EQ(calls_made - before, std::size_t{23} * 5);
}

// Every MAC backends::openssl has: 26 tags, 3 calls each.
void measure_macs() {
    namespace digests = hash::digests;
    namespace macs = hash::macs;
    std::size_t const before = calls_made;
    measure_mac<macs::hmac<digests::md5>>("hmac_md5");
    measure_mac<macs::hmac<digests::sha1>>("hmac_sha1");
    measure_mac<macs::hmac<digests::sha2_224>>("hmac_sha2_224");
    measure_mac<macs::hmac<digests::sha2_256>>("hmac_sha2_256");
    measure_mac<macs::hmac<digests::sha2_384>>("hmac_sha2_384");
    measure_mac<macs::hmac<digests::sha2_512>>("hmac_sha2_512");
    measure_mac<macs::hmac<digests::sha2_512_224>>("hmac_sha2_512_224");
    measure_mac<macs::hmac<digests::sha2_512_256>>("hmac_sha2_512_256");
    measure_mac<macs::hmac<digests::sha3_224>>("hmac_sha3_224");
    measure_mac<macs::hmac<digests::sha3_256>>("hmac_sha3_256");
    measure_mac<macs::hmac<digests::sha3_384>>("hmac_sha3_384");
    measure_mac<macs::hmac<digests::sha3_512>>("hmac_sha3_512");
    measure_mac<macs::hmac<digests::keccak_224>>("hmac_keccak_224");
    measure_mac<macs::hmac<digests::keccak_256>>("hmac_keccak_256");
    measure_mac<macs::hmac<digests::keccak_384>>("hmac_keccak_384");
    measure_mac<macs::hmac<digests::keccak_512>>("hmac_keccak_512");
    measure_mac<macs::hmac<digests::ripemd_160>>("hmac_ripemd_160");
    measure_mac<macs::hmac<digests::blake2b>>("hmac_blake2b");
    measure_mac<macs::hmac<digests::blake2s_256>>("hmac_blake2s_256");
    measure_mac<macs::hmac<digests::sm3>>("hmac_sm3");
    std::span<std::uint8_t const> const customisation(bytes.data(), 5);
    measure_mac<macs::kmac_128>("kmac_128", {.customisation = customisation});
    measure_mac<macs::kmac_256>("kmac_256", {.customisation = customisation, .xof = true});
    measure_mac<macs::siphash_2_4>("siphash_2_4");
    measure_mac<macs::siphash_2_4x>("siphash_2_4x");
    measure_mac<macs::blake2b_mac>("blake2b_mac");
    measure_mac<macs::blake2s_mac>("blake2s_mac");
    BOOST_TEST_EQ(calls_made - before, std::size_t{26} * 3);
}

// A key derivation of backends::openssl, twice, then refused: `derive(output)` derives into the
// span, `refuse()` calls the function with a value its guards refuse with `expected`.
template <class Derive, class Refuse>
void measure_kdf(char const* name, Derive derive, hash::error expected, Refuse refuse) {
    std::array<std::uint8_t, 48> output{};
    for (int round = 1; round != 3; ++round) {
        counted("kdf", "function", name, round,
                [&] { BOOST_TEST(derive(std::span<std::uint8_t>(output)).has_value()); });
    }
    refused_without_allocating(name, expected, refuse);
}

// One variant of argon2, two lanes with a secret and associated data, at 64 KiB.
template <class Variant>
void measure_argon2(char const* name) {
    using hash::backends::openssl;
    std::span<std::uint8_t const> const input(bytes);
    measure_kdf(
        name,
        [&](std::span<std::uint8_t> output) {
            return hash::argon2<Variant, openssl>(output, input.first(20), input.first(16),
                                                  {
                                                      .passes = 1,
                                                      .memory_kibibytes = 64,
                                                      .lanes = 2,
                                                      .secret = input.first(8),
                                                      .associated_data = input.last(12),
                                                  });
        },
        hash::error::invalid_parameters,
        [&] {
            std::array<std::uint8_t, 32> tag{};
            return hash::argon2<Variant, openssl>(tag, input, input.first(16),
                                                  {.passes = 0, .memory_kibibytes = 64});
        });
}

// argon2's three variants, argon2id, scrypt, kbkdf over SHA-256 and SHA3-256, sskdf over SHA-256
// and SHA3-256, x963kdf over SHA-256: 10 derivations, 3 calls each. The memory-hard ones at small
// costs (64 KiB, N = 1024): the count is OpenSSL's bookkeeping and their memory, a measurement.
void measure_kdfs() {
    using hash::backends::openssl;
    namespace digests = hash::digests;
    std::size_t const before = calls_made;
    std::span<std::uint8_t const> const input(bytes);
    measure_argon2<hash::kdfs::argon2d>("argon2_argon2d");
    measure_argon2<hash::kdfs::argon2i>("argon2_argon2i");
    measure_argon2<hash::kdfs::argon2id>("argon2_argon2id");
    std::array<std::uint8_t, 16> salt{};
    measure_kdf(
        "argon2id",
        [&](std::span<std::uint8_t> output) {
            return hash::argon2id<openssl>(output, input.first(20), salt,
                                           {.passes = 1, .memory = std::size_t{64} * 1024});
        },
        hash::error::invalid_salt_size,
        [&] {
            std::array<std::uint8_t, 32> tag{};
            return hash::argon2id<openssl>(tag, input, input.first(15),
                                           {.passes = 1, .memory = std::size_t{64} * 1024});
        });
    measure_kdf(
        "scrypt",
        [&](std::span<std::uint8_t> output) {
            return hash::scrypt<openssl>(output, input.first(20), salt,
                                         {.cost = 1024, .block_size = 8, .parallelism = 1});
        },
        hash::error::invalid_parameters,
        [&] {
            std::array<std::uint8_t, 32> key{};
            return hash::scrypt<openssl>(key, input, salt,
                                         {.cost = 1000, .block_size = 8, .parallelism = 1});
        });
    auto const kbkdf = [&]<class Hmac>(char const* name) {
        measure_kdf(
            name,
            [&](std::span<std::uint8_t> output) {
                return hash::kbkdf<Hmac, openssl>(
                    output, input.first(32), {.label = input.first(5), .context = input.last(7)});
            },
            hash::error::invalid_key_size,
            [&] {
                std::array<std::uint8_t, 32> key{};
                return hash::kbkdf<Hmac, openssl>(key, {});
            });
    };
    kbkdf.template operator()<hash::hmac_sha2_256>("kbkdf_hmac_sha2_256");
    kbkdf.template operator()<hash::hmac_sha3_256>("kbkdf_hmac_sha3_256");
    auto const sskdf = [&]<class Digest>(char const* name) {
        measure_kdf(
            name,
            [&](std::span<std::uint8_t> output) {
                return hash::sskdf<Digest, openssl>(output, input.first(32), input.last(10));
            },
            hash::error::invalid_key_size,
            [&] {
                std::array<std::uint8_t, 32> key{};
                return hash::sskdf<Digest, openssl>(key, {});
            });
    };
    sskdf.template operator()<digests::sha2_256>("sskdf_sha2_256");
    sskdf.template operator()<digests::sha3_256>("sskdf_sha3_256");
    measure_kdf(
        "x963kdf_sha2_256",
        [&](std::span<std::uint8_t> output) {
            return hash::x963kdf<digests::sha2_256, openssl>(output, input.first(32),
                                                             input.last(10));
        },
        hash::error::invalid_key_size,
        [&] {
            std::array<std::uint8_t, 32> key{};
            return hash::x963kdf<digests::sha2_256, openssl>(key, {});
        });
    BOOST_TEST_EQ(calls_made - before, std::size_t{10} * 3);
}

}  // namespace

int main() {
    // Before anything: OpenSSL allocates through the test's functions from here on.
    BOOST_TEST(CRYPTO_set_mem_functions(&counting_malloc, &counting_realloc, &counting_free) == 1);
    measure_one<hash::hmac_sha2_256>("hmac_sha2_256");
    measure_one<hash::hmac_sha2_512>("hmac_sha2_512");
    measure_one<hash::hmac_sha3_256>("hmac_sha3_256");
    measure_one<hash::hmac_blake2b_512>("hmac_blake2b_512");
    measure_digests();
    measure_macs();
    measure_kdfs();
    std::printf("record operation=counter backend=none target=%s c_counted=%d\n",
                webcpp::test::target_name, webcpp::test::c_allocations_counted ? 1 : 0);
    return webcpp::test::exit_status(boost::report_errors());
}
