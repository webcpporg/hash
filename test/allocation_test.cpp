// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// webcpp's code allocates nothing (spec section 7.7): the global operator new and, where the
// target lets a program count it, the C library's allocator (support/counting.hpp) are called
// zero times by every public function and every backend this program links: Keccak-256, BLAKE3,
// Boost.Hash2's digests and hmacs, HKDF and PBKDF2 on hash2, libsodium (HKDF) and BearSSL, on
// every target. A control that allocates once moves the counter, so a zero is not a broken
// counter. Argon2id and scrypt are the one exception, and it is libsodium's: they allocate their
// working memory (64 MiB and more for Argon2id, 128 r N bytes for scrypt) inside libsodium with
// its own malloc, which is the C library's, not webcpp's; the test asserts only that operator
// new is not called, and prints how many C allocations it saw where the target counts them.

#include <webcpp/hash/algorithms.hpp>
#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/pbkdf2.hpp>
#include <webcpp/hash/scrypt.hpp>

#ifdef WEBCPP_HASH_HAS_XKCP
#include <webcpp/hash/keccak.hpp>
#endif
#ifdef WEBCPP_HASH_HAS_BLAKE3
#include <webcpp/hash/blake3.hpp>
#endif
#ifdef WEBCPP_HASH_HAS_SODIUM
#include <webcpp/hash/backends/sodium.hpp>
#endif
#ifdef WEBCPP_HASH_HAS_BEARSSL
#include <webcpp/hash/backends/bearssl.hpp>
#endif

#include <boost/core/lightweight_test.hpp>

#include <webcpp/test/exit_status.hpp>

#include "support/counting.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <new>
#include <span>

namespace hash = webcpp::hash;

namespace {

std::array<std::uint8_t, 100> const message = [] {
    std::array<std::uint8_t, 100> bytes{};
    for (std::size_t i = 0; i != bytes.size(); ++i) {
        bytes[i] = static_cast<std::uint8_t>(i * 7 + 1);
    }
    return bytes;
}();

std::span<std::uint8_t const> const input(message);

/** What a window of calls allocated: operator new's and the C library's, apart. */
struct window {
    std::size_t new_before = webcpp::test::counted_new.load();
    std::size_t c_before = webcpp::test::counted_c.load();

    std::size_t news() const { return webcpp::test::counted_new.load() - new_before; }

    std::size_t cs() const { return webcpp::test::counted_c.load() - c_before; }
};

/** Whether a call allocated nothing at all; says which one when it did. */
template <class F>
void allocates_nothing(char const* name, F&& call) {
    window const w;
    call();
    if (!BOOST_TEST_EQ(w.news(), 0U) || !BOOST_TEST_EQ(w.cs(), 0U)) {
        std::printf("allocated: %s (new %zu, C %zu)\n", name, w.news(), w.cs());
    }
}

/** A digest of Boost.Hash2's, from construction to result, in three update shapes. */
template <class H>
void digest_allocates_nothing(char const* name) {
    allocates_nothing(name, [] {
        H h;
        h.update(message.data(), message.size());
        h.update(message.data(), 0);
        auto const first = h.result();
        h.update(message.data(), 3);
        auto const second = h.result();
        BOOST_TEST(first.size() == second.size());
    });
}

template <class Hmac>
void hmac_allocates_nothing(char const* name) {
    allocates_nothing(name, [] {
        Hmac h(message.data(), 16);
        h.update(message.data(), message.size());
        auto const mac = h.result();
        BOOST_TEST(mac.size() > 0);
    });
}

// `split`: the backend has HKDF's extract and expand apart (BearSSL has the whole function alone).
template <class Hmac, class Backend, bool split>
void kdfs_allocate_nothing(char const* name) {
    if constexpr (split && hash::backend_has_v<Backend, hash::kdfs::hkdf, Hmac>) {
        allocates_nothing(name, [] {
            auto const prk = hash::hkdf_extract<Hmac, Backend>(input.first(20), input);
            BOOST_TEST(prk.has_value());
            if (!prk) {
                return;
            }
            std::array<std::uint8_t, 42> okm{};
            auto const expanded = hash::hkdf_expand<Hmac, Backend>(
                okm, std::span<std::uint8_t const>(prk->data(), prk->size()), input.last(10));
            BOOST_TEST(expanded.has_value());
        });
    }
    if constexpr (hash::backend_has_v<Backend, hash::kdfs::hkdf, Hmac>) {
        allocates_nothing(name, [] {
            std::array<std::uint8_t, 42> okm{};
            auto const full =
                hash::hkdf<Hmac, Backend>(okm, input.first(20), input, input.last(10));
            auto const empty = hash::hkdf<Hmac, Backend>(okm, {}, {}, {});
            BOOST_TEST(full.has_value());
            BOOST_TEST(empty.has_value());
        });
    }
    if constexpr (hash::backend_has_v<Backend, hash::kdfs::pbkdf2, Hmac>) {
        allocates_nothing(name, [] {
            std::array<std::uint8_t, 70> key{};
            auto const done = hash::pbkdf2<Hmac, Backend>(key, input.first(20), input.last(16), 3);
            BOOST_TEST(done.has_value());
        });
    }
}

template <class Backend, bool split = true>
void all_hmacs(char const* name) {
    kdfs_allocate_nothing<hash::hmac_md5_128, Backend, split>(name);
    kdfs_allocate_nothing<hash::hmac_sha1_160, Backend, split>(name);
    kdfs_allocate_nothing<hash::hmac_sha2_224, Backend, split>(name);
    kdfs_allocate_nothing<hash::hmac_sha2_256, Backend, split>(name);
    kdfs_allocate_nothing<hash::hmac_sha2_384, Backend, split>(name);
    kdfs_allocate_nothing<hash::hmac_sha2_512, Backend, split>(name);
    kdfs_allocate_nothing<hash::hmac_sha2_512_224, Backend, split>(name);
    kdfs_allocate_nothing<hash::hmac_sha2_512_256, Backend, split>(name);
    kdfs_allocate_nothing<hash::hmac_sha3_224, Backend, split>(name);
    kdfs_allocate_nothing<hash::hmac_sha3_256, Backend, split>(name);
    kdfs_allocate_nothing<hash::hmac_sha3_384, Backend, split>(name);
    kdfs_allocate_nothing<hash::hmac_sha3_512, Backend, split>(name);
    kdfs_allocate_nothing<hash::hmac_ripemd_128, Backend, split>(name);
    kdfs_allocate_nothing<hash::hmac_ripemd_160, Backend, split>(name);
    kdfs_allocate_nothing<hash::hmac_blake2b_512, Backend, split>(name);
    kdfs_allocate_nothing<hash::hmac_blake2s_256, Backend, split>(name);
}

void control() {
    // The control: one allocation of each kind moves the counter by (at least) one, so a zero
    // below is a measurement and not a counter that does not work.
    window const w;
    void* const block = ::operator new(16);
    BOOST_TEST_GE(w.news(), 1U);
    ::operator delete(block);
    if (webcpp::test::c_allocations_counted) {
        void* const c_block = std::malloc(16);
        BOOST_TEST_GE(w.cs(), 1U);
        std::free(c_block);
    }
    std::size_t const total = webcpp::test::allocations();
    void* const again = ::operator new(16);
    BOOST_TEST_GT(webcpp::test::allocations(), total);
    ::operator delete(again);
}

void digests() {
    digest_allocates_nothing<hash::md5_128>("md5_128");
    digest_allocates_nothing<hash::sha1_160>("sha1_160");
    digest_allocates_nothing<hash::sha2_224>("sha2_224");
    digest_allocates_nothing<hash::sha2_256>("sha2_256");
    digest_allocates_nothing<hash::sha2_384>("sha2_384");
    digest_allocates_nothing<hash::sha2_512>("sha2_512");
    digest_allocates_nothing<hash::sha2_512_224>("sha2_512_224");
    digest_allocates_nothing<hash::sha2_512_256>("sha2_512_256");
    digest_allocates_nothing<hash::sha3_224>("sha3_224");
    digest_allocates_nothing<hash::sha3_256>("sha3_256");
    digest_allocates_nothing<hash::sha3_384>("sha3_384");
    digest_allocates_nothing<hash::sha3_512>("sha3_512");
    digest_allocates_nothing<hash::ripemd_128>("ripemd_128");
    digest_allocates_nothing<hash::ripemd_160>("ripemd_160");
    digest_allocates_nothing<hash::blake2b_512>("blake2b_512");
    digest_allocates_nothing<hash::blake2s_256>("blake2s_256");
    hmac_allocates_nothing<hash::hmac_md5_128>("hmac_md5_128");
    hmac_allocates_nothing<hash::hmac_sha1_160>("hmac_sha1_160");
    hmac_allocates_nothing<hash::hmac_sha2_224>("hmac_sha2_224");
    hmac_allocates_nothing<hash::hmac_sha2_256>("hmac_sha2_256");
    hmac_allocates_nothing<hash::hmac_sha2_384>("hmac_sha2_384");
    hmac_allocates_nothing<hash::hmac_sha2_512>("hmac_sha2_512");
    hmac_allocates_nothing<hash::hmac_sha2_512_224>("hmac_sha2_512_224");
    hmac_allocates_nothing<hash::hmac_sha2_512_256>("hmac_sha2_512_256");
    hmac_allocates_nothing<hash::hmac_sha3_224>("hmac_sha3_224");
    hmac_allocates_nothing<hash::hmac_sha3_256>("hmac_sha3_256");
    hmac_allocates_nothing<hash::hmac_sha3_384>("hmac_sha3_384");
    hmac_allocates_nothing<hash::hmac_sha3_512>("hmac_sha3_512");
    hmac_allocates_nothing<hash::hmac_ripemd_128>("hmac_ripemd_128");
    hmac_allocates_nothing<hash::hmac_ripemd_160>("hmac_ripemd_160");
    hmac_allocates_nothing<hash::hmac_blake2b_512>("hmac_blake2b_512");
    hmac_allocates_nothing<hash::hmac_blake2s_256>("hmac_blake2s_256");
}

#ifdef WEBCPP_HASH_HAS_XKCP
void keccak() {
    allocates_nothing("keccak_256", [] {
        hash::keccak_256 h;
        h.update(message.data(), message.size());
        auto const first = h.result();
        h.update(message.data(), 5);
        auto const second = h.result();
        hash::keccak_256 seeded(std::uint64_t{7});
        seeded.update(message.data(), message.size());
        hash::keccak_256 bytes(message.data(), message.size());
        BOOST_TEST(first.size() == second.size());
        BOOST_TEST(seeded.result().size() == bytes.result().size());
    });
}
#endif

#ifdef WEBCPP_HASH_HAS_BLAKE3
void blake3() {
    allocates_nothing("blake3", [] {
        hash::blake3 h;
        h.update(message.data(), message.size());
        auto const first = h.result();
        std::array<std::uint8_t, 200> xof{};
        h.squeeze(xof, 17);
        h.reset();
        std::array<std::uint8_t, 32> key{};
        auto keyed = hash::blake3::keyed(key);
        keyed.update(message.data(), message.size());
        auto derived = hash::blake3::derive_key("webcpp allocation test");
        derived.update(message.data(), message.size());
        hash::blake3 seeded(std::uint64_t{9});
        hash::blake3 bytes(message.data(), message.size());
        BOOST_TEST(first.size() == keyed.result().size());
        BOOST_TEST(derived.result().size() == seeded.result().size());
        BOOST_TEST(bytes.result().size() == 32);
    });
}
#endif

#if defined(WEBCPP_HASH_HAS_SODIUM)
// Argon2id and scrypt allocate inside libsodium, which is the C library's; the assertion is
// that webcpp's code (operator new) is not called, and the count is stated, never hidden.
void sodium_memory_hard() {
    namespace backends = hash::backends;
    std::array<std::uint8_t, 32> out{};
    std::array<std::uint8_t, 16> salt{};
    window const argon;
    auto const argon_done = hash::argon2id<backends::sodium>(out, input.first(20), salt, {1, 8192});
    BOOST_TEST(argon_done.has_value());
    BOOST_TEST_EQ(argon.news(), 0U);
    std::printf("argon2id (libsodium's own allocation): operator new %zu, C library %zu%s\n",
                argon.news(), argon.cs(),
                webcpp::test::c_allocations_counted ? "" : " (not counted on this target)");
    window const scr;
    auto const scrypt_done =
        hash::scrypt<backends::sodium>(out, input.first(20), salt, {1024, 8, 1});
    BOOST_TEST(scrypt_done.has_value());
    BOOST_TEST_EQ(scr.news(), 0U);
    std::printf("scrypt (libsodium's own allocation): operator new %zu, C library %zu%s\n",
                scr.news(), scr.cs(),
                webcpp::test::c_allocations_counted ? "" : " (not counted on this target)");
}
#endif

}  // namespace

int main() {
    control();
    digests();
    all_hmacs<hash::backends::hash2>("hash2");
#ifdef WEBCPP_HASH_HAS_XKCP
    keccak();
#endif
#ifdef WEBCPP_HASH_HAS_BLAKE3
    blake3();
#endif
#ifdef WEBCPP_HASH_HAS_SODIUM
    all_hmacs<hash::backends::sodium>("sodium");
    sodium_memory_hard();
#endif
#ifdef WEBCPP_HASH_HAS_BEARSSL
    all_hmacs<hash::backends::bearssl, false>("bearssl");
#endif
    std::printf("C library allocations counted on this target: %s\n",
                webcpp::test::c_allocations_counted ? "yes" : "no");
    return webcpp::test::exit_status(boost::report_errors());
}
