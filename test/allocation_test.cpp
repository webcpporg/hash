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
// counter. Every call is counted and the totals asserted exactly per backend, so a backend a
// wrong trait or a dropped define leaves out fails, and the refusals of every guard run under the
// counter too. Argon2id and scrypt are the one exception, and it is libsodium's: their working
// memory (Argon2id's matrix, 128 r N bytes of scrypt) comes from libsodium's own mmap, else
// posix_memalign, else malloc, outside webcpp's code; the test asserts only that operator new is
// not called, and prints the C allocator calls it saw (mmap is not among the calls the counter
// sees, so those are libsodium's small bookkeeping blocks, not the memory). The asynchronous
// family (async.hpp, increment 7) takes its storage from the handler's associated allocator, as
// Asio's operations do: with an arena of the test's bound to the handler, the cheap functions
// (async_digest, async_hmac, async_hkdf, and their guards' refusals) call neither operator new
// nor the C allocator, and the arena gets back every block before the handler runs; the heavy
// functions (natively, on a thread pool) take their state and completion from the arena too and
// call no operator new, the pool's queue and libsodium's memory being the C allocator's; on
// Emscripten the four functions on backends::webcrypto call the C allocator only as often as
// webcpp::asio's promise bridge does for a bare await, once per promise. Every printed result is
// one `record key=value ...` line, collected by bench/allocation_collect.py.

#include <webcpp/hash/algorithms.hpp>
#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/async.hpp>
#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/error.hpp>
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

#include <webcpp/asio/bind_allocator.hpp>
#ifdef WEBCPP_TARGET_EMSCRIPTEN
#include <webcpp/asio/browser/async_await.hpp>
#endif
#include <webcpp/asio/bind_executor.hpp>
#include <webcpp/asio/io_context.hpp>
#ifdef WEBCPP_HASH_HAS_THREADS
#include <webcpp/asio/thread_pool.hpp>
#endif

#include <boost/core/lightweight_test.hpp>
#include <boost/system/error_code.hpp>

#include <webcpp/test/exit_status.hpp>

#include "support/counting.hpp"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <new>
#include <span>
#include <string_view>

namespace hash = webcpp::hash;

namespace {

constexpr std::array<std::uint8_t, 100> message = [] {
    std::array<std::uint8_t, 100> bytes{};
    for (std::size_t i = 0; i != bytes.size(); ++i) {
        bytes[i] = static_cast<std::uint8_t>((i * 7) + 1);
    }
    return bytes;
}();

std::span<std::uint8_t const> const input(message);

/** What a window of calls allocated: operator new's and the C library's, apart. */
struct window {
    std::size_t new_before = webcpp::test::counted_new.load();
    std::size_t c_before = webcpp::test::counted_c.load();

    [[nodiscard]] std::size_t news() const { return webcpp::test::counted_new.load() - new_before; }

    [[nodiscard]] std::size_t cs() const { return webcpp::test::counted_c.load() - c_before; }
};

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): calls under the counter
std::size_t calls_made = 0;

/** Whether a call allocated nothing at all; says which one when it did. */
template <class F>
void allocates_nothing(char const* name, F&& call) {
    ++calls_made;
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

// HKDF's two steps alone: the pair (1), and two refusals of Expand (2).
template <class Hmac, class Backend>
void hkdf_steps_allocate_nothing(char const* name, std::span<std::uint8_t> okm,
                                 std::span<std::uint8_t const> long_info) {
    allocates_nothing(name, [&] {
        auto const prk = hash::hkdf_extract<Hmac, Backend>(input.first(20), input);
        BOOST_TEST(prk.has_value());
        if (!prk) {
            return;
        }
        auto const expanded = hash::hkdf_expand<Hmac, Backend>(
            okm, std::span<std::uint8_t const>(prk->data(), prk->size()), input.last(10));
        BOOST_TEST(expanded.has_value());
    });
    allocates_nothing(name, [&] {
        auto const refused = hash::hkdf_expand<Hmac, Backend>(okm, input.first(3), {});
        BOOST_TEST(!refused.has_value());
    });
    allocates_nothing(name, [&] {
        auto const refused = hash::hkdf_expand<Hmac, Backend>(okm, input.first(3), long_info);
        BOOST_TEST(!refused.has_value());
    });
}

// HKDF whole: a derivation (1) and two refusals (2), then the steps when the backend has them.
// `split`: the backend has HKDF's extract and expand apart (BearSSL has the whole function alone).
template <class Hmac, class Backend, bool split>
void hkdf_allocates_nothing(char const* name) {
    std::array<std::uint8_t, 42> okm{};
    std::span<std::uint8_t> const no_output;
    // One byte over the limit, in a real buffer: the guard refuses on the size alone.
    static std::array<std::uint8_t, hash::hkdf_max_info_size + 1> const long_buffer{};
    std::span<std::uint8_t const> const long_info(long_buffer);
    allocates_nothing(name, [&] {
        auto const full = hash::hkdf<Hmac, Backend>(okm, input.first(20), input, input.last(10));
        auto const empty = hash::hkdf<Hmac, Backend>(okm, {}, {}, {});
        BOOST_TEST(full.has_value());
        BOOST_TEST(empty.has_value());
    });
    allocates_nothing(name, [&] {
        auto const refused = hash::hkdf<Hmac, Backend>(no_output, input, input, input);
        BOOST_TEST(!refused.has_value());
    });
    allocates_nothing(name, [&] {
        auto const refused = hash::hkdf<Hmac, Backend>(okm, input, input, long_info);
        BOOST_TEST(!refused.has_value());
    });
    if constexpr (split) {
        hkdf_steps_allocate_nothing<Hmac, Backend>(name, okm, long_info);
    }
}

// PBKDF2: a derivation (1) and a refusal (1).
template <class Hmac, class Backend>
void pbkdf2_allocates_nothing(char const* name) {
    allocates_nothing(name, [] {
        std::array<std::uint8_t, 70> key{};
        auto const done = hash::pbkdf2<Hmac, Backend>(key, input.first(20), input.last(16), 3);
        BOOST_TEST(done.has_value());
    });
    allocates_nothing(name, [] {
        std::array<std::uint8_t, 70> key{};
        auto const refused = hash::pbkdf2<Hmac, Backend>(key, input, input, 0);
        BOOST_TEST(!refused.has_value());
    });
}

// Per hmac the calls counted are, split: the pair (1), the whole function (1), four refusals (4);
// not split: the whole function (1), two refusals (2); PBKDF2: a derivation (1), a refusal (1).
// Expected totals: hash2 16 hmacs x (6 + 2) = 128; sodium 2 hmacs x 6 = 12; bearssl 6 hmacs x 3
// = 18.
template <class Hmac, class Backend, bool split>
void kdfs_allocate_nothing(char const* name) {
    if constexpr (hash::backend_has_v<Backend, hash::kdfs::hkdf, Hmac>) {
        hkdf_allocates_nothing<Hmac, Backend, split>(name);
    }
    if constexpr (hash::backend_has_v<Backend, hash::kdfs::pbkdf2, Hmac>) {
        pbkdf2_allocates_nothing<Hmac, Backend>(name);
    }
}

template <class Backend, bool split = true>
void all_hmacs(char const* name, std::size_t expected_calls) {
    std::size_t const before = calls_made;
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
    // A backend that fell out (a wrong trait, a dropped define) makes fewer calls than it should.
    BOOST_TEST_EQ(calls_made - before, expected_calls);
    std::printf("record operation=kdf-calls backend=%s target=%s calls=%zu expected=%zu\n", name,
                webcpp::test::target_name, calls_made - before, expected_calls);
}

void control() {
    // The control: one allocation of every form the counter claims moves it, so a zero below is
    // a measurement and not a counter that does not work.
    namespace test = webcpp::test;
    auto const moves_new = [](char const* form, auto&& allocate) {
        window const w;
        allocate();
        if (!BOOST_TEST_GE(w.news(), 1U)) {
            std::printf("operator new form not counted: %s\n", form);
        }
    };
    moves_new("new", [] { ::operator delete(::operator new(16)); });
    moves_new("new[]", [] { ::operator delete[](::operator new[](16)); });
    moves_new("new aligned", [] {
        ::operator delete(::operator new(16, std::align_val_t{64}), std::align_val_t{64});
    });
    moves_new("new[] aligned", [] {
        ::operator delete[](::operator new[](16, std::align_val_t{64}), std::align_val_t{64});
    });
    moves_new("new nothrow", [] { ::operator delete(::operator new(16, std::nothrow)); });
    moves_new("new[] nothrow", [] { ::operator delete[](::operator new[](16, std::nothrow)); });
    moves_new("new aligned nothrow", [] {
        ::operator delete(::operator new(16, std::align_val_t{64}, std::nothrow),
                          std::align_val_t{64});
    });
    moves_new("new[] aligned nothrow", [] {
        ::operator delete[](::operator new[](16, std::align_val_t{64}, std::nothrow),
                            std::align_val_t{64});
    });
    if (test::c_allocations_counted) {
        // Through volatile pointers so that the calls stay calls.
        void* (*volatile const do_malloc)(std::size_t) = &std::malloc;
        void* (*volatile const do_calloc)(std::size_t, std::size_t) = &std::calloc;
        void* (*volatile const do_realloc)(void*, std::size_t) = &std::realloc;
#ifndef _WIN32
        void* (*volatile const do_aligned)(std::size_t, std::size_t) = &std::aligned_alloc;
#endif
        auto const window_c = [](auto&& allocate, char const* form) {
            window const w;
            void* const block = allocate();
            if (!BOOST_TEST_GE(w.cs(), 1U)) {
                std::printf("C allocator form not counted: %s\n", form);
            }
            std::free(block);
        };
        window_c([&] { return do_malloc(16); }, "malloc");
        window_c([&] { return do_calloc(1, 16); }, "calloc");
        window_c([&] { return do_realloc(nullptr, 16); }, "realloc");
#ifndef _WIN32
        window_c([&] { return do_aligned(64, 64); }, "aligned_alloc");
        void* (*volatile const do_posix)(std::size_t) = [](std::size_t size) {
            void* block = nullptr;
            return posix_memalign(&block, 64, size) == 0 ? block : nullptr;
        };
        window_c([&] { return do_posix(64); }, "posix_memalign");
#endif
    }
    std::size_t const total = test::allocations();
    void* const again = ::operator new(16);
    BOOST_TEST_GT(test::allocations(), total);
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
    std::size_t const before = calls_made;
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
    BOOST_TEST_EQ(calls_made - before, 1U);
}
#endif

#ifdef WEBCPP_HASH_HAS_BLAKE3
void blake3() {
    std::size_t const before = calls_made;
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
    BOOST_TEST_EQ(calls_made - before, 1U);
}
#endif

#ifdef WEBCPP_HASH_HAS_SODIUM
// libsodium's first call of the program runs sodium_init, which allocates on some targets (one C
// allocator call measured on WASI): outside webcpp's code, measured here and kept out of the
// zero windows of every other call.
void sodium_first_call() {
    std::array<std::uint8_t, 32> okm{};
    window const w;
    auto const done = hash::hkdf<hash::hmac_sha2_256, hash::backends::sodium>(okm, {}, input, {});
    BOOST_TEST(done.has_value());
    BOOST_TEST_EQ(w.news(), 0U);
    std::printf("record operation=sodium_init backend=sodium target=%s new=%zu c=%zu counted=%d\n",
                webcpp::test::target_name, w.news(), w.cs(),
                webcpp::test::c_allocations_counted ? 1 : 0);
}

// Argon2id and scrypt allocate inside libsodium (mmap, posix_memalign or malloc), outside webcpp;
// the assertion is that webcpp's code (operator new) is not called, and the count is stated, never
// hidden.
void sodium_memory_hard() {
    namespace backends = hash::backends;
    std::array<std::uint8_t, 32> out{};
    std::array<std::uint8_t, 16> salt{};
    window const argon;
    auto const argon_done =
        hash::argon2id<backends::sodium>(out, input.first(20), salt, {.passes = 1, .memory = 8192});
    BOOST_TEST(argon_done.has_value());
    BOOST_TEST_EQ(argon.news(), 0U);
    std::printf("record operation=argon2id backend=sodium target=%s new=%zu c=%zu counted=%d\n",
                webcpp::test::target_name, argon.news(), argon.cs(),
                webcpp::test::c_allocations_counted ? 1 : 0);
    window const scr;
    auto const scrypt_done =
        hash::scrypt<backends::sodium>(out, input.first(20), salt, {.n = 1024, .r = 8, .p = 1});
    BOOST_TEST(scrypt_done.has_value());
    BOOST_TEST_EQ(scr.news(), 0U);
    std::printf("record operation=scrypt backend=sodium target=%s new=%zu c=%zu counted=%d\n",
                webcpp::test::target_name, scr.news(), scr.cs(),
                webcpp::test::c_allocations_counted ? 1 : 0);
}
#endif

// The handler's allocator of the asynchronous family's windows: an arena of the test's, so that
// the operation's storage moves neither counter. `taken` counts the blocks given, `live` those not
// yet given back; the arena starts over when every block is back.
struct arena {
    alignas(std::max_align_t) std::array<std::byte, 16384> bytes{};
    std::size_t top = 0;
    std::atomic<int> live{0};
    std::atomic<int> taken{0};
};

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the handlers' storage
arena handler_arena;

template <class T>
struct arena_allocator {
    using value_type = T;

    arena_allocator() noexcept = default;

    // Allocator rebind conversions must be implicit (Allocator requirements).
    template <class U>
    // NOLINTNEXTLINE(misc-explicit-constructor)
    arena_allocator(arena_allocator<U> const& /*other*/) noexcept {}

    T* allocate(std::size_t count) {
        constexpr std::size_t align = alignof(std::max_align_t);
        std::size_t const size = ((count * sizeof(T)) + align - 1) / align * align;
        if (handler_arena.top + size > handler_arena.bytes.size()) {
            std::abort();
        }
        void* const block = &handler_arena.bytes[handler_arena.top];
        handler_arena.top += size;
        ++handler_arena.live;
        ++handler_arena.taken;
        return static_cast<T*>(block);
    }

    void deallocate(T* /*pointer*/, std::size_t /*count*/) noexcept {
        if (--handler_arena.live == 0) {
            handler_arena.top = 0;
        }
    }

    template <class U>
    bool operator==(arena_allocator<U> const& /*other*/) const noexcept {
        return true;
    }
};

// One asynchronous call in a window: `start(handler)` initiates it with a handler bound to the
// arena, then the context runs until the handler has been called once with `expected`, with every
// block of the arena given back. operator new is not called, the C allocator `others_c` times
// (another library's: webcpp::asio's promise bridge), and the arena gave at least one block.
template <class Start>
void async_allocates_nothing(char const* name, webcpp::asio::io_context& context,
                             boost::system::error_code expected, Start start,
                             std::size_t others_c = 0) {
    ++calls_made;
    int const taken_before = handler_arena.taken.load();
    int calls = 0;
    int live_at_call = -1;
    boost::system::error_code code;
    window const w;
    start(
        webcpp::asio::bind_allocator(arena_allocator<char>(), [&](boost::system::error_code done) {
            ++calls;
            live_at_call = handler_arena.live.load();
            code = done;
        }));
    context.restart();
    context.run();  // lint-run: the call's completion, under the counter
    std::size_t const news = w.news();
    std::size_t const cs = w.cs();
    BOOST_TEST_EQ(calls, 1);
    BOOST_TEST(code == expected);
    BOOST_TEST_EQ(live_at_call, 0);
    BOOST_TEST_GE(handler_arena.taken.load() - taken_before, 1);
    if (!BOOST_TEST_EQ(news, 0U) || !BOOST_TEST_EQ(cs, others_c)) {
        std::printf("allocated: %s (new %zu, C %zu)\n", name, news, cs);
    }
}

// The cheap functions on their default backend, a result and a refusal each (an output of 0
// bytes): 6 calls. One call before the windows lets the io_context make what it makes once.
void async_cheap() {
    namespace asio = webcpp::asio;
    std::size_t const before = calls_made;
    asio::io_context context;
    auto const executor = context.get_executor();
    std::array<std::uint8_t, 32> out{};
    std::span<std::uint8_t> const none{};
    hash::async_digest<hash::digests::sha2_256>(executor, out, input,
                                                [](boost::system::error_code) {});
    context.run();  // lint-run: the context's first run, outside the windows
    boost::system::error_code const fine;
    boost::system::error_code const refused = hash::error::invalid_output_size;
    async_allocates_nothing("async_digest", context, fine, [&](auto handler) {
        hash::async_digest<hash::digests::sha2_256>(executor, out, input, std::move(handler));
    });
    async_allocates_nothing("async_digest refused", context, refused, [&](auto handler) {
        hash::async_digest<hash::digests::sha2_256>(executor, none, input, std::move(handler));
    });
    async_allocates_nothing("async_hmac", context, fine, [&](auto handler) {
        hash::async_hmac<hash::hmac_sha2_256>(executor, out, input.first(16), input,
                                              std::move(handler));
    });
    async_allocates_nothing("async_hmac refused", context, refused, [&](auto handler) {
        hash::async_hmac<hash::hmac_sha2_256>(executor, none, input.first(16), input,
                                              std::move(handler));
    });
    async_allocates_nothing("async_hkdf", context, fine, [&](auto handler) {
        hash::async_hkdf<hash::hmac_sha2_256>(executor, out, {}, input, {}, std::move(handler));
    });
    async_allocates_nothing("async_hkdf refused", context, refused, [&](auto handler) {
        hash::async_hkdf<hash::hmac_sha2_256>(executor, none, {}, input, {}, std::move(handler));
    });
    BOOST_TEST_EQ(calls_made - before, 6U);
}

#ifdef WEBCPP_TARGET_EMSCRIPTEN
// The four functions on backends::webcrypto (Emscripten): the bridge's waits, the operation and
// its posts are the handler's arena's, every block given back before the handler runs, and
// operator new is not called; a refusal (an output of 0 bytes) each too: 8 calls. webcpp::asio's
// promise bridge calls the C allocator itself, for each promise awaited, whoever awaits it: a
// bare async_await, measured first, gives its count, and each call is held to that count per
// promise (one for a digest, two for importKey and then sign or deriveBits), so that webcpp::hash's
// code adds none. One call before the windows lets the bridge and the io_context make what they
// make once.
void async_webcrypto() {
    namespace asio = webcpp::asio;
    using hash::backends::webcrypto;
    std::size_t const before = calls_made;
    asio::io_context context;
    auto const executor = context.get_executor();
    std::array<std::uint8_t, 32> out{};
    std::span<std::uint8_t> const none{};
    hash::async_digest<hash::digests::sha2_256, webcrypto>(executor, out, input,
                                                           [](boost::system::error_code) {});
    hash::async_pbkdf2<hash::hmac_sha2_256, webcrypto>(
        executor, out, input.first(20), input.first(16), 2, [](boost::system::error_code) {});
    context.run();  // lint-run: the context's first run, outside the windows
    window const bare;
    asio::browser::async_await(
        executor, emscripten::val::global("Promise").call<emscripten::val>("resolve", 1),
        asio::bind_allocator(arena_allocator<char>(),
                             [](boost::system::error_code, emscripten::val const&) {}));
    context.restart();
    context.run();  // lint-run: the bare await's completion, under the counter
    BOOST_TEST_EQ(bare.news(), 0U);
    std::size_t const per_promise = bare.cs();
    std::printf("record operation=async_await backend=webcpp_asio target=%s new=%zu c=%zu\n",
                webcpp::test::target_name, bare.news(), per_promise);
    boost::system::error_code const fine;
    boost::system::error_code const refused = hash::error::invalid_output_size;
    async_allocates_nothing(
        "async_digest webcrypto", context, fine,
        [&](auto handler) {
            hash::async_digest<hash::digests::sha2_256, webcrypto>(executor, out, input,
                                                                   std::move(handler));
        },
        per_promise);
    async_allocates_nothing("async_digest webcrypto refused", context, refused, [&](auto handler) {
        hash::async_digest<hash::digests::sha2_256, webcrypto>(executor, none, input,
                                                               std::move(handler));
    });
    async_allocates_nothing(
        "async_hmac webcrypto", context, fine,
        [&](auto handler) {
            hash::async_hmac<hash::hmac_sha2_256, webcrypto>(executor, out, input.first(16), input,
                                                             std::move(handler));
        },
        2 * per_promise);
    async_allocates_nothing("async_hmac webcrypto refused", context, refused, [&](auto handler) {
        hash::async_hmac<hash::hmac_sha2_256, webcrypto>(executor, none, input.first(16), input,
                                                         std::move(handler));
    });
    async_allocates_nothing(
        "async_hkdf webcrypto", context, fine,
        [&](auto handler) {
            hash::async_hkdf<hash::hmac_sha2_256, webcrypto>(executor, out, {}, input, {},
                                                             std::move(handler));
        },
        2 * per_promise);
    async_allocates_nothing("async_hkdf webcrypto refused", context, refused, [&](auto handler) {
        hash::async_hkdf<hash::hmac_sha2_256, webcrypto>(executor, none, {}, input, {},
                                                         std::move(handler));
    });
    async_allocates_nothing(
        "async_pbkdf2 webcrypto", context, fine,
        [&](auto handler) {
            hash::async_pbkdf2<hash::hmac_sha2_256, webcrypto>(
                executor, out, input.first(20), input.first(16), 2, std::move(handler));
        },
        2 * per_promise);
    async_allocates_nothing("async_pbkdf2 webcrypto refused", context, refused, [&](auto handler) {
        hash::async_pbkdf2<hash::hmac_sha2_256, webcrypto>(executor, none, input.first(20),
                                                           input.first(16), 2, std::move(handler));
    });
    BOOST_TEST_EQ(calls_made - before, 8U);
}
#endif

#ifdef WEBCPP_HASH_HAS_THREADS
// One heavy call in a window: `start(handler)` initiates it, its work on `pool` and its
// completion on `context`, the handler bound to the arena; the context runs until the handler has
// been called once, successfully, with every block of the arena given back. The operation's state
// and its completion are the arena's (two blocks at least), and operator new is not called;
// libsodium's own memory (Argon2id's matrix, scrypt's) is the C allocator's, as for the synchronous
// calls, so the C allocator's calls are printed, not asserted. One call before the window lets the
// pool and the context make what they make once.
template <class Start>
void heavy_allocates_nothing(char const* name, webcpp::asio::io_context& context, Start start) {
    namespace asio = webcpp::asio;
    ++calls_made;
    start(asio::bind_executor(context.get_executor(), [](boost::system::error_code) {}));
    context.restart();
    context.run();  // lint-run: the first call's completion, outside the window
    int const taken_before = handler_arena.taken.load();
    int calls = 0;
    int live_at_call = -1;
    window const w;
    start(asio::bind_executor(
        context.get_executor(),
        asio::bind_allocator(arena_allocator<char>(), [&](boost::system::error_code done) {
            ++calls;
            live_at_call = handler_arena.live.load();
            BOOST_TEST(!done);
        })));
    context.restart();
    context.run();  // lint-run: the call's completion, under the counter
    std::size_t const news = w.news();
    std::size_t const cs = w.cs();
    BOOST_TEST_EQ(calls, 1);
    BOOST_TEST_EQ(live_at_call, 0);
    BOOST_TEST_GE(handler_arena.taken.load() - taken_before, 2);
    if (!BOOST_TEST_EQ(news, 0U)) {
        std::printf("allocated: %s (new %zu)\n", name, news);
    }
    std::printf("record operation=%s backend=%s target=%s new=%zu c=%zu\n", name,
                std::string_view(name) == "async_pbkdf2" ? "hash2" : "sodium",
                webcpp::test::target_name, news, cs);
}

// The heavy functions (natively, where the build has threads), each on its default backend but
// async_pbkdf2, on backends::hash2 named: 4 calls, 3 until the family's Argon2id lands.
void async_heavy() {
    namespace asio = webcpp::asio;
    std::size_t const before = calls_made;
    asio::io_context context;
    asio::thread_pool pool(1);
    auto const work = pool.get_executor();
    std::array<std::uint8_t, 32> out{};
    std::array<std::uint8_t, hash::argon2id_salt_size> const salt{};
    auto const password = input.first(20);
    heavy_allocates_nothing("async_pbkdf2", context, [&](auto handler) {
        hash::async_pbkdf2<hash::hmac_sha2_256, hash::backends::hash2>(
            work, out, password, input.first(16), 2, std::move(handler));
    });
    heavy_allocates_nothing("async_argon2id", context, [&](auto handler) {
        hash::async_argon2id(work, out, password, salt, {.passes = 1, .memory = 8192},
                             std::move(handler));
    });
    // The family's Argon2id on its default, backends::sodium, once that engine has landed (stream
    // sodium-2): until then the call refuses at compile time.
    constexpr bool family_on_sodium =
        hash::backend_has_v<hash::backends::sodium, hash::kdfs::argon2id, hash::argon2_parameters>;
    if constexpr (family_on_sodium) {
        heavy_allocates_nothing("async_argon2", context, [&](auto handler) {
            hash::async_argon2<hash::kdfs::argon2id>(
                work, out, password, salt, {.passes = 1, .memory_kib = 8}, std::move(handler));
        });
    }
    heavy_allocates_nothing("async_scrypt", context, [&](auto handler) {
        hash::async_scrypt(work, out, password, salt, {.n = 1024, .r = 8, .p = 1},
                           std::move(handler));
    });
    pool.join();
    BOOST_TEST_EQ(calls_made - before, family_on_sodium ? 4U : 3U);
}
#endif

}  // namespace

int main() {
    control();
    digests();
    all_hmacs<hash::backends::hash2>("hash2", 128);
    async_cheap();
#ifdef WEBCPP_HASH_HAS_THREADS
    async_heavy();
#endif
#ifdef WEBCPP_TARGET_EMSCRIPTEN
    async_webcrypto();
#endif
#ifdef WEBCPP_HASH_HAS_XKCP
    keccak();
#endif
#ifdef WEBCPP_HASH_HAS_BLAKE3
    blake3();
#endif
#ifdef WEBCPP_HASH_HAS_SODIUM
    sodium_first_call();
    all_hmacs<hash::backends::sodium>("sodium", 12);
    sodium_memory_hard();
#endif
#ifdef WEBCPP_HASH_HAS_BEARSSL
    all_hmacs<hash::backends::bearssl, false>("bearssl", 18);
#endif
    std::printf("record operation=counter backend=none target=%s c_counted=%d\n",
                webcpp::test::target_name, webcpp::test::c_allocations_counted ? 1 : 0);
    return webcpp::test::exit_status(boost::report_errors());
}
