// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// backends::webcrypto, the browser's WebCrypto (node's crypto.subtle here), through the
// asynchronous family (spec 11, Emscripten only). The published cases through each function, each
// with a callback, use_awaitable and use_future: SHA-256 of "abc", RFC 4231's case 1, RFC 5869's
// A.1, RFC 6070's case 1 and RFC 7914 section 11's first case. Then 100 random cases per function
// against backends::hash2, over SHA-1, SHA-256, SHA-384 and SHA-512 in turn, the empty inputs among
// them (an empty HMAC key is passed to WebCrypto as one zero byte, the same key by RFC 2104's
// padding: ruling R74). The guards complete through the event loop, never inside the call, the
// output untouched; WebCrypto's own limits (ruling R74) and an executor whose context is not an
// io_context (ruling R73) refuse likewise. A cancellation completes at once with
// operation_aborted, the output zeroed; and the handler's associated allocator gets back every
// block it gave before the handler runs. Without exceptions an error is read by a callback and
// use_awaitable through as_tuple (ruling R71).

#include <webcpp/hash/async.hpp>
#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/backends/webcrypto.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/hash/pbkdf2.hpp>

#include <webcpp/asio/any_io_executor.hpp>
#include <webcpp/asio/as_tuple.hpp>
#include <webcpp/asio/bind_allocator.hpp>
#include <webcpp/asio/bind_cancellation_slot.hpp>
#include <webcpp/asio/bind_executor.hpp>
#include <webcpp/asio/cancellation_signal.hpp>
#include <webcpp/asio/cancellation_type.hpp>
#include <webcpp/asio/co_spawn.hpp>
#include <webcpp/asio/error.hpp>
#include <webcpp/asio/io_context.hpp>
#include <webcpp/asio/steady_timer.hpp>
#include <webcpp/asio/thread_pool.hpp>
#include <webcpp/asio/use_awaitable.hpp>
#include <webcpp/asio/use_future.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/system/error_code.hpp>

#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/random_cases.hpp"
#include "support/rfc5869.hpp"
#include "support/rfc6070.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <iostream>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace asio = webcpp::asio;
namespace hash = webcpp::hash;
using webcpp::hash::backends::webcrypto;
using webcpp::test::from_hex;
using webcpp::test::to_hex;

namespace {

// The random cases per function.
constexpr std::size_t random_cases = 100;

std::span<std::uint8_t const> bytes_of(std::string_view text) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): the text's bytes, as Hash2 reads
    return {reinterpret_cast<std::uint8_t const*>(text.data()), text.size()};
}

// What a callback saw: whether it ran, whether the initiating call had returned when it did, and
// the error code.
struct completion {
    bool called = false;
    bool after_return = false;
    boost::system::error_code code;
};

// Runs `start(token)` with a callback, checks that it completes once, from the event loop, after
// the call has returned, and returns its error code.
template <class Start>
boost::system::error_code complete_by_callback(asio::io_context& context, Start start) {
    completion seen;
    bool returned = false;
    start([&seen, &returned](boost::system::error_code code) {
        seen.called = true;
        seen.after_return = returned;
        seen.code = code;
    });
    returned = true;
    BOOST_TEST(!seen.called);
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST(seen.called);
    BOOST_TEST(seen.after_return);
    return seen.code;
}

// use_future on a success: ready once the context has run (single-threaded, before get()).
template <class Start>
void complete_by_future(asio::io_context& context, Start start) {
    auto done = start(asio::use_future);
    context.restart();
    context.run();  // lint-run: the test's event loop
    done.get();
}

// use_awaitable on a success, in a coroutine of the context; without exceptions through as_tuple.
template <class Start>
void complete_by_awaitable(asio::io_context& context, Start start) {
    bool done = false;
    asio::co_spawn(
        context,
        [&]() -> asio::awaitable<void> {
#ifdef WEBCPP_HASH_NO_EXCEPTIONS
            auto [code] = co_await start(asio::as_tuple(asio::use_awaitable));
            BOOST_TEST(!code);
#else
            co_await start(asio::use_awaitable);
#endif
            done = true;
        },
        [](std::exception_ptr const& failure) { BOOST_TEST(!failure); });
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST(done);
}

// A published case through `start(output, token)`, an output of `expected`'s size, with each of
// the three completion tokens; `name` is printed with a failure.
template <class Start>
void check_published(asio::io_context& context, std::string_view name, std::string_view expected,
                     Start start) {
    std::vector<std::uint8_t> output(expected.size() / 2);
    auto const code = complete_by_callback(
        context, [&](auto token) { start(std::span(output), std::move(token)); });
    BOOST_TEST(!code);
    if (!BOOST_TEST_EQ(to_hex(output), std::string(expected))) {
        std::cerr << "  " << name << " by a callback\n";
    }

    std::vector<std::uint8_t> awaited(output.size());
    complete_by_awaitable(context, [&](auto token) { return start(std::span(awaited), token); });
    if (!BOOST_TEST_EQ(to_hex(awaited), std::string(expected))) {
        std::cerr << "  " << name << " by use_awaitable\n";
    }

    std::vector<std::uint8_t> future(output.size());
    complete_by_future(context, [&](auto token) { return start(std::span(future), token); });
    if (!BOOST_TEST_EQ(to_hex(future), std::string(expected))) {
        std::cerr << "  " << name << " by use_future\n";
    }
}

void check_published_cases(asio::io_context& context) {
    auto const executor = context.get_executor();

    auto const abc = bytes_of("abc");
    check_published(context, "SHA-256 of abc",
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                    [&](std::span<std::uint8_t> output, auto token) {
                        return hash::async_digest<hash::digests::sha2_256, webcrypto>(
                            executor, output, abc, std::move(token));
                    });

    // RFC 4231, section 4.2: test case 1, HMAC-SHA-256.
    std::vector<std::uint8_t> const key(20, 0x0b);
    auto const hi_there = bytes_of("Hi There");
    check_published(context, "RFC 4231 case 1",
                    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
                    [&](std::span<std::uint8_t> output, auto token) {
                        return hash::async_hmac<hash::hmac_sha2_256, webcrypto>(
                            executor, output, key, hi_there, std::move(token));
                    });

    auto const& a1 = webcpp::test::a1;
    auto const ikm = from_hex(a1.ikm);
    auto const salt = from_hex(a1.salt);
    auto const info = from_hex(a1.info);
    check_published(context, "RFC 5869 A.1", a1.okm,
                    [&](std::span<std::uint8_t> output, auto token) {
                        return hash::async_hkdf<hash::hmac_sha2_256, webcrypto>(
                            executor, output, salt, ikm, info, std::move(token));
                    });

    auto const& rfc6070 = webcpp::test::rfc6070_1;
    check_published(context, "RFC 6070 case 1", rfc6070.derived_key,
                    [&](std::span<std::uint8_t> output, auto token) {
                        return hash::async_pbkdf2<hash::hmac_sha1_160, webcrypto>(
                            executor, output, bytes_of(rfc6070.password), bytes_of(rfc6070.salt),
                            rfc6070.iterations, std::move(token));
                    });

    auto const& rfc7914 = webcpp::test::rfc7914_1;
    check_published(context, "RFC 7914 section 11, case 1", rfc7914.derived_key,
                    [&](std::span<std::uint8_t> output, auto token) {
                        return hash::async_pbkdf2<hash::hmac_sha2_256, webcrypto>(
                            executor, output, bytes_of(rfc7914.password), bytes_of(rfc7914.salt),
                            rfc7914.iterations, std::move(token));
                    });
}

// The four hashes WebCrypto has, as a digest tag and as a Boost.Hash2 hmac, with their size.
template <class Digest, class Hmac, std::size_t Size>
struct webcrypto_hash {
    using digest = Digest;
    using hmac = Hmac;
    static constexpr std::size_t size = Size;
};

using sha1 = webcrypto_hash<hash::digests::sha1, hash::hmac_sha1_160, 20>;
using sha256 = webcrypto_hash<hash::digests::sha2_256, hash::hmac_sha2_256, 32>;
using sha384 = webcrypto_hash<hash::digests::sha2_384, hash::hmac_sha2_384, 48>;
using sha512 = webcrypto_hash<hash::digests::sha2_512, hash::hmac_sha2_512, 64>;

// Runs `on<Hash>(index)` for case `index` over the hash of that index, in turn.
template <class On>
void for_each_case(On on) {
    for (std::size_t index = 0; index < random_cases; ++index) {
        switch (index % 4) {
            case 0: on.template operator()<sha1>(index); break;
            case 1: on.template operator()<sha256>(index); break;
            case 2: on.template operator()<sha384>(index); break;
            default: on.template operator()<sha512>(index); break;
        }
    }
}

// The comparison of a random case: WebCrypto's completion and output against hash2's result.
void compare(std::string_view function, std::size_t index, boost::system::error_code code,
             std::span<std::uint8_t const> webcrypto_output,
             std::span<std::uint8_t const> hash2_output) {
    bool const same =
        BOOST_TEST(!code) && BOOST_TEST_EQ(to_hex(webcrypto_output), to_hex(hash2_output));
    if (!same) {
        std::cerr << "  " << function << ", random case " << index << " (seed "
                  << webcpp::test::agreement_seed << "): " << code.message() << '\n';
    }
}

// The size of an input of random case `index`: none for the first four cases, `fixed` for the
// next four, else drawn in [least, most].
std::size_t case_size(webcpp::test::random_source& rnd, std::size_t index, std::size_t fixed,
                      std::size_t least, std::size_t most) {
    if (index < 4) {
        return 0;
    }
    if (index < 8) {
        return fixed;
    }
    return rnd.between(least, most);
}

void check_random_digests(asio::io_context& context) {
    webcpp::test::random_source rnd(webcpp::test::agreement_seed);
    auto const executor = context.get_executor();
    for_each_case([&]<class Hash>(std::size_t index) {
        auto const input = rnd.bytes(index < 4 ? 0 : rnd.between(1, 300));
        std::vector<std::uint8_t> expected(Hash::size);
        BOOST_TEST((hash::digest_of<typename Hash::digest, hash::backends::hash2>(expected, input)
                        .has_value()));
        std::vector<std::uint8_t> output(Hash::size);
        auto const code = complete_by_callback(context, [&](auto token) {
            hash::async_digest<typename Hash::digest, webcrypto>(executor, output, input,
                                                                 std::move(token));
        });
        compare("async_digest", index, code, output, expected);
    });
}

void check_random_hmacs(asio::io_context& context) {
    webcpp::test::random_source rnd(webcpp::test::agreement_seed + 1);
    auto const executor = context.get_executor();
    for_each_case([&]<class Hash>(std::size_t index) {
        // The first four keys are empty, then one longer than every block (SHA-384's and
        // SHA-512's are 128 bytes), then random; every fifth tag is cut to a random size.
        auto const key = rnd.bytes(case_size(rnd, index, 200, 1, 150));
        auto const input = rnd.bytes(rnd.between(0, 300));
        std::size_t const size = index % 5 == 4 ? rnd.between(10, Hash::size) : Hash::size;
        std::vector<std::uint8_t> expected(size);
        BOOST_TEST((hash::mac<hash::macs::hmac<typename Hash::digest>, hash::backends::hash2>(
                        expected, key, input)
                        .has_value()));
        std::vector<std::uint8_t> output(size);
        auto const code = complete_by_callback(context, [&](auto token) {
            hash::async_hmac<typename Hash::hmac, webcrypto>(executor, output, key, input,
                                                             std::move(token));
        });
        compare("async_hmac", index, code, output, expected);
    });
}

void check_random_hkdfs(asio::io_context& context) {
    webcpp::test::random_source rnd(webcpp::test::agreement_seed + 2);
    auto const executor = context.get_executor();
    for_each_case([&]<class Hash>(std::size_t index) {
        // The first four with every input empty, the next four with the longest info WebCrypto
        // takes (1,024 bytes) and the longest output (255 digests).
        bool const empty = index < 4;
        bool const longest = index >= 4 && index < 8;
        auto const salt = rnd.bytes(empty ? 0 : rnd.between(0, 64));
        auto const ikm = rnd.bytes(empty ? 0 : rnd.between(0, 64));
        auto const info = rnd.bytes(case_size(rnd, index, 1024, 0, 1024));
        std::size_t const size = longest ? 255 * Hash::size : rnd.between(1, 3 * Hash::size);
        std::vector<std::uint8_t> expected(size);
        BOOST_TEST(
            (hash::hkdf<typename Hash::hmac, hash::backends::hash2>(expected, salt, ikm, info)
                 .has_value()));
        std::vector<std::uint8_t> output(size);
        auto const code = complete_by_callback(context, [&](auto token) {
            hash::async_hkdf<typename Hash::hmac, webcrypto>(executor, output, salt, ikm, info,
                                                             std::move(token));
        });
        compare("async_hkdf", index, code, output, expected);
    });
}

void check_random_pbkdf2s(asio::io_context& context) {
    webcpp::test::random_source rnd(webcpp::test::agreement_seed + 3);
    auto const executor = context.get_executor();
    for_each_case([&]<class Hash>(std::size_t index) {
        bool const empty = index < 4;
        auto const password = rnd.bytes(empty ? 0 : rnd.between(0, 64));
        auto const salt = rnd.bytes(empty ? 0 : rnd.between(0, 64));
        std::uint64_t const iterations = rnd.between(1, 500);
        std::size_t const size = rnd.between(1, 3 * Hash::size);
        std::vector<std::uint8_t> expected(size);
        BOOST_TEST((hash::pbkdf2<typename Hash::hmac, hash::backends::hash2>(expected, password,
                                                                             salt, iterations)
                        .has_value()));
        std::vector<std::uint8_t> output(size);
        auto const code = complete_by_callback(context, [&](auto token) {
            hash::async_pbkdf2<typename Hash::hmac, webcrypto>(executor, output, password, salt,
                                                               iterations, std::move(token));
        });
        compare("async_pbkdf2", index, code, output, expected);
    });
}

// A refusal: `start(output, token)` completes through the loop with `expected`, the output as it
// was.
template <class Start>
void check_refusal(asio::io_context& context, std::string_view name, std::size_t size,
                   boost::system::error_code expected, Start start) {
    std::vector<std::uint8_t> output(size, 0xa5);
    auto const code = complete_by_callback(
        context, [&](auto token) { start(std::span(output), std::move(token)); });
    if (!BOOST_TEST(code == expected)) {
        std::cerr << "  " << name << ": " << code.message() << '\n';
    }
    BOOST_TEST(output == std::vector<std::uint8_t>(size, 0xa5));
}

// The family's guards and WebCrypto's limits (ruling R74), each refused before any promise.
void check_guards(asio::io_context& context) {
    static_assert(hash::detail::backend_limits<webcrypto>::pbkdf2_iterations == 0xffffffffULL);
    static_assert(hash::detail::backend_limits<webcrypto>::hkdf_info == 1024);
    static_assert(hash::detail::backend_limits<webcrypto>::hkdf_output == 0xffffffffULL / 8);
    static_assert(hash::detail::backend_limits<webcrypto>::pbkdf2_output == 0xffffffffULL / 8);
    static_assert(hash::detail::backend_limits<hash::backends::hash2>::pbkdf2_iterations ==
                  hash::detail::no_limit);

    auto const executor = context.get_executor();
    auto const abc = bytes_of("abc");
    check_refusal(context, "async_digest of 31 bytes", 31, hash::error::invalid_output_size,
                  [&](std::span<std::uint8_t> output, auto token) {
                      hash::async_digest<hash::digests::sha2_256, webcrypto>(executor, output, abc,
                                                                             std::move(token));
                  });
    check_refusal(context, "async_hmac of 9 bytes", 9, hash::error::invalid_output_size,
                  [&](std::span<std::uint8_t> output, auto token) {
                      hash::async_hmac<hash::hmac_sha2_256, webcrypto>(executor, output, abc, abc,
                                                                       std::move(token));
                  });
    check_refusal(context, "async_hmac of 33 bytes", 33, hash::error::invalid_output_size,
                  [&](std::span<std::uint8_t> output, auto token) {
                      hash::async_hmac<hash::hmac_sha2_256, webcrypto>(executor, output, abc, abc,
                                                                       std::move(token));
                  });
    check_refusal(context, "async_hkdf of 0 bytes", 0, hash::error::invalid_output_size,
                  [&](std::span<std::uint8_t> output, auto token) {
                      hash::async_hkdf<hash::hmac_sha2_256, webcrypto>(executor, output, abc, abc,
                                                                       abc, std::move(token));
                  });
    std::vector<std::uint8_t> const long_info(1025, 0x01);
    check_refusal(context, "async_hkdf with 1,025 bytes of info", 32, hash::error::input_too_long,
                  [&](std::span<std::uint8_t> output, auto token) {
                      hash::async_hkdf<hash::hmac_sha2_256, webcrypto>(executor, output, abc, abc,
                                                                       long_info, std::move(token));
                  });
    check_refusal(context, "async_pbkdf2 of 0 iterations", 32, hash::error::invalid_iterations,
                  [&](std::span<std::uint8_t> output, auto token) {
                      hash::async_pbkdf2<hash::hmac_sha2_256, webcrypto>(executor, output, abc, abc,
                                                                         0, std::move(token));
                  });
    check_refusal(context, "async_pbkdf2 of 2^32 iterations", 32, hash::error::invalid_iterations,
                  [&](std::span<std::uint8_t> output, auto token) {
                      hash::async_pbkdf2<hash::hmac_sha2_256, webcrypto>(
                          executor, output, abc, abc, 0x100000000ULL, std::move(token));
                  });
}

// An executor whose context is not an io_context (here a thread_pool's, of no thread, behind
// any_io_executor, so that only a check at run time can see it): the bridge's promise would never
// settle there, so the call refuses with invalid_parameters, posted to the handler's executor
// (ruling R73).
void check_executor(asio::io_context& context) {
    asio::thread_pool pool(0);
    asio::any_io_executor const elsewhere(pool.get_executor());
    std::array<std::uint8_t, 32> output{};
    output.fill(0xa5);
    auto const untouched = output;
    boost::system::error_code code;
    bool called = false;
    hash::async_digest<hash::digests::sha2_256, webcrypto>(
        elsewhere, output, bytes_of("abc"),
        asio::bind_executor(context.get_executor(), [&](boost::system::error_code done) {
            called = true;
            code = done;
        }));
    BOOST_TEST(!called);
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST(called);
    BOOST_TEST(code == hash::error::invalid_parameters);
    BOOST_TEST(output == untouched);
    pool.join();

    // The same io_context behind any_io_executor is accepted.
    asio::any_io_executor const erased(context.get_executor());
    std::array<std::uint8_t, 32> hashed{};
    code = complete_by_callback(context, [&](auto token) {
        hash::async_digest<hash::digests::sha2_256, webcrypto>(erased, hashed, bytes_of("abc"),
                                                               std::move(token));
    });
    BOOST_TEST(!code);
    BOOST_TEST_EQ(to_hex(hashed),
                  std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

// A cancellation through the handler's slot completes at once with operation_aborted, the output
// zeroed, while WebCrypto's promise is still pending: a PBKDF2 of 5,000,000 iterations, which takes
// node about a second, cancelled by a timer of 20 ms once deriveBits runs.
void check_cancellation(asio::io_context& context) {
    asio::cancellation_signal signal;
    std::array<std::uint8_t, 32> output{};
    output.fill(0xa5);
    int calls = 0;
    boost::system::error_code code;
    hash::async_pbkdf2<hash::hmac_sha2_256, webcrypto>(
        context.get_executor(), output, bytes_of("password"), bytes_of("salt"), 5000000,
        asio::bind_cancellation_slot(signal.slot(), [&](boost::system::error_code done) {
            ++calls;
            code = done;
        }));
    asio::steady_timer timer(context, std::chrono::milliseconds(20));
    timer.async_wait(
        [&](boost::system::error_code) { signal.emit(asio::cancellation_type::terminal); });
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST_EQ(calls, 1);
    BOOST_TEST(code == asio::error::operation_aborted);
    BOOST_TEST((output == std::array<std::uint8_t, 32>{}));
}

// An allocator that counts the blocks it has given and not got back.
template <class T>
struct holding_allocator {
    using value_type = T;
    int* held;

    explicit holding_allocator(int* counter) noexcept : held(counter) {}

    // Allocator rebind conversions must be implicit (Allocator requirements).
    template <class U>
    // NOLINTNEXTLINE(misc-explicit-constructor)
    holding_allocator(holding_allocator<U> const& other) noexcept : held(other.held) {}

    T* allocate(std::size_t count) {
        ++*held;
        return std::allocator<T>().allocate(count);
    }

    void deallocate(T* pointer, std::size_t count) noexcept {
        std::allocator<T>().deallocate(pointer, count);
        --*held;
    }

    template <class U>
    bool operator==(holding_allocator<U> const& other) const noexcept {
        return held == other.held;
    }
};

// The operation's storage is the handler's associated allocator's (spec 11.4), every block given
// back before the handler runs: on a success (two promises: importKey, then sign), on a guard's
// refusal and on a cancellation.
void check_allocator(asio::io_context& context) {
    auto const executor = context.get_executor();
    auto const key = bytes_of("key");
    auto const input = bytes_of("The quick brown fox jumps over the lazy dog");
    int held = 0;
    int allocations = 0;
    auto const start = [&](std::span<std::uint8_t> output, asio::cancellation_signal& signal,
                           int& held_at_call, boost::system::error_code& code) {
        held_at_call = -1;
        hash::async_hmac<hash::hmac_sha2_256, webcrypto>(
            executor, output, key, input,
            asio::bind_cancellation_slot(signal.slot(),
                                         asio::bind_allocator(holding_allocator<char>(&held),
                                                              [&](boost::system::error_code done) {
                                                                  held_at_call = held;
                                                                  code = done;
                                                              })));
        allocations = held;
    };

    std::array<std::uint8_t, 32> tag{};
    asio::cancellation_signal done_signal;
    int done_held = 0;
    boost::system::error_code done_code;
    start(tag, done_signal, done_held, done_code);
    BOOST_TEST_GE(allocations, 1);
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST(!done_code);
    BOOST_TEST_EQ(done_held, 0);
    BOOST_TEST_EQ(to_hex(tag),
                  std::string("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"));

    std::array<std::uint8_t, 9> short_tag{};
    asio::cancellation_signal refused_signal;
    int refused_held = 0;
    boost::system::error_code refused_code;
    start(short_tag, refused_signal, refused_held, refused_code);
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST(refused_code == hash::error::invalid_output_size);
    BOOST_TEST_EQ(refused_held, 0);

    asio::cancellation_signal cancel_signal;
    int cancel_held = 0;
    boost::system::error_code cancel_code;
    start(tag, cancel_signal, cancel_held, cancel_code);
    cancel_signal.emit(asio::cancellation_type::terminal);
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST(cancel_code == asio::error::operation_aborted);
    BOOST_TEST_EQ(cancel_held, 0);
    BOOST_TEST_EQ(held, 0);
}

}  // namespace

int main() {
    asio::io_context context;
    check_published_cases(context);
    check_random_digests(context);
    check_random_hmacs(context);
    check_random_hkdfs(context);
    check_random_pbkdf2s(context);
    check_guards(context);
    check_executor(context);
    check_cancellation(context);
    check_allocator(context);
    return webcpp::test::exit_status(boost::report_errors());
}
