// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// backends::webcrypto, the browser's WebCrypto (node's crypto.subtle here), through the
// asynchronous family (spec 11, Emscripten only). The published cases through each function, each
// with a callback, use_awaitable and use_future: SHA-256 of "abc", RFC 4231's case 1, RFC 5869's
// A.1, RFC 6070's case 1 and RFC 7914 section 11's first case. Then 100 random cases per function
// against the synchronous default backend, the call naming none (backends::hash2 for each, as the
// static_asserts below state), over SHA-1, SHA-256, SHA-384 and SHA-512 in turn, the empty inputs
// among them (an empty HMAC key is passed to WebCrypto as one zero byte, the same key by RFC 2104's
// padding: ruling R74). The guards complete through the event loop, never inside the call, the
// output untouched; WebCrypto's own limits (ruling R74) and an executor whose context is not an
// io_context (ruling R73) refuse likewise; the executor's accepted forms, its tracked ones among
// them, and a documented limit (a strand of a strand behind any_io_executor). A cancellation
// completes at once with operation_aborted, the output zeroed, and the promise's later
// settlement writes nothing; and the handler's associated allocator gets back every block it gave
// before the handler runs. Without exceptions an error is read by a callback and
// use_awaitable through as_tuple (ruling R71).
//
// HKDF over pieces (the change hkdf-pieces) on WebCrypto's HMAC (importKey, then sign): async_hkdf,
// async_hkdf_extract and async_hkdf_expand over byte_pieces and the single-buffer
// async_hkdf_extract and async_hkdf_expand, RFC 5869's seven cases split into pieces with the three
// completion tokens over the four hashes (backends::hash2's bytes over the hashes the RFC does not
// give); the empty list, one empty piece and {empty, a, empty} as each list; 100 random cases of
// each against backends::hash2, inputs split into 0 to 8 pieces, empty pieces and empty salts among
// them, and node's own HKDF (deriveBits, through the single-buffer async_hkdf) equal to the form
// over pieces for infos up to 1,024 bytes; an info of 64 KiB in pieces, which the single-buffer
// async_hkdf refuses, and the single-buffer async_hkdf_expand's 32,768 bytes (ruling R3); pieces
// overwritten after the call, with asio::deferred and use_awaitable; the guards; every JavaScript
// buffer that held a secret zeroed before the handler runs, after a success and after a failure of
// each step; the runtime refusing a buffer while the pieces are gathered (backend_failure); a
// cancellation during Expand's chain. Built with WEBCPP_HASH_DETAIL_TEST_WEBCRYPTO_MAX_GATHERED
// (async_webcrypto_gathered), it checks the refusal of pieces longer than that bound alone.

#include <webcpp/hash/async.hpp>
#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/backends/webcrypto.hpp>
#include <webcpp/hash/byte_pieces.hpp>
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
#include <webcpp/asio/deferred.hpp>
#include <webcpp/asio/error.hpp>
#include <webcpp/asio/execution.hpp>
#include <webcpp/asio/io_context.hpp>
#include <webcpp/asio/prefer.hpp>
#include <webcpp/asio/require.hpp>
#include <webcpp/asio/steady_timer.hpp>
#include <webcpp/asio/strand.hpp>
#include <webcpp/asio/thread_pool.hpp>
#include <webcpp/asio/use_awaitable.hpp>
#include <webcpp/asio/use_future.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/system/error_code.hpp>

#include <webcpp/test/exit_status.hpp>

#include <emscripten/em_js.h>

#include "support/hex.hpp"
#include "support/random_cases.hpp"
#include "support/rfc5869.hpp"
#include "support/rfc6070.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <iostream>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
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

// The comparison of a random case: WebCrypto's completion and output against the synchronous
// default's result.
void compare(std::string_view function, std::size_t index, boost::system::error_code code,
             std::span<std::uint8_t const> webcrypto_output,
             std::span<std::uint8_t const> default_output) {
    bool const same =
        BOOST_TEST(!code) && BOOST_TEST_EQ(to_hex(webcrypto_output), to_hex(default_output));
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

// The synchronous default of every function compared: Boost.Hash2's (design D34, ruling R76).
static_assert(
    std::is_same_v<hash::default_backend<hash::digests::sha2_256>, hash::backends::hash2>);
static_assert(std::is_same_v<hash::default_backend<hash::macs::hmac<hash::digests::sha2_256>>,
                             hash::backends::hash2>);
static_assert(std::is_same_v<hash::default_backend<hash::kdfs::hkdf>, hash::backends::hash2>);
static_assert(std::is_same_v<hash::default_backend<hash::kdfs::pbkdf2>, hash::backends::hash2>);

void check_random_digests(asio::io_context& context) {
    webcpp::test::random_source rnd(webcpp::test::agreement_seed);
    auto const executor = context.get_executor();
    for_each_case([&]<class Hash>(std::size_t index) {
        auto const input = rnd.bytes(index < 4 ? 0 : rnd.between(1, 300));
        std::vector<std::uint8_t> expected(Hash::size);
        BOOST_TEST((hash::digest_of<typename Hash::digest>(expected, input).has_value()));
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
        BOOST_TEST(
            (hash::mac<hash::macs::hmac<typename Hash::digest>>(expected, key, input).has_value()));
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
        BOOST_TEST((hash::hkdf<typename Hash::hmac>(expected, salt, ikm, info).has_value()));
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
        BOOST_TEST(
            (hash::pbkdf2<typename Hash::hmac>(expected, password, salt, iterations).has_value()));
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
    static_assert(hash::detail::backend_limits<webcrypto>::hkdf_application_info == 1024);
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

// async_digest of "abc" on `executor`, its handler bound to the context's own executor so that a
// refusal reaches the loop whatever `executor` is: the completion's code, and whether the output
// is SHA-256's (`hashed`) or untouched (neither).
struct digest_outcome {
    boost::system::error_code code;
    bool hashed = false;
    bool untouched = false;
};

template <class Executor>
digest_outcome digest_on(asio::io_context& context, Executor const& executor) {
    std::array<std::uint8_t, 32> output{};
    output.fill(0xa5);
    auto const before = output;
    digest_outcome seen;
    bool called = false;
    hash::async_digest<hash::digests::sha2_256, webcrypto>(
        executor, output, bytes_of("abc"),
        asio::bind_executor(context.get_executor(), [&](boost::system::error_code done) {
            called = true;
            seen.code = done;
        }));
    BOOST_TEST(!called);
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST(called);
    seen.hashed =
        to_hex(output) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    seen.untouched = output == before;
    return seen;
}

// An executor of the io_context, in each form a program has one, is accepted (ruling R73): plain or
// type-erased, a strand of either (make_strand of a socket's any_io_executor gives
// strand<any_io_executor>), the strand type-erased, and the executor with another property
// preferred or required.
void check_io_context_executors(asio::io_context& context) {
    auto const plain = context.get_executor();
    asio::any_io_executor const erased(plain);
    auto const accepted = [&](std::string_view name, auto const& executor) {
        auto const seen = digest_on(context, executor);
        if (!BOOST_TEST(!seen.code) || !BOOST_TEST(seen.hashed)) {
            std::cerr << "  refused: " << name << ": " << seen.code.message() << '\n';
        }
    };
    accepted("any_io_executor", erased);
    accepted("strand<executor_type>", asio::make_strand(plain));
    accepted("strand<any_io_executor>", asio::make_strand(erased));
    accepted("any_io_executor of strand<executor_type>",
             asio::any_io_executor(asio::make_strand(plain)));
    accepted("any_io_executor of strand<any_io_executor>",
             asio::any_io_executor(asio::make_strand(erased)));
    accepted(
        "any_io_executor with relationship.continuation",
        asio::any_io_executor(asio::prefer(plain, asio::execution::relationship_t::continuation)));
    accepted(
        "strand of a type-erased strand, type-erased",
        asio::any_io_executor(asio::make_strand(asio::any_io_executor(asio::make_strand(erased)))));
    accepted("any_io_executor with blocking.never",
             asio::any_io_executor(asio::require(plain, asio::execution::blocking_t::never)));
}

// The executor of the io_context with outstanding_work.tracked, behind any_io_executor, alone
// and with the other two properties: the four tracked forms the run-time check accepts. A tracked
// executor keeps the context's run from returning while it lives, so each is made inside the
// type-erased copy, never kept by the test, and that copy is dropped in the handler.
void check_tracked_executors(asio::io_context& context) {
    using asio::execution::blocking_t;
    using asio::execution::outstanding_work_t;
    using asio::execution::relationship_t;
    auto const accepted = [&](std::string_view name, auto make) {
        std::optional<asio::any_io_executor> erased(
            make(asio::prefer(context.get_executor(), outstanding_work_t::tracked)));
        std::array<std::uint8_t, 32> output{};
        bool called = false;
        boost::system::error_code code;
        hash::async_digest<hash::digests::sha2_256, webcrypto>(
            *erased, output, bytes_of("abc"),
            asio::bind_executor(context.get_executor(), [&](boost::system::error_code done) {
                called = true;
                code = done;
                erased.reset();
            }));
        context.restart();
        context.run();  // lint-run: the test's event loop
        if (!BOOST_TEST(called) || !BOOST_TEST(!code) ||
            !BOOST_TEST_EQ(to_hex(output),
                           std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f"
                                       "20015ad"))) {
            std::cerr << "  refused: " << name << ": " << code.message() << '\n';
        }
    };
    accepted("tracked", [](auto tracked) { return tracked; });
    accepted("tracked, blocking.never",
             [](auto tracked) { return asio::require(tracked, blocking_t::never); });
    accepted("tracked, relationship.continuation",
             [](auto tracked) { return asio::prefer(tracked, relationship_t::continuation); });
    accepted("tracked, blocking.never, relationship.continuation", [](auto tracked) {
        return asio::prefer(asio::require(tracked, blocking_t::never),
                            relationship_t::continuation);
    });
}

// A limit of the check, as documented: behind any_io_executor, a strand of a strand of the
// io_context's executor (two concrete strands, not type-erased ones) is not seen through, and
// the call completes with invalid_parameters, the output untouched. One type-erased strand
// between the two is seen through (check_io_context_executors).
void check_strand_of_strand(asio::io_context& context) {
    auto const seen = digest_on(
        context,
        asio::any_io_executor(asio::make_strand(asio::make_strand(context.get_executor()))));
    BOOST_TEST(seen.code == hash::error::invalid_parameters);
    BOOST_TEST(seen.untouched);
}

// An executor whose context is not an io_context (here a thread_pool's, of no thread, behind
// any_io_executor or a strand of it, so that only a check at run time can see it): the bridge's
// promise would never settle there, so the call refuses with invalid_parameters, posted to the
// handler's executor, the output untouched (ruling R73).
void check_other_executors(asio::io_context& context) {
    asio::thread_pool pool(0);
    asio::any_io_executor const elsewhere(pool.get_executor());
    auto const refused = [&](std::string_view name, auto const& executor) {
        auto const seen = digest_on(context, executor);
        if (!BOOST_TEST(seen.code == hash::error::invalid_parameters) ||
            !BOOST_TEST(seen.untouched)) {
            std::cerr << "  accepted: " << name << ": " << seen.code.message() << '\n';
        }
    };
    refused("any_io_executor of a thread_pool", elsewhere);
    refused("strand<any_io_executor> of a thread_pool", asio::make_strand(elsewhere));
    refused("any_io_executor of strand<any_io_executor> of a thread_pool",
            asio::any_io_executor(asio::make_strand(elsewhere)));
    pool.join();
}

// WebCrypto's failures, provoked under node by replacing crypto.subtle's methods (or crypto
// itself) for one call: each completes with backend_failure, the output zeroed.
// clang-format off
EM_JS(void, stub_subtle, (int mode), {
    const subtle = globalThis.crypto.subtle;
    if (mode === 1) subtle.digest = () => Promise.reject(new Error("stubbed rejection"));
    if (mode === 2) subtle.digest = () => Promise.resolve(new ArrayBuffer(5));
    if (mode === 3) subtle.digest = () => Promise.resolve(new Uint8Array(32));
    if (mode === 4) subtle.sign = () => Promise.reject(new Error("stubbed rejection"));
});

EM_JS(void, stub_pending_digest, (), {
    globalThis.crypto.subtle.digest = () => new Promise(resolve => {
        globalThis.webcpp_test_settle = resolve;
    });
});

EM_JS(int, settle_pending_promise, (), {
    const settle = globalThis.webcpp_test_settle;
    delete globalThis.webcpp_test_settle;
    if (settle === undefined) return 0;
    settle(new Uint8Array(32).fill(0xff).buffer);
    return 1;
});

EM_JS(void, restore_subtle, (), {
    const subtle = globalThis.crypto.subtle;
    delete subtle.digest;
    delete subtle.sign;
    delete subtle.importKey;
});

EM_JS(void, hide_crypto, (), {
    globalThis.webcpp_test_crypto = Object.getOwnPropertyDescriptor(globalThis, "crypto");
    Object.defineProperty(globalThis, "crypto", {value: undefined, configurable: true});
});

EM_JS(void, show_crypto, (), {
    Object.defineProperty(globalThis, "crypto", globalThis.webcpp_test_crypto);
    delete globalThis.webcpp_test_crypto;
});
// clang-format on

// `start(output, token)` completes through the loop with `expected`, the output zeroed.
template <class Start>
void check_zeroed(asio::io_context& context, std::string_view name,
                  boost::system::error_code expected, Start start) {
    std::array<std::uint8_t, 32> output{};
    output.fill(0xa5);
    auto const code = complete_by_callback(
        context, [&](auto token) { start(std::span<std::uint8_t>(output), std::move(token)); });
    if (!BOOST_TEST(code == expected) || !BOOST_TEST((output == std::array<std::uint8_t, 32>{}))) {
        std::cerr << "  " << name << ": " << code.message() << '\n';
    }
}

void check_failures(asio::io_context& context) {
    auto const executor = context.get_executor();
    auto const abc = bytes_of("abc");
    auto const digest = [&](std::span<std::uint8_t> output, auto token) {
        hash::async_digest<hash::digests::sha2_256, webcrypto>(executor, output, abc,
                                                               std::move(token));
    };
    auto const hmac = [&](std::span<std::uint8_t> output, auto token) {
        hash::async_hmac<hash::hmac_sha2_256, webcrypto>(executor, output, abc, abc,
                                                         std::move(token));
    };
    boost::system::error_code const failure = hash::error::backend_failure;

    stub_subtle(1);
    check_zeroed(context, "a rejected promise", failure, digest);
    restore_subtle();
    stub_subtle(2);
    check_zeroed(context, "an ArrayBuffer of 5 bytes", failure, digest);
    restore_subtle();
    stub_subtle(3);
    check_zeroed(context, "a Uint8Array, not an ArrayBuffer", failure, digest);
    restore_subtle();
    stub_subtle(4);
    check_zeroed(context, "the second promise rejected (sign)", failure, hmac);
    restore_subtle();
    hide_crypto();
    check_zeroed(context, "no crypto.subtle", failure, digest);
    show_crypto();

    // Restored: WebCrypto answers again.
    auto const seen = digest_on(context, executor);
    BOOST_TEST(!seen.code);
    BOOST_TEST(seen.hashed);
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

// A cancellation before WebCrypto's promise settles: the completion is operation_aborted at once,
// the output zeroed, and the promise's later settlement writes nothing. The digest's promise is
// held pending by a stub, the operation cancelled, the output then refilled by the test; the
// promise settles with 32 bytes of 0xff and the loop runs on (a timer of 20 ms, which returns to
// the JavaScript event loop): the handler is not called again and the output keeps the test's
// bytes.
void check_no_later_write(asio::io_context& context) {
    stub_pending_digest();
    asio::cancellation_signal signal;
    std::array<std::uint8_t, 32> output{};
    output.fill(0xa5);
    int calls = 0;
    boost::system::error_code code;
    hash::async_digest<hash::digests::sha2_256, webcrypto>(
        context.get_executor(), output, bytes_of("abc"),
        asio::bind_cancellation_slot(signal.slot(), [&](boost::system::error_code done) {
            ++calls;
            code = done;
        }));
    signal.emit(asio::cancellation_type::terminal);
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST_EQ(calls, 1);
    BOOST_TEST(code == asio::error::operation_aborted);
    BOOST_TEST((output == std::array<std::uint8_t, 32>{}));

    output.fill(0x77);
    BOOST_TEST_EQ(settle_pending_promise(), 1);
    asio::steady_timer timer(context, std::chrono::milliseconds(20));
    timer.async_wait([](boost::system::error_code) {});
    context.restart();
    context.run();  // lint-run: the test's event loop, the promise's settlement among it
    restore_subtle();
    BOOST_TEST_EQ(calls, 1);
    BOOST_TEST_EQ(output[0], 0x77);
    BOOST_TEST_EQ(output[31], 0x77);
}

// A partial cancellation is honoured as a terminal one: at once, operation_aborted, the output
// zeroed.
void check_partial_cancellation(asio::io_context& context) {
    asio::cancellation_signal signal;
    std::array<std::uint8_t, 32> output{};
    output.fill(0xa5);
    boost::system::error_code code;
    hash::async_hmac<hash::hmac_sha2_256, webcrypto>(
        context.get_executor(), output, bytes_of("key"), bytes_of("message"),
        asio::bind_cancellation_slot(signal.slot(),
                                     [&](boost::system::error_code done) { code = done; }));
    signal.emit(asio::cancellation_type::partial);
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST(code == asio::error::operation_aborted);
    BOOST_TEST((output == std::array<std::uint8_t, 32>{}));
}

// A cancellation that lands between the two promises, when importKey has settled and before sign
// starts: the handler is bound to a second io_context, so that the first promise's completion,
// run by the first context, leaves the operation's next step queued on the second; the signal is
// emitted then. sign never starts, and the completion is operation_aborted, the output zeroed.
void check_cancellation_between_promises(asio::io_context& context) {
    asio::io_context handlers;
    asio::cancellation_signal signal;
    std::array<std::uint8_t, 32> output{};
    output.fill(0xa5);
    boost::system::error_code code;
    int calls = 0;
    hash::async_hmac<hash::hmac_sha2_256, webcrypto>(
        context.get_executor(), output, bytes_of("key"), bytes_of("message"),
        asio::bind_cancellation_slot(
            signal.slot(),
            asio::bind_executor(handlers.get_executor(), [&](boost::system::error_code done) {
                ++calls;
                code = done;
            })));
    context.restart();
    BOOST_TEST_EQ(context.run_one(), 1U);  // lint-run: importKey's completion alone
    BOOST_TEST_EQ(calls, 0);
    signal.emit(asio::cancellation_type::terminal);
    handlers.run_one();  // lint-run: the operation's next step, on the handler's context
    if (calls == 0) {
        // Not completed by the cancellation: sign started; let it end, so that the test fails
        // rather than wait.
        context.restart();
        context.run_one();  // lint-run: sign's completion
        handlers.restart();
        handlers.poll();
    }
    BOOST_TEST_EQ(calls, 1);
    BOOST_TEST(code == asio::error::operation_aborted);
    BOOST_TEST((output == std::array<std::uint8_t, 32>{}));
}

// HKDF over pieces and its two steps on WebCrypto's HMAC (the change hkdf-pieces): async_hkdf,
// async_hkdf_extract and async_hkdf_expand over byte_pieces, and the single-buffer
// async_hkdf_extract and async_hkdf_expand, which run on the same HMAC chain.

using byte_piece = std::span<std::uint8_t const>;

// `input` split at random points into 0 to 8 pieces, at least one when it is not empty; points
// drawn twice, or at an end, make empty pieces.
std::vector<byte_piece> random_split(webcpp::test::random_source& rnd, byte_piece input) {
    std::size_t count = rnd.between(0, 8);
    if (count == 0 && !input.empty()) {
        count = 1;
    }
    std::vector<std::size_t> points;
    for (std::size_t i = 1; i < count; ++i) {
        points.push_back(rnd.between(0, input.size()));
    }
    std::ranges::sort(points);
    std::vector<byte_piece> pieces;
    std::size_t start = 0;
    for (std::size_t const point : points) {
        pieces.push_back(input.subspan(start, point - start));
        start = point;
    }
    if (count != 0) {
        pieces.push_back(input.subspan(start));
    }
    return pieces;
}

// The inputs of one of RFC 5869's cases through the five forms over Hmac, each with the three
// completion tokens: the input keying material in two halves around an empty piece, the
// application info in two halves between two empty pieces. The pseudorandom key and the output
// keying material expected are backends::hash2's, which over the case's own hash (`own`) are first
// checked against the RFC's.
template <class Hmac>
void check_published_pieces(asio::io_context& context, std::string_view name,
                            webcpp::test::rfc5869_case const& published, bool own) {
    using hash::backends::hash2;
    auto const executor = context.get_executor();
    auto const ikm = from_hex(published.ikm);
    auto const salt = from_hex(published.salt);
    auto const info = from_hex(published.info);
    auto const extracted = hash::hkdf_extract<Hmac, hash2>(salt, hash::byte_pieces{ikm});
    BOOST_TEST(extracted.has_value());
    std::vector<std::uint8_t> const prk(extracted->data(), extracted->data() + extracted->size());
    std::vector<std::uint8_t> derived(published.length);
    BOOST_TEST((hash::hkdf<Hmac, hash2>(derived, salt, ikm, info).has_value()));
    std::string const prk_hex = to_hex(prk);
    std::string const okm_hex = to_hex(derived);
    if (own) {
        BOOST_TEST_EQ(prk_hex, std::string(published.prk));
        BOOST_TEST_EQ(okm_hex, std::string(published.okm));
    }
    byte_piece const empty{};
    byte_piece const whole_ikm(ikm);
    byte_piece const whole_info(info);
    std::array<byte_piece, 3> const ikm_pieces{
        whole_ikm.first(ikm.size() / 2),
        empty,
        whole_ikm.subspan(ikm.size() / 2),
    };
    std::array<byte_piece, 4> const info_pieces{
        empty,
        whole_info.first(info.size() / 2),
        whole_info.subspan(info.size() / 2),
        empty,
    };
    std::string const label(name);
    check_published(context, label + ", async_hkdf over pieces", okm_hex,
                    [&](std::span<std::uint8_t> output, auto token) {
                        return hash::async_hkdf<Hmac, webcrypto>(
                            executor, output, salt, hash::byte_pieces(ikm_pieces),
                            hash::byte_pieces(info_pieces), std::move(token));
                    });
    check_published(context, label + ", async_hkdf_extract over pieces", prk_hex,
                    [&](std::span<std::uint8_t> output, auto token) {
                        return hash::async_hkdf_extract<Hmac, webcrypto>(
                            executor, output, salt, hash::byte_pieces(ikm_pieces),
                            std::move(token));
                    });
    check_published(context, label + ", async_hkdf_expand over pieces", okm_hex,
                    [&](std::span<std::uint8_t> output, auto token) {
                        return hash::async_hkdf_expand<Hmac, webcrypto>(
                            executor, output, prk, hash::byte_pieces(info_pieces),
                            std::move(token));
                    });
    check_published(context, label + ", async_hkdf_extract", prk_hex,
                    [&](std::span<std::uint8_t> output, auto token) {
                        return hash::async_hkdf_extract<Hmac, webcrypto>(executor, output, salt,
                                                                         ikm, std::move(token));
                    });
    check_published(context, label + ", async_hkdf_expand", okm_hex,
                    [&](std::span<std::uint8_t> output, auto token) {
                        return hash::async_hkdf_expand<Hmac, webcrypto>(executor, output, prk, info,
                                                                        std::move(token));
                    });
}

// RFC 5869's seven cases over Hash: their own bytes over the case's hash (SHA-256 for A.1 to A.3,
// SHA-1 for A.4 to A.7), hash2's over the others.
template <class Hash>
void check_published_hkdf_pieces_over(asio::io_context& context, std::string_view hash_name) {
    namespace test = webcpp::test;
    std::array<std::pair<std::string_view, test::rfc5869_case const*>, 7> const cases{{
        {"A.1", &test::a1},
        {"A.2", &test::a2},
        {"A.3", &test::a3},
        {"A.4", &test::a4},
        {"A.5", &test::a5},
        {"A.6", &test::a6},
        {"A.7", &test::a7},
    }};
    for (auto const& [label, published] : cases) {
        check_published_pieces<typename Hash::hmac>(
            context, "RFC 5869 " + std::string(label) + " over " + std::string(hash_name),
            *published, published->hash == hash_name);
    }
}

// RFC 5869's seven cases over the four hmacs WebCrypto has (webcrypto_hmac_v).
void check_published_hkdf_pieces(asio::io_context& context) {
    static_assert(hash::detail::webcrypto_hmac_v<sha1::hmac> &&
                  hash::detail::webcrypto_hmac_v<sha256::hmac> &&
                  hash::detail::webcrypto_hmac_v<sha384::hmac> &&
                  hash::detail::webcrypto_hmac_v<sha512::hmac>);
    check_published_hkdf_pieces_over<sha1>(context, "sha1");
    check_published_hkdf_pieces_over<sha256>(context, "sha256");
    check_published_hkdf_pieces_over<sha384>(context, "sha384");
    check_published_hkdf_pieces_over<sha512>(context, "sha512");
}

// Review Focus 5 of the change hkdf-pieces: the empty list, one empty piece and
// {empty, a, empty}, as the input keying material's list and as the application info's, through
// async_hkdf over pieces (each pair of the two), async_hkdf_extract and async_hkdf_expand over
// pieces, over the four hashes, each against backends::hash2's synchronous result.
template <class Hash>
void check_empty_pieces_over(asio::io_context& context) {
    using hmac = Hash::hmac;
    using hash::backends::hash2;
    auto const executor = context.get_executor();
    auto const salt = bytes_of("salt");
    auto const a = bytes_of("a");
    byte_piece const empty{};
    std::array<byte_piece, 1> const one_empty{empty};
    std::array<byte_piece, 3> const around{empty, a, empty};
    std::array<std::pair<std::string_view, hash::byte_pieces>, 3> const lists{{
        {"{}", hash::byte_pieces{}},
        {"{empty}", hash::byte_pieces(one_empty)},
        {"{empty, a, empty}", hash::byte_pieces(around)},
    }};
    std::vector<std::uint8_t> const key(Hash::size, 0x0b);
    std::size_t const size = (2 * Hash::size) + 3;
    for (auto const& [ikm_name, ikm] : lists) {
        for (auto const& [info_name, info] : lists) {
            std::vector<std::uint8_t> expected(size);
            BOOST_TEST((hash::hkdf<hmac, hash2>(expected, salt, ikm, info).has_value()));
            std::vector<std::uint8_t> output(size);
            auto const code = complete_by_callback(context, [&](auto token) {
                hash::async_hkdf<hmac, webcrypto>(executor, output, salt, ikm, info,
                                                  std::move(token));
            });
            compare("async_hkdf over " + std::string(ikm_name) + " and " + std::string(info_name),
                    Hash::size, code, output, expected);
        }

        auto const extracted = hash::hkdf_extract<hmac, hash2>(salt, ikm);
        BOOST_TEST(extracted.has_value());
        std::vector<std::uint8_t> extract_output(Hash::size);
        auto code = complete_by_callback(context, [&](auto token) {
            hash::async_hkdf_extract<hmac, webcrypto>(executor, extract_output, salt, ikm,
                                                      std::move(token));
        });
        compare("async_hkdf_extract over " + std::string(ikm_name), Hash::size, code,
                extract_output, std::span(extracted->data(), extracted->size()));

        auto const& info = ikm;
        std::vector<std::uint8_t> expanded(size);
        BOOST_TEST((hash::hkdf_expand<hmac, hash2>(expanded, key, info).has_value()));
        std::vector<std::uint8_t> expand_output(size);
        code = complete_by_callback(context, [&](auto token) {
            hash::async_hkdf_expand<hmac, webcrypto>(executor, expand_output, key, info,
                                                     std::move(token));
        });
        compare("async_hkdf_expand over " + std::string(ikm_name), Hash::size, code, expand_output,
                expanded);
    }
}

void check_empty_pieces(asio::io_context& context) {
    check_empty_pieces_over<sha1>(context);
    check_empty_pieces_over<sha256>(context);
    check_empty_pieces_over<sha384>(context);
    check_empty_pieces_over<sha512>(context);
}

static_assert(
    std::is_same_v<hash::default_backend<hash::kdfs::hkdf_pieces>, hash::backends::hash2>);

// 100 random cases of each form against backends::hash2's, over SHA-1, SHA-256, SHA-384 and
// SHA-512 in turn: the first four with every input empty (an empty salt, each empty input split
// into 0 to 8 empty pieces: whether the empty list is drawn depends on the seed, so that
// check_empty_pieces runs it, one empty piece and {empty, a, empty} deterministically), the next
// four with an application info of 1,024 bytes and the longest output (255 digests), then
// salts of 0 to 64 bytes, inputs of 0 to 100 bytes and infos of 0 to 2,048 bytes (beyond
// deriveBits' 1,024), each split into 0 to 8 pieces. Where the info is 1,024 bytes or shorter,
// node's own HKDF (deriveBits, through the single-buffer async_hkdf) gives the bytes of the form
// over pieces too.
void check_random_hkdf_pieces(asio::io_context& context) {
    webcpp::test::random_source rnd(webcpp::test::agreement_seed + 4);
    auto const executor = context.get_executor();
    std::size_t derive_bits_cases = 0;
    for_each_case([&]<class Hash>(std::size_t index) {
        using hmac = Hash::hmac;
        using hash::backends::hash2;
        bool const empty = index < 4;
        bool const longest = index >= 4 && index < 8;
        auto const salt = rnd.bytes(empty ? 0 : rnd.between(0, 64));
        auto const ikm = rnd.bytes(empty ? 0 : rnd.between(0, 100));
        auto const info = rnd.bytes(case_size(rnd, index, 1024, 0, 2048));
        auto const ikm_pieces = random_split(rnd, ikm);
        auto const info_pieces = random_split(rnd, info);
        auto const key = rnd.bytes(Hash::size);
        std::size_t const size = longest ? 255 * Hash::size : rnd.between(1, 3 * Hash::size);

        std::vector<std::uint8_t> expected(size);
        BOOST_TEST((hash::hkdf<hmac, hash2>(expected, salt, hash::byte_pieces(ikm_pieces),
                                            hash::byte_pieces(info_pieces))
                        .has_value()));
        std::vector<std::uint8_t> output(size);
        auto code = complete_by_callback(context, [&](auto token) {
            hash::async_hkdf<hmac, webcrypto>(executor, output, salt, hash::byte_pieces(ikm_pieces),
                                              hash::byte_pieces(info_pieces), std::move(token));
        });
        compare("async_hkdf over pieces", index, code, output, expected);
        if (info.size() <= 1024) {
            ++derive_bits_cases;
            std::vector<std::uint8_t> derived(size);
            code = complete_by_callback(context, [&](auto token) {
                hash::async_hkdf<hmac, webcrypto>(executor, derived, salt, ikm, info,
                                                  std::move(token));
            });
            compare("async_hkdf (deriveBits) against over pieces", index, code, derived, output);
        }

        auto const extracted = hash::hkdf_extract<hmac, hash2>(salt, hash::byte_pieces(ikm_pieces));
        BOOST_TEST(extracted.has_value());
        byte_piece const pseudorandom_key(extracted->data(), extracted->size());
        std::vector<std::uint8_t> extract_output(Hash::size);
        code = complete_by_callback(context, [&](auto token) {
            hash::async_hkdf_extract<hmac, webcrypto>(
                executor, extract_output, salt, hash::byte_pieces(ikm_pieces), std::move(token));
        });
        compare("async_hkdf_extract over pieces", index, code, extract_output, pseudorandom_key);
        std::vector<std::uint8_t> single_extract(Hash::size);
        code = complete_by_callback(context, [&](auto token) {
            hash::async_hkdf_extract<hmac, webcrypto>(executor, single_extract, salt, ikm,
                                                      std::move(token));
        });
        compare("async_hkdf_extract", index, code, single_extract, pseudorandom_key);

        std::vector<std::uint8_t> expanded(size);
        BOOST_TEST((hash::hkdf_expand<hmac, hash2>(expanded, key, hash::byte_pieces(info_pieces))
                        .has_value()));
        std::vector<std::uint8_t> expand_output(size);
        code = complete_by_callback(context, [&](auto token) {
            hash::async_hkdf_expand<hmac, webcrypto>(
                executor, expand_output, key, hash::byte_pieces(info_pieces), std::move(token));
        });
        compare("async_hkdf_expand over pieces", index, code, expand_output, expanded);
        std::vector<std::uint8_t> single_expand(size);
        code = complete_by_callback(context, [&](auto token) {
            hash::async_hkdf_expand<hmac, webcrypto>(executor, single_expand, key, info,
                                                     std::move(token));
        });
        compare("async_hkdf_expand", index, code, single_expand, expanded);
    });
    BOOST_TEST_GE(derive_bits_cases, 40U);
}

// The spec's scenario: an application info of 64 KiB in four pieces gives hash2's bytes, where
// the single-buffer async_hkdf refuses it (input_too_long, the output untouched). The single-buffer
// async_hkdf_expand runs on HMAC and keeps hash's 32,768 bytes (ruling R3), not deriveBits' 1,024:
// 1,025 and 32,768 bytes give hash2's bytes, 32,769 are refused, and the same 32,769 bytes as
// byte_pieces{info} are not.
void check_long_application_info(asio::io_context& context) {
    webcpp::test::random_source rnd(webcpp::test::agreement_seed + 5);
    auto const executor = context.get_executor();
    auto const salt = rnd.bytes(16);
    auto const ikm = rnd.bytes(32);
    auto const info = rnd.bytes(65536);
    byte_piece const whole(info);
    std::array<byte_piece, 4> const quarters{
        whole.first(16384),
        whole.subspan(16384, 16384),
        whole.subspan(32768, 16384),
        whole.subspan(49152),
    };
    std::vector<std::uint8_t> expected(64);
    BOOST_TEST(hash::hkdf<hash::hmac_sha2_256>(expected, salt, hash::byte_pieces{ikm}, quarters)
                   .has_value());
    std::vector<std::uint8_t> output(64);
    auto code = complete_by_callback(context, [&](auto token) {
        hash::async_hkdf<hash::hmac_sha2_256, webcrypto>(
            executor, output, salt, hash::byte_pieces{ikm}, hash::byte_pieces(quarters),
            std::move(token));
    });
    compare("async_hkdf over 64 KiB of pieces", 0, code, output, expected);
    check_refusal(context, "async_hkdf with 64 KiB of info", 64, hash::error::input_too_long,
                  [&](std::span<std::uint8_t> refused, auto token) {
                      hash::async_hkdf<hash::hmac_sha2_256, webcrypto>(executor, refused, salt, ikm,
                                                                       info, std::move(token));
                  });

    auto const key = rnd.bytes(32);
    for (std::size_t const size : {std::size_t{1025}, hash::hkdf_max_application_info_size}) {
        auto const head = whole.first(size);
        std::vector<std::uint8_t> expanded(80);
        BOOST_TEST(hash::hkdf_expand<hash::hmac_sha2_256>(expanded, key, head).has_value());
        std::vector<std::uint8_t> single(80);
        code = complete_by_callback(context, [&](auto token) {
            hash::async_hkdf_expand<hash::hmac_sha2_256, webcrypto>(executor, single, key, head,
                                                                    std::move(token));
        });
        compare("async_hkdf_expand of a long info", size, code, single, expanded);
    }
    auto const over = whole.first(hash::hkdf_max_application_info_size + 1);
    check_refusal(context, "async_hkdf_expand with 32,769 bytes of info", 80,
                  hash::error::input_too_long, [&](std::span<std::uint8_t> refused, auto token) {
                      hash::async_hkdf_expand<hash::hmac_sha2_256, webcrypto>(
                          executor, refused, key, over, std::move(token));
                  });
    std::vector<std::uint8_t> expanded(80);
    BOOST_TEST(
        hash::hkdf_expand<hash::hmac_sha2_256>(expanded, key, hash::byte_pieces{over}).has_value());
    std::vector<std::uint8_t> one_piece(80);
    code = complete_by_callback(context, [&](auto token) {
        hash::async_hkdf_expand<hash::hmac_sha2_256, webcrypto>(
            executor, one_piece, key, hash::byte_pieces{over}, std::move(token));
    });
    compare("async_hkdf_expand over byte_pieces{32,769 bytes}", 0, code, one_piece, expanded);
}

// The pieces are gathered into JavaScript memory in the call (ruling R4): async_hkdf over the
// braced lists {a, b} and {c, d}, whose arrays die at the end of the call's full-expression, then a
// to d overwritten before the operation runs, gives the HKDF of the original bytes with a callback,
// with asio::deferred launched after the overwrite and with a use_awaitable awaitable awaited after
// it; async_hkdf_extract and async_hkdf_expand over pieces likewise with asio::deferred.
void check_pieces_read_in_call(asio::io_context& context) {
    auto const executor = context.get_executor();
    auto const salt = from_hex("000102030405060708090a0b0c");
    std::array<std::uint8_t, 4> a{};
    std::array<std::uint8_t, 3> b{};
    std::array<std::uint8_t, 2> c{};
    std::array<std::uint8_t, 5> d{};
    auto const restore = [&] {
        a = {1, 2, 3, 4};
        b = {5, 6, 7};
        c = {8, 9};
        d = {10, 11, 12, 13, 14};
    };
    auto const overwrite = [&] {
        a.fill(0xff);
        b.fill(0xff);
        c.fill(0xff);
        d.fill(0xff);
    };
    restore();
    std::array<std::uint8_t, 42> expected{};
    BOOST_TEST(hash::hkdf<hash::hmac_sha2_256>(expected, salt, {a, b}, {c, d}).has_value());
    auto const extracted = hash::hkdf_extract<hash::hmac_sha2_256>(salt, {a, b});
    BOOST_TEST(extracted.has_value());
    std::array<std::uint8_t, 32> key{};
    std::ranges::copy(*extracted, key.begin());
    std::array<std::uint8_t, 42> expanded{};
    BOOST_TEST(hash::hkdf_expand<hash::hmac_sha2_256>(expanded, key, {c, d}).has_value());
    BOOST_TEST(expanded == expected);

    std::array<std::uint8_t, 42> output{};
    auto code = complete_by_callback(context, [&](auto token) {
        hash::async_hkdf<hash::hmac_sha2_256, webcrypto>(executor, output, salt, {a, b}, {c, d},
                                                         std::move(token));
        overwrite();
    });
    BOOST_TEST(!code);
    BOOST_TEST(output == expected);

    restore();
    std::array<std::uint8_t, 42> deferred_output{};
    auto launch = hash::async_hkdf<hash::hmac_sha2_256, webcrypto>(executor, deferred_output, salt,
                                                                   {a, b}, {c, d}, asio::deferred);
    overwrite();
    code = complete_by_callback(context, [&](auto token) { std::move(launch)(std::move(token)); });
    BOOST_TEST(!code);
    BOOST_TEST(deferred_output == expected);

    restore();
    std::array<std::uint8_t, 32> extract_output{};
    auto extract = hash::async_hkdf_extract<hash::hmac_sha2_256, webcrypto>(
        executor, extract_output, salt, {a, b}, asio::deferred);
    overwrite();
    code = complete_by_callback(context, [&](auto token) { std::move(extract)(std::move(token)); });
    BOOST_TEST(!code);
    BOOST_TEST(extract_output == key);

    restore();
    std::array<std::uint8_t, 42> expand_output{};
    auto expand = hash::async_hkdf_expand<hash::hmac_sha2_256, webcrypto>(
        executor, expand_output, key, {c, d}, asio::deferred);
    overwrite();
    code = complete_by_callback(context, [&](auto token) { std::move(expand)(std::move(token)); });
    BOOST_TEST(!code);
    BOOST_TEST(expand_output == expected);

    restore();
    std::array<std::uint8_t, 42> awaited{};
    bool done = false;
    asio::co_spawn(
        context,
        [&]() -> asio::awaitable<void> {
            auto derive = hash::async_hkdf<hash::hmac_sha2_256, webcrypto>(
                executor, awaited, salt, {a, b}, {c, d}, asio::as_tuple(asio::use_awaitable));
            overwrite();
            auto [derived] = co_await std::move(derive);
            BOOST_TEST(!derived);
            done = true;
        },
        [](std::exception_ptr const& failure) { BOOST_TEST(!failure); });
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST(done);
    BOOST_TEST(awaited == expected);
}

// The guards of the five forms (RFC 5869's, and hash's 32,768 bytes of the single-buffer
// async_hkdf_expand), each completing through the loop, the output untouched.
void check_hkdf_pieces_guards(asio::io_context& context) {
    auto const executor = context.get_executor();
    auto const abc = bytes_of("abc");
    std::vector<std::uint8_t> const key(32, 0x0b);
    std::vector<std::uint8_t> const short_key(31, 0x0b);
    std::vector<std::uint8_t> const long_info(hash::hkdf_max_application_info_size + 1, 0x01);
    auto const hkdf = [&](std::span<std::uint8_t> output, auto token) {
        hash::async_hkdf<hash::hmac_sha2_256, webcrypto>(executor, output, abc, {abc, abc},
                                                         {abc, abc}, std::move(token));
    };
    check_refusal(context, "async_hkdf over pieces of 0 bytes", 0, hash::error::invalid_output_size,
                  hkdf);
    check_refusal(context, "async_hkdf over pieces of 255 digests and 1 byte", (255 * 32) + 1,
                  hash::error::invalid_output_size, hkdf);
    auto const extract = [&](std::span<std::uint8_t> output, auto token) {
        hash::async_hkdf_extract<hash::hmac_sha2_256, webcrypto>(executor, output, abc, {abc, abc},
                                                                 std::move(token));
    };
    check_refusal(context, "async_hkdf_extract over pieces of 31 bytes", 31,
                  hash::error::invalid_output_size, extract);
    check_refusal(context, "async_hkdf_extract over pieces of 33 bytes", 33,
                  hash::error::invalid_output_size, extract);
    check_refusal(context, "async_hkdf_extract of 0 bytes", 0, hash::error::invalid_output_size,
                  [&](std::span<std::uint8_t> output, auto token) {
                      hash::async_hkdf_extract<hash::hmac_sha2_256, webcrypto>(
                          executor, output, abc, abc, std::move(token));
                  });
    check_refusal(context, "async_hkdf_expand over pieces of 0 bytes", 0,
                  hash::error::invalid_output_size,
                  [&](std::span<std::uint8_t> output, auto token) {
                      hash::async_hkdf_expand<hash::hmac_sha2_256, webcrypto>(
                          executor, output, key, {abc, abc}, std::move(token));
                  });
    check_refusal(context, "async_hkdf_expand over pieces with a key of 31 bytes", 32,
                  hash::error::invalid_key_size, [&](std::span<std::uint8_t> output, auto token) {
                      hash::async_hkdf_expand<hash::hmac_sha2_256, webcrypto>(
                          executor, output, short_key, {abc, abc}, std::move(token));
                  });
    check_refusal(context, "async_hkdf_expand of 255 digests and 1 byte", (255 * 32) + 1,
                  hash::error::invalid_output_size,
                  [&](std::span<std::uint8_t> output, auto token) {
                      hash::async_hkdf_expand<hash::hmac_sha2_256, webcrypto>(
                          executor, output, key, abc, std::move(token));
                  });
    check_refusal(context, "async_hkdf_expand with a key of 31 bytes", 32,
                  hash::error::invalid_key_size, [&](std::span<std::uint8_t> output, auto token) {
                      hash::async_hkdf_expand<hash::hmac_sha2_256, webcrypto>(
                          executor, output, short_key, abc, std::move(token));
                  });
    check_refusal(context, "async_hkdf_expand with 32,769 bytes of info", 32,
                  hash::error::input_too_long, [&](std::span<std::uint8_t> output, auto token) {
                      hash::async_hkdf_expand<hash::hmac_sha2_256, webcrypto>(
                          executor, output, key, long_info, std::move(token));
                  });
}

// crypto.subtle's importKey and sign wrapped for one test: each counted, every buffer they read
// and every tag sign gives recorded, so that the test can check that each was zeroed; sign's
// call number `pending_sign` returns a promise the test settles (settle_pending_promise), its call
// number `failing_sign` and importKey's number `failing_import` reject (0: none).
// clang-format off
EM_JS(void, stub_hmac_calls, (int pending_sign, int failing_sign, int failing_import), {
    const subtle = globalThis.crypto.subtle;
    const original = Object.getPrototypeOf(subtle);
    const state = {signs: 0, imports: 0, buffers: []};
    globalThis.webcpp_test_hmac = state;
    const record = (bytes) => {
        if (ArrayBuffer.isView(bytes)) {
            state.buffers.push(new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength));
        } else if (bytes instanceof ArrayBuffer) {
            state.buffers.push(new Uint8Array(bytes));
        }
    };
    subtle.importKey = function(format, data, ...rest) {
        ++state.imports;
        record(data);
        if (state.imports === failing_import) return Promise.reject(new Error("stubbed rejection"));
        return original.importKey.call(subtle, format, data, ...rest);
    };
    subtle.sign = function(algorithm, key, data) {
        ++state.signs;
        record(data);
        if (state.signs === pending_sign) {
            return new Promise(resolve => { globalThis.webcpp_test_settle = resolve; });
        }
        if (state.signs === failing_sign) return Promise.reject(new Error("stubbed rejection"));
        return original.sign.call(subtle, algorithm, key, data).then(tag => {
            record(tag);
            return tag;
        });
    };
});

EM_JS(int, stubbed_signs, (), { return globalThis.webcpp_test_hmac.signs; });

EM_JS(int, recorded_buffers, (), { return globalThis.webcpp_test_hmac.buffers.length; });

EM_JS(int, unwiped_buffers, (), {
    return globalThis.webcpp_test_hmac.buffers.filter(bytes => bytes.some(b => b !== 0)).length;
});
// clang-format on

// Every JavaScript buffer that held a secret is zeroed by the time the handler runs: the salt and
// the pseudorandom key importKey read, the input keying material and the blocks sign read, and each
// tag sign gave, the last one among them (each case records exactly the buffers of its calls),
// after a success of each of the five forms and after each failure of a step (importKey or sign
// rejected), the failures completing with backend_failure, the output zeroed, the first block of
// the output among it.
void check_secrets_wiped(asio::io_context& context) {
    auto const executor = context.get_executor();
    auto const salt = bytes_of("salt");
    auto const ikm = bytes_of("input key material");
    auto const info = bytes_of("application info");
    std::vector<std::uint8_t> const key(32, 0x0b);
    auto const wiped = [&](std::string_view name, std::size_t size,
                           boost::system::error_code expected, int buffers, auto start) {
        std::vector<std::uint8_t> output(size, 0xa5);
        int unwiped_in_handler = -1;
        auto const code = complete_by_callback(context, [&](auto token) {
            start(std::span(output), [&unwiped_in_handler, token = std::move(token)](
                                         boost::system::error_code done) mutable {
                unwiped_in_handler = unwiped_buffers();
                std::move(token)(done);
            });
        });
        bool const zeroed = std::ranges::all_of(output, [](std::uint8_t b) { return b == 0; });
        if (!BOOST_TEST(code == expected) || !BOOST_TEST_EQ(recorded_buffers(), buffers) ||
            !BOOST_TEST_EQ(unwiped_in_handler, 0) || !BOOST_TEST_EQ(unwiped_buffers(), 0) ||
            !BOOST_TEST(zeroed == bool(code))) {
            std::cerr << "  " << name << ": " << code.message() << '\n';
        }
        restore_subtle();
    };
    auto const hkdf = [&](std::span<std::uint8_t> output, auto token) {
        hash::async_hkdf<hash::hmac_sha2_256, webcrypto>(executor, output, salt, {ikm, ikm},
                                                         {info, info}, std::move(token));
    };
    auto const extract = [&](std::span<std::uint8_t> output, auto token) {
        hash::async_hkdf_extract<hash::hmac_sha2_256, webcrypto>(executor, output, salt, {ikm, ikm},
                                                                 std::move(token));
    };
    auto const expand = [&](std::span<std::uint8_t> output, auto token) {
        hash::async_hkdf_expand<hash::hmac_sha2_256, webcrypto>(executor, output, key, {info, info},
                                                                std::move(token));
    };
    boost::system::error_code const fine;
    boost::system::error_code const failure = hash::error::backend_failure;

    // A 100-byte output is four blocks: four signs over a block, four tags.
    stub_hmac_calls(0, 0, 0);
    wiped("async_hkdf over pieces", 100, fine, 12, hkdf);
    stub_hmac_calls(0, 0, 0);
    wiped("async_hkdf_extract over pieces", 32, fine, 3, extract);
    stub_hmac_calls(0, 0, 0);
    wiped("async_hkdf_expand over pieces", 100, fine, 9, expand);
    stub_hmac_calls(0, 0, 0);
    wiped("async_hkdf_extract", 32, fine, 3, [&](std::span<std::uint8_t> output, auto token) {
        hash::async_hkdf_extract<hash::hmac_sha2_256, webcrypto>(executor, output, salt, ikm,
                                                                 std::move(token));
    });
    stub_hmac_calls(0, 0, 0);
    wiped("async_hkdf_expand", 100, fine, 9, [&](std::span<std::uint8_t> output, auto token) {
        hash::async_hkdf_expand<hash::hmac_sha2_256, webcrypto>(executor, output, key, info,
                                                                std::move(token));
    });

    stub_hmac_calls(0, 0, 1);
    wiped("async_hkdf, the salt's importKey rejected", 100, failure, 1, hkdf);
    stub_hmac_calls(0, 1, 0);
    wiped("async_hkdf, Extract's sign rejected", 100, failure, 2, hkdf);
    stub_hmac_calls(0, 0, 2);
    wiped("async_hkdf, the pseudorandom key's importKey rejected", 100, failure, 4, hkdf);
    stub_hmac_calls(0, 3, 0);
    wiped("async_hkdf, the second block's sign rejected", 100, failure, 7, hkdf);
    stub_hmac_calls(0, 2, 0);
    wiped("async_hkdf_expand, the second block's sign rejected", 100, failure, 4, expand);
}

// The global Uint8Array replaced for one initiating call by a subclass that records the length of
// every array made with a length and every such array, and throws a RangeError for the length
// `refused` (-1: none), as a runtime refuses a buffer its memory cannot hold.
// clang-format off
EM_JS(void, stub_uint8array, (double refused), {
    const original = globalThis.Uint8Array;
    const state = {original, lengths: [], made: []};
    globalThis.webcpp_test_bytes = state;
    globalThis.Uint8Array = class extends original {
        constructor(...args) {
            const sized = typeof args[0] === "number";
            if (sized) {
                state.lengths.push(args[0]);
                if (args[0] === refused) throw new RangeError("stubbed refusal");
            }
            super(...args);
            if (sized) state.made.push(this);
        }
    };
});

EM_JS(void, restore_uint8array, (), {
    globalThis.Uint8Array = globalThis.webcpp_test_bytes.original;
});

EM_JS(int, uint8arrays_of_length, (double length), {
    return globalThis.webcpp_test_bytes.lengths.filter(made => made === length).length;
});

EM_JS(int, uint8arrays_made, (), { return globalThis.webcpp_test_bytes.made.length; });

EM_JS(int, unwiped_uint8arrays, (), {
    return globalThis.webcpp_test_bytes.made.filter(bytes => bytes.some(b => b !== 0)).length;
});
// clang-format on

// `start(output, token)`, an output of `size` bytes, with the Uint8Array stub refusing `refused`
// bytes during the initiating call: it completes through the loop with backend_failure, the output
// zeroed, every buffer made zeroed and none of `skipped` bytes attempted; `made` arrays were made.
template <class Start>
void check_refused_gathering(asio::io_context& context, std::string_view name, std::size_t size,
                             double refused, double skipped, int made, Start start) {
    std::vector<std::uint8_t> output(size, 0xa5);
    auto const code = complete_by_callback(context, [&](auto token) {
        stub_uint8array(refused);
        start(std::span(output), std::move(token));
        restore_uint8array();
    });
    bool const zeroed = std::ranges::all_of(output, [](std::uint8_t b) { return b == 0; });
    if (!BOOST_TEST(code == hash::error::backend_failure) || !BOOST_TEST(zeroed) ||
        !BOOST_TEST_EQ(uint8arrays_of_length(refused), refused < 0 ? 0 : 1) ||
        !BOOST_TEST_EQ(uint8arrays_of_length(skipped), 0) ||
        !BOOST_TEST_EQ(uint8arrays_made(), made) || !BOOST_TEST_EQ(unwiped_uint8arrays(), 0)) {
        std::cerr << "  " << name << ": " << code.message() << '\n';
    }
}

// The runtime refusing a buffer while the pieces are gathered (a RangeError, or an out of memory,
// from new Uint8Array) completes with backend_failure, the output zeroed and the buffers already
// made zeroed, rather than end the program; async_hkdf gathers no application info once Extract's
// inputs were not gathered. The salt is 4 bytes, the input keying material 77 and the info 100.
void check_refused_gathering(asio::io_context& context) {
    auto const executor = context.get_executor();
    std::vector<std::uint8_t> const salt(4, 0x01);
    std::vector<std::uint8_t> const ikm(77, 0x02);
    std::vector<std::uint8_t> const info(100, 0x03);
    std::vector<std::uint8_t> const key(32, 0x0b);
    byte_piece const whole_ikm(ikm);
    byte_piece const whole_info(info);
    std::array<byte_piece, 2> const ikm_pieces{whole_ikm.first(40), whole_ikm.subspan(40)};
    std::array<byte_piece, 2> const info_pieces{whole_info.first(50), whole_info.subspan(50)};
    // Expand's block over SHA-256: 32 + 100 + 1 bytes.
    constexpr double block = 133;
    auto const hkdf = [&](std::span<std::uint8_t> output, auto token) {
        hash::async_hkdf<hash::hmac_sha2_256, webcrypto>(
            executor, output, salt, hash::byte_pieces(ikm_pieces), hash::byte_pieces(info_pieces),
            std::move(token));
    };
    check_refused_gathering(context, "async_hkdf, the salt refused", 100, 4, block, 0, hkdf);
    check_refused_gathering(context, "async_hkdf, the input keying material refused", 100, 77,
                            block, 1, hkdf);
    check_refused_gathering(context, "async_hkdf, the application info refused", 100, block, -1, 2,
                            hkdf);
    check_refused_gathering(context,
                            "async_hkdf_extract over pieces, the input keying material "
                            "refused",
                            32, 77, -1, 1, [&](std::span<std::uint8_t> output, auto token) {
                                hash::async_hkdf_extract<hash::hmac_sha2_256, webcrypto>(
                                    executor, output, salt, hash::byte_pieces(ikm_pieces),
                                    std::move(token));
                            });
    check_refused_gathering(context, "async_hkdf_extract, the input keying material refused", 32,
                            77, -1, 1, [&](std::span<std::uint8_t> output, auto token) {
                                hash::async_hkdf_extract<hash::hmac_sha2_256, webcrypto>(
                                    executor, output, salt, ikm, std::move(token));
                            });
    check_refused_gathering(context, "async_hkdf_expand over pieces, the pseudorandom key refused",
                            100, 32, block, 0, [&](std::span<std::uint8_t> output, auto token) {
                                hash::async_hkdf_expand<hash::hmac_sha2_256, webcrypto>(
                                    executor, output, key, hash::byte_pieces(info_pieces),
                                    std::move(token));
                            });
    check_refused_gathering(context, "async_hkdf_expand over pieces, the application info refused",
                            100, block, -1, 1, [&](std::span<std::uint8_t> output, auto token) {
                                hash::async_hkdf_expand<hash::hmac_sha2_256, webcrypto>(
                                    executor, output, key, hash::byte_pieces(info_pieces),
                                    std::move(token));
                            });
    check_refused_gathering(context, "async_hkdf_expand, the application info refused", 100, block,
                            -1, 1, [&](std::span<std::uint8_t> output, auto token) {
                                hash::async_hkdf_expand<hash::hmac_sha2_256, webcrypto>(
                                    executor, output, key, info, std::move(token));
                            });

    // Restored: the same call succeeds.
    std::vector<std::uint8_t> expected(100);
    BOOST_TEST(hash::hkdf<hash::hmac_sha2_256>(expected, salt, hash::byte_pieces(ikm_pieces),
                                               hash::byte_pieces(info_pieces))
                   .has_value());
    std::vector<std::uint8_t> output(100);
    auto const code = complete_by_callback(context, [&](auto token) { hkdf(output, token); });
    compare("async_hkdf after the stub", 0, code, output, expected);
}

// The test seam lowers webcrypto_max_gathered (2^53 - 1 bytes otherwise, which no runtime holds) to
// 100 bytes: an input keying material of 100 bytes in pieces gives hash2's bytes, one of 101 is
// backend_failure, the output zeroed, before any buffer is made (async_hkdf then gathers no
// application info); over SHA-256, Expand's block of 32 + 67 + 1 bytes is gathered, one of
// 32 + 68 + 1 is backend_failure, every buffer made zeroed.
void check_gathered_bound(asio::io_context& context) {
    BOOST_TEST_EQ(hash::detail::webcrypto_max_gathered, 100U);
    auto const executor = context.get_executor();
    auto const salt = bytes_of("salt");
    std::vector<std::uint8_t> const bytes(101, 0x5c);
    std::vector<std::uint8_t> const key(32, 0x0b);
    byte_piece const whole(bytes);
    auto const split = [&](std::size_t size) {
        return std::array<byte_piece, 2>{whole.first(size / 2),
                                         whole.subspan(size / 2, size - (size / 2))};
    };
    auto const ikm_at = split(100);
    auto const ikm_over = split(101);
    auto const info_at = split(67);
    auto const info_over = split(68);
    auto const short_info = split(10);

    auto const extracted = hash::hkdf_extract<hash::hmac_sha2_256>(salt, hash::byte_pieces(ikm_at));
    BOOST_TEST(extracted.has_value());
    std::vector<std::uint8_t> extract_output(32);
    auto code = complete_by_callback(context, [&](auto token) {
        hash::async_hkdf_extract<hash::hmac_sha2_256, webcrypto>(
            executor, extract_output, salt, hash::byte_pieces(ikm_at), std::move(token));
    });
    compare("async_hkdf_extract over 100 bytes of pieces", 100, code, extract_output,
            std::span(extracted->data(), extracted->size()));
    check_refused_gathering(context, "async_hkdf_extract over 101 bytes of pieces", 32, -1, -1, 0,
                            [&](std::span<std::uint8_t> output, auto token) {
                                hash::async_hkdf_extract<hash::hmac_sha2_256, webcrypto>(
                                    executor, output, salt, hash::byte_pieces(ikm_over),
                                    std::move(token));
                            });
    // Expand's block over the short info: 32 + 10 + 1 bytes, which async_hkdf does not attempt.
    check_refused_gathering(context, "async_hkdf over 101 bytes of pieces", 100, -1, 43, 0,
                            [&](std::span<std::uint8_t> output, auto token) {
                                hash::async_hkdf<hash::hmac_sha2_256, webcrypto>(
                                    executor, output, salt, hash::byte_pieces(ikm_over),
                                    hash::byte_pieces(short_info), std::move(token));
                            });

    std::vector<std::uint8_t> expanded(100);
    BOOST_TEST(hash::hkdf_expand<hash::hmac_sha2_256>(expanded, key, hash::byte_pieces(info_at))
                   .has_value());
    std::vector<std::uint8_t> expand_output(100);
    code = complete_by_callback(context, [&](auto token) {
        hash::async_hkdf_expand<hash::hmac_sha2_256, webcrypto>(
            executor, expand_output, key, hash::byte_pieces(info_at), std::move(token));
    });
    compare("async_hkdf_expand over 67 bytes of pieces", 67, code, expand_output, expanded);
    // The pseudorandom key's buffer is made, then zeroed.
    check_refused_gathering(context, "async_hkdf_expand over 68 bytes of pieces", 100, -1, -1, 1,
                            [&](std::span<std::uint8_t> output, auto token) {
                                hash::async_hkdf_expand<hash::hmac_sha2_256, webcrypto>(
                                    executor, output, key, hash::byte_pieces(info_over),
                                    std::move(token));
                            });
}

// A cancellation during Expand's chain: async_hkdf_expand over pieces of three blocks, the second
// block's sign held pending by a stub once the first block is in the output; a terminal
// cancellation then completes at once with operation_aborted, the output zeroed (the first block
// with it) and every JavaScript buffer zeroed; the pending promise's later settlement writes
// nothing and calls no handler again.
void check_cancellation_in_expand(asio::io_context& context) {
    auto const executor = context.get_executor();
    std::vector<std::uint8_t> const key(32, 0x0b);
    auto const info = bytes_of("application info");
    std::array<std::uint8_t, 96> expected{};
    BOOST_TEST(hash::hkdf_expand<hash::hmac_sha2_256>(expected, key, {info, info}).has_value());
    stub_hmac_calls(2, 0, 0);
    asio::cancellation_signal signal;
    std::array<std::uint8_t, 96> output{};
    output.fill(0xa5);
    int calls = 0;
    boost::system::error_code code;
    hash::async_hkdf_expand<hash::hmac_sha2_256, webcrypto>(
        executor, output, key, {info, info},
        asio::bind_cancellation_slot(signal.slot(), [&](boost::system::error_code done) {
            ++calls;
            code = done;
        }));
    context.restart();
    for (int step = 0; step != 20 && stubbed_signs() < 2; ++step) {
        context.run_one();  // lint-run: one step of the chain, until the second sign is pending
    }
    BOOST_TEST_EQ(stubbed_signs(), 2);
    BOOST_TEST_EQ(calls, 0);
    BOOST_TEST(std::ranges::equal(std::span(output).first(32), std::span(expected).first(32)));
    BOOST_TEST(std::ranges::all_of(std::span(output).subspan(32),
                                   [](std::uint8_t b) { return b == 0xa5; }));
    signal.emit(asio::cancellation_type::terminal);
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST_EQ(calls, 1);
    BOOST_TEST(code == asio::error::operation_aborted);
    BOOST_TEST((output == std::array<std::uint8_t, 96>{}));
    BOOST_TEST_EQ(unwiped_buffers(), 0);

    output.fill(0x77);
    BOOST_TEST_EQ(settle_pending_promise(), 1);
    asio::steady_timer timer(context, std::chrono::milliseconds(20));
    timer.async_wait([](boost::system::error_code) {});
    context.restart();
    context.run();  // lint-run: the test's event loop, the promise's settlement among it
    restore_subtle();
    BOOST_TEST_EQ(calls, 1);
    BOOST_TEST(std::ranges::all_of(output, [](std::uint8_t b) { return b == 0x77; }));
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
    // The seam's program (async_webcrypto_gathered) checks the bound's refusal alone, which the
    // seam makes reachable; the others need the bound of 2^53 - 1 bytes.
    if (hash::detail::webcrypto_max_gathered == 100) {
        check_gathered_bound(context);
        return webcpp::test::exit_status(boost::report_errors());
    }
    check_published_cases(context);
    check_random_digests(context);
    check_random_hmacs(context);
    check_random_hkdfs(context);
    check_random_pbkdf2s(context);
    check_guards(context);
    check_io_context_executors(context);
    check_tracked_executors(context);
    check_strand_of_strand(context);
    check_other_executors(context);
    check_failures(context);
    check_cancellation(context);
    check_no_later_write(context);
    check_partial_cancellation(context);
    check_cancellation_between_promises(context);
    check_allocator(context);
    check_published_hkdf_pieces(context);
    check_empty_pieces(context);
    check_random_hkdf_pieces(context);
    check_long_application_info(context);
    check_pieces_read_in_call(context);
    check_hkdf_pieces_guards(context);
    check_secrets_wiped(context);
    check_refused_gathering(context);
    check_cancellation_in_expand(context);
    return webcpp::test::exit_status(boost::report_errors());
}
