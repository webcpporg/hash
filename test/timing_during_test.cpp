// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// DIT is set while a keyed function computes (design D1; spec scenario "A password derived on
// Apple silicon"): a Boost.Hash2-form hash, dit_probe, records at each update whether DIT was set
// and whether a detail::timing_guard had been entered, and runs as the hash under the hmac of
// hkdf_extract, hkdf_expand, hkdf and pbkdf2 on backends::hash2, and of mac on a stand-in backend
// whose HMAC-SHA-256 is backends::hash2's over the probe. From a thread with DIT clear, every
// update the probe saw ran after a guard was entered and, where the CPU has DIT, with DIT set (and
// clear where it has none); the thread finds DIT clear after the call. A guard that the engine
// call precedes, or one written as a temporary, fails here. With WEBCPP_TEST_TIMING_DURING_ASYNC,
// the same through async_pbkdf2 on a webcpp::asio::thread_pool of one thread, the probe's record
// read on the pool's thread, which computes.

#include "support/timing_seam.hpp"

#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/detail/timing.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/hash/pbkdf2.hpp>
#ifdef WEBCPP_TEST_TIMING_DURING_ASYNC
#include <webcpp/hash/async.hpp>

#include <webcpp/asio/bind_executor.hpp>
#include <webcpp/asio/io_context.hpp>
#include <webcpp/asio/post.hpp>
#include <webcpp/asio/thread_pool.hpp>

#include <boost/system/error_code.hpp>

#include <future>
#endif
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/sha2.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace webcpp::test {
namespace {

/** What dit_probe saw on this thread since probe_reset. */
struct probe_record {
    /** The updates it ran. */
    std::size_t updates = 0;
    /** The updates it ran with DIT clear. */
    std::size_t updates_clear = 0;
    /** The updates it ran before any detail::timing_guard was entered. */
    std::size_t updates_unguarded = 0;
};

/** What dit_probe saw on this thread. */
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): what the probe records
thread_local probe_record probe_seen;

/** Clears the probe's record and the seam's counter of this thread. */
void probe_reset() noexcept {
    probe_seen = {};
    timing_entries = 0;
    timing_first_entry = nullptr;
}

/**
 * SHA-256 in Boost.Hash2's form whose every update records, before it hashes, whether DIT is set
 * and whether a detail::timing_guard has been entered on this thread since probe_reset.
 */
class dit_probe {
public:
    /** The block size, SHA-256's. */
    static constexpr std::size_t block_size = boost::hash2::sha2_256::block_size;
    /** The result, SHA-256's. */
    using result_type = boost::hash2::sha2_256::result_type;

    /** SHA-256 unseeded. */
    dit_probe() = default;

    /**
     * SHA-256 seeded by an integer, as Hash2's.
     *
     * @param seed The seed.
     */
    explicit dit_probe(std::uint64_t seed) : inner_(seed) {}

    /**
     * SHA-256 seeded by bytes, as Hash2's.
     *
     * @param seed The seed. @param size Its size.
     */
    dit_probe(void const* seed, std::size_t size) : inner_(seed, size) {}

    /**
     * Records the update, then hashes `size` bytes at `data`.
     *
     * @param data The bytes. @param size Their number.
     */
    void update(void const* data, std::size_t size) {
        ++probe_seen.updates;
        if (!webcpp::hash::detail::dit_is_set()) {
            ++probe_seen.updates_clear;
        }
        if (timing_entries == 0) {
            ++probe_seen.updates_unguarded;
        }
        inner_.update(data, size);
    }

    /** @return SHA-256's result. */
    result_type result() { return inner_.result(); }

private:
    boost::hash2::sha2_256 inner_;
};

/** A backend whose HMAC-SHA-256 is backends::hash2's over dit_probe. */
struct dit_probe_backend {};

}  // namespace
}  // namespace webcpp::test

namespace webcpp::hash::detail {

/** HMAC-SHA-256 on the probe's backend: backends::hash2's engine, over dit_probe. */
template <>
struct mac_engine<test::dit_probe_backend, macs::hmac<digests::sha2_256>>
    : hash2_hmac_engine<digests::sha2_256, test::dit_probe> {};

}  // namespace webcpp::hash::detail

namespace {

namespace hash = webcpp::hash;
namespace test = webcpp::test;
namespace backends = webcpp::hash::backends;

using probe_hmac = hash::hmac<test::dit_probe>;

constexpr std::array<std::uint8_t, 32> key{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
constexpr std::array<std::uint8_t, 16> salt{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};
constexpr std::array<std::uint8_t, 8> info{'c', 'o', 'n', 't', 'e', 'x', 't', 0};

/**
 * Sets or clears DIT for this thread, as a program can; only where the CPU has DIT, since the
 * instruction traps on a CPU without it.
 */
void force_dit([[maybe_unused]] bool set) {
#ifdef WEBCPP_HASH_DETAIL_TIMING_COVERED
    if (!hash::detail::cpu_has_dit()) {
        return;
    }
    hash::detail::write_dit(set ? hash::detail::dit_bit : 0);
#endif
}

// Reports, by `name`, a probe that never ran, an update before any guard, an update with DIT
// other than the CPU gives under a guard, or a thread left with DIT set.
void check_record(std::string const& name, test::probe_record const& seen, bool dit_set_after) {
    if (seen.updates == 0) {
        BOOST_ERROR((name + ": the probe never ran").c_str());
        return;
    }
    if (seen.updates_unguarded != 0) {
        BOOST_ERROR((name + ": " + std::to_string(seen.updates_unguarded) + " of " +
                     std::to_string(seen.updates) + " updates ran before any guard")
                        .c_str());
    }
    std::size_t const expected_clear = hash::detail::cpu_has_dit() ? 0 : seen.updates;
    if (seen.updates_clear != expected_clear) {
        BOOST_ERROR((name + ": " + std::to_string(seen.updates_clear) + " of " +
                     std::to_string(seen.updates) + " updates ran with DIT clear")
                        .c_str());
    }
    if (dit_set_after) {
        BOOST_ERROR((name + ": DIT left set").c_str());
    }
}

// Runs `call` from a thread with DIT clear, then checks what the probe saw during it.
template <class Call>
void during(std::string const& name, Call call) {
    force_dit(false);
    test::probe_reset();
    call();
    check_record(name, test::probe_seen, hash::detail::dit_is_set());
}

void synchronous() {
    during("hkdf_extract", [] {
        BOOST_TEST((hash::hkdf_extract<probe_hmac, backends::hash2>(salt, key)).has_value());
    });
    auto const prk = hash::hkdf_extract<probe_hmac, backends::hash2>(salt, key);
    if (!BOOST_TEST(prk.has_value())) {
        return;
    }
    std::array<std::uint8_t, 42> okm{};
    during("hkdf_expand", [&] {
        BOOST_TEST((hash::hkdf_expand<probe_hmac, backends::hash2>(okm, *prk, info)).has_value());
    });
    during("hkdf", [&] {
        BOOST_TEST((hash::hkdf<probe_hmac, backends::hash2>(okm, salt, key, info)).has_value());
    });
    std::array<std::uint8_t, 32> derived{};
    during("pbkdf2", [&] {
        BOOST_TEST((hash::pbkdf2<probe_hmac, backends::hash2>(derived, key, salt, 3)).has_value());
    });
    // The probe computes SHA-256: pbkdf2 over it gives the bytes of pbkdf2 over hmac_sha2_256.
    std::array<std::uint8_t, 32> plain{};
    BOOST_TEST(
        (hash::pbkdf2<hash::hmac_sha2_256, backends::hash2>(plain, key, salt, 3)).has_value());
    BOOST_TEST(derived == plain);

    std::array<std::uint8_t, 32> tag{};
    during("mac", [&] {
        BOOST_TEST((hash::mac<hash::macs::hmac<hash::digests::sha2_256>, test::dit_probe_backend>(
                        tag, key, info))
                       .has_value());
    });
    std::array<std::uint8_t, 32> plain_tag{};
    BOOST_TEST((hash::mac<hash::macs::hmac<hash::digests::sha2_256>, backends::hash2>(plain_tag,
                                                                                      key, info))
                   .has_value());
    BOOST_TEST(tag == plain_tag);
}

#ifdef WEBCPP_TEST_TIMING_DURING_ASYNC
namespace asio = webcpp::asio;

// Runs `probe` on the pool's thread and waits for its answer through a future.
template <class Probe>
auto on_pool(asio::thread_pool& pool, Probe probe) {
    std::promise<decltype(probe())> answer;
    auto future = answer.get_future();
    asio::post(pool, [&answer, &probe] { answer.set_value(probe()); });
    return future.get();
}

// async_pbkdf2 on a pool of one thread: the probe ran there, under the guard, with DIT set where
// the CPU has it; the record is read on the pool's thread after the completion.
void on_the_pool() {
    asio::io_context context;
    asio::thread_pool pool(1);
    on_pool(pool, [] {
        force_dit(false);
        test::probe_reset();
        return true;
    });
    test::probe_reset();
    std::array<std::uint8_t, 32> derived{};
    bool called = false;
    boost::system::error_code code;
    hash::async_pbkdf2<probe_hmac, backends::hash2>(
        pool.get_executor(), derived, key, salt, 3,
        asio::bind_executor(context.get_executor(), [&](boost::system::error_code done) {
            called = true;
            code = done;
        }));
    context.run();  // lint-run: the test's event loop
    BOOST_TEST(called);
    BOOST_TEST(!code);

    // What the pool's thread recorded, and whether it was left with DIT set.
    struct pool_state {
        test::probe_record seen;
        bool dit_set = false;
    };

    auto const worker = on_pool(pool, [] {
        return pool_state{.seen = test::probe_seen, .dit_set = hash::detail::dit_is_set()};
    });
    check_record("async_pbkdf2 on the pool's thread", worker.seen, worker.dit_set);
    // The calling thread computed nothing.
    BOOST_TEST_EQ(test::probe_seen.updates, 0u);
    BOOST_TEST(!hash::detail::dit_is_set());
    pool.join();
}
#endif

}  // namespace

int main() {
    synchronous();
#ifdef WEBCPP_TEST_TIMING_DURING_ASYNC
    on_the_pool();
#endif
    return webcpp::test::exit_status(boost::report_errors());
}
