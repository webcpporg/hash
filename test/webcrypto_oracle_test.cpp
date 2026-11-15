// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// WebCrypto, node's `globalThis.crypto.subtle`, as an outside oracle (spec 7.4): 200 random cases
// per function and per hash (SHA-1, SHA-256, SHA-384, SHA-512) of the digest, the hmac, HKDF and
// PBKDF2, compared with Boost.Hash2's digests and hmacs and with every backend linked here:
// backends::hash2, backends::bearssl, and backends::sodium for its two HKDFs (SHA-256 and
// SHA-512). No WebCrypto backend exists: the oracle only checks the others. Each WebCrypto call
// is an EM_ASYNC_JS function, which suspends the program (the default JSPI link) and returns its
// bytes through a heap buffer.

#include <webcpp/hash/algorithms.hpp>
#include <webcpp/hash/backends/bearssl.hpp>
#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/backends/sodium.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/hash/pbkdf2.hpp>

#include <boost/core/lightweight_test.hpp>

#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"

#include <emscripten/em_js.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <random>
#include <span>
#include <vector>

namespace hash = webcpp::hash;
using webcpp::test::to_hex;

// The cases per function and hash, and the seed that makes a failure reproducible.
constexpr std::size_t cases = 200;
constexpr std::uint64_t seed = 0x57656243727970ULL;

// Each function returns the byte count it wrote to `out`, or -1 when WebCrypto refused (the
// message goes to the console). `alg` indexes SHA-1, SHA-256, SHA-384, SHA-512. Inputs are copied
// before the first await; the heap is read again after it.
// clang-format off
EM_ASYNC_JS(int, subtle_digest, (int alg, const std::uint8_t* msg, std::size_t msg_size,
                                 std::uint8_t* out), {
    try {
        const names = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];
        const data = HEAPU8.slice(msg, msg + msg_size);
        const result = new Uint8Array(await globalThis.crypto.subtle.digest(names[alg], data));
        HEAPU8.set(result, out);
        return result.length;
    } catch (e) {
        console.error("subtle.digest: " + e);
        return -1;
    }
});

EM_ASYNC_JS(int, subtle_hmac, (int alg, const std::uint8_t* key, std::size_t key_size,
                               const std::uint8_t* msg, std::size_t msg_size, std::uint8_t* out), {
    try {
        const names = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];
        const key_bytes = HEAPU8.slice(key, key + key_size);
        const data = HEAPU8.slice(msg, msg + msg_size);
        const imported = await globalThis.crypto.subtle.importKey(
            "raw", key_bytes, {name: "HMAC", hash: names[alg]}, false, ["sign"]);
        const result = new Uint8Array(await globalThis.crypto.subtle.sign("HMAC", imported, data));
        HEAPU8.set(result, out);
        return result.length;
    } catch (e) {
        console.error("subtle.sign: " + e);
        return -1;
    }
});

EM_ASYNC_JS(int, subtle_hkdf, (int alg, const std::uint8_t* ikm, std::size_t ikm_size,
                               const std::uint8_t* salt, std::size_t salt_size,
                               const std::uint8_t* info, std::size_t info_size,
                               std::size_t out_size, std::uint8_t* out), {
    try {
        const names = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];
        const material = HEAPU8.slice(ikm, ikm + ikm_size);
        const params = {name: "HKDF", hash: names[alg],
                        salt: HEAPU8.slice(salt, salt + salt_size),
                        info: HEAPU8.slice(info, info + info_size)};
        const imported = await globalThis.crypto.subtle.importKey(
            "raw", material, "HKDF", false, ["deriveBits"]);
        const result = new Uint8Array(
            await globalThis.crypto.subtle.deriveBits(params, imported, out_size * 8));
        HEAPU8.set(result, out);
        return result.length;
    } catch (e) {
        console.error("subtle.deriveBits (HKDF): " + e);
        return -1;
    }
});

EM_ASYNC_JS(int, subtle_pbkdf2, (int alg, const std::uint8_t* password, std::size_t password_size,
                                 const std::uint8_t* salt, std::size_t salt_size,
                                 std::uint32_t iterations, std::size_t out_size,
                                 std::uint8_t* out), {
    try {
        const names = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];
        const material = HEAPU8.slice(password, password + password_size);
        const params = {name: "PBKDF2", hash: names[alg],
                        salt: HEAPU8.slice(salt, salt + salt_size), iterations: iterations};
        const imported = await globalThis.crypto.subtle.importKey(
            "raw", material, "PBKDF2", false, ["deriveBits"]);
        const result = new Uint8Array(
            await globalThis.crypto.subtle.deriveBits(params, imported, out_size * 8));
        HEAPU8.set(result, out);
        return result.length;
    } catch (e) {
        console.error("subtle.deriveBits (PBKDF2): " + e);
        return -1;
    }
});
// clang-format on

namespace {

using bytes = std::vector<std::uint8_t>;

// A byte string of random length in [min_size, max_size].
bytes random_bytes(std::mt19937_64& rng, std::size_t min_size, std::size_t max_size) {
    const auto size = std::uniform_int_distribution<std::size_t>(min_size, max_size)(rng);
    bytes out(size);
    for (auto& b : out) {
        b = static_cast<std::uint8_t>(rng() & 0xffU);
    }
    return out;
}

std::size_t random_size(std::mt19937_64& rng, std::size_t min_size, std::size_t max_size) {
    return std::uniform_int_distribution<std::size_t>(min_size, max_size)(rng);
}

// The hash a row of the table names: its WebCrypto index, its Hash2 digest and hmac.
template <int Alg, class Hash, class Hmac>
struct row {
    static constexpr int alg = Alg;
    using hash_type = Hash;
    using hmac_type = Hmac;
    static constexpr std::size_t digest_size = typename Hmac::result_type().size();
};

using sha1 = row<0, hash::sha1_160, hash::hmac_sha1_160>;
using sha256 = row<1, hash::sha2_256, hash::hmac_sha2_256>;
using sha384 = row<2, hash::sha2_384, hash::hmac_sha2_384>;
using sha512 = row<3, hash::sha2_512, hash::hmac_sha2_512>;

// A backend's derived bytes against the oracle's, when the backend has the kdf for the hmac.
template <class Row, class Backend>
void check_hkdf_backend(bytes const& expected, bytes const& ikm, bytes const& salt,
                        bytes const& info, std::size_t index) {
    using hmac = typename Row::hmac_type;
    if constexpr (hash::backend_has_v<Backend, hash::kdfs::hkdf, hmac>) {
        bytes okm(expected.size());
        const auto done = hash::hkdf<hmac, Backend>(okm, salt, ikm, info);
        BOOST_TEST(done.has_value());
        if (okm != expected) {
            std::printf("hkdf alg %d case %zu: backend differs from WebCrypto\n", Row::alg, index);
            BOOST_ERROR("hkdf differs from WebCrypto");
        }
    }
}

template <class Row, class Backend>
void check_pbkdf2_backend(bytes const& expected, bytes const& password, bytes const& salt,
                          std::uint32_t iterations, std::size_t index) {
    using hmac = typename Row::hmac_type;
    if constexpr (hash::backend_has_v<Backend, hash::kdfs::pbkdf2, hmac>) {
        bytes derived(expected.size());
        const auto done = hash::pbkdf2<hmac, Backend>(derived, password, salt, iterations);
        BOOST_TEST(done.has_value());
        if (derived != expected) {
            std::printf("pbkdf2 alg %d case %zu: backend differs from WebCrypto\n", Row::alg,
                        index);
            BOOST_ERROR("pbkdf2 differs from WebCrypto");
        }
    }
}

template <class Row>
void check_digest(std::mt19937_64& rng) {
    for (std::size_t i = 0; i < cases; ++i) {
        // Past one block of SHA-512 (128 bytes) and across padding's edges.
        const bytes msg = random_bytes(rng, 0, 400);
        bytes oracle(Row::digest_size);
        const int got = subtle_digest(Row::alg, msg.data(), msg.size(), oracle.data());
        BOOST_TEST_EQ(got, static_cast<int>(Row::digest_size));
        typename Row::hash_type h;
        h.update(msg.data(), msg.size());
        const auto digest = h.result();
        const bytes ours(digest.data(), digest.data() + digest.size());
        BOOST_TEST(ours == oracle);
    }
}

template <class Row>
void check_hmac(std::mt19937_64& rng) {
    for (std::size_t i = 0; i < cases; ++i) {
        // Keys shorter than, equal to and longer than the block; WebCrypto refuses an empty one.
        const bytes key = random_bytes(rng, 1, 300);
        const bytes msg = random_bytes(rng, 0, 300);
        bytes oracle(Row::digest_size);
        const int got =
            subtle_hmac(Row::alg, key.data(), key.size(), msg.data(), msg.size(), oracle.data());
        BOOST_TEST_EQ(got, static_cast<int>(Row::digest_size));
        typename Row::hmac_type mac(key.data(), key.size());
        mac.update(msg.data(), msg.size());
        const auto tag = mac.result();
        const bytes ours(tag.data(), tag.data() + tag.size());
        BOOST_TEST(ours == oracle);
    }
}

template <class Row>
void check_hkdf(std::mt19937_64& rng) {
    for (std::size_t i = 0; i < cases; ++i) {
        const bytes ikm = random_bytes(rng, 1, 100);
        const bytes salt = random_bytes(rng, 0, 100);
        const bytes info = random_bytes(rng, 0, 100);
        // 1 to 255 times the digest size is HKDF's whole range; short outputs dominate.
        const std::size_t length =
            random_size(rng, 1, i % 10 == 0 ? 255 * Row::digest_size : 3 * Row::digest_size + 7);
        bytes oracle(length);
        const int got = subtle_hkdf(Row::alg, ikm.data(), ikm.size(), salt.data(), salt.size(),
                                    info.data(), info.size(), length, oracle.data());
        BOOST_TEST_EQ(got, static_cast<int>(length));
        check_hkdf_backend<Row, hash::backends::hash2>(oracle, ikm, salt, info, i);
        check_hkdf_backend<Row, hash::backends::bearssl>(oracle, ikm, salt, info, i);
        check_hkdf_backend<Row, hash::backends::sodium>(oracle, ikm, salt, info, i);
    }
}

template <class Row>
void check_pbkdf2(std::mt19937_64& rng) {
    for (std::size_t i = 0; i < cases; ++i) {
        const bytes password = random_bytes(rng, 0, 100);
        const bytes salt = random_bytes(rng, 0, 100);
        const auto iterations = static_cast<std::uint32_t>(random_size(rng, 1, 64));
        const std::size_t length = random_size(rng, 1, 2 * Row::digest_size + 9);
        bytes oracle(length);
        const int got = subtle_pbkdf2(Row::alg, password.data(), password.size(), salt.data(),
                                      salt.size(), iterations, length, oracle.data());
        BOOST_TEST_EQ(got, static_cast<int>(length));
        check_pbkdf2_backend<Row, hash::backends::hash2>(oracle, password, salt, iterations, i);
        check_pbkdf2_backend<Row, hash::backends::bearssl>(oracle, password, salt, iterations, i);
    }
}

template <class Row>
void check_row(std::uint64_t row_seed) {
    std::mt19937_64 rng(row_seed);
    check_digest<Row>(rng);
    check_hmac<Row>(rng);
    check_hkdf<Row>(rng);
    check_pbkdf2<Row>(rng);
}

}  // namespace

int main() {
    std::printf("webcrypto oracle: seed %llu\n", static_cast<unsigned long long>(seed));
    check_row<sha1>(seed + 1);
    check_row<sha256>(seed + 2);
    check_row<sha384>(seed + 3);
    check_row<sha512>(seed + 4);
    return webcpp::test::exit_status(boost::report_errors());
}
