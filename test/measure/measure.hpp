// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// What every program of the measured table shares (spec section 4.2): the fixed inputs, which
// tools/hash/measure.py computes again to check each result, and the main of a program, which
// computes its cell's workload once and prints `result <hex>`. A program built for throughput
// (WEBCPP_HASH_MEASURE_TIME, at optimization=speed) also takes `--time`: after that first
// computation, which warms it up, it times the workload five times, each `repetitions` times over,
// and prints
// `compiler <version>`, `repetitions <n>` and `runs_ns <n> ...`, each run's nanoseconds. A
// program built for its size (at optimization=space) holds nothing but the computation and the
// printing of its result, so that its bytes are the backend's.

#ifndef WEBCPP_HASH_TEST_MEASURE_MEASURE_HPP
#define WEBCPP_HASH_TEST_MEASURE_MEASURE_HPP

#include <webcpp/hash/hmac.hpp>

#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <type_traits>

#ifdef WEBCPP_HASH_MEASURE_TIME
#include <chrono>
#include <cstring>
#endif

namespace webcpp::test::measure {

// The hmac of a key derivation's program: the build defines WEBCPP_HASH_MEASURE_HMAC as one of
// hmac.hpp's aliases (spec 4.2: a KDF is measured over hmac_sha2_256 and hmac_sha2_512).
#ifdef WEBCPP_HASH_MEASURE_HMAC
using hmac = webcpp::hash::WEBCPP_HASH_MEASURE_HMAC;
#endif

// The input of a hash: 1 MiB, byte i of which is (31 i + 7) mod 256.
inline constexpr std::size_t message_size = std::size_t{1} << 20U;

// The longest result a program prints: SHAKE128's, a block of its 168-byte rate (Boost.Hash2's
// result()).
inline constexpr std::size_t longest_result = 168;

// The bytes of a fixed input of n bytes, byte i of which is (a i + b) mod 256.
template <std::size_t N>
constexpr std::array<std::uint8_t, N> pattern(unsigned a, unsigned b) {
    std::array<std::uint8_t, N> bytes{};
    for (std::size_t i = 0; i < N; ++i) {
        bytes[i] = static_cast<std::uint8_t>((a * i + b) % 256U);
    }
    return bytes;
}

// The key of a MAC (SipHash, HMAC): 32 bytes of (13 i + 1) mod 256.
inline constexpr auto key = pattern<32>(13, 1);
// The salt of a key derivation: 32 bytes of (17 i + 3) mod 256 (its first 16 for PBKDF2,
// Argon2id and scrypt).
inline constexpr auto salt = pattern<32>(17, 3);
// HKDF's input keying material, and a password: 32 bytes of (19 i + 5) mod 256 (its first 16
// for a password).
inline constexpr auto secret = pattern<32>(19, 5);
// HKDF's context: 16 bytes of (23 i + 11) mod 256.
inline constexpr auto info = pattern<16>(23, 11);
// HKDF-Expand's pseudorandom key: 64 bytes of (29 i + 13) mod 256 (its first digest-size bytes).
inline constexpr auto prk = pattern<64>(29, 13);
// The length of a key derivation's output (spec 4.2).
inline constexpr std::size_t output_size = 32;

// The message of a hash, filled once by main before the first computation. Of internal linkage
// (one translation unit includes this file), so that it is zero-initialised storage that adds no
// byte to the program: an inline variable is a weak definition, which a Mach-O executable stores
// whole.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the program's one input
static std::array<std::uint8_t, message_size> message{};

// A result: its bytes, the first `size` of `bytes`.
struct result {
    std::array<std::uint8_t, longest_result> bytes{};
    std::size_t size = 0;
};

// The result of a Boost.Hash2-form type: an integer as its big-endian bytes, else its bytes.
template <class Value>
result result_of(Value const& value) {
    result r;
    if constexpr (std::unsigned_integral<Value>) {
        r.size = sizeof(Value);
        for (std::size_t i = 0; i < r.size; ++i) {
            r.bytes[i] = static_cast<std::uint8_t>(value >> (8U * (r.size - 1 - i)));
        }
    } else {
        r.size = value.size();
        for (std::size_t i = 0; i < r.size; ++i) {
            r.bytes[i] = static_cast<std::uint8_t>(value.data()[i]);
        }
    }
    return r;
}

// The result of a hash over the message, the type default-constructed.
template <class Hash>
result hash_message() {
    Hash h;
    h.update(message.data(), message.size());
    return result_of(h.result());
}

// The result of a MAC over the message, the type constructed with the key.
template <class Mac>
result mac_message() {
    Mac h(key.data(), key.size());
    h.update(message.data(), message.size());
    return result_of(h.result());
}

// The result of a key derivation that fills `output_size` bytes: `derive` calls the function on
// its output and returns its boost::system::result<void>; an error gives an empty result.
template <class Derive>
result derive(Derive derive) {
    result r;
    if (!derive(std::span<std::uint8_t>(r.bytes.data(), output_size)).has_value()) {
        return r;
    }
    r.size = output_size;
    return r;
}

// The first n bytes of a fixed input.
template <std::size_t N>
std::span<std::uint8_t const> first(std::array<std::uint8_t, N> const& bytes, std::size_t n) {
    return std::span<std::uint8_t const>(bytes).first(n);
}

// Prints `result <hex>`.
inline void print(result const& r) {
    std::fputs("result ", stdout);
    for (std::size_t i = 0; i < r.size; ++i) {
        std::printf("%02x", static_cast<unsigned>(r.bytes[i]));
    }
    std::fputs("\n", stdout);
}

// The main of a program: fills the message, computes once and prints the result; with `--time`,
// in a program built for throughput, times the computation as this file's head says. Exits with
// 1 when a computation fails (an empty result).
template <class Compute>
int run(int argc, char** argv, unsigned repetitions, Compute compute) {
    for (std::size_t i = 0; i < message.size(); ++i) {
        message[i] = static_cast<std::uint8_t>((31U * i + 7U) % 256U);
    }
    result const first = compute();
    if (first.size == 0) {
        std::fputs("the computation failed\n", stderr);
        return 1;
    }
    print(first);
#ifdef WEBCPP_HASH_MEASURE_TIME
    if (argc > 1 && std::strcmp(argv[1], "--time") == 0) {
        constexpr int runs = 5;
        std::printf("compiler %s\n", __VERSION__);
        std::printf("repetitions %u\n", repetitions);
        std::fputs("runs_ns", stdout);
        unsigned sink = 0;
        for (int run = 0; run < runs; ++run) {
            auto const start = std::chrono::steady_clock::now();
            for (unsigned k = 0; k < repetitions; ++k) {
                sink += compute().bytes[0];
            }
            auto const stop = std::chrono::steady_clock::now();
            auto const ns = std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start);
            std::printf(" %lld", static_cast<long long>(ns.count()));
        }
        std::printf("\nsink %u\n", sink);
    }
#else
    static_cast<void>(argc);
    static_cast<void>(argv);
    static_cast<void>(repetitions);
#endif
    return 0;
}

}  // namespace webcpp::test::measure

#endif  // WEBCPP_HASH_TEST_MEASURE_MEASURE_HPP
