// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The throughput of PBKDF2-HMAC-SHA-512 (spec 4.3): 64 bytes derived from the password "password"
// and the salt "salt" at 1,000,000 iterations, by each backend that has it on the target:
//
//   hash2        webcpp::hash::pbkdf2 on backends::hash2, every target;
//   openssl      webcpp::hash::pbkdf2 on backends::openssl, native, wasip2 and wasip3;
//   sodium-hmac  RFC 8018's loop written below over libsodium's crypto_auth_hmacsha512_*, every
//                target: a measurement of libsodium's HMAC-SHA-512 in PBKDF2's shape, never part
//                of the library (libsodium has no PBKDF2).
//
// Run with a variant, `pbkdf2_sha512 <variant> [--runs N]` (or `--list`, which prints the variants
// this build has), it derives the key N times (3 by default) and prints one JSON line: the variant,
// target, compiler, iterations, every run's milliseconds, their median, minimum and maximum, and
// whether every derived key equals the independent value. Run with no argument, it is the
// correctness test: every variant the program has derives the key once, after agreeing with
// backends::hash2 at 1,000 iterations, and the program exits 0 only when each key equals the
// independent value (Python's hashlib.pbkdf2_hmac over OpenSSL, computed outside this repository's
// code). A measurement never fails on its time.

#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/pbkdf2.hpp>

#ifdef WEBCPP_HASH_HAS_SODIUM
#include <sodium/crypto_auth_hmacsha512.h>
#include <sodium/utils.h>
#endif

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace hash = webcpp::hash;

namespace {

constexpr std::uint64_t full_iterations = 1'000'000;
constexpr std::uint64_t check_iterations = 1'000;
constexpr std::size_t key_size = 64;

// The independent values: hashlib.pbkdf2_hmac("sha512", b"password", b"salt", c, 64).hex().
constexpr std::string_view expected_full =
    "116d1fea4d3192c8c017577b516416ad17136595a9829b66a7c1fbdb57b6f9818760eb8d5c9c71aab2365a35df7552"
    "ea2aa188e8ece933a349f908ebe2958a03";
constexpr std::string_view expected_check =
    "afe6c5530785b6cc6b1c6453384731bd5ee432ee549fd42fb6695779ad8a1c5bf59de69c48f774efc4007d5298f903"
    "3c0241d5ab69305e7b64eceeb8d834cfec";

using key_bytes = std::array<std::uint8_t, key_size>;

std::span<std::uint8_t const> bytes_of(std::string_view text) {
    return {reinterpret_cast<std::uint8_t const*>(text.data()), text.size()};
}

std::string to_hex(key_bytes const& key) {
    constexpr std::string_view digits = "0123456789abcdef";
    std::string out;
    for (const std::uint8_t b : key) {
        out += digits[b >> 4U];
        out += digits[b & 15U];
    }
    return out;
}

// Derives the key by backend Backend; false when the library refused.
template <class Backend>
bool derive_library(key_bytes& key, std::uint64_t iterations) {
    return hash::pbkdf2<hash::hmac_sha2_512, Backend>(key, bytes_of("password"), bytes_of("salt"),
                                                      iterations)
        .has_value();
}

#ifdef WEBCPP_HASH_HAS_SODIUM
// RFC 8018's PBKDF2 for one block (the key is one HMAC-SHA-512 output) over libsodium's streaming
// HMAC-SHA-512. The keyed state is built once and copied for each iteration, the shape the other
// two backends have, so that the measurement is of the hash and not of the key schedule.
bool derive_sodium_hmac(key_bytes& key, std::uint64_t iterations) {
    const std::string_view password = "password";
    const std::string_view salt = "salt";
    crypto_auth_hmacsha512_state keyed;
    if (crypto_auth_hmacsha512_init(&keyed, bytes_of(password).data(), password.size()) != 0) {
        return false;
    }
    const std::array<std::uint8_t, 4> block_index{0, 0, 0, 1};
    key_bytes u{};
    {
        crypto_auth_hmacsha512_state state = keyed;
        crypto_auth_hmacsha512_update(&state, bytes_of(salt).data(), salt.size());
        crypto_auth_hmacsha512_update(&state, block_index.data(), block_index.size());
        crypto_auth_hmacsha512_final(&state, u.data());
    }
    key = u;
    for (std::uint64_t i = 1; i < iterations; ++i) {
        crypto_auth_hmacsha512_state state = keyed;
        crypto_auth_hmacsha512_update(&state, u.data(), u.size());
        crypto_auth_hmacsha512_final(&state, u.data());
        for (std::size_t j = 0; j < key_size; ++j) {
            key[j] ^= u[j];
        }
    }
    sodium_memzero(&keyed, sizeof keyed);
    return true;
}
#endif

struct variant {
    std::string_view name;
    bool (*derive)(key_bytes&, std::uint64_t);
};

// The variants this program was built with, in the brief's order.
std::vector<variant> variants() {
    std::vector<variant> all;
    all.push_back({.name = "hash2", .derive = derive_library<hash::backends::hash2>});
#ifdef WEBCPP_HASH_HAS_OPENSSL
    all.push_back({.name = "openssl", .derive = derive_library<hash::backends::openssl>});
#endif
#ifdef WEBCPP_HASH_HAS_SODIUM
    all.push_back({.name = "sodium-hmac", .derive = derive_sodium_hmac});
#endif
    return all;
}

constexpr std::string_view target_name() {
#ifdef WEBCPP_TARGET_WASIP2
    return "wasip2";
#elif defined(WEBCPP_TARGET_WASIP3)
    return "wasip3";
#elif defined(WEBCPP_TARGET_EMSCRIPTEN)
    return "emscripten";
#else
    return "native";
#endif
}

// The key a variant derives at `iterations` equals `expected`, and the time it took in
// milliseconds goes to `elapsed`.
bool derive_checked(const variant& v, std::uint64_t iterations, std::string_view expected,
                    double& elapsed) {
    key_bytes key{};
    const auto start = std::chrono::steady_clock::now();
    const bool done = v.derive(key, iterations);
    const auto stop = std::chrono::steady_clock::now();
    elapsed = std::chrono::duration<double, std::milli>(stop - start).count();
    return done && to_hex(key) == expected;
}

// Each variant at 1,000 iterations equals the independent value, hence backends::hash2's too.
bool agree_at_check_iterations(const std::vector<variant>& all) {
    key_bytes reference{};
    if (!derive_library<hash::backends::hash2>(reference, check_iterations) ||
        to_hex(reference) != expected_check) {
        (void)std::fprintf(stderr, "backends::hash2 disagrees with the independent value at %llu\n",
                           static_cast<unsigned long long>(check_iterations));
        return false;
    }
    bool good = true;
    for (const variant& v : all) {
        double ignored = 0;
        if (!derive_checked(v, check_iterations, expected_check, ignored)) {
            (void)std::fprintf(stderr, "%.*s disagrees with backends::hash2 at %llu iterations\n",
                               static_cast<int>(v.name.size()), v.name.data(),
                               static_cast<unsigned long long>(check_iterations));
            good = false;
        }
    }
    return good;
}

int measure(const variant& v, int runs) {
    std::vector<double> times;
    bool correct = true;
    for (int i = 0; i < runs; ++i) {
        double elapsed = 0;
        correct = derive_checked(v, full_iterations, expected_full, elapsed) && correct;
        times.push_back(elapsed);
    }
    std::vector<double> sorted = times;
    std::ranges::sort(sorted);
    const std::size_t n = sorted.size();
    const double median = n % 2 == 1 ? sorted[n / 2] : (sorted[(n / 2) - 1] + sorted[n / 2]) / 2;
#ifdef __VERSION__
    const char* compiler = __VERSION__;
#else
    const char* compiler = "unknown";
#endif
    std::printf(
        "{\"variant\":\"%.*s\",\"target\":\"%.*s\",\"compiler\":\"%s\","
        "\"iterations\":%llu,\"runs_ms\":[",
        static_cast<int>(v.name.size()), v.name.data(), static_cast<int>(target_name().size()),
        target_name().data(), compiler, static_cast<unsigned long long>(full_iterations));
    for (std::size_t i = 0; i < n; ++i) {
        std::printf("%s%.3f", i == 0 ? "" : ",", times[i]);
    }
    std::printf("],\"median_ms\":%.3f,\"min_ms\":%.3f,\"max_ms\":%.3f,\"key_correct\":%s}\n",
                median, sorted.front(), sorted.back(), correct ? "true" : "false");
    return correct ? 0 : 1;
}

// The exit codes: 0 the keys are right, 1 a wrong key, 64 a usage error, 65 a variant this build
// does not have. A time is never an exit code.
constexpr int exit_wrong_key = 1;
constexpr int exit_usage = 64;
constexpr int exit_no_variant = 65;

// `--runs N` parsed whole, N a positive int up to 1,000; false otherwise.
bool parse_runs(std::string_view text, int& runs) {
    int value = 0;
    const char* const first = text.data();
    const char* const last = first + text.size();
    const auto [end, error] = std::from_chars(first, last, value);
    if (error != std::errc{} || end != last || value < 1 || value > 1000) {
        return false;
    }
    runs = value;
    return true;
}

// What the command line asks: every variant checked (no argument), the list, or one variant
// measured over `runs` runs.
struct request {
    bool list = false;
    std::string_view variant;
    int runs = 3;
};

// The request of `args` (argv after the program's name); false on a usage error.
bool parse(const std::vector<std::string_view>& args, request& asked) {
    if (args.size() == 1 && args[0] == "--list") {
        asked.list = true;
        return true;
    }
    if (args.empty()) {
        return true;
    }
    if (args[0].starts_with("--") || args.size() == 2 || args.size() > 3) {
        return false;
    }
    if (args.size() == 3 && (args[1] != "--runs" || !parse_runs(args[2], asked.runs))) {
        return false;
    }
    asked.variant = args[0];
    return true;
}

// Each variant at the full count of iterations derives the expected key; prints one line each.
int check_every(const std::vector<variant>& all) {
    bool good = true;
    for (const variant& v : all) {
        double elapsed = 0;
        const bool same = derive_checked(v, full_iterations, expected_full, elapsed);
        std::printf("%.*s: key %s\n", static_cast<int>(v.name.size()), v.name.data(),
                    same ? "correct" : "WRONG");
        good = good && same;
    }
    return good ? 0 : exit_wrong_key;
}

}  // namespace

int main(int argc, char** argv) {
    const std::vector<variant> all = variants();
    const std::vector<std::string_view> args(argv + 1, argv + argc);
    request asked;
    if (!parse(args, asked)) {
        (void)std::fprintf(stderr, "usage: pbkdf2_sha512 [--list | <variant> [--runs N]]\n");
        return exit_usage;
    }
    if (asked.list) {
        for (const variant& v : all) {
            std::printf("%.*s\n", static_cast<int>(v.name.size()), v.name.data());
        }
        return 0;
    }
    if (!agree_at_check_iterations(all)) {
        return exit_wrong_key;
    }
    if (asked.variant.empty()) {
        return check_every(all);
    }
    for (const variant& v : all) {
        if (v.name == asked.variant) {
            return measure(v, asked.runs) == 0 ? 0 : exit_wrong_key;
        }
    }
    (void)std::fprintf(stderr, "this build has no variant '%.*s'\n",
                       static_cast<int>(asked.variant.size()), asked.variant.data());
    return exit_no_variant;
}
