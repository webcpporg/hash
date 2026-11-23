// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// backends::sodium on a second thread after the first has used it, in a build with threads
// (natively, and on Emscripten with -pthread under node). On Emscripten libsodium's random source
// is a JavaScript function that sodium_init sets on the thread that calls it first, and its
// Argon2 fills the output with random bytes before it hashes: a second thread, a Web Worker,
// stopped the program with "Module.getRandomValue is not a function" until every engine readied
// the source on its own thread. argon2id and scrypt give the first thread's results on the
// second.

#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/backends/sodium.hpp>
#include <webcpp/hash/scrypt.hpp>

#include <boost/core/lightweight_test.hpp>

#include <webcpp/test/exit_status.hpp>

#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <thread>

namespace hash = webcpp::hash;

namespace {

std::span<std::uint8_t const> bytes_of(std::string_view text) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): the text's bytes
    return {reinterpret_cast<std::uint8_t const*>(text.data()), text.size()};
}

}  // namespace

int main() {
    auto const password = bytes_of("password");
    std::array<std::uint8_t, hash::argon2id_salt_size> const salt{0x5a};
    hash::argon2id_parameters const costs{.passes = 1, .memory = 32768};
    hash::scrypt_parameters const scrypt_costs{.cost = 16, .block_size = 1, .parallelism = 1};

    std::array<std::uint8_t, 32> first{};
    std::array<std::uint8_t, 64> first_scrypt{};
    BOOST_TEST(hash::argon2id(first, password, salt, costs).has_value());
    BOOST_TEST(hash::scrypt(first_scrypt, password, salt, scrypt_costs).has_value());

    std::array<std::uint8_t, 32> second{};
    std::array<std::uint8_t, 64> second_scrypt{};
    bool derived = false;
    bool derived_scrypt = false;
    std::thread other([&] {
        derived = hash::argon2id(second, password, salt, costs).has_value();
        derived_scrypt = hash::scrypt(second_scrypt, password, salt, scrypt_costs).has_value();
    });
    other.join();
    BOOST_TEST(derived);
    BOOST_TEST(derived_scrypt);
    BOOST_TEST(second == first);
    BOOST_TEST(second_scrypt == first_scrypt);
    return webcpp::test::exit_status(boost::report_errors());
}
