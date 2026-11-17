// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// async_argon2id at libsodium's interactive costs (2 passes over 64 MiB) on a thread pool, while
// the program's event loop goes on: a timer of 1 ms on the loop fires before the tag is ready. The
// tag is argon2id.cpp's, the same password and salt. Built where the program has threads: natively,
// and on Emscripten with -pthread (b2's threading=multi).

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/async.hpp>

#include <webcpp/asio/bind_executor.hpp>
#include <webcpp/asio/io_context.hpp>
#include <webcpp/asio/steady_timer.hpp>
#include <webcpp/asio/thread_pool.hpp>

#include <boost/system/error_code.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <iostream>

int main() {
    auto const salt = example::from_hex("000102030405060708090a0b0c0d0e0f");
    auto const password = example::bytes("correct horse battery staple");

    webcpp::asio::io_context loop;
    webcpp::asio::thread_pool pool(1);
    std::array<std::uint8_t, 32> tag{};
    bool ticked = false;

    // The work runs on the pool's thread; bind_executor brings the completion back to the loop's.
    webcpp::hash::async_argon2id(
        pool.get_executor(), tag, password, salt, webcpp::hash::argon2id_interactive,
        webcpp::asio::bind_executor(loop.get_executor(), [&](boost::system::error_code code) {
            if (code) {
                std::cerr << code.message() << '\n';
                return;
            }
            std::cout << "argon2id " << example::hex(tag) << '\n';
            std::cout << "the loop ran meanwhile: " << (ticked ? "yes" : "no") << '\n';
        }));

    webcpp::asio::steady_timer timer(loop, std::chrono::milliseconds(1));
    timer.async_wait([&](boost::system::error_code code) { ticked = !code; });
    loop.run();
    pool.join();
}

// end::example[]
