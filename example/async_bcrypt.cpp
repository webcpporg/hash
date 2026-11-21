// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// async_bcrypt and async_bcrypt_verify on backends::botan, on a thread pool, each completion
// brought back to the program's event loop: a login server makes the string of a new password,
// then checks a password typed later against it, without holding its loop for either. The string
// is bcrypt.cpp's, the same password, salt and cost. Built where the program has threads:
// natively, and on Emscripten with -pthread (b2's threading=multi).

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/async.hpp>
#include <webcpp/hash/bcrypt.hpp>

#include <webcpp/asio/bind_executor.hpp>
#include <webcpp/asio/io_context.hpp>
#include <webcpp/asio/thread_pool.hpp>

#include <boost/system/error_code.hpp>

#include <array>
#include <iostream>
#include <string_view>

int main() {
    namespace hash = webcpp::hash;
    using hash::backends::botan;
    auto const salt = example::from_hex("10410410410410410410410410410410");
    auto const password = example::bytes("U*U");

    webcpp::asio::io_context loop;
    webcpp::asio::thread_pool pool(1);
    std::array<char, hash::bcrypt_hash_size> stored{};
    std::string_view const text(stored.data(), stored.size());

    // The work runs on the pool's thread; bind_executor brings each completion back to the loop.
    hash::async_bcrypt<botan>(
        pool.get_executor(), stored, password, salt, {.cost = 5, .version = 'a'},
        webcpp::asio::bind_executor(loop.get_executor(), [&](boost::system::error_code code) {
            if (code) {
                std::cerr << code.message() << '\n';
                return;
            }
            std::cout << "bcrypt " << text << '\n';
            hash::async_bcrypt_verify<botan>(
                pool.get_executor(), password, text,
                webcpp::asio::bind_executor(
                    loop.get_executor(), [](boost::system::error_code checked, bool same) {
                        if (checked) {
                            std::cerr << checked.message() << '\n';
                            return;
                        }
                        std::cout << "verified: " << (same ? "yes" : "no") << '\n';
                    }));
        }));
    loop.run();  // lint-run: the program's event loop
    pool.join();
}

// end::example[]
