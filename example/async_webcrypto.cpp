// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// backends::webcrypto on Emscripten: a password manager in the browser derives the key of its
// vault from the master password with WebCrypto's PBKDF2 (600,000 iterations of HMAC-SHA-256,
// OWASP's figure for it), which the browser runs off the page's thread, then hashes a file with
// WebCrypto's SHA-256, one after the other. The page's event loop is an io_context run on the
// calling thread; it stays free while the browser works, and each completion arrives through it.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/async.hpp>
#include <webcpp/hash/backends/webcrypto.hpp>
#include <webcpp/hash/hmac.hpp>

#include <webcpp/asio/io_context.hpp>

#include <boost/system/error_code.hpp>

#include <array>
#include <cstdint>
#include <iostream>

int main() {
    using webcpp::hash::backends::webcrypto;
    webcpp::asio::io_context loop;

    // The spans are the program's until the completion: they outlive the loop's run.
    auto const password = example::bytes("correct horse battery staple");
    auto const salt = example::bytes("per-user salt 01");
    auto const file = example::bytes("abc");
    std::array<std::uint8_t, 32> vault_key{};
    std::array<std::uint8_t, 32> id{};

    // The vault's key first; the file's hash once the key is there, from the key's handler.
    webcpp::hash::async_pbkdf2<webcpp::hash::hmac_sha2_256, webcrypto>(
        loop.get_executor(), vault_key, password, salt, 600000,
        [&](boost::system::error_code code) {
            if (code) {
                std::cerr << code.message() << '\n';
                return;
            }
            std::cout << "vault key " << example::hex(vault_key) << '\n';
            webcpp::hash::async_digest<webcpp::hash::digests::sha2_256, webcrypto>(
                loop.get_executor(), id, file, [&](boost::system::error_code hashed) {
                    if (hashed) {
                        std::cerr << hashed.message() << '\n';
                        return;
                    }
                    std::cout << "file id " << example::hex(id) << '\n';
                });
        });

    loop.run();  // lint-run: the program's event loop
}

// end::example[]
