// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// async_hkdf on its default backend, backends::hash2: RFC 5869's test case A.1, as hkdf.cpp
// derives it, through an event loop. The completion runs from the loop, after the call has
// returned, on every target; on Emscripten the same call names backends::webcrypto to reach the
// browser's WebCrypto.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/async.hpp>
#include <webcpp/hash/hmac.hpp>

#include <webcpp/asio/io_context.hpp>

#include <boost/system/error_code.hpp>

#include <array>
#include <cstdint>
#include <iostream>

int main() {
    auto const ikm = example::from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    auto const salt = example::from_hex("000102030405060708090a0b0c");
    auto const info = example::from_hex("f0f1f2f3f4f5f6f7f8f9");

    webcpp::asio::io_context loop;
    // The spans are the program's until the completion: okm and the inputs outlive the loop's run.
    std::array<std::uint8_t, 42> okm{};
    bool returned = false;
    webcpp::hash::async_hkdf<webcpp::hash::hmac_sha2_256>(
        loop.get_executor(), okm, salt, ikm, info, [&](boost::system::error_code code) {
            if (code) {
                std::cerr << code.message() << '\n';
                return;
            }
            std::cout << "okm " << example::hex(okm) << '\n';
            std::cout << "completed after the call returned: " << (returned ? "yes" : "no") << '\n';
        });
    returned = true;
    loop.run();
}

// end::example[]
