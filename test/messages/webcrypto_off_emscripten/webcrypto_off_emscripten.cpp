// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// backends::webcrypto named in an asynchronous function off Emscripten stops with ruling R77's
// text (C-m4): the browser's WebCrypto exists on Emscripten alone.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so the
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/hash/async.hpp:* {{webcpp::hash: backends::webcrypto exists only on Emscripten: name a synchronous backend, or leave the default.}}
// clang-format on
#include <webcpp/hash/async.hpp>
#include <webcpp/hash/hmac.hpp>

#include <webcpp/asio/io_context.hpp>

#include <boost/system/error_code.hpp>

#include <array>
#include <cstdint>

int main() {
    webcpp::asio::io_context context;
    std::array<std::uint8_t, 32> output{};
    webcpp::hash::async_hkdf<webcpp::hash::hmac_sha2_256, webcpp::hash::backends::webcrypto>(
        context.get_executor(), output, {}, {}, {}, [](boost::system::error_code /*code*/) {});
    return 0;
}
