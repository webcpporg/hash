// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// async_pbkdf2 in a build without threads stops with spec 11.5's text, which names pbkdf2 (ruling
// R70): natively, where every build has threads, the developer's WEBCPP_HASH_NO_THREADS removes
// them; on wasip2 and wasip3 there are none.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so the
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/hash/async.hpp:* {{webcpp::hash: async_pbkdf2 runs on another thread and needs a build with threads (natively, remove WEBCPP_HASH_NO_THREADS; on Emscripten, link with -pthread). Without threads, call pbkdf2.}}
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
    webcpp::hash::async_pbkdf2<webcpp::hash::hmac_sha2_256>(
        context.get_executor(), output, {}, {}, 1, [](boost::system::error_code /*code*/) {});
    return 0;
}
