// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// async_bcrypt in a build without threads stops with spec 11.5's text, which names bcrypt:
// natively, where every build has threads, the developer's WEBCPP_HASH_NO_THREADS removes them; on
// wasip2 and wasip3 there are none. No Botan is needed: the refusal precedes any engine.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so the
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/hash/async.hpp:* {{webcpp::hash: async_bcrypt runs on another thread and needs a build with threads (natively, remove WEBCPP_HASH_NO_THREADS; on Emscripten, link with -pthread). Without threads, call bcrypt.}}
// clang-format on
#include <webcpp/hash/async.hpp>
#include <webcpp/hash/bcrypt.hpp>

#include <webcpp/asio/io_context.hpp>

#include <boost/system/error_code.hpp>

#include <array>
#include <cstdint>

int main() {
    webcpp::asio::io_context context;
    std::array<char, webcpp::hash::bcrypt_hash_size> output{};
    std::array<std::uint8_t, webcpp::hash::bcrypt_salt_size> const salt{};
    webcpp::hash::async_bcrypt<webcpp::hash::backends::botan>(
        context.get_executor(), output, {}, salt, {}, [](boost::system::error_code /*code*/) {});
    return 0;
}
