// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// async_argon2 in a build without threads stops with spec 11.5's text, which names argon2 (ruling
// R70): natively, where every build has threads, the developer's WEBCPP_HASH_NO_THREADS removes
// them; on wasip2 and wasip3 there are none.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so the
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/hash/async.hpp:* {{webcpp::hash: async_argon2 runs on another thread and needs a build with threads (natively, remove WEBCPP_HASH_NO_THREADS; on Emscripten, link with -pthread). Without threads, call argon2.}}
// clang-format on
#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/async.hpp>

#include <webcpp/asio/io_context.hpp>

#include <boost/system/error_code.hpp>

#include <array>
#include <cstdint>

int main() {
    webcpp::asio::io_context context;
    std::array<std::uint8_t, 32> output{};
    std::array<std::uint8_t, 16> const salt{};
    webcpp::hash::async_argon2<webcpp::hash::kdfs::argon2id>(
        context.get_executor(), output, {}, salt,
        webcpp::hash::argon2_parameters{.passes = 3, .memory_kibibytes = 65536},
        [](boost::system::error_code /*code*/) {});
    return 0;
}
