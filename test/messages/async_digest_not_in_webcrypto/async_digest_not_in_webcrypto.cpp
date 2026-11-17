// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// async_digest over a digest WebCrypto lacks stops (spec 11.2): the cheap functions have an
// asynchronous form only for the algorithms the browser has.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so the
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/hash/async.hpp:* {{webcpp::hash: async_digest takes digests::sha1, digests::sha2_256, digests::sha2_384 or digests::sha2_512, the digests WebCrypto has: call digest_of for the others.}}
// clang-format on
#include <webcpp/hash/async.hpp>

#include <webcpp/asio/io_context.hpp>

#include <boost/system/error_code.hpp>

#include <array>
#include <cstdint>

int main() {
    webcpp::asio::io_context context;
    std::array<std::uint8_t, 64> output{};
    webcpp::hash::async_digest<webcpp::hash::digests::blake2b>(
        context.get_executor(), output, {}, [](boost::system::error_code /*code*/) {});
    return 0;
}
