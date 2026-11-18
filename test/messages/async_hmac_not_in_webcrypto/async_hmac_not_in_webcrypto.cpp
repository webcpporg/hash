// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// async_hmac over an hmac WebCrypto lacks stops (spec 11.2): the cheap functions have an
// asynchronous form only for the algorithms the browser has.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so the
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/hash/async.hpp:* {{webcpp::hash: async_hmac takes hmac_sha1_160, hmac_sha2_256, hmac_sha2_384 or hmac_sha2_512, the hmacs WebCrypto has: call mac for the others.}}
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
    webcpp::hash::async_hmac<webcpp::hash::hmac_sha3_256>(
        context.get_executor(), output, {}, {}, [](boost::system::error_code /*code*/) {});
    return 0;
}
