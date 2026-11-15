// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// RIPEMD-160 of "abc" and of the empty message, checked against the values its authors publish
// (Dobbertin, Bosselaers and Preneel's page for RIPEMD-160). Legacy: it is kept for Bitcoin's
// hash160 (see bitcoin_hash160.cpp). Prefer SHA-2 or SHA-3 in a new design.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/algorithms.hpp>

#include <iostream>
#include <string_view>

int main() {
    std::string_view const abc = "abc";

    webcpp::hash::ripemd_160 of_abc;
    of_abc.update(abc.data(), abc.size());
    auto const abc_digest = example::hex(of_abc.result());
    std::cout << "ripemd_160(abc) " << abc_digest << '\n';

    // Nothing to update: the digest of the empty message.
    webcpp::hash::ripemd_160 of_nothing;
    auto const empty_digest = example::hex(of_nothing.result());
    std::cout << "ripemd_160() " << empty_digest << '\n';

    if (abc_digest != "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc" ||
        empty_digest != "9c1185a5c5e9fc54612808977ee8f548b2258d31") {
        return 1;
    }
}

// end::example[]
