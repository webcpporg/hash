// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// FNV-1a with a 64-bit result: not cryptographic. A checksum against accidents and a hash for
// tables, never a defence against an adversary who can choose the input (see siphash.cpp). The
// value for "abc" agrees with a short Python implementation of FNV-1a (offset basis
// 0xcbf29ce484222325, prime 0x100000001b3), and so does the struct's value over the bytes
// hash_append feeds (little-endian fields, a string's bytes then its size as 32 bits).

// tag::example[]
#include <webcpp/hash/algorithms.hpp>

#include <boost/hash2/flavor.hpp>

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>

namespace {

struct reading {
    std::uint32_t sensor;
    std::int16_t celsius;
    std::string label;
};

}  // namespace

int main() {
    std::cout << std::hex << std::setfill('0');

    std::string_view const text = "abc";
    webcpp::hash::fnv1a_64 plain;
    plain.update(text.data(), text.size());
    std::cout << "fnv1a_64(abc) " << std::setw(16) << plain.result() << '\n';

    // hash_append feeds a value's bytes, field by field: the struct's padding bytes are never
    // hashed, and a string's size follows it, so that "ab" then "c" differs from "a" then "bc".
    // The flavor fixes the byte order: the same bytes, and the same hash, on every target.
    reading const r{.sensor = 1000, .celsius = -7, .label = "abc"};
    webcpp::hash::fnv1a_64 fields;
    boost::hash2::little_endian_flavor const flavor;
    webcpp::hash::hash_append(fields, flavor, r.sensor);
    webcpp::hash::hash_append(fields, flavor, r.celsius);
    webcpp::hash::hash_append(fields, flavor, r.label);
    std::cout << "reading " << std::setw(16) << fields.result() << '\n';
}

// end::example[]
