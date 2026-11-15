// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A Nostr event's id (NIP-01): the SHA-256 of the UTF-8 JSON array
// [0, pubkey, created_at, kind, tags, content] written with no whitespace, where the content
// escapes only the characters NIP-01 lists. This is what a domain library such as webcpp::nostr
// would build from webcpp::hash's SHA-256; webcpp::hash has no Nostr function, and the helpers
// below belong to the example. Both ids agree with Python's json.dumps(separators=(',', ':'),
// ensure_ascii=False) and hashlib.sha256.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/algorithms.hpp>

#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>

namespace {

// NIP-01 escapes the line feed, the double quote, the backslash, the carriage return, the tab,
// the backspace and the form feed, and no other character: another escape would change the
// bytes that are hashed, and so the id.
std::string escape(std::string_view content) {
    std::string out;
    for (char const c : content) {
        switch (c) {
            case '\n': out += "\\n"; break;
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            default: out += c;
        }
    }
    return out;
}

// The event's serialization for its id, with no tags.
std::string serialize(std::string_view pubkey, std::uint64_t created_at, std::uint32_t kind,
                      std::string_view content) {
    return "[0,\"" + std::string(pubkey) + "\"," + std::to_string(created_at) + "," +
           std::to_string(kind) + ",[],\"" + escape(content) + "\"]";
}

std::string id_of(std::string const& serialization) {
    webcpp::hash::sha2_256 hash;
    hash.update(serialization.data(), serialization.size());
    return example::hex(hash.result());
}

}  // namespace

int main() {
    std::string_view const pubkey =
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    auto const text = serialize(pubkey, 1700000000, 1, "hello from webcpp");
    std::cout << "serialization " << text << '\n';
    auto const id = id_of(text);
    std::cout << "id " << id << '\n';

    // A content with a line feed and quotes goes through the escapes.
    auto const quoted = serialize(pubkey, 1700000000, 1, "say \"hi\"\nbye");
    std::cout << "escaped id " << id_of(quoted) << '\n';
}

// end::example[]
