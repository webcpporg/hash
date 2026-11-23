// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A login, as an application would build it from webcpp::hash's Argon2id and webcpp::crypto's
// random bytes and constant-time comparison: the salt, the costs and the tag are stored, never
// the password. webcpp::hash has no login function; the credential and the two functions below
// belong to the example.

// tag::example[]
#include "hex.hpp"

#include <webcpp/crypto/constant_time_equal.hpp>
#include <webcpp/crypto/random_device.hpp>
#include <webcpp/hash/argon2.hpp>

#include <boost/system/result.hpp>

#include <array>
#include <cstdint>
#include <iostream>
#include <span>
#include <string_view>

namespace {

// What the application stores for a user. Without the costs in the record, the service could not
// raise them later: a login verifies an old tag with the costs that made it.
struct credential {
    std::array<std::uint8_t, webcpp::hash::argon2id_salt_size> salt;
    webcpp::hash::argon2id_parameters costs;
    std::array<std::uint8_t, 32> tag;
};

// Without a salt of its own per user, one guess tests every user at once, and two users with the
// same password are visible as such. Without Argon2id's memory cost (a fast hash such as SHA-256
// instead), a GPU tries billions of guesses a second.
boost::system::result<credential> enroll(std::string_view password) {
    credential stored{};
    stored.costs = webcpp::hash::argon2id_interactive;
    auto done = webcpp::crypto::random_device{}.fill(stored.salt);
    if (!done) {
        return done.error();
    }
    done = webcpp::hash::argon2id(stored.tag, example::bytes(password), stored.salt, stored.costs);
    if (!done) {
        return done.error();
    }
    return stored;
}

// Computes the tag again from the salt and the costs that were stored, and compares it with the
// stored one. With == the comparison stops at the first different byte, and the time it takes tells
// an attacker how many leading bytes of a guess's tag are right.
boost::system::result<bool> check(credential const& stored, std::string_view password) {
    std::array<std::uint8_t, 32> candidate{};
    auto const done =
        webcpp::hash::argon2id(candidate, example::bytes(password), stored.salt, stored.costs);
    if (!done) {
        return done.error();
    }
    return webcpp::crypto::constant_time_equal(candidate, stored.tag);
}

}  // namespace

int main() {
    auto stored = enroll("correct-password");
    if (!stored) {
        std::cerr << stored.error().message() << '\n';
        return 1;
    }
    std::cout << "stored a " << stored->salt.size() << "-byte salt, " << stored->costs.passes
              << " passes over " << stored->costs.memory << " bytes, and a " << stored->tag.size()
              << "-byte tag\n";

    for (std::string_view const attempt : {"correct-password", "wrong-password"}) {
        auto const ok = check(*stored, attempt);
        if (!ok) {
            std::cerr << ok.error().message() << '\n';
            return 1;
        }
        std::cout << "login " << attempt << ": " << (*ok ? "accepted" : "refused") << '\n';
    }
}

// end::example[]
