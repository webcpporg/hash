// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Argon2id with every parameter of RFC 9106 on backends::openssl: the inputs of RFC 9106's
// section 5.3 (four lanes, a secret and associated data), checked against the RFC's tag; and the
// same costs with Argon2d, which has no default backend, named in the call.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/argon2.hpp>

#include <array>
#include <cstdint>
#include <iostream>

int main() {
    namespace hash = webcpp::hash;
    using hash::backends::openssl;

    // RFC 9106, section 5.3: 32 bytes of 0x01, 16 of 0x02, a secret of 8 bytes of 0x03 and
    // associated data of 12 bytes of 0x04.
    std::array<std::uint8_t, 32> password{};
    password.fill(0x01);
    std::array<std::uint8_t, 16> salt{};
    salt.fill(0x02);
    std::array<std::uint8_t, 8> pepper{};
    pepper.fill(0x03);
    std::array<std::uint8_t, 12> context{};
    context.fill(0x04);

    // m counts KiB, as RFC 9106 does: 32 KiB over four lanes, three passes. A password hash takes
    // far more memory; these are the RFC's costs, to check the tag.
    hash::argon2_parameters const costs{
        .passes = 3,
        .memory_kibibytes = 32,
        .lanes = 4,
        .secret = pepper,
        .associated_data = context,
    };

    std::array<std::uint8_t, 32> tag{};
    auto const done = hash::argon2<hash::kdfs::argon2id, openssl>(tag, password, salt, costs);
    if (!done) {
        std::cerr << done.error().message() << '\n';
        return 1;
    }
    std::cout << "argon2id " << example::hex(tag) << '\n';
    if (example::hex(tag) != "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659") {
        return 1;
    }

    // Argon2d (RFC 9106, section 5.1), for uses where no attacker shares the machine.
    auto const argon2d_done =
        hash::argon2<hash::kdfs::argon2d, openssl>(tag, password, salt, costs);
    if (!argon2d_done) {
        std::cerr << argon2d_done.error().message() << '\n';
        return 1;
    }
    std::cout << "argon2d " << example::hex(tag) << '\n';
}

// end::example[]
