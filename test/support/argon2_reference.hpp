// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Argon2id by libsodium's private core, argon2_ctx, which takes what crypto_pwhash_argon2id does
// not: lanes, a secret and associated data. The tests reach it through
// /third_party//sodium-test-config, whose include directories hold crypto_pwhash/argon2.

#ifndef WEBCPP_TEST_HASH_SUPPORT_ARGON2_REFERENCE_HPP
#define WEBCPP_TEST_HASH_SUPPORT_ARGON2_REFERENCE_HPP

#include <webcpp/hash/detail/wipe.hpp>

#include <cstdint>
#include <span>

// argon2.h is a C header without a linkage block of its own: argon2_ctx has C linkage.
extern "C" {
#include <argon2.h>  // third_party/libs/libsodium/src/libsodium/crypto_pwhash/argon2
}

namespace webcpp::test {

// The costs and the inputs of one Argon2id run of argon2_ctx.
struct argon2_reference_case {
    std::span<std::uint8_t const> password;
    std::span<std::uint8_t const> salt;
    std::span<std::uint8_t const> secret;
    std::span<std::uint8_t const> associated_data;
    std::uint32_t passes;
    std::uint32_t memory_kib;
    std::uint32_t lanes;
};

// Fills `tag` by argon2_ctx(Argon2_id), version 0x13, with as many threads as lanes, and wipes the
// context, which holds the pointers to the inputs and their lengths. Returns argon2_ctx's code.
inline int argon2_reference(std::span<std::uint8_t> tag, argon2_reference_case const& c) {
    // argon2_ctx writes nothing through the input pointers: with ARGON2_DEFAULT_FLAGS it clears
    // neither the password nor the secret.
    // NOLINTBEGIN(cppcoreguidelines-pro-type-const-cast)
    argon2_context context{
        .out = tag.data(),
        .outlen = static_cast<std::uint32_t>(tag.size()),
        .pwd = const_cast<std::uint8_t*>(c.password.data()),
        .pwdlen = static_cast<std::uint32_t>(c.password.size()),
        .salt = const_cast<std::uint8_t*>(c.salt.data()),
        .saltlen = static_cast<std::uint32_t>(c.salt.size()),
        .secret = const_cast<std::uint8_t*>(c.secret.data()),
        .secretlen = static_cast<std::uint32_t>(c.secret.size()),
        .ad = const_cast<std::uint8_t*>(c.associated_data.data()),
        .adlen = static_cast<std::uint32_t>(c.associated_data.size()),
        .t_cost = c.passes,
        .m_cost = c.memory_kib,
        .lanes = c.lanes,
        .threads = c.lanes,
        .flags = ARGON2_DEFAULT_FLAGS,
    };
    // NOLINTEND(cppcoreguidelines-pro-type-const-cast)
    int const code = argon2_ctx(&context, Argon2_id);
    webcpp::hash::detail::wipe_object(context);
    return code;
}

}  // namespace webcpp::test

#endif  // WEBCPP_TEST_HASH_SUPPORT_ARGON2_REFERENCE_HPP
