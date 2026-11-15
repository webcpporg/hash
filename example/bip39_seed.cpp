// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// BIP39's seed, as a domain library such as webcpp::bitcoin would compute it from webcpp::hash's
// PBKDF2: PBKDF2-HMAC-SHA-512 of the mnemonic sentence, salted with "mnemonic" and the
// passphrase, 2048 iterations, 64 bytes. webcpp::hash itself has no BIP39 function: the word list,
// the checksum and the NFKD normalisation of non-ASCII text are webcpp::bitcoin's, and this shows
// the key derivation step. The first English vector of BIP39's test vectors (passphrase TREZOR),
// whose seed agrees with Python's hashlib.pbkdf2_hmac.

// tag::example[]
#include "hex.hpp"

#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/pbkdf2.hpp>

#include <array>
#include <cstdint>
#include <iostream>
#include <string>

int main() {
    std::string const mnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
        "about";
    std::string const passphrase = "TREZOR";

    // The passphrase goes into the salt, so the same mnemonic with another passphrase is another
    // wallet, and nothing says the passphrase was wrong.
    std::string const salt = "mnemonic" + passphrase;

    std::array<std::uint8_t, 64> seed{};
    auto const done = webcpp::hash::pbkdf2<webcpp::hash::hmac_sha2_512>(
        seed, example::bytes(mnemonic), example::bytes(salt), 2048);
    if (!done) {
        std::cerr << done.error().message() << '\n';
        return 1;
    }
    std::cout << "seed " << example::hex(seed) << '\n';
    if (example::hex(seed) !=
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
        "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04") {
        return 1;
    }
}

// end::example[]
