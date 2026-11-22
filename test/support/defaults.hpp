// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// What the default backends' tests share: each backend's name, the program's linked backends as
// the test reads them from the HAS macros itself, the first backend of a list that serves an
// operation found by a walk at run time (not by the library's type computation), and the cells
// of increment 1's key derivations (every operation over every hmac of hmac.hpp, and one hmac
// over another Hash2 hash).

#ifndef WEBCPP_TEST_HASH_SUPPORT_DEFAULTS_HPP
#define WEBCPP_TEST_HASH_SUPPORT_DEFAULTS_HPP

#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/hash/pbkdf2.hpp>

#include "../require.hpp"
#include "hex.hpp"
#include "rfc5869.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/sha2.hpp>

#include <array>
#include <cstdint>
#include <iostream>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>

namespace webcpp::test {

namespace backends = webcpp::hash::backends;
namespace kdfs = webcpp::hash::kdfs;

// A Hash2 hash over a digest that hmac.hpp has no alias for: spec 3.2's last row.
struct other_hash : boost::hash2::sha2_256 {};

// The cells of the key derivations: every alias of hmac.hpp, and hmac<other_hash>.
using kdf_hmacs = std::tuple<hash::hmac_md5_128, hash::hmac_sha1_160, hash::hmac_sha2_224,
                             hash::hmac_sha2_256, hash::hmac_sha2_384, hash::hmac_sha2_512,
                             hash::hmac_sha2_512_224, hash::hmac_sha2_512_256, hash::hmac_sha3_224,
                             hash::hmac_sha3_256, hash::hmac_sha3_384, hash::hmac_sha3_512,
                             hash::hmac_ripemd_128, hash::hmac_ripemd_160, hash::hmac_blake2b_512,
                             hash::hmac_blake2s_256, hash::hmac<other_hash>>;

// Increment 1's key derivation operations, each with a default of its own, so that a backend
// without an operation never makes it refuse.
using kdf_operations = std::tuple<kdfs::hkdf_extract, kdfs::hkdf_expand, kdfs::hkdf, kdfs::pbkdf2>;

template <class Backend>
constexpr std::string_view name_of() {
    if constexpr (std::is_same_v<Backend, backends::hash2>) {
        return "hash2";
    } else if constexpr (std::is_same_v<Backend, backends::sodium>) {
        return "sodium";
    } else if constexpr (std::is_same_v<Backend, backends::bearssl>) {
        return "bearssl";
    } else if constexpr (std::is_same_v<Backend, backends::openssl>) {
        return "openssl";
    } else if constexpr (std::is_same_v<Backend, backends::xkcp>) {
        return "xkcp";
    } else if constexpr (std::is_same_v<Backend, backends::blake3>) {
        return "blake3";
    } else if constexpr (std::is_same_v<Backend, backends::botan>) {
        return "botan";
    } else {
        return "?";
    }
}

template <class Backend>
constexpr std::string_view name_of_macro() {
    if constexpr (std::is_same_v<Backend, backends::hash2>) {
        return "HASH2";
    } else if constexpr (std::is_same_v<Backend, backends::sodium>) {
        return "SODIUM";
    } else if constexpr (std::is_same_v<Backend, backends::bearssl>) {
        return "BEARSSL";
    } else if constexpr (std::is_same_v<Backend, backends::openssl>) {
        return "OPENSSL";
    } else if constexpr (std::is_same_v<Backend, backends::xkcp>) {
        return "XKCP";
    } else if constexpr (std::is_same_v<Backend, backends::blake3>) {
        return "BLAKE3";
    } else if constexpr (std::is_same_v<Backend, backends::botan>) {
        return "BOTAN";
    } else {
        return "?";
    }
}

template <class Operation>
constexpr std::string_view name_of_operation() {
    if constexpr (std::is_same_v<Operation, kdfs::hkdf_extract>) {
        return "hkdf_extract";
    } else if constexpr (std::is_same_v<Operation, kdfs::hkdf_expand>) {
        return "hkdf_expand";
    } else if constexpr (std::is_same_v<Operation, kdfs::hkdf>) {
        return "hkdf";
    } else {
        return "pbkdf2";
    }
}

template <class Hmac>
constexpr std::string_view name_of_hmac() {
    using namespace webcpp::hash;
    constexpr auto names = std::to_array<std::pair<bool, std::string_view>>({
        {std::is_same_v<Hmac, hmac_md5_128>, "hmac_md5_128"},
        {std::is_same_v<Hmac, hmac_sha1_160>, "hmac_sha1_160"},
        {std::is_same_v<Hmac, hmac_sha2_224>, "hmac_sha2_224"},
        {std::is_same_v<Hmac, hmac_sha2_256>, "hmac_sha2_256"},
        {std::is_same_v<Hmac, hmac_sha2_384>, "hmac_sha2_384"},
        {std::is_same_v<Hmac, hmac_sha2_512>, "hmac_sha2_512"},
        {std::is_same_v<Hmac, hmac_sha2_512_224>, "hmac_sha2_512_224"},
        {std::is_same_v<Hmac, hmac_sha2_512_256>, "hmac_sha2_512_256"},
        {std::is_same_v<Hmac, hmac_sha3_224>, "hmac_sha3_224"},
        {std::is_same_v<Hmac, hmac_sha3_256>, "hmac_sha3_256"},
        {std::is_same_v<Hmac, hmac_sha3_384>, "hmac_sha3_384"},
        {std::is_same_v<Hmac, hmac_sha3_512>, "hmac_sha3_512"},
        {std::is_same_v<Hmac, hmac_ripemd_128>, "hmac_ripemd_128"},
        {std::is_same_v<Hmac, hmac_ripemd_160>, "hmac_ripemd_160"},
        {std::is_same_v<Hmac, hmac_blake2b_512>, "hmac_blake2b_512"},
        {std::is_same_v<Hmac, hmac_blake2s_256>, "hmac_blake2s_256"},
    });
    for (auto const& [same, name] : names) {
        if (same) {
            return name;
        }
    }
    return "other";
}

// Whether the program links each library, read from the HAS macros its target defines.
#ifdef WEBCPP_HASH_HAS_SODIUM
inline constexpr bool sodium_linked = true;
#else
inline constexpr bool sodium_linked = false;
#endif
#ifdef WEBCPP_HASH_HAS_BEARSSL
inline constexpr bool bearssl_linked = true;
#else
inline constexpr bool bearssl_linked = false;
#endif
#ifdef WEBCPP_HASH_HAS_OPENSSL
inline constexpr bool openssl_linked = true;
#else
inline constexpr bool openssl_linked = false;
#endif
#ifdef WEBCPP_HASH_HAS_XKCP
inline constexpr bool xkcp_linked = true;
#else
inline constexpr bool xkcp_linked = false;
#endif
#ifdef WEBCPP_HASH_HAS_BLAKE3
inline constexpr bool blake3_linked = true;
#else
inline constexpr bool blake3_linked = false;
#endif
// Botan is a program's only with exceptions (backends/botan.hpp declares nothing without them).
#if defined(WEBCPP_HASH_HAS_BOTAN) && !defined(WEBCPP_HASH_NO_EXCEPTIONS)
inline constexpr bool botan_linked = true;
#else
inline constexpr bool botan_linked = false;
#endif

// Whether the program links Backend.
template <class Backend>
constexpr bool linked() {
    return std::is_same_v<Backend, backends::hash2> ||
           (std::is_same_v<Backend, backends::sodium> && sodium_linked) ||
           (std::is_same_v<Backend, backends::bearssl> && bearssl_linked) ||
           (std::is_same_v<Backend, backends::openssl> && openssl_linked) ||
           (std::is_same_v<Backend, backends::xkcp> && xkcp_linked) ||
           (std::is_same_v<Backend, backends::blake3> && blake3_linked) ||
           (std::is_same_v<Backend, backends::botan> && botan_linked);
}

// Calls check.template operator()<Operation, Hmac>() for every cell of the key derivations.
template <class Check>
void for_each_kdf_cell(Check check) {
    [&]<class... Operation>(std::tuple<Operation...>*) {
        (
            [&]<class Op>(Op*) {
                [&]<class... Hmac>(std::tuple<Hmac...>*) {
                    (check.template operator()<Op, Hmac>(), ...);
                }(static_cast<kdf_hmacs*>(nullptr));
            }(static_cast<Operation*>(nullptr)),
            ...);
    }(static_cast<kdf_operations*>(nullptr));
}

// The default's name for one cell against the expected name, the cell named on a failure.
template <class Operation, class Hmac>
void expect_default(std::string_view expected) {
    std::string_view const chosen = name_of<hash::default_kdf_backend<Hmac, Operation>>();
    if (!BOOST_TEST_EQ(chosen, expected)) {
        std::cerr << "  default of " << name_of_operation<Operation>() << " over "
                  << name_of_hmac<Hmac>() << '\n';
    }
}

// Each default of hmac_sha2_256 called (a default that cannot serve would not compile), against
// RFC 5869's A.1 and backends::hash2's PBKDF2.
inline void check_calls() {
    using hmac = hash::hmac_sha2_256;
    auto const ikm = from_hex(a1.ikm);
    auto const salt = from_hex(a1.salt);
    auto const info = from_hex(a1.info);

    auto const prk = hash::hkdf_extract<hmac>(salt, ikm);
    require(prk.has_value());
    BOOST_TEST_EQ(to_hex(*prk), a1.prk);

    std::array<std::uint8_t, 42> expanded{};
    require(hash::hkdf_expand<hmac>(expanded, *prk, info).has_value());
    BOOST_TEST_EQ(to_hex(expanded), a1.okm);

    std::array<std::uint8_t, 42> whole{};
    require(hash::hkdf<hmac>(whole, salt, ikm, info).has_value());
    BOOST_TEST_EQ(to_hex(whole), a1.okm);

    std::array<std::uint8_t, 32> derived{};
    std::array<std::uint8_t, 32> derived_hash2{};
    require(hash::pbkdf2<hmac>(derived, ikm, salt, 2).has_value());
    require(hash::pbkdf2<hmac, backends::hash2>(derived_hash2, ikm, salt, 2).has_value());
    BOOST_TEST(derived == derived_hash2);
}

}  // namespace webcpp::test

#endif  // WEBCPP_TEST_HASH_SUPPORT_DEFAULTS_HPP
