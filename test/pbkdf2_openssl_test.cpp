// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// PBKDF2 on backends::openssl (OpenSSL 3.5.9's EVP_KDF "PBKDF2", with pkcs5 set, so that SP
// 800-132's lower bounds do not apply): RFC 6070's six cases, the fourth of 16,777,216 iterations
// among them, and RFC 7914 section 11's two; every hmac of spec 3.2's OpenSSL column against
// backends::hash2, the empty password and salt among the shapes; and the default backend. It
// includes pbkdf2.hpp alone, which brings backends/openssl.hpp in when the program links OpenSSL.

#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/pbkdf2.hpp>

#include <boost/core/lightweight_test.hpp>

#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/rfc6070.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace hash = webcpp::hash;
using webcpp::test::pbkdf2_case;
using webcpp::test::to_hex;

namespace {

using hash::backends::hash2;
using hash::backends::openssl;

std::span<std::uint8_t const> bytes_of(std::string_view text) {
    return {reinterpret_cast<std::uint8_t const*>(text.data()), text.size()};
}

template <class Hmac, class Backend = openssl>
void check(const pbkdf2_case& c) {
    std::vector<std::uint8_t> derived(c.length);
    const auto done =
        hash::pbkdf2<Hmac, Backend>(derived, bytes_of(c.password), bytes_of(c.salt), c.iterations);
    BOOST_TEST(done.has_value());
    BOOST_TEST_EQ(to_hex(derived), std::string(c.derived_key));
}

// Bytes of a fixed pattern, different for each `seed`.
std::vector<std::uint8_t> pattern(std::size_t size, unsigned seed) {
    std::vector<std::uint8_t> bytes(size);
    for (std::size_t i = 0; i < size; ++i) {
        bytes[i] = static_cast<std::uint8_t>((i * 131U) + (std::size_t{seed} * 29U) + 7U);
    }
    return bytes;
}

// One shape: the sizes of password and salt, the iterations, the output in digests and bytes.
struct shape {
    std::size_t password;
    std::size_t salt;
    std::uint64_t iterations;
    std::size_t digests;
    std::size_t bytes;
};

// OpenSSL and backends::hash2 agree over Hmac, for every shape.
template <class Hmac>
void agree() {
    constexpr std::size_t size = typename Hmac::result_type().size();
    for (const shape s : {
             shape{.password = 0, .salt = 0, .iterations = 1, .digests = 0, .bytes = 1},
             shape{.password = 8, .salt = 4, .iterations = 2, .digests = 1, .bytes = 0},
             shape{.password = 0, .salt = 16, .iterations = 3, .digests = 2, .bytes = 7},
             shape{.password = 300, .salt = 0, .iterations = 64, .digests = 3, .bytes = 1},
             shape{.password = 200, .salt = 300, .iterations = 17, .digests = 4, .bytes = 0},
         }) {
        const auto password = pattern(s.password, 5);
        const auto salt = pattern(s.salt, 6);
        const std::size_t length = (s.digests * size) + s.bytes;
        std::vector<std::uint8_t> expected(length);
        BOOST_TEST((hash::pbkdf2<Hmac, hash2>(expected, password, salt, s.iterations).has_value()));
        std::vector<std::uint8_t> derived(length);
        BOOST_TEST(
            (hash::pbkdf2<Hmac, openssl>(derived, password, salt, s.iterations).has_value()));
        BOOST_TEST(derived == expected);
    }
}

template <class... Hmacs>
void agree_on() {
    (agree<Hmacs>(), ...);
}

}  // namespace

int main() {
    check<hash::hmac_sha1_160>(webcpp::test::rfc6070_1);
    check<hash::hmac_sha1_160>(webcpp::test::rfc6070_2);
    check<hash::hmac_sha1_160>(webcpp::test::rfc6070_3);
    check<hash::hmac_sha1_160>(webcpp::test::rfc6070_4);
    check<hash::hmac_sha1_160>(webcpp::test::rfc6070_5);
    check<hash::hmac_sha1_160>(webcpp::test::rfc6070_6);
    check<hash::hmac_sha2_256>(webcpp::test::rfc7914_1);
    check<hash::hmac_sha2_256>(webcpp::test::rfc7914_2);

    agree_on<hash::hmac_md5_128, hash::hmac_sha1_160, hash::hmac_sha2_224, hash::hmac_sha2_256,
             hash::hmac_sha2_384, hash::hmac_sha2_512, hash::hmac_sha2_512_224,
             hash::hmac_sha2_512_256, hash::hmac_sha3_224, hash::hmac_sha3_256, hash::hmac_sha3_384,
             hash::hmac_sha3_512, hash::hmac_ripemd_160, hash::hmac_blake2b_512,
             hash::hmac_blake2s_256>();

    // The default backend of a program that links OpenSSL: OpenSSL natively, the fastest;
    // backends::hash2 on WebAssembly, the smallest (detail/ranking.hpp).
    using chosen = hash::default_kdf_backend<hash::hmac_sha2_256, hash::kdfs::pbkdf2>;
#ifdef WEBCPP_HASH_WEBASSEMBLY
    static_assert(std::is_same_v<chosen, hash2>);
#else
    static_assert(std::is_same_v<chosen, openssl>);
#endif
    static_assert(
        std::is_same_v<hash::default_kdf_backend<hash::hmac_ripemd_128, hash::kdfs::pbkdf2>,
                       hash2>);
    check<hash::hmac_sha2_256, chosen>(webcpp::test::rfc7914_1);

    return webcpp::test::exit_status(boost::report_errors());
}
