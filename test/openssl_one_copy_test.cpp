// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// hash's and crypto's OpenSSL aliases in one program (spec section 5.5): both defines, one
// OpenSSL 3.5.9, and HKDF on backends::openssl, so the link holds libcrypto. That the link line
// names each archive once, from one directory, is checked by tools/test/openssl_one_copy_test.py,
// which reads it from b2 -d+2.

#include <webcpp/hash/backends/openssl.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>

#include <boost/core/lightweight_test.hpp>

#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/rfc5869.hpp"

#include <openssl/crypto.h>

#include <cstdint>
#include <span>
#include <string>
#include <vector>

int main() {
#if !defined(WEBCPP_HASH_HAS_OPENSSL) || !defined(WEBCPP_CRYPTO_HAS_OPENSSL)
    BOOST_ERROR("both aliases give their define");
#endif
    BOOST_TEST_EQ(OpenSSL_version_num(), 0x30500090UL);  // tools/openssl/pin.json: 3.5.9
    using webcpp::test::a1;
    using webcpp::test::from_hex;
    std::vector<std::uint8_t> okm(a1.length);
    BOOST_TEST((webcpp::hash::hkdf<webcpp::hash::hmac_sha2_256, webcpp::hash::backends::openssl>(
                    okm, from_hex(a1.salt), from_hex(a1.ikm), from_hex(a1.info))
                    .has_value()));
    BOOST_TEST_EQ(webcpp::test::to_hex(okm), std::string(a1.okm));
    return webcpp::test::exit_status(boost::report_errors());
}
