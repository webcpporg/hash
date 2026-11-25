// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// HKDF over pieces on backends::hash2 (design D2, D8): hkdf_extract, hkdf_expand and hkdf over
// byte_pieces give the single-buffer forms' bytes on the concatenation, with RFC 5869's cases,
// random splits, empty pieces and lists, many pieces and long inputs, and refuse only RFC 5869's
// sizes (support/hkdf_pieces.hpp), over SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, MD5 and an
// hmac over another Hash2 hash. Built again as hkdf_pieces_sliced with the test seam
// WEBCPP_HASH_DETAIL_TEST_HKDF_PIECES_SLICE, which makes the engine feed every piece to the HMAC in
// slices of a few bytes (Review Focus 4), over SHA-256 and the other hash: the bytes are the
// same, 1 MiB pieces included.

#include "support/hkdf_pieces.hpp"

#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>

#include <boost/core/lightweight_test.hpp>

#include <webcpp/test/exit_status.hpp>

#include <cstdint>
#include <iostream>

namespace hash = webcpp::hash;
namespace test = webcpp::test;

int main() {
    using hash::backends::hash2;
    std::cout << "backends::hash2 feeds its HMAC slices of at most "
              << hash::detail::hkdf_pieces_slice<hash2> << " bytes\n";
#ifdef WEBCPP_HASH_DETAIL_TEST_HKDF_PIECES_SLICE
    // The slicing is the engine's, whatever the hmac: two hmacs, one of an alias and the other's.
    BOOST_TEST_EQ(hash::detail::hkdf_pieces_slice<hash2>,
                  std::uint64_t{WEBCPP_HASH_DETAIL_TEST_HKDF_PIECES_SLICE});
    test::check_hkdf_pieces<hash::hmac_sha2_256, hash2>("hash2");
    test::check_hkdf_pieces<hash::hmac<test::other_hash>, hash2>("hash2");
#else
    test::check_hkdf_pieces<hash::hmac_sha1_160, hash2>("hash2");
    test::check_hkdf_pieces<hash::hmac_sha2_256, hash2>("hash2");
    test::check_hkdf_pieces<hash::hmac_sha2_384, hash2>("hash2");
    test::check_hkdf_pieces<hash::hmac_sha2_512, hash2>("hash2");
    test::check_hkdf_pieces<hash::hmac_sha3_256, hash2>("hash2");
    test::check_hkdf_pieces<hash::hmac_md5_128, hash2>("hash2");
    test::check_hkdf_pieces<hash::hmac<test::other_hash>, hash2>("hash2");
#endif
    return webcpp::test::exit_status(boost::report_errors());
}
