// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The proposal to Boost.Hash2 (spec section 9.1, upstream/keccak.hpp): its own test, in Hash2's
// style, between the tags, which doc/upstream.adoc shows as the test proposed with it; then the
// proof that webcpp::hash::keccak_256 gives the proposed keccak_256's results for every length
// from 0 to 3 blocks and for random sequences of updates and results, so that the alias of spec
// 9.1 changes no result. The digests of the empty message and of the byte 0xCC are the first two
// of the Keccak team's KAT files for the SHA-3 competition's third round (ShortMsgKAT_224.txt to
// ShortMsgKAT_512.txt, Len = 0 and Len = 8); those of "abc" were computed with an independent
// Python Keccak that gives those KAT values and hashlib's SHA-3, and so was the HMAC's.

#include "upstream/keccak.hpp"

#include <webcpp/hash/keccak.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/digest.hpp>
#include <boost/hash2/hmac.hpp>
#include <boost/hash2/sha3.hpp>

#include <webcpp/test/exit_status.hpp>

#include <cstddef>
#include <cstdint>
#include <random>
#include <string>
#include <vector>

// clang-format off
// tag::test[]
namespace
{

template<class H> std::string digest( std::string const& s )
{
    H h;
    h.update( s.data(), s.size() );
    return to_string( h.result() );
}

template<class H> std::string digest_in_pieces( std::string const& s )
{
    H h;

    for( char c: s )
    {
        h.update( &c, 1 );
    }

    return to_string( h.result() );
}

void test_published()
{
    using namespace boost::hash2;

    std::string const empty;
    std::string const cc( 1, static_cast<char>( 0xCC ) );
    std::string const abc( "abc" );

    BOOST_TEST_EQ( digest<keccak_224>( empty ), "f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd" );
    BOOST_TEST_EQ( digest<keccak_224>( cc ), "a9cab59eb40a10b246290f2d6086e32e3689faf1d26b470c899f2802" );
    BOOST_TEST_EQ( digest<keccak_224>( abc ), "c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8" );

    BOOST_TEST_EQ( digest<keccak_256>( empty ), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" );
    BOOST_TEST_EQ( digest<keccak_256>( cc ), "eead6dbfc7340a56caedc044696a168870549a6a7f6f56961e84a54bd9970b8a" );
    BOOST_TEST_EQ( digest<keccak_256>( abc ), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45" );

    BOOST_TEST_EQ( digest<keccak_384>( empty ), "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff" );
    BOOST_TEST_EQ( digest<keccak_384>( cc ), "1b84e62a46e5a201861754af5dc95c4a1a69caf4a796ae405680161e29572641f5fa1e8641d7958336ee7b11c58f73e9" );
    BOOST_TEST_EQ( digest<keccak_384>( abc ), "f7df1165f033337be098e7d288ad6a2f74409d7a60b49c36642218de161b1f99f8c681e4afaf31a34db29fb763e3c28e" );

    BOOST_TEST_EQ( digest<keccak_512>( empty ), "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e" );
    BOOST_TEST_EQ( digest<keccak_512>( cc ), "8630c13cbd066ea74bbe7fe468fec1dee10edc1254fb4c1b7c5fd69b646e44160b8ce01d05a0908ca790dfb080f4b513bc3b6225ece7a810371441a5ac666eb9" );
    BOOST_TEST_EQ( digest<keccak_512>( abc ), "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96" );
}

void test_hmac()
{
    // RFC 4231's second case, over Keccak-256 instead of SHA-256
    boost::hash2::hmac_keccak_256 mac( "Jefe", 4 );
    std::string const message( "what do ya want for nothing?" );
    mac.update( message.data(), message.size() );

    BOOST_TEST_EQ( to_string( mac.result() ), "aa9aed448c7abc8b5e326ffa6a01cdedf7b4b831881468c044ba8dd4566369a1" );
}

template<class H> void test_incremental()
{
    std::string const s( 1000, 'a' );
    BOOST_TEST_EQ( digest<H>( s ), digest_in_pieces<H>( s ) );
}

template<class H, int D> void test_seeded()
{
    // A seed feeds the hash as it feeds the SHA-3 class of the same size: its eight
    // bytes, little-endian, then a result; a key of n bytes, likewise
    boost::hash2::detail::keccak_base<0x01, 2 * D, D> expected;

    std::string const seed( "\x07\0\0\0\0\0\0\0", 8 );
    expected.update( seed.data(), seed.size() );
    expected.result();
    expected.update( seed.data(), 0 );

    H h( 7 );
    BOOST_TEST_EQ( to_string( h.result() ), to_string( expected.result() ) );

    H h0( 0 );
    BOOST_TEST_EQ( to_string( h0.result() ), digest<H>( "" ) );

    boost::hash2::detail::keccak_base<0x01, 2 * D, D> expected_key;

    std::string const key( "key" );
    expected_key.update( key.data(), key.size() );
    expected_key.result();
    expected_key.update( key.data(), 0 );

    H hk( key.data(), key.size() );
    BOOST_TEST_EQ( to_string( hk.result() ), to_string( expected_key.result() ) );
}

} // namespace
// end::test[]
// clang-format on

namespace {

// webcpp's keccak_256, over XKCP's permutation, against the proposed keccak_256: every length up
// to three blocks, then random sequences of updates and results.
void test_webcpp_agrees() {
    for (std::size_t n = 0; n <= 3 * webcpp::hash::keccak_256::block_size; ++n) {
        std::string const message(n, static_cast<char>('a' + (n % 26)));
        webcpp::hash::keccak_256 ours;
        ours.update(message.data(), message.size());
        BOOST_TEST_EQ(to_string(ours.result()), digest<boost::hash2::keccak_256>(message));
    }
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp): reproducible
    std::mt19937 random(2026);
    for (int round = 0; round < 200; ++round) {
        webcpp::hash::keccak_256 ours;
        boost::hash2::keccak_256 proposed;
        for (int step = 0; step < 8; ++step) {
            std::vector<unsigned char> bytes(random() % 300);
            for (auto& b : bytes) {
                b = static_cast<unsigned char>(random());
            }
            ours.update(bytes.data(), bytes.size());
            proposed.update(bytes.data(), bytes.size());
            if (random() % 3 == 0) {
                BOOST_TEST_EQ(to_string(ours.result()), to_string(proposed.result()));
            }
        }
        BOOST_TEST_EQ(to_string(ours.result()), to_string(proposed.result()));
    }
}

}  // namespace

int main() {
    test_published();
    test_hmac();
    test_incremental<boost::hash2::keccak_224>();
    test_incremental<boost::hash2::keccak_256>();
    test_incremental<boost::hash2::keccak_384>();
    test_incremental<boost::hash2::keccak_512>();
    test_seeded<boost::hash2::keccak_224, 224>();
    test_seeded<boost::hash2::keccak_256, 256>();
    test_seeded<boost::hash2::keccak_384, 384>();
    test_seeded<boost::hash2::keccak_512, 512>();
    test_webcpp_agrees();
    return webcpp::test::exit_status(boost::report_errors());
}
