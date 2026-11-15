// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The text proposed to Boost.Hash2 (spec section 9.1): keccak_224, keccak_256, keccak_384 and
// keccak_512, public, after sha3.hpp's shake_256, in Hash2's own style, which is why the
// formatter is off here. Each is the Keccak team's submission to the SHA-3 competition, Hash2's
// detail::keccak_base with the padding byte 0x01, seeded as sha3_224 to sha3_512 are. The test
// upstream_keccak_test.cpp compiles it against Boost.Hash2 1.92 and checks the published digests;
// doc/upstream.adoc shows the region between the tags as the proposal's text.

#ifndef WEBCPP_HASH_TEST_UPSTREAM_KECCAK_HPP
#define WEBCPP_HASH_TEST_UPSTREAM_KECCAK_HPP

#include <boost/hash2/sha3.hpp>

#include <cstddef>
#include <cstdint>

// clang-format off
// Boost.Hash2's style, which the proposal keeps: its nested namespaces, its empty constructor
// bodies and its int loop counter.
// NOLINTBEGIN(modernize-concat-nested-namespaces,modernize-use-equals-default,bugprone-signed-bitwise)
// tag::proposal[]
namespace boost
{
namespace hash2
{
namespace detail
{

// Keccak as submitted to the SHA-3 competition: keccak_base with the padding
// byte 0x01, seeded as the SHA-3 classes are
template<int D>
class keccak_seeded: public keccak_base<0x01, 2 * D, D>
{
public:

    BOOST_HASH2_SHA3_CONSTEXPR keccak_seeded()
    {
    }

    BOOST_HASH2_SHA3_CONSTEXPR explicit keccak_seeded( std::uint64_t seed )
    {
        if( seed != 0 )
        {
            unsigned char byte = 0;

            for( int i = 0; i < 8; ++i )
            {
                byte = static_cast<unsigned char>( seed >> ( 8 * i ) );
                this->update( &byte, 1 );
            }

            this->result();
            this->update( &byte, 0 ); // sets finalized_ to false
        }
    }

    BOOST_HASH2_SHA3_CONSTEXPR keccak_seeded( unsigned char const * p, std::size_t n )
    {
        if( n != 0 )
        {
            this->update( p, n );
            this->result();
            this->update( p, 0 ); // sets finalized_ to false
        }
    }

    keccak_seeded( void const * p, std::size_t n ): keccak_seeded( static_cast<unsigned char const*>( p ), n )
    {
    }
};

} // namespace detail

class keccak_224: public detail::keccak_seeded<224>
{
public:

    using detail::keccak_seeded<224>::keccak_seeded;
};

class keccak_256: public detail::keccak_seeded<256>
{
public:

    using detail::keccak_seeded<256>::keccak_seeded;
};

class keccak_384: public detail::keccak_seeded<384>
{
public:

    using detail::keccak_seeded<384>::keccak_seeded;
};

class keccak_512: public detail::keccak_seeded<512>
{
public:

    using detail::keccak_seeded<512>::keccak_seeded;
};

using hmac_keccak_224 = hmac<keccak_224>;
using hmac_keccak_256 = hmac<keccak_256>;
using hmac_keccak_384 = hmac<keccak_384>;
using hmac_keccak_512 = hmac<keccak_512>;

} // namespace hash2
} // namespace boost
// end::proposal[]
// NOLINTEND(modernize-concat-nested-namespaces,modernize-use-equals-default,bugprone-signed-bitwise)
// clang-format on

#endif  // WEBCPP_HASH_TEST_UPSTREAM_KECCAK_HPP
