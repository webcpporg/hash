// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 Keccak-256 as the Keccak team submitted it to the SHA-3 competition and as Ethereum uses it,
 over XKCP's Keccak-p[1600]: a program links `/third_party//xkcp`.

 @see "Using webcpp::hash in your Jamfile", in the guide.
*/
#ifndef WEBCPP_HASH_KECCAK_HPP
#define WEBCPP_HASH_KECCAK_HPP

#include <webcpp/hash/config.hpp>

#ifndef WEBCPP_HASH_HAS_XKCP
// clang-format off
#error "webcpp::hash: keccak_256 needs XKCP. Add /third_party//xkcp to the program's Jamfile: exe app : app.cpp /webcpp/hash//hash /third_party//xkcp ;"
// clang-format on
#else

#include <webcpp/hash/detail/canary.h>
#include <webcpp/hash/detail/xkcp.hpp>

#include <boost/hash2/digest.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

#ifdef WEBCPP_HASH_XKCP_CANARY_CONFIGURATION
/** The configuration the canary names: a test's, here. */
#define WEBCPP_HASH_DETAIL_XKCP_CONFIGURATION WEBCPP_HASH_XKCP_CANARY_CONFIGURATION
#else
/** The configuration the canary names: `/third_party//xkcp` builds XKCP's generic64 alone. */
#define WEBCPP_HASH_DETAIL_XKCP_CONFIGURATION generic64
#endif
/** The canary's name, which every member of keccak_256 that calls XKCP reads (spec section 5.4). */
#define WEBCPP_HASH_DETAIL_XKCP_CANARY \
    WEBCPP_HASH_DETAIL_CANARY(xkcp, WEBCPP_HASH_XKCP_COMMIT, WEBCPP_HASH_DETAIL_XKCP_CONFIGURATION)

#ifdef _MSC_VER
#pragma detect_mismatch("webcpp_hash_backend_xkcp",                                      \
                        WEBCPP_HASH_DETAIL_MISMATCH_VALUE(xkcp, WEBCPP_HASH_XKCP_COMMIT, \
                                                          WEBCPP_HASH_DETAIL_XKCP_CONFIGURATION))
#endif

extern "C" const char WEBCPP_HASH_DETAIL_XKCP_CANARY;

namespace webcpp::hash::detail {

/**
 Reads XKCP's canary with a volatile load, which no linker can drop: a program built without
 `/third_party//xkcp`, or with one of another commit or configuration, fails to link with the
 canary's name.
*/
inline void touch_xkcp_canary() noexcept {
    // The volatile glvalue is converted to a value: a discarded one is not read by gcc
    // ("conversion to void will not access object").
    char const value = *static_cast<char const volatile*>(&WEBCPP_HASH_DETAIL_XKCP_CANARY);
    static_cast<void>(value);
}

}  // namespace webcpp::hash::detail

namespace webcpp::hash {

/**
 Keccak-256 with the original padding, Ethereum's hash, in Boost.Hash2's HashAlgorithm form.

 The permutation is XKCP's Keccak-p[1600]; the sponge follows Boost.Hash2's
 `detail::keccak_base<0x01, 512, 256>` exactly, so that every sequence of calls gives its
 results.
*/
class keccak_256 {
public:
    /** The digest, 32 bytes. */
    using result_type = boost::hash2::digest<32>;
    /** The rate, 136 bytes. */
    static constexpr std::size_t block_size = 136;

    /** Constructs the hash of nothing yet. */
    keccak_256() noexcept;
    /** Constructs a hash seeded by `seed`, as Hash2's sha3_256 is: nothing when it is zero. @param
     * seed The seed. */
    explicit keccak_256(std::uint64_t seed) noexcept;
    /** Constructs a hash seeded by the `n` bytes at `p`, as Hash2's sha3_256 is. @param p The seed.
     * @param n Its size. */
    keccak_256(void const* p, std::size_t n) noexcept;
    /** The same, from bytes. @param p The seed. @param n Its size. */
    keccak_256(unsigned char const* p, std::size_t n) noexcept;

    /** Absorbs `n` bytes. @param p The bytes. @param n Their number. */
    void update(void const* p, std::size_t n) noexcept;
    /** The same, from bytes. @param p The bytes. @param n Their number. */
    void update(unsigned char const* p, std::size_t n) noexcept;

    /**
     Pads, if nothing was padded since the last update, permutes and returns the first 32 bytes
     of the state; a further call returns the next permutation's.

     @return The digest.
    */
    result_type result() noexcept;

private:
    std::array<std::uint64_t, 25> state_;  // Keccak-p[1600]'s state, in XKCP's plain64 layout
    std::size_t m_ = 0;                    // bytes absorbed into the current block
    bool finalized_ = false;               // the padding is in the state
};

inline keccak_256::keccak_256() noexcept : state_{} {
    detail::touch_xkcp_canary();
    webcpp_hash_xkcp_initialize(state_.data());
}

inline keccak_256::keccak_256(std::uint64_t seed) noexcept : keccak_256() {
    if (seed == 0) {
        return;
    }
    // Hash2's detail::write64le: the seed's eight bytes, little-endian.
    std::array<unsigned char, 8> tmp{};
    for (std::size_t i = 0; i < tmp.size(); ++i) {
        tmp[i] = static_cast<unsigned char>(seed >> (8 * i));
    }
    update(tmp.data(), tmp.size());
    static_cast<void>(result());
    update(tmp.data(), 0);  // clears finalized_
}

inline keccak_256::keccak_256(unsigned char const* p, std::size_t n) noexcept : keccak_256() {
    if (n == 0) {
        return;
    }
    update(p, n);
    static_cast<void>(result());
    update(p, 0);  // clears finalized_
}

inline keccak_256::keccak_256(void const* p, std::size_t n) noexcept
    : keccak_256(static_cast<unsigned char const*>(p), n) {}

inline void keccak_256::update(void const* p, std::size_t n) noexcept {
    update(static_cast<unsigned char const*>(p), n);
}

inline void keccak_256::update(unsigned char const* p, std::size_t n) noexcept {
    detail::touch_xkcp_canary();
    finalized_ = false;
    if (n == 0) {
        return;
    }
    if (m_ > 0) {
        std::size_t const k = std::min(n, block_size - m_);
        webcpp_hash_xkcp_add_bytes(state_.data(), p, m_, k);
        p += k;
        n -= k;
        m_ += k;
        if (m_ < block_size) {
            return;
        }
        webcpp_hash_xkcp_permute(state_.data());
        m_ = 0;
    }
    while (n >= block_size) {
        webcpp_hash_xkcp_add_bytes(state_.data(), p, 0, block_size);
        webcpp_hash_xkcp_permute(state_.data());
        p += block_size;
        n -= block_size;
    }
    if (n > 0) {
        webcpp_hash_xkcp_add_bytes(state_.data(), p, 0, n);
        m_ = n;
    }
}

inline keccak_256::result_type keccak_256::result() noexcept {
    detail::touch_xkcp_canary();
    if (!finalized_) {
        constexpr unsigned char first = 0x01;  // Keccak's original padding delimiter
        constexpr unsigned char last = 0x80;
        webcpp_hash_xkcp_add_bytes(state_.data(), &first, m_, 1);
        webcpp_hash_xkcp_add_bytes(state_.data(), &last, block_size - 1, 1);
        m_ = 0;
        finalized_ = true;
    }
    webcpp_hash_xkcp_permute(state_.data());
    result_type digest;
    webcpp_hash_xkcp_extract_bytes(state_.data(), digest.data(), 0, digest.size());
    return digest;
}

}  // namespace webcpp::hash

#endif  // WEBCPP_HASH_HAS_XKCP

#endif  // WEBCPP_HASH_KECCAK_HPP
