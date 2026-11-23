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

// A declaration: src/canary_xkcp.c defines it, constant, in /third_party//xkcp, so its
// initialisation is static, never dynamic; constinit, on this declaration, states it.
extern "C" constinit const char WEBCPP_HASH_DETAIL_XKCP_CANARY;

namespace webcpp::hash::detail {

/**
 Reads XKCP's canary with a volatile load, which no linker can drop: a program built without
 `/third_party//xkcp`, or with one of another commit or configuration, fails to link with the
 canary's name.
*/
inline void touch_xkcp_canary() noexcept {
    // The volatile glvalue is converted to a value: a discarded one is not read by gcc
    // ("conversion to void will not access object").
    char const canary_copy = *static_cast<char const volatile*>(&WEBCPP_HASH_DETAIL_XKCP_CANARY);
    static_cast<void>(canary_copy);
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
    /** Constructs a hash seeded by `seed_value`, as Hash2's sha3_256 is: nothing when it is zero.
     * @param seed_value The seed. */
    explicit keccak_256(std::uint64_t seed_value) noexcept;
    /** Constructs a hash seeded by the `input_size` bytes at `input_data`, as Hash2's sha3_256 is.
     * @param input_data The seed.
     * @param input_size Its size. */
    keccak_256(void const* input_data, std::size_t input_size) noexcept;
    /** The same, from bytes. @param input_data The seed. @param input_size Its size. */
    keccak_256(unsigned char const* input_data, std::size_t input_size) noexcept;

    /** Absorbs `input_size` bytes. @param input_data The bytes. @param input_size Their number. */
    void update(void const* input_data, std::size_t input_size) noexcept;
    /** The same, from bytes. @param input_data The bytes. @param input_size Their number. */
    void update(unsigned char const* input_data, std::size_t input_size) noexcept;

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

inline keccak_256::keccak_256(std::uint64_t seed_value) noexcept : keccak_256() {
    if (seed_value == 0) {
        return;
    }
    // Hash2's detail::write64le: the seed's eight bytes, little-endian.
    std::array<unsigned char, 8> seed_bytes{};
    for (std::size_t byte_index = 0; byte_index < seed_bytes.size(); ++byte_index) {
        seed_bytes[byte_index] = static_cast<unsigned char>(seed_value >> (8 * byte_index));
    }
    update(seed_bytes.data(), seed_bytes.size());
    static_cast<void>(result());
    update(seed_bytes.data(), 0);  // clears finalized_
}

inline keccak_256::keccak_256(unsigned char const* input_data, std::size_t input_size) noexcept
    : keccak_256() {
    if (input_size == 0) {
        return;
    }
    update(input_data, input_size);
    static_cast<void>(result());
    update(input_data, 0);  // clears finalized_
}

inline keccak_256::keccak_256(void const* input_data, std::size_t input_size) noexcept
    : keccak_256(static_cast<unsigned char const*>(input_data), input_size) {}

inline void keccak_256::update(void const* input_data, std::size_t input_size) noexcept {
    update(static_cast<unsigned char const*>(input_data), input_size);
}

inline void keccak_256::update(unsigned char const* input_data, std::size_t input_size) noexcept {
    detail::touch_xkcp_canary();
    finalized_ = false;
    if (input_size == 0) {
        return;
    }
    if (m_ > 0) {
        std::size_t const absorbed_count = std::min(input_size, block_size - m_);
        webcpp_hash_xkcp_add_bytes(state_.data(), input_data, m_, absorbed_count);
        input_data += absorbed_count;
        input_size -= absorbed_count;
        m_ += absorbed_count;
        if (m_ < block_size) {
            return;
        }
        webcpp_hash_xkcp_permute(state_.data());
        m_ = 0;
    }
    while (input_size >= block_size) {
        webcpp_hash_xkcp_add_bytes(state_.data(), input_data, 0, block_size);
        webcpp_hash_xkcp_permute(state_.data());
        input_data += block_size;
        input_size -= block_size;
    }
    if (input_size > 0) {
        webcpp_hash_xkcp_add_bytes(state_.data(), input_data, 0, input_size);
        m_ = input_size;
    }
}

inline keccak_256::result_type keccak_256::result() noexcept {
    detail::touch_xkcp_canary();
    if (!finalized_) {
        constexpr unsigned char first_delimiter = 0x01;  // Keccak's original padding delimiter
        constexpr unsigned char last_delimiter = 0x80;
        webcpp_hash_xkcp_add_bytes(state_.data(), &first_delimiter, m_, 1);
        webcpp_hash_xkcp_add_bytes(state_.data(), &last_delimiter, block_size - 1, 1);
        m_ = 0;
        finalized_ = true;
    }
    webcpp_hash_xkcp_permute(state_.data());
    result_type digest_value;
    webcpp_hash_xkcp_extract_bytes(state_.data(), digest_value.data(), 0, digest_value.size());
    return digest_value;
}

}  // namespace webcpp::hash

#endif  // WEBCPP_HASH_HAS_XKCP

#endif  // WEBCPP_HASH_KECCAK_HPP
