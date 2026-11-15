// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

#ifndef WEBCPP_HASH_DETAIL_WIPE_HPP
#define WEBCPP_HASH_DETAIL_WIPE_HPP

#include <webcpp/hash/config.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>

#ifdef WEBCPP_HASH_DETAIL_TEST_WIPE_RECORD
namespace webcpp::hash::detail::test {

/**
 The test seam of @ref webcpp::hash::detail::wipe: a program built with
 `WEBCPP_HASH_DETAIL_TEST_WIPE_RECORD` defines this function, which each wipe calls once its
 bytes are zero, with what it wiped. A program built without the macro neither declares nor
 calls it.

 @param data The first byte wiped, or null when `size` is 0.
 @param size How many bytes.
*/
void wipe_record(void const* data, std::size_t size) noexcept;

}  // namespace webcpp::hash::detail::test
#endif

namespace webcpp::hash::detail {

/**
 Zeroes `size` bytes at `data` with stores the optimiser cannot drop.

 Tip: a `memset` before an object dies is a dead store a compiler may remove; stores through a
 volatile pointer, then a signal fence, are kept (spec section 6.1).

 @param data The first byte, or null when `size` is 0.
 @param size How many bytes.
*/
inline void wipe(void* data, std::size_t size) noexcept {
    auto* const bytes = static_cast<unsigned char volatile*>(data);
    for (std::size_t i = 0; i < size; ++i) {
        bytes[i] = 0;
    }
    std::atomic_signal_fence(std::memory_order_seq_cst);
#ifdef WEBCPP_HASH_DETAIL_TEST_WIPE_RECORD
    test::wipe_record(data, size);
#endif
}

/**
 Zeroes the bytes of a span, as @ref wipe(void*, std::size_t) does: an output a backend's failure
 leaves.

 @param bytes The bytes.
*/
inline void wipe(std::span<std::uint8_t> bytes) noexcept {
    wipe(bytes.data(), bytes.size());
}

/**
 Zeroes an object's bytes, as @ref wipe(void*, std::size_t) does: a keyed hmac, a block of a key
 derivation, a C library's context.

 @tparam T A trivially copyable type, whose bytes are all its state.
 @param object The object.
*/
template <class T>
void wipe_object(T& object) noexcept {
    static_assert(std::is_trivially_copyable_v<T>, "only a plain object's bytes are wiped");
    wipe(&object, sizeof object);
}

}  // namespace webcpp::hash::detail

#endif  // WEBCPP_HASH_DETAIL_WIPE_HPP
