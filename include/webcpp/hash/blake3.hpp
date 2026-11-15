// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 BLAKE3 over its official C implementation, built from source by `/third_party//blake3`, in
 Boost.Hash2's HashAlgorithm form: the plain hash, the keyed hash, the key derivation and the
 extendable output, on every target.

 @see "BLAKE3", in the guide.
*/
#ifndef WEBCPP_HASH_BLAKE3_HPP
#define WEBCPP_HASH_BLAKE3_HPP

#include <webcpp/hash/config.hpp>

#ifndef WEBCPP_HASH_HAS_BLAKE3
#error \
    "webcpp::hash: blake3 needs BLAKE3's C implementation. Add /third_party//blake3 to the program's Jamfile: exe app : app.cpp /webcpp/hash//hash /third_party//blake3 ;"
#else

#include <webcpp/hash/detail/canary.h>

#include <boost/hash2/digest.hpp>

#include <blake3.h>  // third_party/libs/blake3/c, through /third_party//blake3

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#ifdef WEBCPP_HASH_BLAKE3_CANARY_CONFIGURATION
/** The configuration the canary names: a test's, here. */
#define WEBCPP_HASH_DETAIL_BLAKE3_CONFIGURATION WEBCPP_HASH_BLAKE3_CANARY_CONFIGURATION
#elif defined(WEBCPP_HASH_WEBASSEMBLY)
/** The configuration the canary names: on WebAssembly, the portable code alone. */
#define WEBCPP_HASH_DETAIL_BLAKE3_CONFIGURATION portable
#elif defined(__x86_64__) || defined(_M_X64)
/** The configuration the canary names: on x86-64, the four intrinsics files, dispatched. */
#define WEBCPP_HASH_DETAIL_BLAKE3_CONFIGURATION x86
#elif defined(__aarch64__) || defined(_M_ARM64)
/** The configuration the canary names: on arm64, the NEON file, dispatched. */
#define WEBCPP_HASH_DETAIL_BLAKE3_CONFIGURATION neon
#else
/** The configuration the canary names: on any other target, the portable code alone. */
#define WEBCPP_HASH_DETAIL_BLAKE3_CONFIGURATION portable
#endif
/** The canary's name, which every function of this header that calls BLAKE3 reads (spec 5.4). */
#define WEBCPP_HASH_DETAIL_BLAKE3_CANARY                         \
    WEBCPP_HASH_DETAIL_CANARY(blake3, WEBCPP_HASH_BLAKE3_COMMIT, \
                              WEBCPP_HASH_DETAIL_BLAKE3_CONFIGURATION)

#ifdef _MSC_VER
#pragma detect_mismatch(                                                 \
    "webcpp_hash_backend_blake3",                                        \
    WEBCPP_HASH_DETAIL_MISMATCH_VALUE(blake3, WEBCPP_HASH_BLAKE3_COMMIT, \
                                      WEBCPP_HASH_DETAIL_BLAKE3_CONFIGURATION))
#endif

// A declaration: src/canary_blake3.c defines it, constant, in /third_party//blake3.
// NOLINTNEXTLINE(bugprone-dynamic-static-initializers)
extern "C" const char WEBCPP_HASH_DETAIL_BLAKE3_CANARY;

namespace webcpp::hash {

namespace detail {

/**
 Reads BLAKE3's canary with a volatile load, which no linker can drop: a program built without
 `/third_party//blake3`, or with one of another commit or configuration, then fails to link,
 naming the canary (spec 5.4).
*/
inline void touch_blake3_canary() noexcept {
    // The volatile glvalue is converted to a value: a discarded one is not read by gcc
    // ("conversion to void will not access object").
    char const value = *static_cast<char const volatile*>(&WEBCPP_HASH_DETAIL_BLAKE3_CANARY);
    static_cast<void>(value);
}

}  // namespace detail

/**
 BLAKE3, its keyed mode, its key derivation and its extendable output, over the official C
 implementation, in Boost.Hash2's HashAlgorithm form.

 The object holds the C implementation's state, 1,912 bytes on 64-bit targets, and allocates
 nothing. Its destructor does not wipe that state, as Hash2's own algorithms do not.
*/
class blake3 {
public:
    /** The digest, 32 bytes. */
    using result_type = boost::hash2::digest<32>;
    /** BLAKE3's block, 64 bytes. */
    static constexpr std::size_t block_size = 64;
    /** The key of the keyed mode, 32 bytes. */
    static constexpr std::size_t key_size = 32;

    /** Constructs the plain hash. */
    blake3() noexcept;
    /**
     Constructs a hash seeded by `seed`: plain when it is zero, else as from its 8 little-endian
     bytes.

     @param seed The seed.
    */
    explicit blake3(std::uint64_t seed) noexcept;
    /**
     Constructs a hash seeded by `n` bytes: plain when `n` is zero; else BLAKE3's keyed hash
     under the first 32 bytes, zero-padded when there are fewer, with the bytes past them
     absorbed as the start of the input and one result() taken. That result() only moves the
     output's position, which the next update() starts again: a seed of 32 bytes `K` and more
     bytes `R`, then the input `M`, hashes as the seed `K` then the input `R` and `M`; with no
     update() after such a seed, the first result() returns bytes 32 to 63 of the output of
     `K` over `R`, the next 64 to 95, and so on. Two seeds of at most 32 bytes that differ
     only by trailing zero bytes are the same key.

     @param p The seed. @param n Its size.
    */
    blake3(void const* p, std::size_t n) noexcept;
    /** The same, from bytes. @param p The seed. @param n Its size. */
    blake3(unsigned char const* p, std::size_t n) noexcept;

    /** The keyed hash, BLAKE3's `keyed_hash`. @param key The key. @return The hash. */
    static blake3 keyed(std::span<std::uint8_t const, 32> key) noexcept;
    /**
     The key derivation, BLAKE3's `derive_key`, under `context`.

     @param context The context string, any bytes. @return The hash.
    */
    static blake3 derive_key(std::string_view context) noexcept;

    /** Absorbs `n` bytes. @param p The bytes. @param n Their number. */
    void update(void const* p, std::size_t n) noexcept;
    /** The same, from bytes. @param p The bytes. @param n Their number. */
    void update(unsigned char const* p, std::size_t n) noexcept;

    /**
     Returns the next 32 bytes of the output: the digest the first time after input was added,
     then the following 32 bytes of the extendable output at each call.

     @return 32 bytes of output.
    */
    result_type result() noexcept;

    /**
     Writes `output.size()` bytes of the extendable output, from byte `position` on, without
     changing the hash.

     @param output Where to write. @param position The first byte's position in the output.
    */
    void squeeze(std::span<std::uint8_t> output, std::uint64_t position = 0) const noexcept;

    /** Forgets the input, keeping the mode and its key or context. */
    void reset() noexcept;

private:
    // What keyed and derive_key construct, each then initializing hasher_ itself.
    struct uninitialized {};

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init): keyed and derive_key initialize it.
    explicit blake3(uninitialized /*tag*/) noexcept {}

    blake3_hasher hasher_;        // the C implementation's state, 1,912 bytes on 64-bit targets
    std::uint64_t squeezed_ = 0;  // bytes result() returned since input was last added
};

// Each constructor initializes hasher_ through BLAKE3's own init function, which writes what
// the C implementation reads; a value-initialization first would clear its 1,912 bytes for
// nothing at every construction, which Hash2 does once per value it hashes.
// NOLINTBEGIN(cppcoreguidelines-pro-type-member-init)
inline blake3::blake3() noexcept {
    detail::touch_blake3_canary();
    blake3_hasher_init(&hasher_);
}

inline blake3::blake3(std::uint64_t seed) noexcept {
    detail::touch_blake3_canary();
    if (seed == 0) {
        blake3_hasher_init(&hasher_);
        return;
    }
    std::array<std::uint8_t, key_size> key{};
    for (std::size_t i = 0; i < 8; ++i) {
        key[i] = static_cast<std::uint8_t>(seed >> (8 * i));
    }
    blake3_hasher_init_keyed(&hasher_, key.data());
}

inline blake3::blake3(void const* p, std::size_t n) noexcept
    : blake3(static_cast<unsigned char const*>(p), n) {}

inline blake3::blake3(unsigned char const* p, std::size_t n) noexcept {
    detail::touch_blake3_canary();
    if (n == 0) {
        blake3_hasher_init(&hasher_);
        return;
    }
    std::array<std::uint8_t, key_size> key{};
    std::copy_n(p, (std::min)(n, key_size), key.begin());
    blake3_hasher_init_keyed(&hasher_, key.data());
    if (n > key_size) {
        // result() only advances squeezed_, which the next update sets back to zero.
        update(p + key_size, n - key_size);
        result();
    }
}

// NOLINTEND(cppcoreguidelines-pro-type-member-init)

inline blake3 blake3::keyed(std::span<std::uint8_t const, 32> key) noexcept {
    detail::touch_blake3_canary();
    blake3 hasher{uninitialized{}};
    blake3_hasher_init_keyed(&hasher.hasher_, key.data());
    return hasher;
}

inline blake3 blake3::derive_key(std::string_view context) noexcept {
    detail::touch_blake3_canary();
    blake3 hasher{uninitialized{}};
    blake3_hasher_init_derive_key_raw(&hasher.hasher_, context.data(), context.size());
    return hasher;
}

inline void blake3::update(void const* p, std::size_t n) noexcept {
    update(static_cast<unsigned char const*>(p), n);
}

inline void blake3::update(unsigned char const* p, std::size_t n) noexcept {
    detail::touch_blake3_canary();
    if (n == 0) {
        return;
    }
    blake3_hasher_update(&hasher_, p, n);
    squeezed_ = 0;
}

inline blake3::result_type blake3::result() noexcept {
    detail::touch_blake3_canary();
    result_type output;
    blake3_hasher_finalize_seek(&hasher_, squeezed_, output.data(), output.size());
    squeezed_ += output.size();
    return output;
}

inline void blake3::squeeze(std::span<std::uint8_t> output, std::uint64_t position) const noexcept {
    detail::touch_blake3_canary();
    blake3_hasher_finalize_seek(&hasher_, position, output.data(), output.size());
}

inline void blake3::reset() noexcept {
    detail::touch_blake3_canary();
    blake3_hasher_reset(&hasher_);
    squeezed_ = 0;
}

}  // namespace webcpp::hash

#endif  // WEBCPP_HASH_HAS_BLAKE3

#endif  // WEBCPP_HASH_BLAKE3_HPP
