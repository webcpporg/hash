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
#include <webcpp/hash/detail/timing.hpp>

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
    char const canary_copy = *static_cast<char const volatile*>(&WEBCPP_HASH_DETAIL_BLAKE3_CANARY);
    static_cast<void>(canary_copy);
}

}  // namespace detail

/**
 BLAKE3, its keyed mode, its key derivation and its extendable output, over the official C
 implementation, in Boost.Hash2's HashAlgorithm form.

 The object holds the C implementation's state, 1,912 bytes on 64-bit targets, a count of the
 bytes `result()` returned and a flag that says whether the object is keyed, 1,928 bytes in all on
 64-bit targets (the flag costs one alignment), and allocates nothing. Its destructor does not wipe
 that state, as Hash2's own algorithms do not.

 The keyed modes compute on a secret, and every call on a keyed object sets the CPU's
 data-independent timing (DIT) for the call where the CPU has it, as `mac` does, and leaves the
 thread's state as it found it (design D1): `keyed`, `derive_key`, a non-zero integer seed and a
 seed of bytes, then `update`, `result`, `squeeze` and `reset` of the object they make, which keeps
 the flag through copies and moves. The plain mode, a zero integer seed and a seed of no bytes
 compute on public data and hold no guard (design D2).
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
     Constructs a hash seeded by `seed_value`: plain when it is zero, else as from its 8
     little-endian bytes.

     @param seed_value The seed.
    */
    explicit blake3(std::uint64_t seed_value) noexcept;
    /**
     Constructs a hash seeded by `input_size` bytes: plain when `input_size` is zero; else BLAKE3's
     keyed hash under the first 32 bytes, zero-padded when there are fewer, with the bytes past them
     absorbed as the start of the input and one result() taken.

     That result() only moves the output's position, which the next update() starts again: a seed
     of 32 bytes `K` and more bytes `R`, then the input `M`, hashes as the seed `K` then the input
     `R` and `M`; with no update() after such a seed, the first result() returns bytes 32 to 63 of
     the output of `K` over `R`, the next 64 to 95, and so on. Two seeds of at most 32 bytes that
     differ only by trailing zero bytes are the same key.

     @param input_data The seed. @param input_size Its size.
    */
    blake3(void const* input_data, std::size_t input_size) noexcept;
    /** The same, from bytes. @param input_data The seed. @param input_size Its size. */
    blake3(unsigned char const* input_data, std::size_t input_size) noexcept;

    /** The keyed hash, BLAKE3's `keyed_hash`. @param key_bytes The key. @return The hash. */
    static blake3 keyed(std::span<std::uint8_t const, 32> key_bytes) noexcept;
    /**
     The key derivation, BLAKE3's `derive_key`, under `context_string`.

     @param context_string The context string, any bytes. @return The hash.
    */
    static blake3 derive_key(std::string_view context_string) noexcept;

    /** Absorbs `input_size` bytes. @param input_data The bytes. @param input_size Their number. */
    void update(void const* input_data, std::size_t input_size) noexcept;
    /** The same, from bytes. @param input_data The bytes. @param input_size Their number. */
    void update(unsigned char const* input_data, std::size_t input_size) noexcept;

    /**
     Returns the next 32 bytes of the output: the digest the first time after input was added,
     then the following 32 bytes of the extendable output at each call.

     @return 32 bytes of output.
    */
    result_type result() noexcept;

    /**
     Writes `output_bytes.size()` bytes of the extendable output, from byte `seek_position` on,
     without changing the hash.

     @param output_bytes Where to write. @param seek_position The first byte's position in the
     output.
    */
    void squeeze(std::span<std::uint8_t> output_bytes,
                 std::uint64_t seek_position = 0) const noexcept;

    /** Forgets the input, keeping the mode and its key or context. */
    void reset() noexcept;

private:
    // What keyed and derive_key construct, each then initializing hasher_ itself.
    struct uninitialized {};

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init): keyed and derive_key initialize it.
    explicit blake3(uninitialized /*tag*/) noexcept {}

    blake3_hasher hasher_;        // the C implementation's state, 1,912 bytes on 64-bit targets
    std::uint64_t squeezed_ = 0;  // bytes result() returned since input was last added
    bool keyed_ = false;          // keyed or derived from a key: every call holds the timing guard
};

// Each constructor initializes hasher_ through BLAKE3's own init function, which writes what
// the C implementation reads; a value-initialization first would clear its 1,912 bytes for
// nothing at every construction, which Hash2 does once per value it hashes.
// NOLINTBEGIN(cppcoreguidelines-pro-type-member-init)
inline blake3::blake3() noexcept {
    detail::touch_blake3_canary();
    blake3_hasher_init(&hasher_);
}

inline blake3::blake3(std::uint64_t seed_value) noexcept {
    detail::timing_guard const timing{seed_value != 0};
    detail::touch_blake3_canary();
    keyed_ = seed_value != 0;
    if (seed_value == 0) {
        blake3_hasher_init(&hasher_);
        return;
    }
    std::array<std::uint8_t, key_size> key_bytes{};
    for (std::size_t byte_index = 0; byte_index < 8; ++byte_index) {
        key_bytes[byte_index] = static_cast<std::uint8_t>(seed_value >> (8 * byte_index));
    }
    blake3_hasher_init_keyed(&hasher_, key_bytes.data());
}

inline blake3::blake3(void const* input_data, std::size_t input_size) noexcept
    : blake3(static_cast<unsigned char const*>(input_data), input_size) {}

inline blake3::blake3(unsigned char const* input_data, std::size_t input_size) noexcept {
    detail::timing_guard const timing{input_size != 0};
    detail::touch_blake3_canary();
    keyed_ = input_size != 0;
    if (input_size == 0) {
        blake3_hasher_init(&hasher_);
        return;
    }
    std::array<std::uint8_t, key_size> key_bytes{};
    std::copy_n(input_data, (std::min)(input_size, key_size), key_bytes.begin());
    blake3_hasher_init_keyed(&hasher_, key_bytes.data());
    if (input_size > key_size) {
        // result() only advances squeezed_, which the next update sets back to zero.
        update(input_data + key_size, input_size - key_size);
        result();
    }
}

// NOLINTEND(cppcoreguidelines-pro-type-member-init)

inline blake3 blake3::keyed(std::span<std::uint8_t const, 32> key_bytes) noexcept {
    detail::timing_guard const timing;
    detail::touch_blake3_canary();
    blake3 derived_hasher{uninitialized{}};
    derived_hasher.keyed_ = true;
    blake3_hasher_init_keyed(&derived_hasher.hasher_, key_bytes.data());
    return derived_hasher;
}

inline blake3 blake3::derive_key(std::string_view context_string) noexcept {
    detail::timing_guard const timing;
    detail::touch_blake3_canary();
    blake3 derived_hasher{uninitialized{}};
    derived_hasher.keyed_ = true;
    blake3_hasher_init_derive_key_raw(&derived_hasher.hasher_, context_string.data(),
                                      context_string.size());
    return derived_hasher;
}

inline void blake3::update(void const* input_data, std::size_t input_size) noexcept {
    detail::timing_guard const timing{keyed_};
    update(static_cast<unsigned char const*>(input_data), input_size);
}

inline void blake3::update(unsigned char const* input_data, std::size_t input_size) noexcept {
    detail::timing_guard const timing{keyed_};
    detail::touch_blake3_canary();
    if (input_size == 0) {
        return;
    }
    blake3_hasher_update(&hasher_, input_data, input_size);
    squeezed_ = 0;
}

inline blake3::result_type blake3::result() noexcept {
    detail::timing_guard const timing{keyed_};
    detail::touch_blake3_canary();
    result_type output_bytes;
    blake3_hasher_finalize_seek(&hasher_, squeezed_, output_bytes.data(), output_bytes.size());
    squeezed_ += output_bytes.size();
    return output_bytes;
}

inline void blake3::squeeze(std::span<std::uint8_t> output_bytes,
                            std::uint64_t seek_position) const noexcept {
    detail::timing_guard const timing{keyed_};
    detail::touch_blake3_canary();
    blake3_hasher_finalize_seek(&hasher_, seek_position, output_bytes.data(), output_bytes.size());
}

inline void blake3::reset() noexcept {
    detail::timing_guard const timing{keyed_};
    detail::touch_blake3_canary();
    blake3_hasher_reset(&hasher_);
    squeezed_ = 0;
}

}  // namespace webcpp::hash

#endif  // WEBCPP_HASH_HAS_BLAKE3

#endif  // WEBCPP_HASH_BLAKE3_HPP
