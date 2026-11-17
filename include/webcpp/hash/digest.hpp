// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The digest family (spec 2.15): `digest_of`, a hash in one call, and `hasher`, the same hash fed in
 pieces, each over a tag of `digests` and a backend, `default_backend` of the tag by default.

 The guards are the same on every backend and run before any work: an output of a size the tag
 does not produce is `invalid_output_size` (a fixed-size digest takes exactly its size, an
 extendable-output function any size from 1 byte); a value the tag accepts and the chosen backend
 does not is `unsupported_by_backend`. A guard's refusal leaves the output as it was; a backend's
 failure zeroes it.

 @code
 std::array<std::uint8_t, 32> id{};
 auto done = webcpp::hash::digest_of<webcpp::hash::digests::sha2_256>(id, message);

 auto hashing = webcpp::hash::hasher<webcpp::hash::digests::sha2_256>::make();
 // hashing->update(piece) for each piece, then hashing->finish(id), once
 @endcode

 The Hash2-form types (`sha2_256`, `keccak_256`, `blake3`, ...) stay the types to use with
 `hash_append`; a family reaches every backend's implementation of the same algorithm.

 @see "Digests", in the guide.
*/
#ifndef WEBCPP_HASH_DIGEST_HPP
#define WEBCPP_HASH_DIGEST_HPP

#include <webcpp/hash/config.hpp>

#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/detail/limits.hpp>
#include <webcpp/hash/detail/wipe.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/kdf.hpp>

#include <boost/system/result.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

namespace webcpp::hash {

/**
 The parameters of a digest: none for most tags, which this primary template serves. A tag with
 parameters (BLAKE2b's key, salt and personalisation; cSHAKE's and the SP 800-185 functions' names
 and customisations; KT128's and KT256's customisation; TurboSHAKE's domain byte) has its own
 specialisation, from the increment that brings its first backend.

 @tparam Digest A tag of `digests`.
*/
template <class Digest>
struct digest_options {};

namespace detail {

/** The output sizes of a digest of `Size` bytes, fixed: the output is exactly that. */
template <std::size_t Size>
struct fixed_output {
    /**
     The shortest output, the digest's size.

     @return `Size`.
    */
    template <class Options>
    static constexpr std::uint64_t min_output(Options const& /*options*/) noexcept {
        return Size;
    }

    /**
     The longest output, the digest's size.

     @return `Size`.
    */
    template <class Options>
    static constexpr std::uint64_t max_output(Options const& /*options*/) noexcept {
        return Size;
    }

    /**
     Checks a tag's options: none to check.

     @return Success.
    */
    template <class Options>
    [[nodiscard]] static constexpr boost::system::result<void> check(
        Options const& /*options*/) noexcept {
        return {};
    }
};

/** The output sizes of an extendable-output function: any size from 1 byte. */
struct extendable_output {
    /**
     The shortest output, 1 byte.

     @return 1.
    */
    template <class Options>
    static constexpr std::uint64_t min_output(Options const& /*options*/) noexcept {
        return 1;
    }

    /**
     The longest output: no limit.

     @return `no_limit`.
    */
    template <class Options>
    static constexpr std::uint64_t max_output(Options const& /*options*/) noexcept {
        return no_limit;
    }

    /**
     Checks a tag's options: none to check.

     @return Success.
    */
    template <class Options>
    [[nodiscard]] static constexpr boost::system::result<void> check(
        Options const& /*options*/) noexcept {
        return {};
    }
};

/**
 The family's guards of a tag of `digests`, in one place (spec 2.15): `min_output(options)` and
 `max_output(options)`, the output sizes the tag produces (`invalid_output_size` outside them);
 `check(options)`, the options' own guards (`invalid_parameters`, `invalid_key_size` or
 `invalid_salt_size`), success for a tag without options. Every tag of `digests` has a
 specialisation; the increment that gives a tag options adds their check to it.

 The primary template, reached only by a type that is not a tag, guards nothing: the engine's
 refusal is then the call's only error.

 @tparam Digest A tag of `digests`.
*/
template <class Digest>
struct digest_traits : extendable_output {};

// clang-format off
/** MD5: 16 bytes. */
template <> struct digest_traits<digests::md5> : fixed_output<16> {};
/** SHA-1: 20 bytes. */
template <> struct digest_traits<digests::sha1> : fixed_output<20> {};
/** SHA-224: 28 bytes. */
template <> struct digest_traits<digests::sha2_224> : fixed_output<28> {};
/** SHA-256: 32 bytes. */
template <> struct digest_traits<digests::sha2_256> : fixed_output<32> {};
/** SHA-384: 48 bytes. */
template <> struct digest_traits<digests::sha2_384> : fixed_output<48> {};
/** SHA-512: 64 bytes. */
template <> struct digest_traits<digests::sha2_512> : fixed_output<64> {};
/** SHA-512/224: 28 bytes. */
template <> struct digest_traits<digests::sha2_512_224> : fixed_output<28> {};
/** SHA-512/256: 32 bytes. */
template <> struct digest_traits<digests::sha2_512_256> : fixed_output<32> {};
/** SHA3-224: 28 bytes. */
template <> struct digest_traits<digests::sha3_224> : fixed_output<28> {};
/** SHA3-256: 32 bytes. */
template <> struct digest_traits<digests::sha3_256> : fixed_output<32> {};
/** SHA3-384: 48 bytes. */
template <> struct digest_traits<digests::sha3_384> : fixed_output<48> {};
/** SHA3-512: 64 bytes. */
template <> struct digest_traits<digests::sha3_512> : fixed_output<64> {};
/** SHAKE128: any size from 1 byte. */
template <> struct digest_traits<digests::shake_128> : extendable_output {};
/** SHAKE256: any size from 1 byte. */
template <> struct digest_traits<digests::shake_256> : extendable_output {};
/** Keccak-224: 28 bytes. */
template <> struct digest_traits<digests::keccak_224> : fixed_output<28> {};
/** Keccak-256: 32 bytes. */
template <> struct digest_traits<digests::keccak_256> : fixed_output<32> {};
/** Keccak-384: 48 bytes. */
template <> struct digest_traits<digests::keccak_384> : fixed_output<48> {};
/** Keccak-512: 64 bytes. */
template <> struct digest_traits<digests::keccak_512> : fixed_output<64> {};
/** cSHAKE128: any size from 1 byte. */
template <> struct digest_traits<digests::cshake_128> : extendable_output {};
/** cSHAKE256: any size from 1 byte. */
template <> struct digest_traits<digests::cshake_256> : extendable_output {};
/** KT128: any size from 1 byte. */
template <> struct digest_traits<digests::kt128> : extendable_output {};
/** KT256: any size from 1 byte. */
template <> struct digest_traits<digests::kt256> : extendable_output {};
/** TurboSHAKE128: any size from 1 byte. */
template <> struct digest_traits<digests::turboshake_128> : extendable_output {};
/** TurboSHAKE256: any size from 1 byte. */
template <> struct digest_traits<digests::turboshake_256> : extendable_output {};
/** TupleHash128: any size from 1 byte (its L). */
template <> struct digest_traits<digests::tuplehash_128> : extendable_output {};
/** TupleHash256: any size from 1 byte (its L). */
template <> struct digest_traits<digests::tuplehash_256> : extendable_output {};
/** ParallelHash128: any size from 1 byte (its L). */
template <> struct digest_traits<digests::parallelhash_128> : extendable_output {};
/** ParallelHash256: any size from 1 byte (its L). */
template <> struct digest_traits<digests::parallelhash_256> : extendable_output {};
/** BLAKE2s-256: 32 bytes. */
template <> struct digest_traits<digests::blake2s_256> : fixed_output<32> {};
/** BLAKE3: any size from 1 byte (its digest is the first 32). */
template <> struct digest_traits<digests::blake3> : extendable_output {};
/** RIPEMD-160: 20 bytes. */
template <> struct digest_traits<digests::ripemd_160> : fixed_output<20> {};
/** MD5 then SHA-1: 36 bytes. */
template <> struct digest_traits<digests::md5_sha1> : fixed_output<36> {};
/** SM3: 32 bytes. */
template <> struct digest_traits<digests::sm3> : fixed_output<32> {};
/** Streebog-256: 32 bytes. */
template <> struct digest_traits<digests::streebog_256> : fixed_output<32> {};
/** Streebog-512: 64 bytes. */
template <> struct digest_traits<digests::streebog_512> : fixed_output<64> {};
/** Whirlpool: 64 bytes. */
template <> struct digest_traits<digests::whirlpool> : fixed_output<64> {};
/** Skein-512: 64 bytes. */
template <> struct digest_traits<digests::skein_512> : fixed_output<64> {};
// clang-format on

/** BLAKE2b: 1 to 64 bytes (RFC 7693); its options' guards come with its first backend. */
template <>
struct digest_traits<digests::blake2b> : fixed_output<64> {
    /**
     The shortest output, 1 byte.

     @return 1.
    */
    template <class Options>
    static constexpr std::uint64_t min_output(Options const& /*options*/) noexcept {
        return 1;
    }
};

/**
 The family's guards of `digest_of` and `hasher::finish` on an output of `output_size` bytes: the
 tag's sizes (`invalid_output_size`), then the backend's shortest and longest outputs
 (`unsupported_by_backend`).

 @tparam Digest A tag of `digests`. @tparam Engine Its engine on the chosen backend.
 @param output_size The output's size. @param min_size The tag's shortest output for its options.
 @param max_size The tag's longest output for its options.
 @return Success, or the guard's error.
*/
template <class Digest, class Engine>
[[nodiscard]] boost::system::result<void> check_output(std::size_t output_size,
                                                       std::uint64_t min_size,
                                                       std::uint64_t max_size) noexcept {
    if (output_size < min_size || exceeds(output_size, max_size)) {
        return error::invalid_output_size;
    }
    if (exceeds(Engine::min_output, output_size) || exceeds(output_size, Engine::max_output)) {
        return error::unsupported_by_backend;
    }
    return {};
}

}  // namespace detail

/**
 Hashes `input` into `output` with the digest `Digest` on `Backend`, in one call.

 @code
 std::array<std::uint8_t, 32> id{};
 auto done = webcpp::hash::digest_of<webcpp::hash::digests::sha2_256>(id, message);
 @endcode

 @tparam Digest A tag of `digests`, as `digests::sha2_256`.
 @tparam Backend The backend; by default @ref default_backend of `Digest` (spec 4.1). A backend
 without the tag, or one the program does not link, refuses at compile time, naming those that
 have it, or the Jamfile line to add.
 @param output The digest: exactly the digest's size for a fixed-size digest, any size from 1
 byte for an extendable-output function.
 @param input The data, of any size.
 @param options The digest's parameters (none for most tags).
 @return Success; or the first guard's error (`invalid_output_size`, an option's error,
 `unsupported_by_backend`), `output` untouched; or the backend's failure, `output` zeroed.
*/
template <class Digest, class Backend = default_backend<Digest>>
[[nodiscard]] boost::system::result<void> digest_of(std::span<std::uint8_t> output,
                                                    std::span<std::uint8_t const> input,
                                                    digest_options<Digest> const& options = {}) {
    using engine = detail::digest_engine<Backend, Digest>;
    using traits = detail::digest_traits<Digest>;
    auto sized = detail::check_output<Digest, engine>(output.size(), traits::min_output(options),
                                                      traits::max_output(options));
    if (!sized) {
        return sized;
    }
    auto checked = traits::check(options);
    if (!checked) {
        return checked;
    }
    if (!engine::accepts(options)) {
        return error::unsupported_by_backend;
    }
    auto hashed = engine::one_shot(output, input, options);
    if (!hashed) {
        detail::wipe(output);
    }
    return hashed;
}

/**
 A hash fed in pieces, with one result: `make`, `update` as often as the data comes, then `finish`.

 `finish` is called once (spec 2.15). Unlike Boost.Hash2's types, the result is final: an `update`
 or a `finish` after `finish`, or on a hasher moved from, is `error::invalid_state`.

 Move-only. The state is wiped (and what the backend allocated for it freed) by `finish`, by the
 destructor, and in the hasher moved from.

 @code
 auto hashing = webcpp::hash::hasher<webcpp::hash::digests::sha2_256>::make();
 if (!hashing) {
     return hashing.error();
 }
 for (auto piece : pieces) {
     if (auto fed = hashing->update(piece); !fed) {
         return fed.error();
     }
 }
 std::array<std::uint8_t, 32> id{};
 auto done = hashing->finish(id);
 @endcode

 @tparam Digest A tag of `digests`.
 @tparam Backend The backend; by default @ref default_backend of `Digest`.
*/
template <class Digest, class Backend = default_backend<Digest>>
class hasher {
    using engine = detail::digest_engine<Backend, Digest>;
    using traits = detail::digest_traits<Digest>;

public:
    /**
     Starts a hash.

     @param options The digest's parameters (none for most tags).
     @return The hasher; or an option's error or `unsupported_by_backend`; or the backend's
     failure.
    */
    [[nodiscard]] static boost::system::result<hasher> make(
        digest_options<Digest> const& options = {}) noexcept {
        auto const checked = traits::check(options);
        if (!checked) {
            return checked.error();
        }
        if (!engine::accepts(options)) {
            return error::unsupported_by_backend;
        }
        hasher started;
        auto const initialised = engine::init(started.state_, options);
        if (!initialised) {
            engine::destroy(started.state_);
            started.phase_ = phase::spent;
            return initialised.error();
        }
        started.min_output_ = traits::min_output(options);
        started.max_output_ = traits::max_output(options);
        started.phase_ = phase::hashing;
        return started;
    }

    /**
     Takes the hash of `moved_from`, which is wiped and then answers `invalid_state`.

     @param moved_from The hasher moved from.
    */
    hasher(hasher&& moved_from) noexcept
        : state_(std::move(moved_from.state_)),
          min_output_(moved_from.min_output_),
          max_output_(moved_from.max_output_),
          phase_(moved_from.phase_) {
        moved_from.leave();
    }

    /**
     Ends this hash (its state wiped) and takes that of `moved_from`, which is wiped and then
     answers `invalid_state`.

     @param moved_from The hasher moved from.
     @return This hasher.
    */
    hasher& operator=(hasher&& moved_from) noexcept {
        if (this != &moved_from) {
            end();
            state_ = std::move(moved_from.state_);
            min_output_ = moved_from.min_output_;
            max_output_ = moved_from.max_output_;
            phase_ = moved_from.phase_;
            moved_from.leave();
        }
        return *this;
    }

    /** Not copyable: a copy would be a second result of one hash, and a second state to wipe. */
    hasher(hasher const&) = delete;
    /** Not copyable. @return Never. */
    hasher& operator=(hasher const&) = delete;

    /** Wipes the state, and frees what the backend allocated for it. */
    ~hasher() { end(); }

    /**
     Absorbs `input`.

     @param input The next piece of the data, of any size.
     @return Success; `invalid_state` after `finish` or once moved from; or the backend's failure,
     after which the hasher is spent (`invalid_state`).
    */
    [[nodiscard]] boost::system::result<void> update(std::span<std::uint8_t const> input) noexcept {
        if (phase_ != phase::hashing) {
            return error::invalid_state;
        }
        auto absorbed = engine::update(state_, input);
        if (!absorbed) {
            end();
        }
        return absorbed;
    }

    /**
     Writes the hash's result into `output`, once.

     @param output The digest: exactly the digest's size for a fixed-size digest, any size from 1
     byte for an extendable-output function.
     @return Success, after which the hasher is spent; `invalid_state` after `finish` or once
     moved from; a guard's error (`invalid_output_size`, `unsupported_by_backend`), `output`
     untouched and the hasher still hashing; or the backend's failure, `output` zeroed and the
     hasher spent.
    */
    [[nodiscard]] boost::system::result<void> finish(std::span<std::uint8_t> output) noexcept {
        if (phase_ != phase::hashing) {
            return error::invalid_state;
        }
        auto sized = detail::check_output<Digest, engine>(output.size(), min_output_, max_output_);
        if (!sized) {
            return sized;
        }
        auto finished = engine::finish(state_, output);
        if (!finished) {
            detail::wipe(output);
        }
        end();
        return finished;
    }

private:
    // hashing: make succeeded and finish has not run; spent: finished, failed or never started;
    // moved: the hash went to another hasher.
    enum class phase : unsigned char { spent, hashing, moved };

    hasher() noexcept = default;

    // Wipes the state of a hash in progress, which is then spent.
    void end() noexcept {
        if (phase_ == phase::hashing) {
            engine::destroy(state_);
            phase_ = phase::spent;
        }
    }

    // After its hash was moved out: what is left of the state is wiped.
    void leave() noexcept {
        if (phase_ == phase::hashing) {
            engine::destroy(state_);
        }
        phase_ = phase::moved;
    }

    engine::state state_{};
    std::uint64_t min_output_ = 0;
    std::uint64_t max_output_ = 0;
    phase phase_ = phase::spent;
};

}  // namespace webcpp::hash

// The engines of each backend the program links, so that `digest_of` and `hasher` reach them on a
// call that names the backend, and on the default: backends::hash2 above, always; the others when
// their target defines their WEBCPP_HASH_HAS_<NAME>.
#ifdef WEBCPP_HASH_HAS_XKCP
#include <webcpp/hash/backends/xkcp.hpp>
#endif
#ifdef WEBCPP_HASH_HAS_BLAKE3
#include <webcpp/hash/backends/blake3.hpp>
#endif
#ifdef WEBCPP_HASH_HAS_SODIUM
#include <webcpp/hash/backends/sodium.hpp>
#endif
#ifdef WEBCPP_HASH_HAS_BEARSSL
#include <webcpp/hash/backends/bearssl.hpp>
#endif
#ifdef WEBCPP_HASH_HAS_OPENSSL
#include <webcpp/hash/backends/openssl.hpp>
#endif

#endif  // WEBCPP_HASH_DIGEST_HPP
