// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A backend for the tests of the families (spec 2.15), webcpp::crypto's pattern: it specialises
// the engines of a few tags with a transform that is NOT a hash (each output byte is the sum of
// the input's bytes, the key's and the byte's index), so that the guards, hasher's state machine
// and the error paths run on every target with every engine call observable. Its knobs make each
// engine call fail, or refuse the options, on demand. Every engine call checks the contract the
// families owe an engine (no work on a state that is not live, one finish per init, one destroy
// per init and per state moved from) and counts each breach in mock_control.violations, which a
// test expects to stay 0.

#ifndef WEBCPP_TEST_HASH_SUPPORT_MOCK_BACKEND_HPP
#define WEBCPP_TEST_HASH_SUPPORT_MOCK_BACKEND_HPP

#include <webcpp/hash/config.hpp>

#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/mac.hpp>

#include <boost/system/error_code.hpp>
#include <boost/system/result.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

namespace webcpp::test {

/** The mock backend's tag. */
struct mock {};

/** What a test makes the mock do, and what the mock saw. */
struct mock_knobs {
    /** The error of `init`, `update`, `finish`, `one_shot`, `compute` and `derive`, when set. */
    boost::system::error_code init;
    boost::system::error_code update;
    boost::system::error_code finish;
    boost::system::error_code one_shot;
    boost::system::error_code compute;
    boost::system::error_code derive;
    /** What the engines' `accepts` answer. */
    bool accepts = true;
    /** The calls of each engine function so far. */
    int inits = 0;
    int updates = 0;
    int finishes = 0;
    int destroys = 0;
    /** The destroys that ended a live state (the others found a state moved from). */
    int ends = 0;
    int one_shots = 0;
    int computes = 0;
    int derives = 0;
    /** The states initialised and not yet destroyed. */
    int live = 0;
    /** The breaches of the engine contract seen so far. */
    int violations = 0;
};

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the knobs a test turns
inline mock_knobs mock_control{};

/** Clears every knob and counter. */
inline void mock_reset() {
    mock_control = mock_knobs{};
}

/**
 The mock's state: a running sum, and whether it is live (initialised, not destroyed). It owns its
 liveness as OpenSSL's state owns its context: a move carries it, and the state moved from owns
 nothing, so that destroying it ends nothing.
*/
struct mock_state {
    /** The sum of the bytes absorbed. */
    std::uint64_t sum = 0;
    /** Whether init made it and no destroy ended it. */
    bool live = false;
    /** Whether finish ran on it. */
    bool finished = false;

    mock_state() = default;

    mock_state(std::uint64_t first_sum, bool is_live, bool is_finished)
        : sum(first_sum), live(is_live), finished(is_finished) {}

    mock_state(mock_state const&) = delete;
    mock_state& operator=(mock_state const&) = delete;

    mock_state(mock_state&& other) noexcept
        : sum(other.sum), live(std::exchange(other.live, false)), finished(other.finished) {}

    mock_state& operator=(mock_state&& other) noexcept {
        if (this != &other) {
            if (live) {
                ++mock_control.violations;  // the families destroy a live state before reusing it
            }
            sum = other.sum;
            live = std::exchange(other.live, false);
            finished = other.finished;
        }
        return *this;
    }

    ~mock_state() = default;
};

/** The mock's transform: each output byte is the sum plus its index, cut to a byte. */
inline void mock_fill(std::span<std::uint8_t> output, std::uint64_t sum) {
    for (std::size_t index = 0; index < output.size(); ++index) {
        output[index] = static_cast<std::uint8_t>(sum + index);
    }
}

/** The sum of some bytes. */
inline std::uint64_t mock_sum(std::span<std::uint8_t const> bytes) {
    std::uint64_t sum = 0;
    for (auto const byte : bytes) {
        sum += byte;
    }
    return sum;
}

/** A digest engine of the mock, as a backend's header would write it. */
template <class Digest, std::uint64_t MaxOutput>
struct mock_digest_engine {
    using state = mock_state;
    static constexpr std::uint64_t min_output = 0;
    static constexpr std::uint64_t max_output = MaxOutput;

    static bool accepts(hash::digest_options<Digest> const& /*options*/) noexcept {
        return mock_control.accepts;
    }

    static boost::system::result<void> init(
        state& hashed, hash::digest_options<Digest> const& /*options*/) noexcept {
        ++mock_control.inits;
        if (hashed.live) {
            ++mock_control.violations;
        }
        hashed.live = true;
        hashed.sum = 0;
        hashed.finished = false;
        ++mock_control.live;
        if (mock_control.init) {
            return mock_control.init;
        }
        return {};
    }

    static boost::system::result<void> update(state& hashed,
                                              std::span<std::uint8_t const> input) noexcept {
        ++mock_control.updates;
        if (!hashed.live || hashed.finished) {
            ++mock_control.violations;
        }
        if (mock_control.update) {
            return mock_control.update;
        }
        hashed.sum += mock_sum(input);
        return {};
    }

    static boost::system::result<void> finish(state& hashed,
                                              std::span<std::uint8_t> output) noexcept {
        ++mock_control.finishes;
        if (!hashed.live || hashed.finished) {
            ++mock_control.violations;
        }
        hashed.finished = true;
        if (mock_control.finish) {
            mock_fill(output, 0xAB);  // what a backend may leave before it fails
            return mock_control.finish;
        }
        mock_fill(output, hashed.sum);
        return {};
    }

    static void destroy(state& hashed) noexcept {
        ++mock_control.destroys;
        if (hashed.live) {
            --mock_control.live;
            ++mock_control.ends;
        }
        hashed.live = false;
        hashed.sum = 0;
    }

    static boost::system::result<void> one_shot(
        std::span<std::uint8_t> output, std::span<std::uint8_t const> input,
        hash::digest_options<Digest> const& /*options*/) noexcept {
        ++mock_control.one_shots;
        if (mock_control.one_shot) {
            mock_fill(output, 0xAB);
            return mock_control.one_shot;
        }
        mock_fill(output, mock_sum(input));
        return {};
    }
};

/** A MAC engine of the mock. */
template <class Mac>
struct mock_mac_engine {
    static bool accepts(hash::mac_options<Mac> const& /*options*/, std::size_t /*key_size*/,
                        std::size_t /*output_size*/) noexcept {
        return mock_control.accepts;
    }

    static boost::system::result<void> compute(std::span<std::uint8_t> output,
                                               std::span<std::uint8_t const> key,
                                               std::span<std::uint8_t const> input,
                                               hash::mac_options<Mac> const& /*options*/) noexcept {
        ++mock_control.computes;
        if (mock_control.compute) {
            mock_fill(output, 0xAB);
            return mock_control.compute;
        }
        mock_fill(output, mock_sum(key) + mock_sum(input));
        return {};
    }
};

}  // namespace webcpp::test

namespace webcpp::hash::detail {

/** SHA-256's tag on the mock: a fixed-size digest. */
template <>
struct digest_engine<::webcpp::test::mock, digests::sha2_256>
    : ::webcpp::test::mock_digest_engine<digests::sha2_256, no_limit> {};

/** SHAKE128's tag on the mock: an extendable output of at most 100 bytes, a partial cell. */
template <>
struct digest_engine<::webcpp::test::mock, digests::shake_128>
    : ::webcpp::test::mock_digest_engine<digests::shake_128, 100> {};

/** HMAC-SHA-256's tag on the mock. */
template <>
struct mac_engine<::webcpp::test::mock, macs::hmac<digests::sha2_256>>
    : ::webcpp::test::mock_mac_engine<macs::hmac<digests::sha2_256>> {};

/** SipHash-2-4's tag on the mock: a fixed key and tag. */
template <>
struct mac_engine<::webcpp::test::mock, macs::siphash_2_4>
    : ::webcpp::test::mock_mac_engine<macs::siphash_2_4> {};

/** Argon2id on the mock, with libsodium's limits: one lane, no secret or associated data. */
template <>
struct argon2_engine<::webcpp::test::mock, kdfs::argon2id> {
    static constexpr argon2_limits limits{
        .min_passes = 3,
        .max_memory_kib = 1U << 20U,
        .max_lanes = 1,
        .min_output = 16,
        .min_salt = 16,
        .max_salt = 16,
        .secret = false,
        .associated_data = false,
    };

    static boost::system::result<void> derive(std::span<std::uint8_t> output,
                                              std::span<std::uint8_t const> password,
                                              std::span<std::uint8_t const> salt,
                                              argon2_parameters const& parameters) noexcept {
        ++::webcpp::test::mock_control.derives;
        if (::webcpp::test::mock_control.derive) {
            ::webcpp::test::mock_fill(output, 0xAB);
            return ::webcpp::test::mock_control.derive;
        }
        ::webcpp::test::mock_fill(output, ::webcpp::test::mock_sum(password) +
                                              ::webcpp::test::mock_sum(salt) + parameters.passes +
                                              parameters.memory_kib);
        return {};
    }
};

/** Argon2d on the mock, with every parameter. */
template <>
struct argon2_engine<::webcpp::test::mock, kdfs::argon2d> {
    static constexpr argon2_limits limits{};

    static boost::system::result<void> derive(std::span<std::uint8_t> output,
                                              std::span<std::uint8_t const> password,
                                              std::span<std::uint8_t const> salt,
                                              argon2_parameters const& parameters) noexcept {
        ++::webcpp::test::mock_control.derives;
        ::webcpp::test::mock_fill(
            output, ::webcpp::test::mock_sum(password) + ::webcpp::test::mock_sum(salt) +
                        ::webcpp::test::mock_sum(parameters.secret) +
                        ::webcpp::test::mock_sum(parameters.associated_data) + parameters.lanes);
        return {};
    }
};

}  // namespace webcpp::hash::detail

#endif  // WEBCPP_TEST_HASH_SUPPORT_MOCK_BACKEND_HPP
