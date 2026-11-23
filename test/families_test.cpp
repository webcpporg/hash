// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The families of spec 2.15, digest_of, hasher, mac and argon2: each family's guards on the mock
// backend (an output of the wrong size for a fixed-size digest is invalid_output_size; an
// extendable output takes any size from 1; a value the family accepts and the engine does not is
// unsupported_by_backend; a backend's failure zeroes the output; a refusal leaves it as it was);
// then the engines this increment wires, against the Hash2-form types they wrap: Boost.Hash2's
// digests and HMACs on backends::hash2 (SHAKE a whole extendable output), keccak_256 on
// backends::xkcp and BLAKE3's extendable output on backends::blake3; and the default backend of
// every tag (design D34).

#include <webcpp/hash/algorithms.hpp>
#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/test/exit_status.hpp>

#ifdef WEBCPP_HASH_HAS_XKCP
#include <webcpp/hash/keccak.hpp>
#endif
#ifdef WEBCPP_HASH_HAS_BLAKE3
#include <webcpp/hash/blake3.hpp>
#endif

#include "require.hpp"
#include "support/hex.hpp"
#include "support/mock_backend.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <vector>

namespace {

namespace hash = webcpp::hash;
namespace digests = webcpp::hash::digests;
namespace macs = webcpp::hash::macs;
namespace kdfs = webcpp::hash::kdfs;
namespace backends = webcpp::hash::backends;
namespace test = webcpp::test;
using test::mock;

// Bytes 0, 1, 2, ... of a given size.
std::vector<std::uint8_t> counting(std::size_t size) {
    std::vector<std::uint8_t> bytes(size);
    for (std::size_t index = 0; index < size; ++index) {
        bytes[index] = static_cast<std::uint8_t>((index * 7) + 3);
    }
    return bytes;
}

// The inputs every agreement runs on: empty, one byte, "abc", and more than a block of each hash.
std::vector<std::vector<std::uint8_t>> const& inputs() {
    static std::vector<std::vector<std::uint8_t>> const all{
        {}, {0x61}, {0x61, 0x62, 0x63}, counting(200), counting(1000),
    };
    return all;
}

// Whether every byte is `value`.
bool all_of(std::span<std::uint8_t const> bytes, std::uint8_t value) {
    return std::ranges::all_of(bytes, [value](std::uint8_t byte) { return byte == value; });
}

// Whether `outcome`, a result of digest_of, mac, argon2 or hasher::make, is the error `expected`.
template <class Value>
bool failed_with(boost::system::result<Value> const& outcome, hash::error expected) {
    return outcome.has_error() && outcome.error() == expected;
}

// digest_of's guards: a fixed-size digest takes its size alone; an extendable output any size from
// 1 to the engine's longest; the output untouched by a refusal.
void check_digest_guards() {
    test::mock_reset();
    std::vector<std::uint8_t> const input{1, 2, 3};
    for (std::size_t const size : {0U, 1U, 31U, 33U, 64U}) {
        std::vector<std::uint8_t> output(size, 0x5A);
        auto const refused = hash::digest_of<digests::sha2_256, mock>(output, input);
        BOOST_TEST(failed_with(refused, hash::error::invalid_output_size));
        BOOST_TEST(all_of(output, 0x5A));
    }
    std::array<std::uint8_t, 32> fixed{};
    BOOST_TEST((hash::digest_of<digests::sha2_256, mock>(fixed, input).has_value()));
    BOOST_TEST_EQ(fixed[0], 6U);
    BOOST_TEST_EQ(fixed[31], 37U);

    // An extendable output: 0 is refused by the family, past the engine's 100 bytes by the backend.
    std::vector<std::uint8_t> none;
    BOOST_TEST(failed_with(hash::digest_of<digests::shake_128, mock>(none, input),
                           hash::error::invalid_output_size));
    for (std::size_t const size : {1U, 2U, 99U, 100U}) {
        std::vector<std::uint8_t> output(size);
        BOOST_TEST((hash::digest_of<digests::shake_128, mock>(output, input).has_value()));
    }
    std::vector<std::uint8_t> past(101, 0x5A);
    BOOST_TEST(failed_with(hash::digest_of<digests::shake_128, mock>(past, input),
                           hash::error::unsupported_by_backend));
    BOOST_TEST(all_of(past, 0x5A));

    // Options the engine does not take, then a failure of the backend, which zeroes the output.
    test::mock_control.accepts = false;
    std::ranges::fill(fixed, 0x5A);
    BOOST_TEST(failed_with(hash::digest_of<digests::sha2_256, mock>(fixed, input),
                           hash::error::unsupported_by_backend));
    BOOST_TEST(all_of(fixed, 0x5A));
    test::mock_control.accepts = true;
    test::mock_control.one_shot = hash::error::backend_failure;
    BOOST_TEST(failed_with(hash::digest_of<digests::sha2_256, mock>(fixed, input),
                           hash::error::backend_failure));
    BOOST_TEST(all_of(fixed, 0));
    BOOST_TEST_EQ(test::mock_control.violations, 0);
}

// mac's guards: HMAC's tag is 10 bytes up to the digest's size; SipHash's key is 16 bytes.
void check_mac_guards() {
    test::mock_reset();
    using hmac = macs::hmac<digests::sha2_256>;
    std::vector<std::uint8_t> const key{9, 9};
    std::vector<std::uint8_t> const input{1, 2, 3};
    for (std::size_t const size : {0U, 9U, 33U}) {
        std::vector<std::uint8_t> output(size, 0x5A);
        BOOST_TEST(failed_with(hash::mac<hmac, mock>(output, key, input),
                               hash::error::invalid_output_size));
        BOOST_TEST(all_of(output, 0x5A));
    }
    for (std::size_t const size : {10U, 16U, 32U}) {
        std::vector<std::uint8_t> output(size);
        BOOST_TEST((hash::mac<hmac, mock>(output, key, input).has_value()));
        BOOST_TEST_EQ(output[0], 24U);
    }
    std::array<std::uint8_t, 32> tag{};
    BOOST_TEST((hash::mac<hmac, mock>(tag, {}, input).has_value()));  // HMAC takes any key

    std::array<std::uint8_t, 8> short_tag{};
    for (std::size_t const size : {0U, 15U, 17U}) {
        std::vector<std::uint8_t> const sip_key(size);
        BOOST_TEST(failed_with(hash::mac<macs::siphash_2_4, mock>(short_tag, sip_key, input),
                               hash::error::invalid_key_size));
    }
    std::array<std::uint8_t, 16> const sip_key{};
    BOOST_TEST((hash::mac<macs::siphash_2_4, mock>(short_tag, sip_key, input).has_value()));
    std::array<std::uint8_t, 16> long_tag{};
    BOOST_TEST(failed_with(hash::mac<macs::siphash_2_4, mock>(long_tag, sip_key, input),
                           hash::error::invalid_output_size));

    test::mock_control.accepts = false;
    std::ranges::fill(tag, 0x5A);
    BOOST_TEST(
        failed_with(hash::mac<hmac, mock>(tag, key, input), hash::error::unsupported_by_backend));
    BOOST_TEST(all_of(tag, 0x5A));
    test::mock_control.accepts = true;
    test::mock_control.compute = hash::error::backend_failure;
    BOOST_TEST(failed_with(hash::mac<hmac, mock>(tag, key, input), hash::error::backend_failure));
    BOOST_TEST(all_of(tag, 0));
}

// argon2's guards: RFC 9106's, then the engine's limits as unsupported_by_backend.
void check_argon2_guards() {
    test::mock_reset();
    std::vector<std::uint8_t> const password{1, 2, 3};
    std::array<std::uint8_t, 16> const salt{};
    hash::argon2_parameters const fine{.passes = 3, .memory_kibibytes = 64};
    std::array<std::uint8_t, 32> output{};
    BOOST_TEST((hash::argon2<kdfs::argon2id, mock>(output, password, salt, fine).has_value()));

    auto const refuses = [&](std::span<std::uint8_t> tag, std::span<std::uint8_t const> salt_bytes,
                             hash::argon2_parameters const& parameters, hash::error expected) {
        std::ranges::fill(tag, 0x5A);
        bool const refused = failed_with(
            hash::argon2<kdfs::argon2id, mock>(tag, password, salt_bytes, parameters), expected);
        return refused && all_of(tag, 0x5A);
    };
    std::array<std::uint8_t, 3> tiny{};
    BOOST_TEST(refuses(tiny, salt, fine, hash::error::invalid_output_size));
    std::array<std::uint8_t, 7> short_salt{};
    BOOST_TEST(refuses(output, short_salt, fine, hash::error::invalid_salt_size));
    BOOST_TEST(refuses(output, salt, {.passes = 0, .memory_kibibytes = 64},
                       hash::error::invalid_parameters));
    BOOST_TEST(refuses(output, salt, {.passes = 3, .memory_kibibytes = 64, .lanes = 0},
                       hash::error::invalid_parameters));
    BOOST_TEST(refuses(output, salt,
                       {.passes = 3, .memory_kibibytes = 1U << 30U, .lanes = 1U << 24U},
                       hash::error::invalid_parameters));
    BOOST_TEST(refuses(output, salt, {.passes = 3, .memory_kibibytes = 7},
                       hash::error::invalid_parameters));
    BOOST_TEST(refuses(output, salt, {.passes = 3, .memory_kibibytes = 15, .lanes = 2},
                       hash::error::invalid_parameters));

    // Valid for RFC 9106, outside the engine's limits.
    std::array<std::uint8_t, 4> rfc_shortest{};
    BOOST_TEST(refuses(rfc_shortest, salt, fine, hash::error::unsupported_by_backend));
    std::array<std::uint8_t, 8> rfc_salt{};
    BOOST_TEST(refuses(output, rfc_salt, fine, hash::error::unsupported_by_backend));
    BOOST_TEST(refuses(output, salt, {.passes = 2, .memory_kibibytes = 64},
                       hash::error::unsupported_by_backend));
    BOOST_TEST(refuses(output, salt, {.passes = 3, .memory_kibibytes = 64, .lanes = 2},
                       hash::error::unsupported_by_backend));
    BOOST_TEST(refuses(output, salt, {.passes = 3, .memory_kibibytes = (1U << 20U) + 1U},
                       hash::error::unsupported_by_backend));
    std::array<std::uint8_t, 4> const extra{1, 2, 3, 4};
    BOOST_TEST(refuses(output, salt, {.passes = 3, .memory_kibibytes = 64, .secret = extra},
                       hash::error::unsupported_by_backend));
    BOOST_TEST(refuses(output, salt,
                       {.passes = 3, .memory_kibibytes = 64, .associated_data = extra},
                       hash::error::unsupported_by_backend));

    // An engine with every parameter takes them; a failure zeroes the output.
    auto const every = hash::argon2<kdfs::argon2d, mock>(rfc_shortest, password, rfc_salt,
                                                         {.passes = 1,
                                                          .memory_kibibytes = 16,
                                                          .lanes = 2,
                                                          .secret = extra,
                                                          .associated_data = extra});
    BOOST_TEST(every.has_value());
    test::mock_control.derive = hash::error::backend_failure;
    BOOST_TEST(failed_with(hash::argon2<kdfs::argon2id, mock>(output, password, salt, fine),
                           hash::error::backend_failure));
    BOOST_TEST(all_of(output, 0));
}

// The first `size` bytes of a Hash2 XOF's stream over `input`: its successive results.
template <class Hash>
std::vector<std::uint8_t> stream_of(std::span<std::uint8_t const> input, std::size_t size) {
    Hash hashed;
    hashed.update(input.data(), input.size());
    std::vector<std::uint8_t> stream;
    while (stream.size() < size) {
        auto const result = hashed.result();
        stream.insert(stream.end(), result.begin(), result.end());
    }
    stream.resize(size);
    return stream;
}

// A Hash2 algorithm's result over `input`, cut to `size` bytes.
template <class Hash>
std::vector<std::uint8_t> hash2_of(std::span<std::uint8_t const> input, std::size_t size) {
    Hash hashed;
    hashed.update(input.data(), input.size());
    auto const result = hashed.result();
    return {result.begin(), result.begin() + static_cast<std::ptrdiff_t>(size)};
}

// digest_of, and hasher in two pieces, against the Hash2 type, on every input.
template <class Digest, class Backend, class Reference>
void agree(std::string_view name, std::size_t size, Reference const& reference) {
    for (auto const& input : inputs()) {
        std::vector<std::uint8_t> once(size);
        test::require(BOOST_TEST((hash::digest_of<Digest, Backend>(once, input).has_value())));
        auto const expected = reference(input, size);
        if (!BOOST_TEST(once == expected)) {
            std::cerr << "  digest_of of " << name << " over " << input.size() << " bytes\n";
        }
        auto hashing = hash::hasher<Digest, Backend>::make();
        test::require(BOOST_TEST(hashing.has_value()));
        std::span<std::uint8_t const> const whole(input);
        auto const half = whole.size() / 2;
        BOOST_TEST(hashing->update(whole.first(half)).has_value());
        BOOST_TEST(hashing->update(whole.subspan(half)).has_value());
        std::vector<std::uint8_t> pieces(size);
        BOOST_TEST(hashing->finish(pieces).has_value());
        if (!BOOST_TEST(pieces == expected)) {
            std::cerr << "  hasher of " << name << " over " << input.size() << " bytes\n";
        }
    }
}

template <class Digest, class Hash>
void agree_hash2(std::string_view name) {
    constexpr std::size_t size = typename Hash::result_type{}.size();
    agree<Digest, backends::hash2>(
        name, size, [](auto const& input, std::size_t n) { return hash2_of<Hash>(input, n); });
    agree<Digest, hash::default_backend<Digest>>(
        name, size, [](auto const& input, std::size_t n) { return hash2_of<Hash>(input, n); });
}

void check_hash2_digests() {
    namespace h2 = boost::hash2;
    agree_hash2<digests::md5, h2::md5_128>("md5");
    agree_hash2<digests::sha1, h2::sha1_160>("sha1");
    agree_hash2<digests::sha2_224, h2::sha2_224>("sha2_224");
    agree_hash2<digests::sha2_256, h2::sha2_256>("sha2_256");
    agree_hash2<digests::sha2_384, h2::sha2_384>("sha2_384");
    agree_hash2<digests::sha2_512, h2::sha2_512>("sha2_512");
    agree_hash2<digests::sha2_512_224, h2::sha2_512_224>("sha2_512_224");
    agree_hash2<digests::sha2_512_256, h2::sha2_512_256>("sha2_512_256");
    agree_hash2<digests::sha3_224, h2::sha3_224>("sha3_224");
    agree_hash2<digests::sha3_256, h2::sha3_256>("sha3_256");
    agree_hash2<digests::sha3_384, h2::sha3_384>("sha3_384");
    agree_hash2<digests::sha3_512, h2::sha3_512>("sha3_512");
    agree_hash2<digests::ripemd_160, h2::ripemd_160>("ripemd_160");
    agree_hash2<digests::blake2s_256, h2::blake2s_256>("blake2s_256");

    // FIPS 180-4's "abc" (Appendix B.1), through the family on its default.
    std::array<std::uint8_t, 32> abc{};
    std::array<std::uint8_t, 3> const message{0x61, 0x62, 0x63};
    BOOST_TEST(hash::digest_of<digests::sha2_256>(abc, message).has_value());
    BOOST_TEST_EQ(test::to_hex(abc),
                  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // SHAKE on backends::hash2 is a whole extendable output (ruling R89): any size is the first
    // bytes of the stream, Hash2's successive results, one block each (168 and 136 bytes), on the
    // default and on the backend named; across the blocks' edges. FIPS 202's vectors past several
    // blocks are hash2_shake_vectors_test's.
    for (std::size_t const size : {1U, 32U, 167U, 168U, 169U, 300U, 1000U}) {
        agree<digests::shake_128, backends::hash2>(
            "shake_128", size,
            [](auto const& input, std::size_t n) { return stream_of<h2::shake_128>(input, n); });
        agree<digests::shake_128, hash::default_backend<digests::shake_128>>(
            "shake_128", size,
            [](auto const& input, std::size_t n) { return stream_of<h2::shake_128>(input, n); });
    }
    for (std::size_t const size : {1U, 64U, 135U, 136U, 137U, 300U, 1000U}) {
        agree<digests::shake_256, backends::hash2>(
            "shake_256", size,
            [](auto const& input, std::size_t n) { return stream_of<h2::shake_256>(input, n); });
        agree<digests::shake_256, hash::default_backend<digests::shake_256>>(
            "shake_256", size,
            [](auto const& input, std::size_t n) { return stream_of<h2::shake_256>(input, n); });
    }
    // A longer output's first bytes are a shorter one's.
    std::array<std::uint8_t, 1000> long_shake{};
    std::array<std::uint8_t, 32> short_shake{};
    BOOST_TEST(hash::digest_of<digests::shake_128>(long_shake, message).has_value());
    BOOST_TEST(hash::digest_of<digests::shake_128>(short_shake, message).has_value());
    BOOST_TEST(std::ranges::equal(short_shake, std::span(long_shake).first(32)));
}

// BLAKE2b on backends::hash2 against Boost.Hash2's blake2b_512, and its partial cell.
void check_hash2_blake2b() {
    namespace h2 = boost::hash2;
    std::array<std::uint8_t, 3> const message{0x61, 0x62, 0x63};
    // BLAKE2b on backends::hash2 is partial (ruling R82): its 64-byte output, Boost.Hash2's
    // blake2b_512, with no key, salt or personalisation; a shorter output size, or an option, which
    // the family accepts, is unsupported_by_backend, before any work, in digest_of and in
    // hasher::make (ruling R86).
    agree<digests::blake2b, backends::hash2>("blake2b", 64, [](auto const& input, std::size_t n) {
        return hash2_of<h2::blake2b_512>(input, n);
    });
    std::array<std::uint8_t, 64> blake2b_abc{};
    BOOST_TEST(
        (hash::digest_of<digests::blake2b, backends::hash2>(blake2b_abc, message).has_value()));
    // RFC 7693, Appendix A: BLAKE2b-512("abc").
    BOOST_TEST_EQ(test::to_hex(blake2b_abc),
                  "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
                  "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
    for (std::size_t const size : {1U, 32U, 63U}) {
        std::vector<std::uint8_t> shorter(size, 0x5A);
        hash::digest_options<digests::blake2b> const sized{.output_size = size};
        BOOST_TEST(
            failed_with(hash::digest_of<digests::blake2b, backends::hash2>(shorter, message, sized),
                        hash::error::unsupported_by_backend));
        BOOST_TEST(all_of(shorter, 0x5A));
        BOOST_TEST(failed_with(hash::hasher<digests::blake2b, backends::hash2>::make(sized),
                               hash::error::unsupported_by_backend));
    }
    std::array<std::uint8_t, 16> const option_bytes{};
    for (auto const& option : {
             hash::digest_options<digests::blake2b>{.key = option_bytes},
             hash::digest_options<digests::blake2b>{.salt = option_bytes},
             hash::digest_options<digests::blake2b>{.personalisation = option_bytes},
         }) {
        std::ranges::fill(blake2b_abc, 0x5A);
        BOOST_TEST(failed_with(
            hash::digest_of<digests::blake2b, backends::hash2>(blake2b_abc, message, option),
            hash::error::unsupported_by_backend));
        BOOST_TEST(all_of(blake2b_abc, 0x5A));
        BOOST_TEST(failed_with(hash::hasher<digests::blake2b, backends::hash2>::make(option),
                               hash::error::unsupported_by_backend));
    }
    // An option's error comes before unsupported_by_backend, in digest_of as in hasher::make: a
    // 32-byte output, shorter than hash2's 64 bytes, with an 8-byte salt is invalid_salt_size.
    std::array<std::uint8_t, 8> const short_salt{};
    hash::digest_options<digests::blake2b> const bad_salt{.salt = short_salt, .output_size = 32};
    std::vector<std::uint8_t> cut(32, 0x5A);
    BOOST_TEST(
        failed_with(hash::digest_of<digests::blake2b, backends::hash2>(cut, message, bad_salt),
                    hash::error::invalid_salt_size));
    BOOST_TEST(all_of(cut, 0x5A));
    BOOST_TEST(failed_with(hash::hasher<digests::blake2b, backends::hash2>::make(bad_salt),
                           hash::error::invalid_salt_size));
    // An output of another size than the options' (64 by default) is the family's refusal.
    std::vector<std::uint8_t> shorter(32, 0x5A);
    BOOST_TEST(failed_with(hash::digest_of<digests::blake2b, backends::hash2>(shorter, message),
                           hash::error::invalid_output_size));
    BOOST_TEST(all_of(shorter, 0x5A));
    std::array<std::uint8_t, 65> past_blake2b{};
    BOOST_TEST(
        failed_with(hash::digest_of<digests::blake2b, backends::hash2>(past_blake2b, message),
                    hash::error::invalid_output_size));
    auto blake2b_hashing = hash::hasher<digests::blake2b, backends::hash2>::make();
    test::require(BOOST_TEST(blake2b_hashing.has_value()));
    BOOST_TEST(failed_with(blake2b_hashing->finish(shorter), hash::error::invalid_output_size));
    BOOST_TEST(blake2b_hashing->finish(blake2b_abc).has_value());
}

// mac over HMAC on backends::hash2 against Boost.Hash2's hmac, whole and cut.
template <class Digest, class Hmac>
void agree_hmac(std::string_view name) {
    constexpr std::size_t size = typename Hmac::result_type{}.size();
    using tag = macs::hmac<Digest>;
    static_assert(std::is_same_v<hash::default_backend<tag>, backends::hash2>);
    static_assert(std::is_same_v<typename hash::detail::digest_tag_of<Hmac>::type, Digest>);
    for (auto const& key : {counting(0), counting(16), counting(200)}) {
        for (auto const& input : inputs()) {
            Hmac reference(key.data(), key.size());
            reference.update(input.data(), input.size());
            auto const expected = reference.result();
            for (std::size_t const cut : {size, std::size_t{10}}) {
                std::vector<std::uint8_t> output(cut);
                test::require(BOOST_TEST(hash::mac<tag>(output, key, input).has_value()));
                if (!BOOST_TEST(std::ranges::equal(output, std::span(expected).first(cut)))) {
                    std::cerr << "  mac of " << name << ", key " << key.size() << ", input "
                              << input.size() << ", tag " << cut << '\n';
                }
            }
        }
    }
}

void check_hash2_hmacs() {
    agree_hmac<digests::md5, hash::hmac_md5_128>("md5");
    agree_hmac<digests::sha1, hash::hmac_sha1_160>("sha1");
    agree_hmac<digests::sha2_224, hash::hmac_sha2_224>("sha2_224");
    agree_hmac<digests::sha2_256, hash::hmac_sha2_256>("sha2_256");
    agree_hmac<digests::sha2_384, hash::hmac_sha2_384>("sha2_384");
    agree_hmac<digests::sha2_512, hash::hmac_sha2_512>("sha2_512");
    agree_hmac<digests::sha2_512_224, hash::hmac_sha2_512_224>("sha2_512_224");
    agree_hmac<digests::sha2_512_256, hash::hmac_sha2_512_256>("sha2_512_256");
    agree_hmac<digests::sha3_224, hash::hmac_sha3_224>("sha3_224");
    agree_hmac<digests::sha3_256, hash::hmac_sha3_256>("sha3_256");
    agree_hmac<digests::sha3_384, hash::hmac_sha3_384>("sha3_384");
    agree_hmac<digests::sha3_512, hash::hmac_sha3_512>("sha3_512");
    agree_hmac<digests::ripemd_160, hash::hmac_ripemd_160>("ripemd_160");
    agree_hmac<digests::blake2b, hash::hmac_blake2b_512>("blake2b");
    agree_hmac<digests::blake2s_256, hash::hmac_blake2s_256>("blake2s_256");
    static_assert(std::is_void_v<hash::detail::digest_tag_of<hash::hmac_ripemd_128>::type>);

    // HMAC over an extendable-output function has no digest size: every tag is refused.
    static_assert(hash::detail::mac_traits<macs::hmac<digests::shake_128>>::max_output == 0);

    // RFC 4231's test case 2 (key "Jefe"), on the default; and its case 5, cut to 16 bytes.
    std::array<std::uint8_t, 32> tag{};
    std::string_view const jefe = "Jefe";
    std::string_view const question = "what do ya want for nothing?";
    auto const bytes = [](std::string_view text) {
        return std::span(reinterpret_cast<std::uint8_t const*>(text.data()), text.size());
    };
    BOOST_TEST(
        hash::mac<macs::hmac<digests::sha2_256>>(tag, bytes(jefe), bytes(question)).has_value());
    BOOST_TEST_EQ(test::to_hex(tag),
                  "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    std::array<std::uint8_t, 16> cut{};
    std::vector<std::uint8_t> const key(20, 0x0c);
    BOOST_TEST(hash::mac<macs::hmac<digests::sha2_256>>(cut, key, bytes("Test With Truncation"))
                   .has_value());
    BOOST_TEST_EQ(test::to_hex(cut), "a3b6167473100ee06e0c796c2955552b");
}

// SipHash-2-4 and keyed BLAKE2s on backends::hash2 (ruling R82) against Boost.Hash2's siphash_64
// and keyed blake2s_256, on their defaults; keyed BLAKE2s is partial, a 32-byte tag alone. Their
// published vectors are hash2_mac_vectors_test's.
void check_hash2_keyed() {
    for (auto const& input : inputs()) {
        auto const key = counting(16);
        boost::hash2::siphash_64 reference(key.data(), key.size());
        reference.update(input.data(), input.size());
        std::uint64_t expected = reference.result();
        std::array<std::uint8_t, 8> expected_bytes{};
        for (std::uint8_t& byte : expected_bytes) {
            byte = static_cast<std::uint8_t>(expected & 0xffU);
            expected >>= 8U;
        }
        std::array<std::uint8_t, 8> tag{};
        BOOST_TEST(hash::mac<macs::siphash_2_4>(tag, key, input).has_value());
        if (!BOOST_TEST(tag == expected_bytes)) {
            std::cerr << "  siphash_2_4 of input " << input.size() << '\n';
        }

        for (std::size_t const key_size : {1U, 16U, 32U}) {
            auto const blake2s_key = counting(key_size);
            boost::hash2::blake2s_256 keyed(blake2s_key.data(), blake2s_key.size());
            keyed.update(input.data(), input.size());
            auto const keyed_expected = keyed.result();
            std::array<std::uint8_t, 32> keyed_tag{};
            BOOST_TEST(hash::mac<macs::blake2s_mac>(keyed_tag, blake2s_key, input).has_value());
            if (!BOOST_TEST(std::ranges::equal(keyed_tag, keyed_expected))) {
                std::cerr << "  blake2s_mac, key " << key_size << ", input " << input.size()
                          << '\n';
            }
        }
    }
    std::array<std::uint8_t, 16> const key{};
    std::array<std::uint8_t, 3> const message{0x61, 0x62, 0x63};
    std::array<std::uint8_t, 16> shorter{};
    shorter.fill(0x5A);
    BOOST_TEST(failed_with(hash::mac<macs::blake2s_mac, backends::hash2>(shorter, key, message),
                           hash::error::unsupported_by_backend));
    BOOST_TEST(all_of(shorter, 0x5A));
    std::array<std::uint8_t, 33> longer{};
    BOOST_TEST(failed_with(hash::mac<macs::blake2s_mac, backends::hash2>(longer, key, message),
                           hash::error::invalid_output_size));
    std::array<std::uint8_t, 32> keyed_tag{};
    BOOST_TEST(failed_with(hash::mac<macs::blake2s_mac, backends::hash2>(keyed_tag, {}, message),
                           hash::error::invalid_key_size));
}

void check_library_digests() {
#ifdef WEBCPP_HASH_HAS_XKCP
    static_assert(std::is_same_v<hash::default_backend<digests::keccak_256>, backends::xkcp>);
    agree<digests::keccak_256, backends::xkcp>(
        "keccak_256", 32,
        [](auto const& input, std::size_t n) { return hash2_of<hash::keccak_256>(input, n); });
    // Keccak-256 of nothing, Ethereum's empty-code hash.
    std::array<std::uint8_t, 32> empty{};
    BOOST_TEST(hash::digest_of<digests::keccak_256>(empty, {}).has_value());
    BOOST_TEST_EQ(test::to_hex(empty),
                  "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    std::array<std::uint8_t, 31> short_digest{};
    BOOST_TEST(failed_with(hash::digest_of<digests::keccak_256>(short_digest, {}),
                           hash::error::invalid_output_size));
#endif
#ifdef WEBCPP_HASH_HAS_BLAKE3
    static_assert(std::is_same_v<hash::default_backend<digests::blake3>, backends::blake3>);
    // An extendable output: any size, the stream's first bytes.
    for (std::size_t const size : {1U, 31U, 32U, 33U, 100U, 1025U}) {
        agree<digests::blake3, backends::blake3>("blake3", size,
                                                 [](auto const& input, std::size_t n) {
                                                     hash::blake3 reference;
                                                     reference.update(input.data(), input.size());
                                                     std::vector<std::uint8_t> output(n);
                                                     reference.squeeze(output);
                                                     return output;
                                                 });
    }
#endif
}

// Every tag's default (design D34): the first of hash2, xkcp, blake3, sodium that has it once
// increments 2 to 7 have landed, else none.
template <class Tag, class Expected>
void expect_default(std::string_view name) {
    if (!BOOST_TEST((std::is_same_v<hash::default_backend<Tag>, Expected>))) {
        std::cerr << "  the default of " << name << '\n';
    }
}

void check_defaults() {
    using backends::hash2;
    using backends::sodium;
    using backends::xkcp;
    using none = hash::detail::no_default;
    expect_default<digests::md5, hash2>("md5");
    expect_default<digests::sha1, hash2>("sha1");
    expect_default<digests::sha2_224, hash2>("sha2_224");
    expect_default<digests::sha2_256, hash2>("sha2_256");
    expect_default<digests::sha2_384, hash2>("sha2_384");
    expect_default<digests::sha2_512, hash2>("sha2_512");
    expect_default<digests::sha2_512_224, hash2>("sha2_512_224");
    expect_default<digests::sha2_512_256, hash2>("sha2_512_256");
    expect_default<digests::sha3_224, hash2>("sha3_224");
    expect_default<digests::sha3_256, hash2>("sha3_256");
    expect_default<digests::sha3_384, hash2>("sha3_384");
    expect_default<digests::sha3_512, hash2>("sha3_512");
    expect_default<digests::ripemd_160, hash2>("ripemd_160");
    expect_default<digests::blake2s_256, hash2>("blake2s_256");
    expect_default<digests::shake_128, hash2>("shake_128");
    expect_default<digests::shake_256, hash2>("shake_256");
    expect_default<digests::keccak_224, xkcp>("keccak_224");
    expect_default<digests::keccak_256, xkcp>("keccak_256");
    expect_default<digests::keccak_384, xkcp>("keccak_384");
    expect_default<digests::keccak_512, xkcp>("keccak_512");
    expect_default<digests::cshake_128, xkcp>("cshake_128");
    expect_default<digests::cshake_256, xkcp>("cshake_256");
    expect_default<digests::kt128, xkcp>("kt128");
    expect_default<digests::kt256, xkcp>("kt256");
    expect_default<digests::turboshake_128, xkcp>("turboshake_128");
    expect_default<digests::turboshake_256, xkcp>("turboshake_256");
    expect_default<digests::tuplehash_128, xkcp>("tuplehash_128");
    expect_default<digests::tuplehash_256, xkcp>("tuplehash_256");
    expect_default<digests::parallelhash_128, xkcp>("parallelhash_128");
    expect_default<digests::parallelhash_256, xkcp>("parallelhash_256");
    expect_default<digests::blake3, backends::blake3>("blake3");
    expect_default<digests::blake2b, sodium>("blake2b");
    expect_default<digests::md5_sha1, none>("md5_sha1");
    expect_default<digests::sm3, none>("sm3");
    expect_default<digests::streebog_256, none>("streebog_256");
    expect_default<digests::streebog_512, none>("streebog_512");
    expect_default<digests::whirlpool, none>("whirlpool");
    expect_default<digests::skein_512, none>("skein_512");

    expect_default<macs::hmac<digests::sha2_256>, hash2>("hmac<sha2_256>");
    expect_default<macs::hmac<digests::blake2b>, hash2>("hmac<blake2b>");
    expect_default<macs::hmac<digests::keccak_256>, none>("hmac<keccak_256>");
    expect_default<macs::hmac<digests::sm3>, none>("hmac<sm3>");
    expect_default<macs::kmac_128, xkcp>("kmac_128");
    expect_default<macs::kmac_256, xkcp>("kmac_256");
    expect_default<macs::siphash_2_4, hash2>("siphash_2_4");
    expect_default<macs::siphash_2_4x, sodium>("siphash_2_4x");
    expect_default<macs::blake2b_mac, sodium>("blake2b_mac");
    expect_default<macs::blake2s_mac, hash2>("blake2s_mac");

    expect_default<kdfs::argon2id, sodium>("argon2id");
    expect_default<kdfs::argon2i, sodium>("argon2i");
    expect_default<kdfs::argon2d, none>("argon2d");
    expect_default<kdfs::blake2b_subkey, sodium>("blake2b_subkey");
    expect_default<kdfs::bcrypt, none>("bcrypt");
    expect_default<kdfs::bcrypt_pbkdf, none>("bcrypt_pbkdf");
    expect_default<kdfs::kbkdf_hmac, none>("kbkdf_hmac");
    expect_default<kdfs::sskdf, none>("sskdf");
    expect_default<kdfs::x963kdf, none>("x963kdf");
}

}  // namespace

int main() {
    check_digest_guards();
    check_mac_guards();
    check_argon2_guards();
    check_hash2_digests();
    check_hash2_blake2b();
    check_hash2_hmacs();
    check_hash2_keyed();
    check_library_digests();
    check_defaults();
    return webcpp::test::exit_status(boost::report_errors());
}
