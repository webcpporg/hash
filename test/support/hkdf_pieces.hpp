// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The equality harness of HKDF over pieces, which every backend's pieces test calls:
// check_hkdf_pieces<Hmac, Backend, Oracle>(name) checks that hkdf_extract, hkdf_expand and hkdf
// over byte_pieces on Backend give the bytes of the single-buffer forms on the concatenation of
// the pieces (design D8), those of Oracle (backends::hash2 by default) and, where Backend has
// them, Backend's own:
// - RFC 5869's seven cases (support/rfc5869.hpp) over the hmac of their hash, each input split at
//   every byte offset into two pieces, into one piece per byte with an empty piece between every
//   two, as {empty, input, empty}, and, where it is empty, as the empty list;
// - the edge output lengths, each a case of its own: 1 byte, a digest less one byte, a digest, a
//   digest and one byte, 255 digests less one byte and 255 digests (the counter's last block),
//   each input split at random, as {empty, input, empty} and, where it is empty, as the empty list;
// - 1,000 cases from the fixed seed printed below, each input of 0 to 300 bytes split at random
//   points into 0 to 16 pieces (empty pieces among them), outputs of 1 byte to 4 digests, except
//   every 100th case, whose output is of 1 byte to 255 digests: the edges above reach the long
//   outputs, so the random cases spend their time on the splits, not on the blocks;
// - a list of 10,000 one-byte pieces;
// - long inputs, each in four pieces: an application info of 4 KiB, 32 KiB + 1 and 1 MiB, and an
//   input keying material of 1 MiB; up to hkdf_max_application_info_size bytes of application info
//   against the single-buffer forms, and every one against reference_hkdf below, RFC 5869 written
//   over Boost.Hash2's hmac on the concatenated bytes, and against Backend on another split;
// - the guards: an output of no byte or of 255 digests and one byte (invalid_output_size, the
//   output untouched), a pseudorandom key of one byte less than the digest (invalid_key_size).

#ifndef WEBCPP_TEST_HASH_SUPPORT_HKDF_PIECES_HPP
#define WEBCPP_TEST_HASH_SUPPORT_HKDF_PIECES_HPP

#include <webcpp/hash/byte_pieces.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/kdf.hpp>

#include "../require.hpp"
#include "defaults.hpp"
#include "hex.hpp"
#include "rfc5869.hpp"

#include <boost/core/lightweight_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <random>
#include <span>
#include <string_view>
#include <type_traits>
#include <vector>

namespace webcpp::test {

/** The seed of the random cases of HKDF over pieces, "hkdf-pie" in ASCII, printed by each run. */
inline constexpr std::uint64_t hkdf_pieces_seed = 0x686b64662d706965ULL;

/** The number of random cases per hmac and backend. */
inline constexpr std::size_t hkdf_pieces_cases = 1000;

/** The longest output of most random cases, in digests. */
inline constexpr std::size_t hkdf_pieces_short_blocks = 4;

/** Every how many random cases one draws its output from the whole range, 1 byte to 255 digests. */
inline constexpr std::size_t hkdf_pieces_long_every = 100;

/** A byte span, one piece. */
using byte_piece = std::span<std::uint8_t const>;

/** The bytes of a list of pieces, one after another. */
inline std::vector<std::uint8_t> joined_bytes(hash::byte_pieces pieces) {
    std::vector<std::uint8_t> bytes;
    for (byte_piece const piece : pieces) {
        bytes.insert(bytes.end(), piece.begin(), piece.end());
    }
    return bytes;
}

/**
 * RFC 5869 over Boost.Hash2's `hmac<H>` (`Hmac`) on contiguous bytes, independent of hash's code:
 * the pseudorandom key of section 2.2, then section 2.3's output of `length` bytes.
 */
template <class Hmac>
struct reference_hkdf {
    std::vector<std::uint8_t> pseudorandom_key;
    std::vector<std::uint8_t> output_key_material;

    reference_hkdf(byte_piece salt, byte_piece input_key_material, byte_piece application_info,
                   std::size_t length) {
        std::size_t const hash_length = typename Hmac::result_type().size();
        std::vector<std::uint8_t> const zeros(hash_length, 0);
        byte_piece const key = salt.empty() ? byte_piece(zeros) : salt;
        Hmac extract(key.data(), key.size());
        extract.update(input_key_material.data(), input_key_material.size());
        auto const prk = extract.result();
        pseudorandom_key.assign(prk.begin(), prk.end());
        std::vector<std::uint8_t> block;
        for (unsigned counter = 1; output_key_material.size() < length; ++counter) {
            Hmac expand(pseudorandom_key.data(), pseudorandom_key.size());
            expand.update(block.data(), block.size());
            expand.update(application_info.data(), application_info.size());
            auto const octet = static_cast<std::uint8_t>(counter);
            expand.update(&octet, 1);
            auto const t = expand.result();
            block.assign(t.begin(), t.end());
            std::size_t const taken = std::min(block.size(), length - output_key_material.size());
            output_key_material.insert(output_key_material.end(), block.begin(),
                                       block.begin() + static_cast<std::ptrdiff_t>(taken));
        }
    }
};

/**
 * The random draws of the cases, the same on every standard library: std::mt19937_64's sequence
 * is the standard's, and a draw in a range is the modulo of one output.
 */
class pieces_random {
public:
    explicit pieces_random(std::uint64_t seed) : engine_(seed) {}

    /** A value in [low, high]. */
    std::size_t between(std::size_t low, std::size_t high) {
        return low + static_cast<std::size_t>(engine_() % (std::uint64_t{high - low} + 1));
    }

    /** `size` random bytes. */
    std::vector<std::uint8_t> bytes(std::size_t size) {
        std::vector<std::uint8_t> out(size);
        for (auto& b : out) {
            b = static_cast<std::uint8_t>(engine_() >> 56U);
        }
        return out;
    }

    /**
     * `input` split at random points into 0 to 16 pieces, at least one when it is not empty;
     * points drawn twice, or at an end, make empty pieces.
     */
    std::vector<byte_piece> split(byte_piece input) {
        std::size_t count = between(0, 16);
        if (count == 0 && !input.empty()) {
            count = 1;
        }
        std::vector<std::size_t> points;
        for (std::size_t i = 1; i < count; ++i) {
            points.push_back(between(0, input.size()));
        }
        std::ranges::sort(points);
        std::vector<byte_piece> pieces;
        std::size_t start = 0;
        for (std::size_t const point : points) {
            pieces.push_back(input.subspan(start, point - start));
            start = point;
        }
        if (count != 0) {
            pieces.push_back(input.subspan(start));
        }
        return pieces;
    }

private:
    std::mt19937_64 engine_;
};

/** `input` in `count` pieces of nearly equal sizes, the last one the longest. */
inline std::vector<byte_piece> even_split(byte_piece input, std::size_t count) {
    std::vector<byte_piece> pieces;
    std::size_t const size = input.size() / count;
    for (std::size_t i = 0; i + 1 < count; ++i) {
        pieces.push_back(input.subspan(i * size, size));
    }
    pieces.push_back(input.subspan((count - 1) * size));
    return pieces;
}

/** `input` in one piece per byte, with an empty piece between every two. */
inline std::vector<byte_piece> bytewise_split(byte_piece input) {
    std::vector<byte_piece> pieces;
    for (std::size_t i = 0; i != input.size(); ++i) {
        if (i != 0) {
            pieces.emplace_back();
        }
        pieces.push_back(input.subspan(i, 1));
    }
    return pieces;
}

/** Where one check runs, printed on a failure. */
struct pieces_place {
    std::string_view backend;
    std::string_view hmac;
    std::string_view what;
    std::size_t index = 0;
};

inline std::ostream& operator<<(std::ostream& out, pieces_place const& place) {
    return out << "  HKDF over pieces on " << place.backend << " over " << place.hmac << ": "
               << place.what << " " << place.index << " (seed 0x" << std::hex << hkdf_pieces_seed
               << std::dec << ")\n";
}

/**
 * The three pieces forms on Backend for one case, against the expected pseudorandom key and output
 * keying material: hkdf_extract over `input_key_material`, hkdf_expand over `application_info`
 * under the expected key, and hkdf over both.
 */
template <class Hmac, class Backend>
void expect_pieces(pieces_place const& place, byte_piece salt, hash::byte_pieces input_key_material,
                   hash::byte_pieces application_info, std::vector<std::uint8_t> const& prk,
                   std::vector<std::uint8_t> const& okm) {
    auto const extracted = hash::hkdf_extract<Hmac, Backend>(salt, input_key_material);
    if (!BOOST_TEST(extracted.has_value()) || !BOOST_TEST(std::ranges::equal(*extracted, prk))) {
        std::cerr << "hkdf_extract" << place;
    }
    std::vector<std::uint8_t> expanded(okm.size());
    auto const expanded_done = hash::hkdf_expand<Hmac, Backend>(expanded, prk, application_info);
    if (!BOOST_TEST(expanded_done.has_value()) || !BOOST_TEST(expanded == okm)) {
        std::cerr << "hkdf_expand" << place;
    }
    std::vector<std::uint8_t> whole(okm.size());
    auto const whole_done =
        hash::hkdf<Hmac, Backend>(whole, salt, input_key_material, application_info);
    if (!BOOST_TEST(whole_done.has_value()) || !BOOST_TEST(whole == okm)) {
        std::cerr << "hkdf" << place;
    }
}

/**
 * The single-buffer forms on `Single` over the concatenations, each step where `Single` has it,
 * against the expected key and output: the oracle of a pieces case, checked once more.
 */
template <class Hmac, class Single>
void expect_single(pieces_place const& place, byte_piece salt, byte_piece input_key_material,
                   byte_piece application_info, std::vector<std::uint8_t> const& prk,
                   std::vector<std::uint8_t> const& okm) {
    if constexpr (hash::backend_has_v<Single, hash::kdfs::hkdf_extract, Hmac>) {
        auto const extracted = hash::hkdf_extract<Hmac, Single>(salt, input_key_material);
        if (!BOOST_TEST(extracted.has_value()) ||
            !BOOST_TEST(std::ranges::equal(*extracted, prk))) {
            std::cerr << "single-buffer hkdf_extract on " << name_of<Single>() << place;
        }
    }
    if constexpr (hash::backend_has_v<Single, hash::kdfs::hkdf_expand, Hmac>) {
        std::vector<std::uint8_t> expanded(okm.size());
        auto const done = hash::hkdf_expand<Hmac, Single>(expanded, prk, application_info);
        if (!BOOST_TEST(done.has_value()) || !BOOST_TEST(expanded == okm)) {
            std::cerr << "single-buffer hkdf_expand on " << name_of<Single>() << place;
        }
    }
    if constexpr (hash::backend_has_v<Single, hash::kdfs::hkdf, Hmac>) {
        std::vector<std::uint8_t> whole(okm.size());
        auto const done =
            hash::hkdf<Hmac, Single>(whole, salt, input_key_material, application_info);
        if (!BOOST_TEST(done.has_value()) || !BOOST_TEST(whole == okm)) {
            std::cerr << "single-buffer hkdf on " << name_of<Single>() << place;
        }
    }
}

/**
 * One case whose expected bytes the single-buffer forms give: Oracle's computes them, Backend's
 * own, where Backend has them and is not Oracle, gives them too, and the pieces forms on Backend
 * over every listed split of the inputs give them.
 */
template <class Hmac, class Backend, class Oracle>
void check_case(pieces_place const& place, byte_piece salt, byte_piece input_key_material,
                byte_piece application_info, std::size_t length,
                std::vector<std::vector<byte_piece>> const& input_splits,
                std::vector<std::vector<byte_piece>> const& info_splits) {
    auto const oracle_prk = hash::hkdf_extract<Hmac, Oracle>(salt, input_key_material);
    require(oracle_prk.has_value());
    std::vector<std::uint8_t> const prk(oracle_prk->begin(), oracle_prk->end());
    std::vector<std::uint8_t> okm(length);
    require(hash::hkdf_expand<Hmac, Oracle>(okm, prk, application_info).has_value());
    if constexpr (!std::is_same_v<Backend, Oracle> && hash::detail::linked_v<Backend>) {
        expect_single<Hmac, Backend>(place, salt, input_key_material, application_info, prk, okm);
    }
    for (std::size_t i = 0; i != std::max(input_splits.size(), info_splits.size()); ++i) {
        auto const& ikm = input_splits[i % input_splits.size()];
        auto const& info = info_splits[i % info_splits.size()];
        pieces_place here = place;
        here.index = (place.index * 1000) + i;
        expect_pieces<Hmac, Backend>(here, salt, ikm, info, prk, okm);
    }
}

/** RFC 5869's cases over the hmac of their hash: every split of section D8, and the vector. */
template <class Hmac, class Backend, class Oracle>
void check_rfc5869(std::string_view backend) {
    std::vector<rfc5869_case> const cases = [] {
        if constexpr (std::is_same_v<Hmac, hash::hmac_sha2_256>) {
            return std::vector<rfc5869_case>{a1, a2, a3};
        } else if constexpr (std::is_same_v<Hmac, hash::hmac_sha1_160>) {
            return std::vector<rfc5869_case>{a4, a5, a6, a7};
        } else {
            return std::vector<rfc5869_case>{};
        }
    }();
    std::size_t index = 0;
    for (rfc5869_case const& c : cases) {
        auto const ikm = from_hex(c.ikm);
        auto const salt = from_hex(c.salt);
        auto const info = from_hex(c.info);
        auto const prk = from_hex(c.prk);
        auto const okm = from_hex(c.okm);
        pieces_place const place{backend, name_of_hmac<Hmac>(), "RFC 5869 case", ++index};

        // Every split in two, of each input; then one piece per byte, then {empty, input, empty}.
        std::vector<std::vector<byte_piece>> ikm_splits;
        std::vector<std::vector<byte_piece>> info_splits;
        for (std::size_t at = 0; at <= ikm.size(); ++at) {
            ikm_splits.push_back({byte_piece(ikm).first(at), byte_piece(ikm).subspan(at)});
        }
        for (std::size_t at = 0; at <= info.size(); ++at) {
            info_splits.push_back({byte_piece(info).first(at), byte_piece(info).subspan(at)});
        }
        ikm_splits.push_back(bytewise_split(ikm));
        info_splits.push_back(bytewise_split(info));
        ikm_splits.push_back({byte_piece{}, byte_piece(ikm), byte_piece{}});
        info_splits.push_back({byte_piece{}, byte_piece(info), byte_piece{}});
        if (info.empty()) {
            info_splits.emplace_back();  // the empty list
        }
        if (ikm.empty()) {
            ikm_splits.emplace_back();
        }
        for (std::size_t i = 0; i != std::max(ikm_splits.size(), info_splits.size()); ++i) {
            pieces_place here = place;
            here.index = (place.index * 1000) + i;
            expect_pieces<Hmac, Backend>(here, salt, ikm_splits[i % ikm_splits.size()],
                                         info_splits[i % info_splits.size()], prk, okm);
        }
        // The vector's bytes are also the oracle's.
        check_case<Hmac, Backend, Oracle>(place, salt, ikm, info, c.length, {{byte_piece(ikm)}},
                                          {{byte_piece(info)}});
        expect_single<Hmac, Oracle>(place, salt, ikm, info, prk, okm);
    }
}

/**
 * The edge output lengths, each in a case of its own: 1 byte, a digest less one byte, a digest, a
 * digest and one byte, 255 digests less one byte and 255 digests. Each input is split at random,
 * as {empty, input, empty} and, where it is empty, as the empty list. The refused lengths, no
 * byte and 255 digests and one byte, are check_guards'.
 */
template <class Hmac, class Backend, class Oracle>
void check_edges(std::string_view backend) {
    std::size_t const hash_length = typename Hmac::result_type().size();
    std::array<std::size_t, 6> const lengths{
        1,
        hash_length - 1,
        hash_length,
        hash_length + 1,
        (255 * hash_length) - 1,
        255 * hash_length,
    };
    pieces_random random(hkdf_pieces_seed + 2);
    std::size_t index = 0;
    for (std::size_t const length : lengths) {
        // An empty input keying material and application info once, then random ones.
        std::size_t const most = index == 0 ? 0 : 300;
        auto const salt = random.bytes(random.between(0, 300));
        auto const ikm = random.bytes(random.between(0, most));
        auto const info = random.bytes(random.between(0, most));
        std::vector<std::vector<byte_piece>> ikm_splits{
            random.split(ikm), {byte_piece{}, byte_piece(ikm), byte_piece{}}};
        std::vector<std::vector<byte_piece>> info_splits{
            random.split(info), {byte_piece{}, byte_piece(info), byte_piece{}}};
        if (ikm.empty()) {
            ikm_splits.emplace_back();  // the empty list
        }
        if (info.empty()) {
            info_splits.emplace_back();
        }
        check_case<Hmac, Backend, Oracle>({backend, name_of_hmac<Hmac>(), "edge length", ++index},
                                          salt, ikm, info, length, ikm_splits, info_splits);
    }
}

/**
 * The random cases: inputs of 0 to 300 bytes in 0 to 16 pieces, outputs of 1 byte to 4 digests,
 * of 1 byte to 255 digests in every 100th case.
 */
template <class Hmac, class Backend, class Oracle>
void check_random(std::string_view backend) {
    std::size_t const hash_length = typename Hmac::result_type().size();
    pieces_random random(hkdf_pieces_seed);
    for (std::size_t index = 0; index != hkdf_pieces_cases; ++index) {
        auto const salt = random.bytes(random.between(0, 300));
        auto const ikm = random.bytes(random.between(0, 300));
        auto const info = random.bytes(random.between(0, 300));
        std::size_t const blocks =
            index % hkdf_pieces_long_every == 0 ? 255 : hkdf_pieces_short_blocks;
        std::size_t const length = random.between(1, blocks * hash_length);
        std::vector<std::vector<byte_piece>> const ikm_splits{random.split(ikm)};
        std::vector<std::vector<byte_piece>> const info_splits{random.split(info)};
        check_case<Hmac, Backend, Oracle>({backend, name_of_hmac<Hmac>(), "random case", index},
                                          salt, ikm, info, length, ikm_splits, info_splits);
    }
}

/** Long inputs and many pieces, against the single-buffer forms where they take the input and
 * against reference_hkdf and another split always. */
template <class Hmac, class Backend, class Oracle>
void check_long(std::string_view backend) {
    pieces_random random(hkdf_pieces_seed + 1);
    auto const salt = random.bytes(13);
    auto const short_input = random.bytes(40);

    // 10,000 one-byte pieces, of each input.
    {
        auto const many = random.bytes(10000);
        std::vector<byte_piece> bytes;
        for (std::size_t i = 0; i != many.size(); ++i) {
            bytes.push_back(byte_piece(many).subspan(i, 1));
        }
        check_case<Hmac, Backend, Oracle>({backend, name_of_hmac<Hmac>(), "one-byte pieces", 1},
                                          salt, many, short_input, 100, {bytes}, {{short_input}});
        check_case<Hmac, Backend, Oracle>({backend, name_of_hmac<Hmac>(), "one-byte pieces", 2},
                                          salt, short_input, many, 100, {{short_input}}, {bytes});
    }

    // Long inputs in four pieces.
    constexpr std::array<std::size_t, 3> info_sizes{
        4096,
        hash::hkdf_max_application_info_size + 1,
        std::size_t{1} << 20U,
    };
    std::size_t index = 0;
    for (std::size_t const size : info_sizes) {
        auto const info = random.bytes(size);
        pieces_place const place{backend, name_of_hmac<Hmac>(), "long application info", ++index};
        reference_hkdf<Hmac> const reference(salt, short_input, info, 42);
        if (size <= hash::hkdf_max_application_info_size) {
            check_case<Hmac, Backend, Oracle>(place, salt, short_input, info, 42, {{short_input}},
                                              {even_split(info, 4)});
        }
        expect_pieces<Hmac, Backend>(place, salt, {byte_piece(short_input)}, even_split(info, 4),
                                     reference.pseudorandom_key, reference.output_key_material);
        expect_pieces<Hmac, Backend>(place, salt, even_split(short_input, 3), even_split(info, 7),
                                     reference.pseudorandom_key, reference.output_key_material);
    }
    {
        auto const ikm = random.bytes(std::size_t{1} << 20U);
        pieces_place const place{backend, name_of_hmac<Hmac>(), "long input keying material", 1};
        reference_hkdf<Hmac> const reference(salt, ikm, short_input, 42);
        // The single-buffer forms cap no input keying material.
        check_case<Hmac, Backend, Oracle>(place, salt, ikm, short_input, 42, {even_split(ikm, 4)},
                                          {{short_input}});
        expect_pieces<Hmac, Backend>(place, salt, even_split(ikm, 4), {byte_piece(short_input)},
                                     reference.pseudorandom_key, reference.output_key_material);
        expect_pieces<Hmac, Backend>(place, salt, even_split(ikm, 9), {byte_piece(short_input)},
                                     reference.pseudorandom_key, reference.output_key_material);
    }
}

/** The guards: RFC 5869's output and pseudorandom key sizes, the output untouched. */
template <class Hmac, class Backend>
void check_guards(std::string_view backend) {
    std::size_t const hash_length = typename Hmac::result_type().size();
    std::array<std::uint8_t, 5> const bytes{1, 2, 3, 4, 5};
    byte_piece const input(bytes);
    std::vector<std::uint8_t> const prk(hash_length, 0x0b);
    auto const refused = [&](char const* what, auto const& done, hash::error expected,
                             std::vector<std::uint8_t> const& output) {
        bool const untouched =
            std::ranges::all_of(output, [](std::uint8_t b) { return b == 0xa5; });
        if (!BOOST_TEST(!done.has_value() && done.error() == expected) || !BOOST_TEST(untouched)) {
            std::cerr << "  the guard of " << what << " on " << backend << " over "
                      << name_of_hmac<Hmac>() << '\n';
        }
    };
    for (std::size_t const size : {std::size_t{0}, (255 * hash_length) + 1}) {
        std::vector<std::uint8_t> output(size, 0xa5);
        refused("hkdf_expand's output size",
                hash::hkdf_expand<Hmac, Backend>(output, prk, {input, input}),
                hash::error::invalid_output_size, output);
        refused("hkdf's output size",
                hash::hkdf<Hmac, Backend>(output, input, {input, input}, {input, input}),
                hash::error::invalid_output_size, output);
    }
    std::vector<std::uint8_t> output(42, 0xa5);
    refused("hkdf_expand's pseudorandom key size",
            hash::hkdf_expand<Hmac, Backend>(output, byte_piece(prk).first(hash_length - 1),
                                             {input, input}),
            hash::error::invalid_key_size, output);
    // The largest output is taken.
    std::vector<std::uint8_t> largest(255 * hash_length);
    BOOST_TEST((hash::hkdf_expand<Hmac, Backend>(largest, prk, {input, input}).has_value()));
}

/**
 * Every check of the harness over `Hmac` on `Backend`, against `Oracle`'s single-buffer forms.
 *
 * @param backend Backend's name, as a failure names it.
 */
template <class Hmac, class Backend, class Oracle = hash::backends::hash2>
void check_hkdf_pieces(std::string_view backend) {
    std::cout << "HKDF over pieces on " << backend << " over " << name_of_hmac<Hmac>()
              << ", random cases from the seed 0x" << std::hex << hkdf_pieces_seed << std::dec
              << '\n';
    check_rfc5869<Hmac, Backend, Oracle>(backend);
    check_edges<Hmac, Backend, Oracle>(backend);
    check_random<Hmac, Backend, Oracle>(backend);
    check_long<Hmac, Backend, Oracle>(backend);
    check_guards<Hmac, Backend>(backend);
}

}  // namespace webcpp::test

#endif  // WEBCPP_TEST_HASH_SUPPORT_HKDF_PIECES_HPP
