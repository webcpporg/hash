// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Every linked backend that has a tag of `digests` or `macs` gives the same bytes as every other,
// on 1,000 seeded random cases per tag, the empty input first (spec section 7.2). The tags are
// every one backends::openssl has (increment 4): per tag, backend_has_v and the program's links
// pick the backends, each computed through the families, `digest_of` and a `hasher` fed in random
// pieces (empty ones among them) for a digest, `mac` for a MAC. The backends each tag must compare
// are written out below, from doc/capabilities.json and the Jamfile's links (OpenSSL on every
// target but Emscripten): a cell lost from a trait or a library lost from a Jamfile line fails the
// test instead of shrinking the comparison. A backend that is linked and has the tag is compared
// too, written out or not, so that a cell another increment brings is compared from its merge.
//
// A partial cell (doc/capabilities.json's `partial`) answers unsupported_by_backend outside what
// it serves, and only it may: Boost.Hash2's BLAKE2b (64 bytes, no options) and keyed BLAKE2s (a
// 32-byte tag), Boost.Hash2's SHAKE (at most one result on this branch, ruling R14), OpenSSL's
// BLAKE2b (no key, salt or personalisation) and KMAC (a key of 4 to 512 bytes). Each compared
// backend must answer some cases, so that a partial cell is never compared on nothing. Every other
// answer than the bytes or that refusal is a failure, and a difference is a bug of webcpp's code.

#include <webcpp/hash.hpp>

#include <boost/core/lightweight_test.hpp>

#include <webcpp/test/exit_status.hpp>

#include "support/random_cases.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace hash = webcpp::hash;
namespace digests = webcpp::hash::digests;
namespace macs = webcpp::hash::macs;
namespace backends = webcpp::hash::backends;
using bytes = std::vector<std::uint8_t>;
using webcpp::test::random_source;

namespace {

// Whether the program links Backend and Backend has the tag.
template <class Backend, class Tag>
constexpr bool available_v =
    hash::detail::linked_v<Backend> && hash::backend_has_v<Backend, Tag, void>;

// The names of a comma-separated list, in order.
std::vector<std::string_view> names_of(std::string_view names) {
    std::vector<std::string_view> split;
    while (!names.empty()) {
        std::size_t const end = std::min(names.find(','), names.size());
        split.push_back(names.substr(0, end));
        names.remove_prefix(std::min(end + 1, names.size()));
    }
    return split;
}

// Whether the comma-separated `names` holds `name`.
bool lists(std::string_view names, std::string_view name) {
    auto const split = names_of(names);
    return std::ranges::find(split, name) != split.end();
}

// Whether webcpp builds the backend on this target: OpenSSL on every target but Emscripten.
constexpr bool built_here(std::string_view name) {
#ifdef WEBCPP_TARGET_EMSCRIPTEN
    return name != "openssl";
#else
    static_cast<void>(name);
    return true;
#endif
}

// One way of computing a case: its backend's name, how, and what it answered over the run.
template <class Case>
struct way {
    std::string_view backend;
    std::string_view how;
    boost::system::result<void> (*compute)(bytes& out, Case const& c);
    std::size_t answered = 0;
    std::size_t refused = 0;
};

// Every way of `ways` on `c` against the first that answers; a way that differs, or fails in
// another way than a partial cell's refusal, is an error.
template <class Case>
void compare(std::vector<way<Case>>& ways, Case const& c, std::string_view partial,
             std::string_view tag, std::size_t index) {
    bytes reference;
    way<Case> const* first = nullptr;
    for (auto& w : ways) {
        bytes computed;
        auto const done = w.compute(computed, c);
        if (!done) {
            bool const may_refuse =
                lists(partial, w.backend) && done.error() == hash::error::unsupported_by_backend;
            if (may_refuse) {
                ++w.refused;
            } else {
                BOOST_ERROR("a backend failed a case another answers");
                BOOST_LIGHTWEIGHT_TEST_OSTREAM << "  " << tag << " case " << index << ": "
                                               << w.backend << " " << w.how << " answered "
                                               << done.error().message() << '\n';
            }
            continue;
        }
        ++w.answered;
        if (first == nullptr) {
            reference = std::move(computed);
            first = &w;
            continue;
        }
        if (!BOOST_TEST(computed == reference)) {
            BOOST_LIGHTWEIGHT_TEST_OSTREAM
                << "  " << tag << " case " << index << " seed " << webcpp::test::agreement_seed
                << ": " << w.backend << " " << w.how << " differs from " << first->backend << " "
                << first->how << '\n';
        }
    }
}

// The names of the backends of `ways`, each once, in order.
template <class Case>
std::string backends_of(std::vector<way<Case>> const& ways) {
    std::string names;
    for (auto const& w : ways) {
        if (!lists(names, w.backend)) {
            names += names.empty() ? "" : ",";
            names += w.backend;
        }
    }
    return names;
}

// Every backend `expected` lists that this target builds is among those compared, and each
// compared way answered; prints the comparison, each way's answers and refusals out of the cases.
template <class Case>
void check_backends(std::vector<way<Case>> const& ways, std::string_view tag,
                    std::string_view expected) {
    std::string const compared = backends_of(ways);
    for (std::string_view const name : names_of(expected)) {
        if (built_here(name) && !BOOST_TEST(lists(compared, name))) {
            BOOST_LIGHTWEIGHT_TEST_OSTREAM << "  " << tag << ": " << name
                                           << " is not compared (compared: " << compared << ")\n";
        }
    }
    BOOST_LIGHTWEIGHT_TEST_OSTREAM << "agreement " << tag << ":";
    for (auto const& w : ways) {
        BOOST_TEST_GT(w.answered, 0U);
        BOOST_LIGHTWEIGHT_TEST_OSTREAM << ' ' << w.backend << ' ' << w.how << ' ' << w.answered;
        if (w.refused != 0) {
            BOOST_LIGHTWEIGHT_TEST_OSTREAM << " (" << w.refused << " unsupported_by_backend)";
        }
    }
    BOOST_LIGHTWEIGHT_TEST_OSTREAM << '\n';
}

// ---- Digests ----

template <class Digest>
struct digest_case {
    bytes input;
    bytes key;
    bytes salt;
    bytes personalisation;
    std::size_t output = 0;
    // The sizes of the pieces a hasher is fed, which add up to the input's.
    std::vector<std::size_t> pieces;

    [[nodiscard]] hash::digest_options<Digest> options() const {
        if constexpr (std::is_same_v<Digest, digests::blake2b>) {
            return {
                .key = key,
                .salt = salt,
                .personalisation = personalisation,
                .output_size = output,
            };
        } else {
            return {};
        }
    }
};

template <class Digest>
constexpr bool extendable_v =
    hash::detail::digest_traits<Digest>::max_output(hash::digest_options<Digest>{}) ==
    hash::detail::no_limit;

// Case `index` of Digest: the empty input first; inputs of 0 to 300 bytes, one in 16 of up to
// 3,000; an extendable output of 1 to 200 bytes, one in 8 of up to 2,000; BLAKE2b's options one
// case in two (a key of 1 to 64 bytes, a 16-byte salt and personalisation, each one time in
// two), its output of 1 to 64 bytes one case in two, else 64.
template <class Digest>
digest_case<Digest> next_digest_case(random_source& rnd, std::size_t index) {
    digest_case<Digest> c;
    std::size_t const longest = rnd.between(0, 15) == 0 ? 3000 : 300;
    c.input = index == 0 ? bytes{} : rnd.bytes(rnd.between(0, longest));
    if constexpr (std::is_same_v<Digest, digests::blake2b>) {
        bool const with_options = rnd.between(0, 1) == 0;
        if (with_options && rnd.between(0, 1) == 0) {
            c.key = rnd.bytes(rnd.between(1, 64));
        }
        if (with_options && rnd.between(0, 1) == 0) {
            c.salt = rnd.bytes(16);
        }
        if (with_options && rnd.between(0, 1) == 0) {
            c.personalisation = rnd.bytes(16);
        }
        c.output = rnd.between(0, 1) == 0 ? rnd.between(1, 64) : 64;
    } else if constexpr (extendable_v<Digest>) {
        c.output = rnd.between(0, 7) == 0 ? rnd.between(1, 2000) : rnd.between(1, 200);
    } else {
        c.output = hash::detail::digest_traits<Digest>::max_output(hash::digest_options<Digest>{});
    }
    std::size_t left = c.input.size();
    while (left != 0) {
        std::size_t const piece = rnd.between(0, left);
        c.pieces.push_back(piece);
        left -= piece;
    }
    return c;
}

template <class Digest, class Backend>
boost::system::result<void> digest_whole(bytes& out, digest_case<Digest> const& c) {
    out.assign(c.output, 0);
    return hash::digest_of<Digest, Backend>(out, c.input, c.options());
}

template <class Digest, class Backend>
boost::system::result<void> digest_in_pieces(bytes& out, digest_case<Digest> const& c) {
    out.assign(c.output, 0);
    auto hashing = hash::hasher<Digest, Backend>::make(c.options());
    if (!hashing) {
        return hashing.error();
    }
    std::span<std::uint8_t const> rest(c.input);
    for (std::size_t const piece : c.pieces) {
        auto const fed = hashing->update(rest.first(piece));
        if (!fed) {
            return fed;
        }
        rest = rest.subspan(piece);
    }
    return hashing->finish(out);
}

template <class Digest, class Backend>
void add_digest_ways(std::vector<way<digest_case<Digest>>>& ways, std::string_view name) {
    if constexpr (available_v<Backend, Digest>) {
        ways.push_back(
            {.backend = name, .how = "digest_of", .compute = &digest_whole<Digest, Backend>});
        ways.push_back(
            {.backend = name, .how = "hasher", .compute = &digest_in_pieces<Digest, Backend>});
    }
}

template <class Digest>
void agree_digest(std::string_view tag, std::string_view expected, std::string_view partial = {}) {
    std::vector<way<digest_case<Digest>>> ways;
    add_digest_ways<Digest, backends::hash2>(ways, "hash2");
    add_digest_ways<Digest, backends::xkcp>(ways, "xkcp");
    add_digest_ways<Digest, backends::blake3>(ways, "blake3");
    add_digest_ways<Digest, backends::sodium>(ways, "sodium");
    add_digest_ways<Digest, backends::bearssl>(ways, "bearssl");
    add_digest_ways<Digest, backends::openssl>(ways, "openssl");
    random_source rnd(webcpp::test::agreement_seed);
    for (std::size_t index = 0; index < webcpp::test::agreement_cases; ++index) {
        auto const c = next_digest_case<Digest>(rnd, index);
        compare(ways, c, partial, tag, index);
    }
    check_backends(ways, tag, expected);
}

void digests_agree() {
    agree_digest<digests::md5>("digests::md5", "hash2,openssl");
    agree_digest<digests::sha1>("digests::sha1", "hash2,openssl");
    agree_digest<digests::sha2_224>("digests::sha2_224", "hash2,openssl");
    agree_digest<digests::sha2_256>("digests::sha2_256", "hash2,openssl");
    agree_digest<digests::sha2_384>("digests::sha2_384", "hash2,openssl");
    agree_digest<digests::sha2_512>("digests::sha2_512", "hash2,openssl");
    agree_digest<digests::sha2_512_224>("digests::sha2_512_224", "hash2,openssl");
    agree_digest<digests::sha2_512_256>("digests::sha2_512_256", "hash2,openssl");
    agree_digest<digests::sha3_224>("digests::sha3_224", "hash2,openssl");
    agree_digest<digests::sha3_256>("digests::sha3_256", "hash2,openssl");
    agree_digest<digests::sha3_384>("digests::sha3_384", "hash2,openssl");
    agree_digest<digests::sha3_512>("digests::sha3_512", "hash2,openssl");
    agree_digest<digests::shake_128>("digests::shake_128", "hash2,openssl", "hash2");
    agree_digest<digests::shake_256>("digests::shake_256", "hash2,openssl", "hash2");
    agree_digest<digests::keccak_224>("digests::keccak_224", "openssl");
    agree_digest<digests::keccak_256>("digests::keccak_256", "xkcp,openssl");
    agree_digest<digests::keccak_384>("digests::keccak_384", "openssl");
    agree_digest<digests::keccak_512>("digests::keccak_512", "openssl");
    agree_digest<digests::blake2b>("digests::blake2b", "hash2,sodium,openssl", "hash2,openssl");
    agree_digest<digests::blake2s_256>("digests::blake2s_256", "hash2,openssl");
    agree_digest<digests::ripemd_160>("digests::ripemd_160", "hash2,openssl");
    agree_digest<digests::md5_sha1>("digests::md5_sha1", "openssl");
    agree_digest<digests::sm3>("digests::sm3", "openssl");
}

// ---- MACs ----

template <class Mac>
struct mac_case {
    bytes key;
    bytes input;
    bytes customisation;
    bool xof = false;
    std::size_t output = 0;

    [[nodiscard]] hash::mac_options<Mac> options() const {
        if constexpr (std::is_same_v<Mac, macs::kmac_128> || std::is_same_v<Mac, macs::kmac_256>) {
            return {.customisation = customisation, .xof = xof};
        } else {
            return {};
        }
    }
};

// Case `index` of Mac within the family's guards: the empty input first; inputs of 0 to 300
// bytes, one in 16 of up to 3,000; a key from the shortest the tag takes to 200 bytes (one in
// eight of the shortest); a tag of the longest the tag gives, at most 200 bytes, one case in four,
// else from the shortest to that; KMAC's customisation of 0 to 64 bytes and its XOF form one case
// in two.
template <class Mac>
mac_case<Mac> next_mac_case(random_source& rnd, std::size_t index) {
    using traits = hash::detail::mac_traits<Mac>;
    constexpr std::size_t cap = 200;
    constexpr std::size_t min_key = traits::min_key;
    constexpr std::size_t max_key = traits::max_key < cap ? traits::max_key : cap;
    constexpr std::size_t min_output = traits::min_output;
    constexpr std::size_t max_output = traits::max_output < cap ? traits::max_output : cap;
    mac_case<Mac> c;
    std::size_t const longest = rnd.between(0, 15) == 0 ? 3000 : 300;
    c.input = index == 0 ? bytes{} : rnd.bytes(rnd.between(0, longest));
    c.key = rnd.bytes(rnd.between(0, 7) == 0 ? min_key : rnd.between(min_key, max_key));
    c.output = rnd.between(0, 3) == 0 ? max_output : rnd.between(min_output, max_output);
    if constexpr (std::is_same_v<Mac, macs::kmac_128> || std::is_same_v<Mac, macs::kmac_256>) {
        c.customisation = rnd.bytes(rnd.between(0, 64));
        c.xof = rnd.between(0, 1) == 0;
    }
    return c;
}

template <class Mac, class Backend>
boost::system::result<void> mac_of(bytes& out, mac_case<Mac> const& c) {
    out.assign(c.output, 0);
    return hash::mac<Mac, Backend>(out, c.key, c.input, c.options());
}

template <class Mac, class Backend>
void add_mac_way(std::vector<way<mac_case<Mac>>>& ways, std::string_view name) {
    if constexpr (available_v<Backend, Mac>) {
        ways.push_back({.backend = name, .how = "mac", .compute = &mac_of<Mac, Backend>});
    }
}

template <class Mac>
void agree_mac(std::string_view tag, std::string_view expected, std::string_view partial = {}) {
    std::vector<way<mac_case<Mac>>> ways;
    add_mac_way<Mac, backends::hash2>(ways, "hash2");
    add_mac_way<Mac, backends::xkcp>(ways, "xkcp");
    add_mac_way<Mac, backends::blake3>(ways, "blake3");
    add_mac_way<Mac, backends::sodium>(ways, "sodium");
    add_mac_way<Mac, backends::bearssl>(ways, "bearssl");
    add_mac_way<Mac, backends::openssl>(ways, "openssl");
    random_source rnd(webcpp::test::agreement_seed);
    for (std::size_t index = 0; index < webcpp::test::agreement_cases; ++index) {
        auto const c = next_mac_case<Mac>(rnd, index);
        compare(ways, c, partial, tag, index);
    }
    check_backends(ways, tag, expected);
}

template <class Digest>
void agree_hmac(std::string_view tag, std::string_view expected) {
    agree_mac<macs::hmac<Digest>>(tag, expected);
}

void macs_agree() {
    agree_hmac<digests::md5>("macs::hmac<digests::md5>", "hash2,openssl");
    agree_hmac<digests::sha1>("macs::hmac<digests::sha1>", "hash2,openssl");
    agree_hmac<digests::sha2_224>("macs::hmac<digests::sha2_224>", "hash2,openssl");
    agree_hmac<digests::sha2_256>("macs::hmac<digests::sha2_256>", "hash2,openssl");
    agree_hmac<digests::sha2_384>("macs::hmac<digests::sha2_384>", "hash2,openssl");
    agree_hmac<digests::sha2_512>("macs::hmac<digests::sha2_512>", "hash2,openssl");
    agree_hmac<digests::sha2_512_224>("macs::hmac<digests::sha2_512_224>", "hash2,openssl");
    agree_hmac<digests::sha2_512_256>("macs::hmac<digests::sha2_512_256>", "hash2,openssl");
    agree_hmac<digests::sha3_224>("macs::hmac<digests::sha3_224>", "hash2,openssl");
    agree_hmac<digests::sha3_256>("macs::hmac<digests::sha3_256>", "hash2,openssl");
    agree_hmac<digests::sha3_384>("macs::hmac<digests::sha3_384>", "hash2,openssl");
    agree_hmac<digests::sha3_512>("macs::hmac<digests::sha3_512>", "hash2,openssl");
    agree_hmac<digests::keccak_224>("macs::hmac<digests::keccak_224>", "openssl");
    agree_hmac<digests::keccak_256>("macs::hmac<digests::keccak_256>", "openssl");
    agree_hmac<digests::keccak_384>("macs::hmac<digests::keccak_384>", "openssl");
    agree_hmac<digests::keccak_512>("macs::hmac<digests::keccak_512>", "openssl");
    agree_hmac<digests::ripemd_160>("macs::hmac<digests::ripemd_160>", "hash2,openssl");
    agree_hmac<digests::blake2b>("macs::hmac<digests::blake2b>", "hash2,openssl");
    agree_hmac<digests::blake2s_256>("macs::hmac<digests::blake2s_256>", "hash2,openssl");
    agree_hmac<digests::sm3>("macs::hmac<digests::sm3>", "openssl");
    agree_mac<macs::kmac_128>("macs::kmac_128", "openssl", "openssl");
    agree_mac<macs::kmac_256>("macs::kmac_256", "openssl", "openssl");
    agree_mac<macs::siphash_2_4>("macs::siphash_2_4", "hash2,sodium,openssl");
    agree_mac<macs::siphash_2_4x>("macs::siphash_2_4x", "sodium,openssl");
    agree_mac<macs::blake2b_mac>("macs::blake2b_mac", "openssl");
    agree_mac<macs::blake2s_mac>("macs::blake2s_mac", "hash2,openssl", "hash2");
}

}  // namespace

int main() {
    digests_agree();
    macs_agree();
    return webcpp::test::exit_status(boost::report_errors());
}
