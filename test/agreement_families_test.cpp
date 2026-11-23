// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Every backend that has a tag of `digests`, `macs` or `kdfs` gives the same bytes as every other
// that has it, on seeded random cases, the empty input first (spec section 7.2; the controller's
// task "Agreement across increments", ruling R6). The tags are every one that two or more backends
// have once increments 1 to 7 have landed (doc/capabilities.json), and every tag of
// backends::openssl and backends::botan, whose digest_of and hasher agree with each other where
// it is alone. Botan is compared where the program links it with exceptions
// (agreement_families_botan), its pairs left out elsewhere. A digest
// is computed through `digest_of` and through a `hasher` fed in random pieces (empty ones among
// them), a MAC through `mac` (1,000 cases per tag), Argon2i and Argon2id through `argon2` (100
// cases each). The backends each tag compares are written out below, from doc/capabilities.json
// and the Jamfile's links (OpenSSL on every target but Emscripten), and the backends compared
// must be exactly those: a cell lost from a trait, a library lost from a Jamfile line, or a cell
// a later change brings without its line here, fails the test.
//
// A partial cell (doc/capabilities.json's `partial`) states what it serves, and the test holds it
// to that exactly: on a case it serves it must answer, on any other it must answer
// unsupported_by_backend, and the run must give it cases of both kinds. The partial cells within
// these cases: Boost.Hash2's BLAKE2b (a 64-byte output, no option) and keyed BLAKE2s (a 32-byte
// tag), OpenSSL's BLAKE2b (no key, salt or personalisation) and KMAC (a key of 4 to 512 bytes, a
// customisation of at most 512), Botan's BLAKE2b (no salt or personalisation) and KMAC (a key of
// at most 192 bytes, no XOF form), and libsodium's Argon2 (one lane, a 16-byte salt, a tag of 16
// bytes or more, no secret or associated data, and for Argon2i 3 passes or more). Boost.Hash2's
// SHAKE is whole (ruling R89). OpenSSL's HMAC and Argon2 are partial only past INT_MAX bytes of
// key and past 4 GiB of memory on wasm32, which no case reaches, so they are held to every case.
// Every other answer than the bytes or that refusal is a failure, and a difference is a bug of
// webcpp's code.
//
// The key derivations of increment 1 compare in agreement_hkdf and agreement_pbkdf2, the function
// argon2id and scrypt of libsodium and OpenSSL in argon2_openssl and scrypt_openssl, and
// backends::webcrypto's asynchronous cells against the synchronous default in async_webcrypto.

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
namespace kdfs = webcpp::hash::kdfs;
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

// Whether Botan is compared here: where the program links it (agreement_families_botan) and has
// exceptions, which Botan needs.
#if defined(WEBCPP_HASH_HAS_BOTAN) && !defined(WEBCPP_HASH_NO_EXCEPTIONS)
constexpr bool botan_here = true;
#else
constexpr bool botan_here = false;
#endif

// Whether the backend is compared on this target: OpenSSL on every target but Emscripten, Botan
// where the program links it.
constexpr bool built_here(std::string_view name) {
    if (name == "botan") {
        return botan_here;
    }
#ifdef WEBCPP_TARGET_EMSCRIPTEN
    return name != "openssl";
#else
    return true;
#endif
}

// One way of computing a case: its backend's name, how, what it serves (null for a whole cell; a
// partial cell's predicate of the cases it serves), and what it answered over the run.
template <class Case>
struct way {
    std::string_view backend;
    std::string_view how;
    boost::system::result<void> (*compute)(bytes& out, Case const& c);
    bool (*serves)(Case const& c) = nullptr;
    std::size_t answered = 0;
    std::size_t refused = 0;
};

// Every way of `ways` on `c` against the first that answers. A way that differs is an error, and
// so is any failure but a partial cell's unsupported_by_backend on a case it does not serve, or
// an answer of a partial cell on a case it does not serve.
template <class Case>
void compare(std::vector<way<Case>>& ways, Case const& c, std::string_view tag, std::size_t index) {
    bytes reference;
    way<Case> const* first = nullptr;
    for (auto& w : ways) {
        bytes computed;
        auto const done = w.compute(computed, c);
        bool const served = w.serves == nullptr || w.serves(c);
        if (!served) {
            if (!done && done.error() == hash::error::unsupported_by_backend) {
                ++w.refused;
            } else {
                BOOST_ERROR("a partial cell did not refuse a case it does not serve");
                BOOST_LIGHTWEIGHT_TEST_OSTREAM
                    << "  " << tag << " case " << index << ": " << w.backend << " " << w.how
                    << " answered " << (done ? "the bytes" : done.error().message()) << '\n';
            }
            continue;
        }
        if (!done) {
            BOOST_ERROR("a backend failed a case it serves");
            BOOST_LIGHTWEIGHT_TEST_OSTREAM << "  " << tag << " case " << index << ": " << w.backend
                                           << " " << w.how << " answered " << done.error().message()
                                           << '\n';
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

// The backends compared are exactly those `expected` lists that this target builds, and each way
// answered, a partial cell's refused too; prints the comparison, each way's answers and refusals
// out of the cases.
template <class Case>
void check_backends(std::vector<way<Case>> const& ways, std::string_view tag,
                    std::string_view expected) {
    std::string built;
    for (std::string_view const name : names_of(expected)) {
        if (built_here(name)) {
            built += built.empty() ? "" : ",";
            built += name;
        }
    }
    std::string const compared = backends_of(ways);
    if (!BOOST_TEST_EQ(compared, built)) {
        BOOST_LIGHTWEIGHT_TEST_OSTREAM << "  " << tag << ": the backends compared are not those "
                                       << "of its row\n";
    }
    BOOST_LIGHTWEIGHT_TEST_OSTREAM << "agreement " << tag << ":";
    for (auto const& w : ways) {
        BOOST_TEST_GT(w.answered, 0U);
        if (w.serves != nullptr) {
            BOOST_TEST_GT(w.refused, 0U);
        }
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
    std::uint8_t domain = 0x1F;
    std::size_t output = 0;
    // The sizes of the pieces a hasher is fed, which add up to the input's.
    std::vector<std::size_t> pieces;

    [[nodiscard]] hash::digest_options<Digest> options() const {
        hash::digest_options<Digest> chosen{};
        if constexpr (std::is_same_v<Digest, digests::blake2b>) {
            chosen.key = key;
            chosen.salt = salt;
            chosen.personalisation = personalisation;
            chosen.output_size = output;
        }
        if constexpr (requires { chosen.domain; }) {
            chosen.domain = domain;
        }
        return chosen;
    }
};

template <class Digest>
constexpr bool extendable_v =
    hash::detail::digest_traits<Digest>::max_output(hash::digest_options<Digest>{}) ==
    hash::detail::no_limit;

// Case `index` of Digest: the empty input first; inputs of 0 to 300 bytes, one in 16 of up to
// 3,000; an extendable output of 1 to 200 bytes, one in 8 of up to 2,000; BLAKE2b's options one
// case in two (a key of 1 to 64 bytes, a 16-byte salt and personalisation, each one time in
// two), its output of 1 to 64 bytes one case in two, else 64; TurboSHAKE's domain byte, 0x01 to
// 0x7F, one case in two, else its default 0x1F.
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
    if constexpr (requires { hash::digest_options<Digest>{}.domain; }) {
        if (rnd.between(0, 1) == 0) {
            c.domain = static_cast<std::uint8_t>(rnd.between(0x01, 0x7F));
        }
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

// What a partial digest cell serves (doc/capabilities.json's `partial`), null for a whole one:
// Boost.Hash2's BLAKE2b a 64-byte output without options, OpenSSL's BLAKE2b no option.
template <class Digest, class Backend>
constexpr auto digest_served() -> bool (*)(digest_case<Digest> const&) {
    if constexpr (std::is_same_v<Digest, digests::blake2b> &&
                  std::is_same_v<Backend, backends::hash2>) {
        return [](digest_case<Digest> const& c) {
            return c.output == 64 && c.key.empty() && c.salt.empty() && c.personalisation.empty();
        };
    } else if constexpr (std::is_same_v<Digest, digests::blake2b> &&
                         std::is_same_v<Backend, backends::openssl>) {
        return [](digest_case<Digest> const& c) {
            return c.key.empty() && c.salt.empty() && c.personalisation.empty();
        };
    } else if constexpr (std::is_same_v<Digest, digests::blake2b> &&
                         std::is_same_v<Backend, backends::botan>) {
        return [](digest_case<Digest> const& c) {
            return c.salt.empty() && c.personalisation.empty();
        };
    } else {
        return nullptr;
    }
}

template <class Digest, class Backend>
void add_digest_ways(std::vector<way<digest_case<Digest>>>& ways, std::string_view name) {
    if constexpr (available_v<Backend, Digest>) {
        constexpr auto serves = digest_served<Digest, Backend>();
        ways.push_back({
            .backend = name,
            .how = "digest_of",
            .compute = &digest_whole<Digest, Backend>,
            .serves = serves,
        });
        ways.push_back({
            .backend = name,
            .how = "hasher",
            .compute = &digest_in_pieces<Digest, Backend>,
            .serves = serves,
        });
    }
}

template <class Digest>
void agree_digest(std::string_view tag, std::string_view expected) {
    std::vector<way<digest_case<Digest>>> ways;
    add_digest_ways<Digest, backends::hash2>(ways, "hash2");
    add_digest_ways<Digest, backends::xkcp>(ways, "xkcp");
    add_digest_ways<Digest, backends::blake3>(ways, "blake3");
    add_digest_ways<Digest, backends::sodium>(ways, "sodium");
    add_digest_ways<Digest, backends::bearssl>(ways, "bearssl");
    add_digest_ways<Digest, backends::openssl>(ways, "openssl");
    add_digest_ways<Digest, backends::botan>(ways, "botan");
    random_source rnd(webcpp::test::agreement_seed);
    for (std::size_t index = 0; index < webcpp::test::agreement_cases; ++index) {
        auto const c = next_digest_case<Digest>(rnd, index);
        compare(ways, c, tag, index);
    }
    check_backends(ways, tag, expected);
}

// Each tag's row of doc/capabilities.json, backends::webcrypto left out (its cells are the
// asynchronous family's, compared in async_webcrypto).
void digests_agree() {
    agree_digest<digests::md5>("digests::md5", "hash2,bearssl,openssl,botan");
    agree_digest<digests::sha1>("digests::sha1", "hash2,bearssl,openssl,botan");
    agree_digest<digests::sha2_224>("digests::sha2_224", "hash2,bearssl,openssl,botan");
    agree_digest<digests::sha2_256>("digests::sha2_256", "hash2,sodium,bearssl,openssl,botan");
    agree_digest<digests::sha2_384>("digests::sha2_384", "hash2,bearssl,openssl,botan");
    agree_digest<digests::sha2_512>("digests::sha2_512", "hash2,sodium,bearssl,openssl,botan");
    agree_digest<digests::sha2_512_224>("digests::sha2_512_224", "hash2,openssl");
    agree_digest<digests::sha2_512_256>("digests::sha2_512_256", "hash2,openssl,botan");
    agree_digest<digests::md5_sha1>("digests::md5_sha1", "bearssl,openssl");
    agree_digest<digests::sha3_224>("digests::sha3_224", "hash2,xkcp,openssl,botan");
    agree_digest<digests::sha3_256>("digests::sha3_256", "hash2,xkcp,sodium,openssl,botan");
    agree_digest<digests::sha3_384>("digests::sha3_384", "hash2,xkcp,openssl,botan");
    agree_digest<digests::sha3_512>("digests::sha3_512", "hash2,xkcp,sodium,openssl,botan");
    agree_digest<digests::shake_128>("digests::shake_128",
                                     "hash2,xkcp,sodium,bearssl,openssl,botan");
    agree_digest<digests::shake_256>("digests::shake_256",
                                     "hash2,xkcp,sodium,bearssl,openssl,botan");
    agree_digest<digests::turboshake_128>("digests::turboshake_128", "xkcp,sodium");
    agree_digest<digests::turboshake_256>("digests::turboshake_256", "xkcp,sodium");
    agree_digest<digests::keccak_224>("digests::keccak_224", "xkcp,openssl,botan");
    agree_digest<digests::keccak_256>("digests::keccak_256", "xkcp,openssl,botan");
    agree_digest<digests::keccak_384>("digests::keccak_384", "xkcp,openssl,botan");
    agree_digest<digests::keccak_512>("digests::keccak_512", "xkcp,openssl,botan");
    agree_digest<digests::blake2b>("digests::blake2b", "hash2,sodium,openssl,botan");
    agree_digest<digests::blake2s_256>("digests::blake2s_256", "hash2,openssl,botan");
    agree_digest<digests::ripemd_160>("digests::ripemd_160", "hash2,openssl,botan");
    agree_digest<digests::sm3>("digests::sm3", "openssl,botan");
    // Botan's alone: its digest_of and hasher agree with each other.
    agree_digest<digests::streebog_256>("digests::streebog_256", "botan");
    agree_digest<digests::streebog_512>("digests::streebog_512", "botan");
    agree_digest<digests::whirlpool>("digests::whirlpool", "botan");
    agree_digest<digests::skein_512>("digests::skein_512", "botan");
}

// ---- MACs ----

template <class Mac>
constexpr bool kmac_v = std::is_same_v<Mac, macs::kmac_128> || std::is_same_v<Mac, macs::kmac_256>;

template <class Mac>
struct mac_case {
    bytes key;
    bytes input;
    bytes customisation;
    bool xof = false;
    std::size_t output = 0;

    [[nodiscard]] hash::mac_options<Mac> options() const {
        if constexpr (kmac_v<Mac>) {
            return {.customisation = customisation, .xof = xof};
        } else {
            return {};
        }
    }
};

// Case `index` of Mac within the family's guards: the empty input first; inputs of 0 to 300
// bytes, one in 16 of up to 3,000; a key from the shortest the tag takes to 200 bytes (one in
// eight of the shortest); a tag of the longest the tag gives, at most 200 bytes, one case in four,
// else from the shortest to that. KMAC's customisation of 0 to 64 bytes and its XOF form one case
// in two, and one case in eight a key, one in sixteen a customisation, of 500 to 600 bytes, about
// OpenSSL's limit of 512.
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
    if constexpr (kmac_v<Mac>) {
        constexpr std::size_t about_limit = 500;
        constexpr std::size_t past_limit = 600;
        c.customisation = rnd.bytes(rnd.between(0, 64));
        c.xof = rnd.between(0, 1) == 0;
        if (rnd.between(0, 7) == 0) {
            c.key = rnd.bytes(rnd.between(about_limit, past_limit));
        }
        if (rnd.between(0, 15) == 0) {
            c.customisation = rnd.bytes(rnd.between(about_limit, past_limit));
        }
    }
    return c;
}

template <class Mac, class Backend>
boost::system::result<void> mac_of(bytes& out, mac_case<Mac> const& c) {
    out.assign(c.output, 0);
    return hash::mac<Mac, Backend>(out, c.key, c.input, c.options());
}

// What a partial MAC cell serves, null for a whole one: Boost.Hash2's keyed BLAKE2s a 32-byte tag,
// OpenSSL's KMAC a key of 4 to 512 bytes and a customisation of at most 512 (its third limit, a
// tag of 2,097,151 bytes, is past the cases).
template <class Mac, class Backend>
constexpr auto mac_served() -> bool (*)(mac_case<Mac> const&) {
    if constexpr (std::is_same_v<Mac, macs::blake2s_mac> &&
                  std::is_same_v<Backend, backends::hash2>) {
        return [](mac_case<Mac> const& c) { return c.output == 32; };
    } else if constexpr (kmac_v<Mac> && std::is_same_v<Backend, backends::openssl>) {
        return [](mac_case<Mac> const& c) {
            constexpr std::size_t shortest_key = 4;
            constexpr std::size_t longest_string = 512;
            return c.key.size() >= shortest_key && c.key.size() <= longest_string &&
                   c.customisation.size() <= longest_string;
        };
    } else if constexpr (kmac_v<Mac> && std::is_same_v<Backend, backends::botan>) {
        return [](mac_case<Mac> const& c) {
            constexpr std::size_t longest_key = 192;
            return c.key.size() <= longest_key && !c.xof;
        };
    } else {
        return nullptr;
    }
}

template <class Mac, class Backend>
void add_mac_way(std::vector<way<mac_case<Mac>>>& ways, std::string_view name) {
    if constexpr (available_v<Backend, Mac>) {
        ways.push_back({
            .backend = name,
            .how = "mac",
            .compute = &mac_of<Mac, Backend>,
            .serves = mac_served<Mac, Backend>(),
        });
    }
}

template <class Mac>
void agree_mac(std::string_view tag, std::string_view expected) {
    std::vector<way<mac_case<Mac>>> ways;
    add_mac_way<Mac, backends::hash2>(ways, "hash2");
    add_mac_way<Mac, backends::xkcp>(ways, "xkcp");
    add_mac_way<Mac, backends::blake3>(ways, "blake3");
    add_mac_way<Mac, backends::sodium>(ways, "sodium");
    add_mac_way<Mac, backends::bearssl>(ways, "bearssl");
    add_mac_way<Mac, backends::openssl>(ways, "openssl");
    add_mac_way<Mac, backends::botan>(ways, "botan");
    random_source rnd(webcpp::test::agreement_seed);
    for (std::size_t index = 0; index < webcpp::test::agreement_cases; ++index) {
        auto const c = next_mac_case<Mac>(rnd, index);
        compare(ways, c, tag, index);
    }
    check_backends(ways, tag, expected);
}

template <class Digest>
void agree_hmac(std::string_view tag, std::string_view expected) {
    agree_mac<macs::hmac<Digest>>(tag, expected);
}

void macs_agree() {
    agree_hmac<digests::md5>("macs::hmac<digests::md5>", "hash2,bearssl,openssl,botan");
    agree_hmac<digests::sha1>("macs::hmac<digests::sha1>", "hash2,bearssl,openssl,botan");
    agree_hmac<digests::sha2_224>("macs::hmac<digests::sha2_224>", "hash2,bearssl,openssl,botan");
    agree_hmac<digests::sha2_256>("macs::hmac<digests::sha2_256>",
                                  "hash2,sodium,bearssl,openssl,botan");
    agree_hmac<digests::sha2_384>("macs::hmac<digests::sha2_384>", "hash2,bearssl,openssl,botan");
    agree_hmac<digests::sha2_512>("macs::hmac<digests::sha2_512>",
                                  "hash2,sodium,bearssl,openssl,botan");
    agree_hmac<digests::sha2_512_224>("macs::hmac<digests::sha2_512_224>", "hash2,openssl");
    agree_hmac<digests::sha2_512_256>("macs::hmac<digests::sha2_512_256>", "hash2,openssl,botan");
    agree_hmac<digests::sha3_224>("macs::hmac<digests::sha3_224>", "hash2,openssl,botan");
    agree_hmac<digests::sha3_256>("macs::hmac<digests::sha3_256>", "hash2,openssl,botan");
    agree_hmac<digests::sha3_384>("macs::hmac<digests::sha3_384>", "hash2,openssl,botan");
    agree_hmac<digests::sha3_512>("macs::hmac<digests::sha3_512>", "hash2,openssl,botan");
    agree_hmac<digests::keccak_224>("macs::hmac<digests::keccak_224>", "openssl,botan");
    agree_hmac<digests::keccak_256>("macs::hmac<digests::keccak_256>", "openssl,botan");
    agree_hmac<digests::keccak_384>("macs::hmac<digests::keccak_384>", "openssl,botan");
    agree_hmac<digests::keccak_512>("macs::hmac<digests::keccak_512>", "openssl,botan");
    agree_hmac<digests::ripemd_160>("macs::hmac<digests::ripemd_160>", "hash2,openssl,botan");
    agree_hmac<digests::blake2b>("macs::hmac<digests::blake2b>", "hash2,openssl,botan");
    agree_hmac<digests::blake2s_256>("macs::hmac<digests::blake2s_256>", "hash2,openssl,botan");
    agree_hmac<digests::sm3>("macs::hmac<digests::sm3>", "openssl,botan");
    agree_hmac<digests::streebog_256>("macs::hmac<digests::streebog_256>", "botan");
    agree_hmac<digests::streebog_512>("macs::hmac<digests::streebog_512>", "botan");
    agree_hmac<digests::whirlpool>("macs::hmac<digests::whirlpool>", "botan");
    agree_hmac<digests::skein_512>("macs::hmac<digests::skein_512>", "botan");
    agree_mac<macs::kmac_128>("macs::kmac_128", "xkcp,openssl,botan");
    agree_mac<macs::kmac_256>("macs::kmac_256", "xkcp,openssl,botan");
    agree_mac<macs::siphash_2_4>("macs::siphash_2_4", "hash2,sodium,openssl,botan");
    agree_mac<macs::siphash_2_4x>("macs::siphash_2_4x", "sodium,openssl");
    agree_mac<macs::blake2b_mac>("macs::blake2b_mac", "sodium,openssl,botan");
    agree_mac<macs::blake2s_mac>("macs::blake2s_mac", "hash2,openssl");
}

// ---- Argon2 ----

struct argon2_case {
    bytes password;
    bytes salt;
    bytes secret;
    bytes associated_data;
    std::uint32_t passes = 1;
    std::uint32_t memory_kibibytes = 8;
    std::uint32_t lanes = 1;
    std::size_t output = 0;
};

// The cases of Argon2 per variant: the memory-hard function is slow in a debug build.
constexpr std::size_t argon2_cases = 100;

// Case `index`: the empty password first; passwords of 0 to 64 bytes, t of 1 to 4, m of 8p to
// 256 KiB, and from libsodium's shape (one lane, a 16-byte salt, no secret or associated data, a
// tag of 16 to 80 bytes) each of those five one time in four to any of RFC 9106's within small
// costs: p of 2 to 4, a salt of 8 to 32 bytes but 16, a secret and associated data of 1 to 32
// bytes, a tag of 4 to 15 bytes. So every bound of libsodium's is crossed alone, and together.
argon2_case next_argon2_case(random_source& rnd, std::size_t index) {
    constexpr std::size_t sodium_salt = 16;
    constexpr std::size_t sodium_shortest_tag = 16;
    argon2_case c;
    c.password = index == 0 ? bytes{} : rnd.bytes(rnd.between(0, 64));
    bool const other_salt = rnd.between(0, 3) == 0;
    std::size_t salt_size = sodium_salt;
    while (other_salt && salt_size == sodium_salt) {
        salt_size = rnd.between(8, 32);
    }
    c.salt = rnd.bytes(salt_size);
    if (rnd.between(0, 3) == 0) {
        c.secret = rnd.bytes(rnd.between(1, 32));
    }
    if (rnd.between(0, 3) == 0) {
        c.associated_data = rnd.bytes(rnd.between(1, 32));
    }
    if (rnd.between(0, 3) == 0) {
        c.lanes = static_cast<std::uint32_t>(rnd.between(2, 4));
    }
    c.output = rnd.between(0, 3) == 0 ? rnd.between(4, sodium_shortest_tag - 1)
                                      : rnd.between(sodium_shortest_tag, 80);
    c.passes = static_cast<std::uint32_t>(rnd.between(1, 4));
    c.memory_kibibytes = static_cast<std::uint32_t>(rnd.between(std::size_t{8} * c.lanes, 256));
    return c;
}

template <class Variant, class Backend>
boost::system::result<void> argon2_of(bytes& out, argon2_case const& c) {
    out.assign(c.output, 0);
    return hash::argon2<Variant, Backend>(out, c.password, c.salt,
                                          {
                                              .passes = c.passes,
                                              .memory_kibibytes = c.memory_kibibytes,
                                              .lanes = c.lanes,
                                              .secret = c.secret,
                                              .associated_data = c.associated_data,
                                          });
}

// What libsodium's Argon2 serves: one lane, a 16-byte salt, no secret or associated data, a tag
// of 16 bytes or more, and for Argon2i 3 passes or more; null for every other cell.
template <class Variant, class Backend>
constexpr auto argon2_served() -> bool (*)(argon2_case const&) {
    if constexpr (std::is_same_v<Backend, backends::sodium>) {
        return [](argon2_case const& c) {
            constexpr std::size_t salt = 16;
            constexpr std::size_t shortest_tag = 16;
            constexpr std::uint32_t argon2i_passes = 3;
            bool const passes =
                !std::is_same_v<Variant, kdfs::argon2i> || c.passes >= argon2i_passes;
            return c.lanes == 1 && c.salt.size() == salt && c.secret.empty() &&
                   c.associated_data.empty() && c.output >= shortest_tag && passes;
        };
    } else {
        return nullptr;
    }
}

template <class Variant, class Backend>
void add_argon2_way(std::vector<way<argon2_case>>& ways, std::string_view name) {
    // argon2's variants are told from the function argon2id by argon2_parameters.
    if constexpr (hash::detail::linked_v<Backend> &&
                  hash::backend_has_v<Backend, Variant, hash::argon2_parameters>) {
        ways.push_back({
            .backend = name,
            .how = "argon2",
            .compute = &argon2_of<Variant, Backend>,
            .serves = argon2_served<Variant, Backend>(),
        });
    }
}

template <class Variant>
void agree_argon2(std::string_view tag, std::string_view expected) {
    std::vector<way<argon2_case>> ways;
    add_argon2_way<Variant, backends::sodium>(ways, "sodium");
    add_argon2_way<Variant, backends::openssl>(ways, "openssl");
    random_source rnd(webcpp::test::agreement_seed);
    for (std::size_t index = 0; index < argon2_cases; ++index) {
        compare(ways, next_argon2_case(rnd, index), tag, index);
    }
    check_backends(ways, tag, expected);
}

void kdfs_agree() {
    agree_argon2<kdfs::argon2i>("kdfs::argon2i", "sodium,openssl");
    agree_argon2<kdfs::argon2id>("kdfs::argon2id", "sodium,openssl");
}

}  // namespace

int main() {
    digests_agree();
    macs_agree();
    kdfs_agree();
    return webcpp::test::exit_status(boost::report_errors());
}
