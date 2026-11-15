// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Every linked backend that has HKDF over an hmac gives the same output as every other, on 1,000
// seeded random cases per hmac, the empty inputs first (spec section 7.2). Per hmac, backend_has_v
// and the program's links pick the backends: backends::hash2 always, then sodium, bearssl and
// openssl as the Jamfile links them (OpenSSL is absent on Emscripten). Each backend's `hkdf` is
// compared, and its `hkdf_extract` then `hkdf_expand` too, except BearSSL's, which has `hkdf`
// alone. A difference is a bug of webcpp's code. The lengths stay within every backend's limits
// (ruling R24).

#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>

#include <boost/core/lightweight_test.hpp>

#include <webcpp/test/exit_status.hpp>

#include "support/random_cases.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

namespace hash = webcpp::hash;
using webcpp::test::random_hkdf_case;

namespace {

// Whether the program links Backend and Backend has HKDF over Hmac.
template <class Backend, class Hmac>
constexpr bool available_v =
    hash::detail::linked_v<Backend> && hash::backend_has_v<Backend, hash::kdfs::hkdf, Hmac>;

// One way of deriving: its backend's name, and the function.
struct way {
    const char* name;
    bool (*derive)(std::vector<std::uint8_t>& out, const random_hkdf_case& c);
};

template <class Hmac, class Backend>
bool derive_whole(std::vector<std::uint8_t>& out, const random_hkdf_case& c) {
    out.assign(c.output, 0);
    return hash::hkdf<Hmac, Backend>(out, c.salt, c.ikm, c.info).has_value();
}

template <class Hmac, class Backend>
bool derive_split(std::vector<std::uint8_t>& out, const random_hkdf_case& c) {
    auto prk = hash::hkdf_extract<Hmac, Backend>(c.salt, c.ikm);
    if (!prk) {
        return false;
    }
    out.assign(c.output, 0);
    return hash::hkdf_expand<Hmac, Backend>(out, std::span<std::uint8_t const>(*prk), c.info)
        .has_value();
}

// The ways Hmac has: `hkdf` on each available backend, `hkdf_extract` and `hkdf_expand` on each
// but BearSSL.
template <class Hmac, class Backend>
void add_ways(std::vector<way>& ways, const char* name) {
    if constexpr (available_v<Backend, Hmac>) {
        ways.push_back({name, &derive_whole<Hmac, Backend>});
        if constexpr (!std::is_same_v<Backend, hash::backends::bearssl>) {
            ways.push_back({name, &derive_split<Hmac, Backend>});
        }
    }
}

template <class Hmac>
void agree(const char* hmac_name) {
    std::vector<way> ways;
    add_ways<Hmac, hash::backends::hash2>(ways, "hash2");
    add_ways<Hmac, hash::backends::sodium>(ways, "sodium");
    add_ways<Hmac, hash::backends::bearssl>(ways, "bearssl");
    add_ways<Hmac, hash::backends::openssl>(ways, "openssl");

    constexpr std::size_t digest = typename Hmac::result_type().size();
    webcpp::test::random_source rnd(webcpp::test::agreement_seed);
    std::vector<std::uint8_t> reference;
    std::vector<std::uint8_t> other;
    for (std::size_t i = 0; i < webcpp::test::agreement_cases; ++i) {
        const auto c = webcpp::test::next_hkdf_case(rnd, i, digest);
        const int before = boost::report_errors();
        if (!BOOST_TEST(ways[0].derive(reference, c))) {
            continue;
        }
        for (std::size_t w = 1; w < ways.size(); ++w) {
            if (BOOST_TEST(ways[w].derive(other, c))) {
                BOOST_TEST(other == reference);
            }
        }
        if (boost::report_errors() != before) {
            BOOST_LIGHTWEIGHT_TEST_OSTREAM << "agreement_hkdf: " << hmac_name << " case " << i
                                           << " seed " << webcpp::test::agreement_seed << " salt "
                                           << c.salt.size() << " ikm " << c.ikm.size() << " info "
                                           << c.info.size() << " output " << c.output << "\n";
        }
    }
    // Every way was compared to the first (backends::hash2's `hkdf`): every pair, by transitivity.
}

}  // namespace

int main() {
    agree<hash::hmac_md5_128>("md5");
    agree<hash::hmac_sha1_160>("sha1");
    agree<hash::hmac_sha2_224>("sha2_224");
    agree<hash::hmac_sha2_256>("sha2_256");
    agree<hash::hmac_sha2_384>("sha2_384");
    agree<hash::hmac_sha2_512>("sha2_512");
    agree<hash::hmac_sha2_512_224>("sha2_512_224");
    agree<hash::hmac_sha2_512_256>("sha2_512_256");
    agree<hash::hmac_sha3_224>("sha3_224");
    agree<hash::hmac_sha3_256>("sha3_256");
    agree<hash::hmac_sha3_384>("sha3_384");
    agree<hash::hmac_sha3_512>("sha3_512");
    agree<hash::hmac_ripemd_128>("ripemd_128");
    agree<hash::hmac_ripemd_160>("ripemd_160");
    agree<hash::hmac_blake2b_512>("blake2b_512");
    agree<hash::hmac_blake2s_256>("blake2s_256");
    return webcpp::test::exit_status(boost::report_errors());
}
