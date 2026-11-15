// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Every linked backend that has PBKDF2 over an hmac gives the same output as every other, on 1,000
// seeded random cases per hmac, the empty inputs first (spec section 7.2). Per hmac, backend_has_v
// and the program's links pick the backends: backends::hash2 always, then openssl where the
// Jamfile links it (sodium and BearSSL have no PBKDF2; OpenSSL is absent on Emscripten, where
// backends::hash2 alone remains: the test asserts that, and compares nothing there). A difference
// is a bug of webcpp's code. The lengths stay within every backend's limits, beyond which a
// backend refuses before its library is called.

#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/pbkdf2.hpp>

#include <boost/core/lightweight_test.hpp>

#include <webcpp/test/exit_status.hpp>

#include "support/agreement_expect.hpp"
#include "support/random_cases.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace hash = webcpp::hash;
using webcpp::test::random_pbkdf2_case;

namespace {

// Whether the program links Backend and Backend has PBKDF2 over Hmac.
template <class Backend, class Hmac>
constexpr bool available_v =
    hash::detail::linked_v<Backend> && hash::backend_has_v<Backend, hash::kdfs::pbkdf2, Hmac>;

// One backend: its name, and its PBKDF2.
struct way {
    const char* name;
    bool (*derive)(std::vector<std::uint8_t>& out, const random_pbkdf2_case& c);
};

template <class Hmac, class Backend>
bool derive(std::vector<std::uint8_t>& out, const random_pbkdf2_case& c) {
    out.assign(c.output, 0);
    return hash::pbkdf2<Hmac, Backend>(out, c.password, c.salt, c.iterations).has_value();
}

template <class Hmac, class Backend>
void add_way(std::vector<way>& ways, const char* name) {
    if constexpr (available_v<Backend, Hmac>) {
        ways.push_back({name, &derive<Hmac, Backend>});
    }
}

// The names of `ways`, in order, one per backend.
std::string backends_of(const std::vector<way>& ways) {
    std::string names;
    for (const way& w : ways) {
        if (!names.empty()) {
            names += ',';
        }
        names += w.name;
    }
    return names;
}

// Every way against the first (backends::hash2's) on `c`: every pair, by transitivity.
void compare(const std::vector<way>& ways, const random_pbkdf2_case& c) {
    std::vector<std::uint8_t> reference;
    std::vector<std::uint8_t> other;
    const bool first = ways[0].derive(reference, c);
    BOOST_TEST(first);
    if (!first) {
        return;
    }
    for (std::size_t w = 1; w < ways.size(); ++w) {
        const bool done = ways[w].derive(other, c);
        BOOST_TEST(done);
        if (done) {
            BOOST_TEST(other == reference);
        }
    }
}

template <class Hmac>
void agree(const char* hmac_name) {
    std::vector<way> ways;
    add_way<Hmac, hash::backends::hash2>(ways, "hash2");
    add_way<Hmac, hash::backends::sodium>(ways, "sodium");
    add_way<Hmac, hash::backends::bearssl>(ways, "bearssl");
    add_way<Hmac, hash::backends::openssl>(ways, "openssl");

    // The backends compared against the table written out in agreement_expect.hpp. On Emscripten
    // that is backends::hash2 alone (no other library has PBKDF2 there): the test expects exactly
    // that and compares hash2's output with nothing but its own success.
    BOOST_TEST_EQ(backends_of(ways), webcpp::test::expected_pbkdf2_backends<Hmac>());
    if (ways.empty() || std::string_view(ways[0].name) != "hash2") {
        BOOST_ERROR("agreement_pbkdf2: the first way is not backends::hash2");
        return;
    }

    constexpr std::size_t digest = typename Hmac::result_type().size();
    webcpp::test::random_source rnd(webcpp::test::agreement_seed);
    for (std::size_t i = 0; i < webcpp::test::agreement_cases; ++i) {
        const auto c = webcpp::test::next_pbkdf2_case(rnd, i, digest);
        const int before = boost::report_errors();
        compare(ways, c);
        if (boost::report_errors() != before) {
            BOOST_LIGHTWEIGHT_TEST_OSTREAM
                << "agreement_pbkdf2: " << hmac_name << " case " << i << " seed "
                << webcpp::test::agreement_seed << " password " << c.password.size() << " salt "
                << c.salt.size() << " iterations " << c.iterations << " output " << c.output
                << "\n";
        }
    }
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
