// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

#include <webcpp/hash/error.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/system/result.hpp>

#include <webcpp/test/exit_status.hpp>

#include <array>
#include <cstring>
#include <string>
#include <string_view>

namespace hash = webcpp::hash;

namespace {

struct expected_message {
    hash::error value;
    int number;
    std::string_view text;
};

constexpr std::array<expected_message, 8> messages{{
    {hash::error::invalid_output_size, 1,
     "the output is empty or longer than the function produces"},
    {hash::error::invalid_key_size, 2, "the pseudorandom key is not of the hmac's digest size"},
    {hash::error::invalid_salt_size, 3, "the salt is not of a size the function accepts"},
    {hash::error::invalid_iterations, 4, "the iteration count is zero"},
    {hash::error::invalid_parameters, 5, "a cost is outside the function's limits"},
    {hash::error::input_too_long, 6, "an input is longer than the function accepts"},
    {hash::error::backend_failure, 7, "the backend failed where it should not"},
    {hash::error::unsupported_by_backend, 8,
     "the backend does not take this parameter; name a backend that does"},
}};

void check_values_and_messages() {
    for (const auto& expected : messages) {
        const boost::system::error_code code = expected.value;
        BOOST_TEST_EQ(code.value(), expected.number);
        BOOST_TEST_EQ(std::string_view(code.category().name()), "webcpp.hash");
        BOOST_TEST_EQ(code.message(), std::string(expected.text));
        std::array<char, 8> small{};
        const char* whole = code.category().message(code.value(), small.data(), small.size());
        BOOST_TEST_EQ(std::string_view(whole), expected.text);
        BOOST_TEST_EQ(std::strlen(small.data()), small.size() - 1);
    }
    BOOST_TEST_EQ(hash::category().message(0), std::string("unknown webcpp.hash error"));
}

void check_result() {
    const boost::system::result<int> failed =
        boost::system::error_code(hash::error::backend_failure);
    BOOST_TEST(!failed);
    BOOST_TEST(failed.error() == hash::error::backend_failure);
}

}  // namespace

int main() {
    check_values_and_messages();
    check_result();
    return webcpp::test::exit_status(boost::report_errors());
}
