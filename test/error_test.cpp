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

constexpr std::array<expected_message, 9> messages{
    {
        {
            .value = hash::error::invalid_output_size,
            .number = 1,
            .text = "the output is empty or longer than the function produces",
        },
        {
            .value = hash::error::invalid_key_size,
            .number = 2,
            .text = "the key is not of a size the function accepts",
        },
        {
            .value = hash::error::invalid_salt_size,
            .number = 3,
            .text = "the salt is not of a size the function accepts",
        },
        {
            .value = hash::error::invalid_iterations,
            .number = 4,
            .text = "the iteration count is zero",
        },
        {
            .value = hash::error::invalid_parameters,
            .number = 5,
            .text = "a parameter is outside the function's limits",
        },
        {
            .value = hash::error::input_too_long,
            .number = 6,
            .text = "an input is longer than the function accepts",
        },
        {
            .value = hash::error::backend_failure,
            .number = 7,
            .text = "the backend failed where it should not",
        },
        {
            .value = hash::error::unsupported_by_backend,
            .number = 8,
            .text = "the backend does not take this parameter; name a backend that does",
        },
        {
            .value = hash::error::invalid_state,
            .number = 9,
            .text = "the hasher was finished or moved from",
        },
    },
};

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
    BOOST_TEST_EQ(hash::category().message(10), std::string("unknown webcpp.hash error"));
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
