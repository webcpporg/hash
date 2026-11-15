// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The errors of webcpp::hash, in the category `webcpp.hash`.

 @see "Errors", in the guide.
*/
#ifndef WEBCPP_HASH_ERROR_HPP
#define WEBCPP_HASH_ERROR_HPP

#include <webcpp/hash/config.hpp>

#include <boost/system/error_category.hpp>
#include <boost/system/error_code.hpp>

#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>
#include <type_traits>

namespace webcpp::hash {

/**
 Why an operation of webcpp::hash failed.

 The values are fixed and never reused.

 @see "Errors", in the guide.
*/
enum class error : int {
    /** An output that is empty or longer than the function produces. */
    invalid_output_size = 1,
    /** A pseudorandom key that is not of the hmac's digest size. */
    invalid_key_size = 2,
    /** A salt that is not of a size the function accepts. */
    invalid_salt_size = 3,
    /** An iteration count of zero. */
    invalid_iterations = 4,
    /** A cost that is outside the function's limits. */
    invalid_parameters = 5,
    /** An input that is longer than the function accepts. */
    input_too_long = 6,
    /** A backend failed where its contract says it does not. */
    backend_failure = 7,
    /** A parameter the chosen backend does not take; name a backend that does. */
    unsupported_by_backend = 8,
    // 9 comes with a later task, which declares it; never reused.
};

namespace detail {

/** The message of a value of @ref error, or the unknown message for a value it does not define. */
inline const char* message_of(int value) noexcept {
    switch (static_cast<error>(value)) {
        case error::invalid_output_size:
            return "the output is empty or longer than the function produces";
        case error::invalid_key_size:
            return "the pseudorandom key is not of the hmac's digest size";
        case error::invalid_salt_size: return "the salt is not of a size the function accepts";
        case error::invalid_iterations: return "the iteration count is zero";
        case error::invalid_parameters: return "a cost is outside the function's limits";
        case error::input_too_long: return "an input is longer than the function accepts";
        case error::backend_failure: return "the backend failed where it should not";
        case error::unsupported_by_backend:
            return "the backend does not take this parameter; name a backend that does";
    }
    return "unknown webcpp.hash error";
}

/**
 A constant category with a fixed identity, so it holds no mutable state.

 @note The identity is the ASCII of "hash" followed by four zero bytes.
*/
class category final : public boost::system::error_category {
public:
    /** Constructs the category with its fixed identity. */
    constexpr category() noexcept : boost::system::error_category(0x6861736800000000ULL) {}

    /** The category's name, "webcpp.hash". */
    const char* name() const noexcept override { return "webcpp.hash"; }

    /** The message of the error `value`, as @ref message_of spells it. */
    std::string message(int value) const override { return message_of(value); }

    /**
     Copies the message of the error `value` into `buffer`, cut to fit `size` bytes with its
     terminating zero, and returns the whole message, a static text.
    */
    const char* message(int value, char* buffer, std::size_t size) const noexcept override {
        const char* text = message_of(value);
        if (buffer != nullptr && size != 0) {
            const std::string_view spelling(text);
            const std::size_t limit = size - 1;
            const std::size_t count = spelling.size() < limit ? spelling.size() : limit;
            std::memcpy(buffer, spelling.data(), count);
            buffer[count] = '\0';
        }
        return text;
    }
};

/** The one category of hash's errors, which @ref webcpp::hash::category returns. */
inline constexpr category the_category{};

}  // namespace detail

/**
 The category of every @ref error.

 Its `name()` is "webcpp.hash", and its `message(value)` the message of the error, or
 "unknown webcpp.hash error" for a value @ref error does not define.

 @return The category, a constant with a fixed identity.
 @see "Errors", in the guide.
*/
inline const boost::system::error_category& category() noexcept {
    return detail::the_category;
}

/**
 Makes the `error_code` of an @ref error, as its implicit conversion does.

 @param e The error.
 @return `e` as an `error_code` of the category @ref category.
*/
inline boost::system::error_code make_error_code(error e) noexcept {
    return {static_cast<int>(e), category()};
}

}  // namespace webcpp::hash

namespace boost::system {
template <>
struct is_error_code_enum<webcpp::hash::error> : std::true_type {};
}  // namespace boost::system

#endif  // WEBCPP_HASH_ERROR_HPP
