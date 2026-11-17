// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `backends::webcrypto`: the browser's WebCrypto (`crypto.subtle`, the Web Cryptography API) as a
 backend of the asynchronous family of `<webcpp/hash/async.hpp>`, on Emscripten, where node and
 every browser have it: `async_digest` over SHA-1, SHA-256, SHA-384 and SHA-512, and `async_hmac`,
 `async_hkdf` and `async_pbkdf2` over the hmacs of those four. It is never a default: a program
 names it in the type. No synchronous function takes it.

 Each operation builds WebCrypto's call with `emscripten::val` (`digest`; `importKey`, then `sign`
 or `deriveBits`), awaits its promise through webcpp::asio's
 `webcpp::asio::browser::async_await`, and copies the resulting bytes into the output in its
 completion; a rejected promise is `error::backend_failure`, and a cancellation through the
 handler's slot `asio::error::operation_aborted`, both with the output zeroed. The same guards as
 the synchronous function run first, then WebCrypto's own limits (`detail::backend_limits`), then
 the executor's check: its context must be an `io_context` that runs on the calling thread, whose
 `run` returns to the JavaScript event loop where the promise settles. A refusal completes through
 a post to the handler's associated executor, the output untouched.

 `async.hpp` includes this header: a program includes either. It needs webcpp::asio
 (`<library>/webcpp/asio//asio`) and nothing else; off Emscripten it holds only the limits, since
 an asynchronous function that names `backends::webcrypto` there refuses at compile time.

 @code
 // On Emscripten, in a handler of the page's event loop (an io_context run on the main thread):
 webcpp::hash::async_pbkdf2<webcpp::hash::hmac_sha2_256, webcpp::hash::backends::webcrypto>(
     loop.get_executor(), key, password, salt, 600000, [&](boost::system::error_code code) {
         // the browser derived the key off the page's thread
     });
 @endcode

 @see "WebCrypto in the browser", in the guide.
*/
#ifndef WEBCPP_HASH_BACKENDS_WEBCRYPTO_HPP
#define WEBCPP_HASH_BACKENDS_WEBCRYPTO_HPP

#include <webcpp/hash/config.hpp>

#include <webcpp/hash/async.hpp>
#include <webcpp/hash/detail/engines.hpp>

#include <cstdint>

namespace webcpp::hash::detail {

/**
 WebCrypto's limits (ruling R74), measured under node 26.13 and read in the Web Cryptography API:
 `deriveBits` takes its length in bits as an `unsigned long`, so an output of HKDF or PBKDF2 is at
 most (2^32 - 1) / 8 bytes; PBKDF2's iteration count is an `unsigned long`, at most 2^32 - 1;
 node refuses an HKDF info longer than 1,024 bytes ("algorithm.info must be at most 1024
 bytes"), where the other backends take `hkdf_max_info_size`. No limit elsewhere.
*/
template <>
struct backend_limits<backends::webcrypto> {
    /** HKDF's salt: no limit of WebCrypto's own. */
    static constexpr std::uint64_t hkdf_salt = no_limit;
    /** HKDF's input keying material: no limit of WebCrypto's own. */
    static constexpr std::uint64_t hkdf_ikm = no_limit;
    /** HKDF's pseudorandom key: WebCrypto has no `hkdf_expand` (no limit to state). */
    static constexpr std::uint64_t hkdf_prk = no_limit;
    /** HKDF's info: node's 1,024 bytes (`input_too_long` beyond). */
    static constexpr std::uint64_t hkdf_info = 1024;
    /** HKDF's output: `deriveBits`' length, (2^32 - 1) bits, in whole bytes. */
    static constexpr std::uint64_t hkdf_output = 0xffffffffULL / 8;
    /** PBKDF2's password: no limit of WebCrypto's own. */
    static constexpr std::uint64_t pbkdf2_password = no_limit;
    /** PBKDF2's salt: no limit of WebCrypto's own. */
    static constexpr std::uint64_t pbkdf2_salt = no_limit;
    /** PBKDF2's output: `deriveBits`' length, (2^32 - 1) bits, in whole bytes. */
    static constexpr std::uint64_t pbkdf2_output = 0xffffffffULL / 8;
    /** PBKDF2's iteration count: an `unsigned long`, 2^32 - 1 (`invalid_iterations` beyond). */
    static constexpr std::uint64_t pbkdf2_iterations = 0xffffffffULL;
    /** WebCrypto has no Argon2id: no limit to state. */
    static constexpr std::uint64_t argon2id_password = no_limit;
    /** WebCrypto has no Argon2id: no limit to state. */
    static constexpr std::uint64_t argon2id_salt = no_limit;
    /** WebCrypto has no Argon2id: no limit to state. */
    static constexpr std::uint64_t argon2id_output = no_limit;
    /** WebCrypto has no scrypt: no limit to state. */
    static constexpr std::uint64_t scrypt_password = no_limit;
    /** WebCrypto has no scrypt: no limit to state. */
    static constexpr std::uint64_t scrypt_salt = no_limit;
    /** WebCrypto has no scrypt: no limit to state. */
    static constexpr std::uint64_t scrypt_output = no_limit;
};

}  // namespace webcpp::hash::detail

#ifdef WEBCPP_TARGET_EMSCRIPTEN

#include <webcpp/hash/detail/limits.hpp>
#include <webcpp/hash/detail/wipe.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/hash/pbkdf2.hpp>

#include <webcpp/asio/append.hpp>
#include <webcpp/asio/associated_executor.hpp>
#include <webcpp/asio/async_result.hpp>
#include <webcpp/asio/browser/async_await.hpp>
#include <webcpp/asio/cancellation_state.hpp>
#include <webcpp/asio/cancellation_type.hpp>
#include <webcpp/asio/compose.hpp>
#include <webcpp/asio/error.hpp>
#include <webcpp/asio/execution/context.hpp>
#include <webcpp/asio/execution/outstanding_work.hpp>
#include <webcpp/asio/io_context.hpp>
#include <webcpp/asio/post.hpp>
#include <webcpp/asio/prefer.hpp>
#include <webcpp/asio/query.hpp>
#include <webcpp/asio/strand.hpp>

#include <emscripten/val.h>

#include <boost/system/error_code.hpp>
#include <boost/system/result.hpp>

#include <array>
#include <cstddef>
#include <span>
#include <type_traits>
#include <utility>

namespace webcpp::hash::detail {

/**
 WebCrypto's name of the digest `Digest` (`"SHA-1"`, `"SHA-256"`, `"SHA-384"`, `"SHA-512"`), the
 `hash` of every call; empty for a digest WebCrypto lacks.
*/
template <class Digest>
constexpr char const* webcrypto_hash_name_of() noexcept {
    if constexpr (std::is_same_v<Digest, digests::sha1>) {
        return "SHA-1";
    } else if constexpr (std::is_same_v<Digest, digests::sha2_256>) {
        return "SHA-256";
    } else if constexpr (std::is_same_v<Digest, digests::sha2_384>) {
        return "SHA-384";
    } else if constexpr (std::is_same_v<Digest, digests::sha2_512>) {
        return "SHA-512";
    } else {
        return "";
    }
}

/** @ref webcrypto_hash_name_of as a constant. */
template <class Digest>
inline constexpr char const* webcrypto_hash_name = webcrypto_hash_name_of<Digest>();

/** What an executor's context is, as its type tells: an `io_context`, unknown, or another. */
enum class webcrypto_context : std::uint8_t {
    /** An `io_context` (or a type derived from it): accepted at compile time. */
    io_context,
    /** A type-erased executor's `execution_context`: checked at run time. */
    erased,
    /** Another context (a `thread_pool`'s, the system's): refused at compile time. */
    other,
};

/** The context of `Executor`, `execution::context` queried, without reference or `const`. */
template <class Executor>
using webcrypto_context_t = std::remove_cvref_t<decltype(webcpp::asio::query(
    std::declval<Executor const&>(), webcpp::asio::execution::context))>;

/**
 What the context of `Executor` is, by its type (ruling R73). An `io_context`'s executor names
 Asio's own `io_context`, the base of webcpp::asio's.
*/
template <class Executor>
constexpr webcrypto_context webcrypto_context_kind() noexcept {
    using context = webcrypto_context_t<Executor>;
    if constexpr (std::is_base_of_v<webcpp::asio_backend::io_context, context>) {
        return webcrypto_context::io_context;
    } else if constexpr (std::is_same_v<webcpp::asio::execution_context, context>) {
        return webcrypto_context::erased;
    } else {
        return webcrypto_context::other;
    }
}

/** @ref webcrypto_context_kind as a constant. */
template <class Executor>
inline constexpr webcrypto_context webcrypto_context_of = webcrypto_context_kind<Executor>();

/**
 Whether a type-erased executor holds one of an `io_context`: its own executor, the same with
 outstanding work, or a strand over either (ruling R73). An executor of another kind behind it, or
 an erased type without `target`, is answered false: the operation would await a promise on a
 context whose threads never return to the JavaScript event loop.

 @param executor The executor. @return Whether its target is an `io_context`'s.
*/
template <class Executor>
bool holds_io_context_executor(Executor const& executor) noexcept {
    using plain = webcpp::asio_backend::io_context::executor_type;
    using tracked = std::remove_cvref_t<decltype(webcpp::asio::prefer(
        std::declval<plain const&>(), webcpp::asio::execution::outstanding_work_t::tracked))>;
    if constexpr (requires { std::declval<Executor const&>().template target<plain>(); }) {
        return executor.template target<plain>() != nullptr ||
               executor.template target<tracked>() != nullptr ||
               executor.template target<webcpp::asio::strand<plain>>() != nullptr ||
               executor.template target<webcpp::asio::strand<tracked>>() != nullptr;
    } else {
        return false;
    }
}

/**
 Whether WebCrypto's promise can settle where `executor` completes (ruling R73): at compile time
 for a concrete executor (another context refuses with a `static_assert`), at run time for a
 type-erased one.

 @param executor The executor the call was given. @return Whether its context is an io_context.
*/
template <class Executor>
bool webcrypto_executor_accepted(Executor const& executor) noexcept {
    constexpr auto kind = webcrypto_context_of<Executor>;
    // clang-format off
    static_assert(kind != webcrypto_context::other,
                  "webcpp::hash: backends::webcrypto completes through an io_context run on the calling thread, whose run returns to the JavaScript event loop where WebCrypto's promise settles: pass that io_context's executor, not a thread_pool's.");
    // clang-format on
    if constexpr (kind == webcrypto_context::io_context) {
        return true;
    } else {
        return holds_io_context_executor(executor);
    }
}

/**
 The browser's `crypto.subtle`, or `undefined` where the JavaScript runtime has none.

 @return The `SubtleCrypto` object.
*/
inline emscripten::val subtle_crypto() {
    auto const crypto = emscripten::val::global("crypto");
    if (crypto.isUndefined() || crypto.isNull()) {
        return emscripten::val::undefined();
    }
    return crypto["subtle"];
}

/**
 A JavaScript copy of `bytes`, a `Uint8Array` over an `ArrayBuffer` of its own: WebCrypto takes
 no view of the program's memory, which a build with threads shares.

 @param bytes The bytes. @return The copy.
*/
inline emscripten::val webcrypto_bytes(std::span<std::uint8_t const> bytes) {
    return emscripten::val(emscripten::typed_memory_view(bytes.size(), bytes.data()))
        .call<emscripten::val>("slice");
}

/**
 The usages of an imported key: one string, `"sign"` or `"deriveBits"`.

 @param usage The usage. @return A JavaScript array of it.
*/
inline emscripten::val webcrypto_usages(char const* usage) {
    auto usages = emscripten::val::array();
    usages.set(0, emscripten::val(usage));
    return usages;
}

/** `crypto.subtle.digest(hash, input)`: one promise, of the digest. */
struct webcrypto_digest_request {
    /** WebCrypto's name of the hash. */
    char const* hash;
    /** The data. */
    std::span<std::uint8_t const> input;

    /** The call has one promise. */
    static constexpr bool two_promises = false;

    /** The digest's promise. @param subtle `crypto.subtle`. @return The promise. */
    [[nodiscard]] emscripten::val first(emscripten::val const& subtle) const {
        return subtle.call<emscripten::val>("digest", emscripten::val(hash),
                                            webcrypto_bytes(input));
    }

    /** Never called: the call has one promise. @return `undefined`. */
    [[nodiscard]] static emscripten::val second(emscripten::val const& /*subtle*/,
                                                emscripten::val const& /*key*/) {
        return emscripten::val::undefined();
    }
};

/**
 `importKey("raw", key, {name: "HMAC", hash}, false, ["sign"])`, then `sign("HMAC", key, input)`.
 An empty key is imported as one zero byte, which WebCrypto takes where it refuses an empty one:
 HMAC pads a key to the block with zeros (RFC 2104), so both are the same key (ruling R74).
*/
struct webcrypto_hmac_request {
    /** WebCrypto's name of the hash. */
    char const* hash;
    /** The key. */
    std::span<std::uint8_t const> key;
    /** The message. */
    std::span<std::uint8_t const> input;

    /** The call has two promises: the key, then the tag. */
    static constexpr bool two_promises = true;

    /** The key's promise. @param subtle `crypto.subtle`. @return The promise. */
    [[nodiscard]] emscripten::val first(emscripten::val const& subtle) const {
        std::array<std::uint8_t, 1> const zero{};
        auto algorithm = emscripten::val::object();
        algorithm.set("name", emscripten::val("HMAC"));
        algorithm.set("hash", emscripten::val(hash));
        return subtle.call<emscripten::val>(
            "importKey", emscripten::val("raw"),
            webcrypto_bytes(key.empty() ? std::span<std::uint8_t const>(zero) : key), algorithm,
            emscripten::val(false), webcrypto_usages("sign"));
    }

    /**
     The tag's promise. @param subtle `crypto.subtle`. @param imported The key.
     @return The promise.
    */
    [[nodiscard]] emscripten::val second(emscripten::val const& subtle,
                                         emscripten::val const& imported) const {
        return subtle.call<emscripten::val>("sign", emscripten::val("HMAC"), imported,
                                            webcrypto_bytes(input));
    }
};

/**
 `importKey("raw", ikm, "HKDF", false, ["deriveBits"])`, then
 `deriveBits({name: "HKDF", hash, salt, info}, key, bits)`.
*/
struct webcrypto_hkdf_request {
    /** WebCrypto's name of the hash. */
    char const* hash;
    /** The salt. */
    std::span<std::uint8_t const> salt;
    /** The input keying material. */
    std::span<std::uint8_t const> ikm;
    /** The info. */
    std::span<std::uint8_t const> info;
    /** The output's length in bits, within `backend_limits`. */
    std::uint32_t bits;

    /** The call has two promises: the key, then the bits. */
    static constexpr bool two_promises = true;

    /** The key's promise. @param subtle `crypto.subtle`. @return The promise. */
    [[nodiscard]] emscripten::val first(emscripten::val const& subtle) const {
        return subtle.call<emscripten::val>("importKey", emscripten::val("raw"),
                                            webcrypto_bytes(ikm), emscripten::val("HKDF"),
                                            emscripten::val(false), webcrypto_usages("deriveBits"));
    }

    /**
     The bits' promise. @param subtle `crypto.subtle`. @param imported The key.
     @return The promise.
    */
    [[nodiscard]] emscripten::val second(emscripten::val const& subtle,
                                         emscripten::val const& imported) const {
        auto algorithm = emscripten::val::object();
        algorithm.set("name", emscripten::val("HKDF"));
        algorithm.set("hash", emscripten::val(hash));
        algorithm.set("salt", webcrypto_bytes(salt));
        algorithm.set("info", webcrypto_bytes(info));
        return subtle.call<emscripten::val>("deriveBits", algorithm, imported,
                                            emscripten::val(bits));
    }
};

/**
 `importKey("raw", password, "PBKDF2", false, ["deriveBits"])`, then
 `deriveBits({name: "PBKDF2", hash, salt, iterations}, key, bits)`.
*/
struct webcrypto_pbkdf2_request {
    /** WebCrypto's name of the hash. */
    char const* hash;
    /** The password. */
    std::span<std::uint8_t const> password;
    /** The salt. */
    std::span<std::uint8_t const> salt;
    /** The iteration count, within `backend_limits`. */
    std::uint32_t iterations;
    /** The output's length in bits, within `backend_limits`. */
    std::uint32_t bits;

    /** The call has two promises: the key, then the bits. */
    static constexpr bool two_promises = true;

    /** The key's promise. @param subtle `crypto.subtle`. @return The promise. */
    [[nodiscard]] emscripten::val first(emscripten::val const& subtle) const {
        return subtle.call<emscripten::val>("importKey", emscripten::val("raw"),
                                            webcrypto_bytes(password), emscripten::val("PBKDF2"),
                                            emscripten::val(false), webcrypto_usages("deriveBits"));
    }

    /**
     The bits' promise. @param subtle `crypto.subtle`. @param imported The key.
     @return The promise.
    */
    [[nodiscard]] emscripten::val second(emscripten::val const& subtle,
                                         emscripten::val const& imported) const {
        auto algorithm = emscripten::val::object();
        algorithm.set("name", emscripten::val("PBKDF2"));
        algorithm.set("hash", emscripten::val(hash));
        algorithm.set("salt", webcrypto_bytes(salt));
        algorithm.set("iterations", emscripten::val(iterations));
        return subtle.call<emscripten::val>("deriveBits", algorithm, imported,
                                            emscripten::val(bits));
    }
};

/**
 One WebCrypto call as an Asio composed operation (`async_compose`): the request's first promise
 awaited through `browser::async_await`, then, for a call of two, its second with the first's
 result (the imported key); the completion copies the resulting `ArrayBuffer` into `output`.

 Its storage is the bridge's, one wait at a time, taken from the handler's associated allocator
 and given back before the wait's completion is posted, so that nothing of that allocator
 outlives the completion. A `terminal` or `partial` cancellation through the handler's slot
 completes at once with `operation_aborted` (the bridge's wait completes and drops the promise's
 later settlement); `total` is not honoured, since the output is then zeroed.

 @tparam Executor The io_context's executor. @tparam Request The call: one of the
 `webcrypto_*_request` types.
*/
template <class Executor, class Request>
class webcrypto_operation {
public:
    /**
     The operation of `request` into `output`.

     @param executor The io_context's executor. @param output The output.
     @param produced The bytes WebCrypto gives: `output`'s size, or an HMAC's whole tag, which
     `output` takes the first bytes of. @param request The call.
    */
    webcrypto_operation(Executor executor, std::span<std::uint8_t> output, std::size_t produced,
                        Request const& request)
        : executor_(std::move(executor)), output_(output), produced_(produced), request_(request) {}

    /**
     Starts the operation: the first promise.

     @param self The composed operation.
    */
    template <class Self>
    void operator()(Self& self) {
        self.reset_cancellation_state(webcpp::asio::enable_partial_cancellation());
        // A copy: the wait moves `self`, and this operation with it, before it reads the executor.
        auto const executor = executor_;
        webcpp::asio::browser::async_await(executor, request_.first(subtle_crypto()),
                                           std::move(self));
    }

    /**
     A promise has settled, been rejected, or been cancelled: the next promise, or the completion.

     @param self The composed operation. @param code The wait's error.
     @param value The promise's value: the imported key, or the result's `ArrayBuffer`.
    */
    template <class Self>
    void operator()(Self& self, boost::system::error_code code, emscripten::val const& value) {
        if constexpr (Request::two_promises) {
            if (!code && !second_) {
                second_ = true;
                if (self.cancelled() != webcpp::asio::cancellation_type::none) {
                    self.complete(fail(webcpp::asio::error::operation_aborted));
                    return;
                }
                auto const executor = executor_;
                webcpp::asio::browser::async_await(
                    executor, request_.second(subtle_crypto(), value), std::move(self));
                return;
            }
        }
        if (code) {
            self.complete(fail(code == webcpp::asio::error::operation_aborted
                                   ? code
                                   : boost::system::error_code(error::backend_failure)));
            return;
        }
        self.complete(copy(value));
    }

private:
    // The output zeroed, with the completion's error.
    boost::system::error_code fail(boost::system::error_code code) noexcept {
        wipe(output_);
        return code;
    }

    // The result's bytes into the output: an ArrayBuffer of exactly `produced_` bytes, else
    // WebCrypto answered something else, a backend failure.
    boost::system::error_code copy(emscripten::val const& result) {
        if (!result.instanceof(emscripten::val::global("ArrayBuffer")) ||
            result["byteLength"].as<std::size_t>() != produced_) {
            return fail(error::backend_failure);
        }
        auto const bytes = emscripten::val::global("Uint8Array")
                               .new_(result, 0, static_cast<double>(output_.size()));
        emscripten::val(emscripten::typed_memory_view(output_.size(), output_.data()))
            .call<void>("set", bytes);
        return {};
    }

    Executor executor_;
    std::span<std::uint8_t> output_;
    std::size_t produced_;
    Request request_;
    bool second_ = false;
};

/**
 The initiation of a WebCrypto call: the guards' verdict, then the executor's check (ruling R73),
 then `crypto.subtle`'s presence; a refusal is posted to the handler's associated executor
 (`executor` by default) with its error, the output untouched; else the composed operation starts.
*/
struct webcrypto_initiation {
    /**
     Refuses or starts the call.

     @param handler The completion handler. @param executor The io_context's executor.
     @param output The output. @param produced The bytes WebCrypto gives.
     @param request The call. @param guarded The guards' verdict.
    */
    template <class Handler, class Executor, class Request>
    void operator()(Handler&& handler, Executor const& executor, std::span<std::uint8_t> output,
                    std::size_t produced, Request const& request,
                    boost::system::result<void> const& guarded) const {
        boost::system::error_code refusal;
        if (!guarded) {
            refusal = guarded.error();
        } else if (!webcrypto_executor_accepted(executor)) {
            refusal = error::invalid_parameters;
        } else if (subtle_crypto().isUndefined()) {
            refusal = error::backend_failure;
        }
        if (refusal) {
            auto const target = webcpp::asio::get_associated_executor(handler, executor);
            webcpp::asio::post(target,
                               webcpp::asio::append(std::forward<Handler>(handler), refusal));
            return;
        }
        std::decay_t<Handler> owned(std::forward<Handler>(handler));
        webcpp::asio::async_compose<std::decay_t<Handler>, void(boost::system::error_code)>(
            webcrypto_operation<Executor, Request>(executor, output, produced, request), owned,
            executor);
    }
};

/**
 Initiates a WebCrypto call.

 @param executor The io_context's executor. @param output The output.
 @param produced The bytes WebCrypto gives. @param request The call.
 @param guarded The guards' verdict. @param token The completion token.
 @return What the completion token's `async_result` gives.
*/
template <class CompletionToken, class Executor, class Request>
auto start_webcrypto(Executor const& executor, std::span<std::uint8_t> output, std::size_t produced,
                     Request const& request, boost::system::result<void> guarded,
                     CompletionToken& token) {
    return webcpp::asio_backend::async_initiate<CompletionToken, void(boost::system::error_code)>(
        webcrypto_initiation{}, token, executor, output, produced, request, guarded);
}

/**
 The asynchronous family on `backends::webcrypto` (spec 11.1): each function checks the
 synchronous function's guards and WebCrypto's limits, then the executor, then runs WebCrypto's
 call, completing as @ref webcrypto_operation does.
*/
template <>
struct async_engine<backends::webcrypto> {
    /**
     `async_digest`: `crypto.subtle.digest`.

     @tparam Digest `digests::sha1`, `digests::sha2_256`, `digests::sha2_384` or
     `digests::sha2_512`. @param executor The io_context's executor. @param output The digest.
     @param input The data. @param token The completion token.
     @return What the completion token's `async_result` gives.
    */
    template <class Digest, class Executor, class CompletionToken>
    static auto digest(Executor const& executor, std::span<std::uint8_t> output,
                       std::span<std::uint8_t const> input, CompletionToken&& token) {
        using traits = digest_traits<Digest>;
        constexpr std::uint64_t size = traits::max_output(digest_options<Digest>{});
        boost::system::result<void> guarded;
        if (output.size() != size) {
            guarded = error::invalid_output_size;
        }
        webcrypto_digest_request const request{
            .hash = webcrypto_hash_name<Digest>,
            .input = input,
        };
        return start_webcrypto(executor, output, output.size(), request, guarded, token);
    }

    /**
     `async_hmac`: `importKey`, then `sign`; a tag shorter than the digest is its first bytes.

     @tparam Hmac `hmac_sha1_160`, `hmac_sha2_256`, `hmac_sha2_384` or `hmac_sha2_512`.
     @param executor The io_context's executor. @param output The tag. @param key The key.
     @param input The message. @param token The completion token.
     @return What the completion token's `async_result` gives.
    */
    template <class Hmac, class Executor, class CompletionToken>
    static auto hmac(Executor const& executor, std::span<std::uint8_t> output,
                     std::span<std::uint8_t const> key, std::span<std::uint8_t const> input,
                     CompletionToken&& token) {
        using digest = digest_tag_of<Hmac>::type;
        using traits = mac_traits<macs::hmac<digest>>;
        boost::system::result<void> guarded;
        if (exceeds(traits::min_output, output.size()) ||
            exceeds(output.size(), traits::max_output)) {
            guarded = error::invalid_output_size;
        }
        webcrypto_hmac_request const request{
            .hash = webcrypto_hash_name<digest>,
            .key = key,
            .input = input,
        };
        return start_webcrypto(executor, output, static_cast<std::size_t>(traits::max_output),
                               request, guarded, token);
    }

    /**
     `async_hkdf`: `importKey`, then `deriveBits`.

     @tparam Hmac `hmac_sha1_160`, `hmac_sha2_256`, `hmac_sha2_384` or `hmac_sha2_512`.
     @param executor The io_context's executor. @param output The output keying material.
     @param salt The salt. @param ikm The input keying material. @param info The info.
     @param token The completion token.
     @return What the completion token's `async_result` gives.
    */
    template <class Hmac, class Executor, class CompletionToken>
    static auto hkdf(Executor const& executor, std::span<std::uint8_t> output,
                     std::span<std::uint8_t const> salt, std::span<std::uint8_t const> ikm,
                     std::span<std::uint8_t const> info, CompletionToken&& token) {
        using digest = digest_tag_of<Hmac>::type;
        auto const guarded = hkdf_guards<Hmac, backends::webcrypto>(output.size(), salt.size(),
                                                                    ikm.size(), info.size());
        webcrypto_hkdf_request const request{
            .hash = webcrypto_hash_name<digest>,
            .salt = salt,
            .ikm = ikm,
            .info = info,
            .bits = static_cast<std::uint32_t>(guarded ? output.size() * 8 : 0),
        };
        return start_webcrypto(executor, output, output.size(), request, guarded, token);
    }

    /**
     `async_pbkdf2`: `importKey`, then `deriveBits`.

     @tparam Hmac `hmac_sha1_160`, `hmac_sha2_256`, `hmac_sha2_384` or `hmac_sha2_512`; another
     refuses at compile time. @param executor The io_context's executor.
     @param output The derived key. @param password The password. @param salt The salt.
     @param iterations The iteration count. @param token The completion token.
     @return What the completion token's `async_result` gives.
    */
    template <class Hmac, class Executor, class CompletionToken>
    static auto pbkdf2(Executor const& executor, std::span<std::uint8_t> output,
                       std::span<std::uint8_t const> password, std::span<std::uint8_t const> salt,
                       std::uint64_t iterations, CompletionToken&& token) {
        if constexpr (!webcrypto_hmac_v<Hmac>) {
            // clang-format off
            static_assert(always_false<Hmac>,
                          "webcpp::hash: backends::webcrypto has PBKDF2 over hmac_sha1_160, hmac_sha2_256, hmac_sha2_384 and hmac_sha2_512 alone: name a synchronous backend for the others.");
            // clang-format on
        } else {
            using digest = digest_tag_of<Hmac>::type;
            auto const guarded = pbkdf2_guards<Hmac, backends::webcrypto>(
                output.size(), password.size(), salt.size(), iterations);
            // Within backend_limits once the guards pass: 2^32 - 1 iterations, (2^32 - 1) bits.
            webcrypto_pbkdf2_request const request{
                .hash = webcrypto_hash_name<digest>,
                .password = password,
                .salt = salt,
                .iterations = static_cast<std::uint32_t>(guarded ? iterations : 0),
                .bits = static_cast<std::uint32_t>(guarded ? output.size() * 8 : 0),
            };
            return start_webcrypto(executor, output, output.size(), request, guarded, token);
        }
    }
};

}  // namespace webcpp::hash::detail

#endif  // WEBCPP_TARGET_EMSCRIPTEN

#endif  // WEBCPP_HASH_BACKENDS_WEBCRYPTO_HPP
