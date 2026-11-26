// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `backends::webcrypto`: the browser's WebCrypto (`crypto.subtle`, the Web Cryptography API) as a
 backend of the asynchronous family of `<webcpp/hash/async.hpp>`, on Emscripten, where the
 browsers and node have it (tested under node): `async_digest` over SHA-1, SHA-256, SHA-384 and
 SHA-512, and `async_hmac`, `async_hkdf`, `async_hkdf_extract`, `async_hkdf_expand` (each HKDF
 function also over `byte_pieces`) and `async_pbkdf2` over the hmacs of those four. It is never a
 default: a program names it in the type. No synchronous function takes it.

 Each operation builds WebCrypto's call with `emscripten::val` (`digest`; `importKey`, then `sign`
 or `deriveBits`), awaits its promise through webcpp::asio's
 `webcpp::asio::browser::async_await`, and copies the resulting bytes into the output in its
 completion; a rejected promise is `error::backend_failure`, and a cancellation through the
 handler's slot `asio::error::operation_aborted`, both with the output zeroed. The single-buffer
 `async_hkdf` is `deriveBits` (an info of at most 1,024 bytes, node's limit); HKDF's two steps and
 every form over pieces run RFC 5869 on WebCrypto's HMAC, one `sign` per block, the pieces gathered
 into JavaScript memory in the initiating call and every buffer that held a secret zeroed at the
 end. The same guards as the synchronous function run first, then WebCrypto's own limits
 (`detail::backend_limits`), then the executor's check (ruling R73): its context must be an
 `io_context`, checked at compile time for a concrete executor and at run time for a type-erased
 one (`invalid_parameters`). That the `io_context` runs on the calling thread, whose `run` returns
 to the JavaScript event loop where the promise settles, is the program's duty: it cannot be
 checked. A refusal completes through a post to the handler's associated executor (the executor
 given, unless the handler is bound to another), the output untouched; a runtime without WebCrypto
 is `backend_failure`, the output zeroed.

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
 bytes"), where the other backends take `hkdf_max_application_info_size`: a limit of the
 single-buffer `async_hkdf` alone, since HKDF's steps and HKDF over pieces run on WebCrypto's HMAC.
 No limit elsewhere.
*/
template <>
struct backend_limits<backends::webcrypto> {
    /** HKDF's salt: no limit of WebCrypto's own. */
    static constexpr std::uint64_t hkdf_salt = no_limit;
    /** HKDF's input keying material: no limit of WebCrypto's own. */
    static constexpr std::uint64_t hkdf_input_key_material = no_limit;
    /** HKDF's pseudorandom key, Expand's HMAC key: no limit of WebCrypto's own. */
    static constexpr std::uint64_t hkdf_pseudorandom_key = no_limit;
    /**
     HKDF's info in `deriveBits`, which the single-buffer `async_hkdf` calls: node's 1,024 bytes
     (`input_too_long` beyond). `async_hkdf_expand` and the forms over pieces run on HMAC and do
     not read it.
    */
    static constexpr std::uint64_t hkdf_application_info = 1024;
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

#include <webcpp/hash/byte_pieces.hpp>
#include <webcpp/hash/detail/limits.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/hash/pbkdf2.hpp>
#include <webcpp/secure/erase_secret.hpp>
#include <webcpp/secure/timing_guard.hpp>

#include <webcpp/asio/any_io_executor.hpp>
#include <webcpp/asio/append.hpp>
#include <webcpp/asio/associated_executor.hpp>
#include <webcpp/asio/async_result.hpp>
#include <webcpp/asio/browser/async_await.hpp>
#include <webcpp/asio/cancellation_state.hpp>
#include <webcpp/asio/cancellation_type.hpp>
#include <webcpp/asio/compose.hpp>
#include <webcpp/asio/error.hpp>
#include <webcpp/asio/execution/context.hpp>
#include <webcpp/asio/io_context.hpp>
#include <webcpp/asio/post.hpp>
#include <webcpp/asio/query.hpp>
#include <webcpp/asio/strand.hpp>

#include <emscripten/em_asm.h>
#include <emscripten/val.h>

#include <boost/system/error_code.hpp>
#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <memory>
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
 An `io_context`'s executor with the standard allocator and the property bits `Bits` (blocking
 never, relationship continuation, outstanding work tracked: the eight combinations `prefer` and
 `require` give).
*/
template <std::uintptr_t Bits>
using io_context_executor_with =
    webcpp::asio_backend::io_context::basic_executor_type<std::allocator<void>, Bits>;

/**
 Whether the type-erased `completion_executor` holds an `io_context`'s executor of one of the bits
 `Bits...`, or a strand over one.

 @param completion_executor The type-erased executor. @return Whether its target is one.
*/
template <class Executor, std::uintptr_t... Bits>
bool targets_io_context(Executor const& completion_executor,
                        std::integer_sequence<std::uintptr_t, Bits...> /*bit_sequence*/) noexcept {
    return ((completion_executor.template target<io_context_executor_with<Bits>>() != nullptr) ||
            ...) ||
           ((completion_executor
                 .template target<webcpp::asio::strand<io_context_executor_with<Bits>>>() !=
             nullptr) ||
            ...);
}

/**
 Whether `completion_executor` completes on an `io_context` (ruling R73), whatever its form: a
 concrete executor whose context is one (any allocator, any property); a strand, through the
 executor it wraps, recursively; a type-erased executor (`any_io_executor`) that holds an
 `io_context`'s executor with the standard allocator and any property, a strand over one, or a
 type-erased strand, recursively. Anything else is answered false, among it, behind type erasure, an
 `io_context`'s executor rebound to another allocator and a concrete strand of a concrete strand
 of one (`make_strand(make_strand(completion_executor))`), whose types the erasure hides: the
 operation would await a promise on a context it cannot tell runs the JavaScript event loop.

 @param completion_executor The executor. @return Whether it completes on an io_context.
*/
template <class Executor>
bool completes_on_io_context(Executor const& completion_executor) noexcept {
    constexpr auto context_kind = webcrypto_context_of<Executor>;
    if constexpr (context_kind == webcrypto_context::io_context) {
        return true;
    } else if constexpr (context_kind == webcrypto_context::erased &&
                         requires { completion_executor.get_inner_executor(); }) {
        return completes_on_io_context(completion_executor.get_inner_executor());
    } else if constexpr (context_kind == webcrypto_context::erased && requires {
                             completion_executor.template target<webcpp::asio::any_io_executor>();
                         }) {
        // Type-erased strands, unwrapped one after the other, then the executor they wrap.
        using strand = webcpp::asio::strand<webcpp::asio::any_io_executor>;
        auto const* const nested_strand = completion_executor.template target<strand>();
        if (nested_strand == nullptr) {
            return targets_io_context(completion_executor,
                                      std::make_integer_sequence<std::uintptr_t, 8>{});
        }
        webcpp::asio::any_io_executor inner_executor = nested_strand->get_inner_executor();
        for (auto const* deeper_strand = inner_executor.template target<strand>();
             deeper_strand != nullptr; deeper_strand = inner_executor.template target<strand>()) {
            inner_executor = deeper_strand->get_inner_executor();
        }
        return targets_io_context(inner_executor, std::make_integer_sequence<std::uintptr_t, 8>{});
    } else {
        return false;
    }
}

/**
 Whether WebCrypto's promise can settle where `completion_executor` completes (ruling R73): the
 executor's context must be an `io_context`, checked at compile time for a concrete executor
 (another context refuses with a `static_assert`) and at run time for a type-erased one, as @ref
 completes_on_io_context says. That the `io_context` runs on the calling thread, whose JavaScript
 event loop settles the promise, is the program's duty: it cannot be checked.

 @param completion_executor The executor the call was given. @return Whether its context is an
 io_context.
*/
template <class Executor>
bool webcrypto_executor_accepted(Executor const& completion_executor) noexcept {
    // clang-format off
    static_assert(webcrypto_context_of<Executor> != webcrypto_context::other,
                  "webcpp::hash: backends::webcrypto completes through an io_context run on the calling thread, whose run returns to the JavaScript event loop where WebCrypto's promise settles: pass that io_context's executor, not a thread_pool's.");
    // clang-format on
    return completes_on_io_context(completion_executor);
}

/**
 The browser's `crypto.subtle`, or `undefined` where the JavaScript runtime has none.

 @return The `SubtleCrypto` object.
*/
inline emscripten::val subtle_crypto() {
    auto const crypto_object = emscripten::val::global("crypto");
    if (crypto_object.isUndefined() || crypto_object.isNull()) {
        return emscripten::val::undefined();
    }
    return crypto_object["subtle"];
}

/**
 A JavaScript copy of `source_bytes`, a `Uint8Array` over an `ArrayBuffer` of its own: WebCrypto
 takes no view of the program's memory, which a build with threads shares.

 @param source_bytes The bytes. @return The copy.
*/
inline emscripten::val webcrypto_bytes(std::span<std::uint8_t const> source_bytes) {
    return emscripten::val(emscripten::typed_memory_view(source_bytes.size(), source_bytes.data()))
        .call<emscripten::val>("slice");
}

/**
 The usages of an imported key: one string, `"sign"` or `"deriveBits"`.

 @param key_usage The usage. @return A JavaScript array of it.
*/
inline emscripten::val webcrypto_usages(char const* key_usage) {
    auto usage_array = emscripten::val::array();
    usage_array.set(0, emscripten::val(key_usage));
    return usage_array;
}

/** `crypto.subtle.digest(hash, input)`: one promise, of the digest. */
struct webcrypto_digest_request {
    /** WebCrypto's name of the hash. */
    char const* hash;
    /** The data. */
    std::span<std::uint8_t const> input;

    /** The call has one promise. */
    static constexpr bool two_promises = false;

    /** The digest's promise. @param subtle_object `crypto.subtle`. @return The promise. */
    [[nodiscard]] emscripten::val first(emscripten::val const& subtle_object) const {
        return subtle_object.call<emscripten::val>("digest", emscripten::val(hash),
                                                   webcrypto_bytes(input));
    }

    /** Never called: the call has one promise. @return `undefined`. */
    [[nodiscard]] static emscripten::val second(emscripten::val const& /*subtle_object*/,
                                                emscripten::val const& /*key_bytes*/) {
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

    /** The key's promise. @param subtle_object `crypto.subtle`. @return The promise. */
    [[nodiscard]] emscripten::val first(emscripten::val const& subtle_object) const {
        std::array<std::uint8_t, 1> const zero_byte{};
        auto algorithm_object = emscripten::val::object();
        algorithm_object.set("name", emscripten::val("HMAC"));
        algorithm_object.set("hash", emscripten::val(hash));
        return subtle_object.call<emscripten::val>(
            "importKey", emscripten::val("raw"),
            webcrypto_bytes(key.empty() ? std::span<std::uint8_t const>(zero_byte) : key),
            algorithm_object, emscripten::val(false), webcrypto_usages("sign"));
    }

    /**
     The tag's promise. @param subtle_object `crypto.subtle`. @param imported_key The key.
     @return The promise.
    */
    [[nodiscard]] emscripten::val second(emscripten::val const& subtle_object,
                                         emscripten::val const& imported_key) const {
        return subtle_object.call<emscripten::val>("sign", emscripten::val("HMAC"), imported_key,
                                                   webcrypto_bytes(input));
    }
};

/**
 `importKey("raw", the input key material, "HKDF", false, ["deriveBits"])`, then
 `deriveBits({name: "HKDF", hash, salt, info: application_info}, key, bits)`.
*/
struct webcrypto_hkdf_request {
    /** WebCrypto's name of the hash. */
    char const* hash;
    /** The salt. */
    std::span<std::uint8_t const> salt;
    /** The input keying material. */
    std::span<std::uint8_t const> input_key_material;
    /** The application info. */
    std::span<std::uint8_t const> application_info;
    /** The output key material's length in bits, within `backend_limits`. */
    std::uint32_t bits;

    /** The call has two promises: the key, then the bits. */
    static constexpr bool two_promises = true;

    /** The key's promise. @param subtle_object `crypto.subtle`. @return The promise. */
    [[nodiscard]] emscripten::val first(emscripten::val const& subtle_object) const {
        return subtle_object.call<emscripten::val>(
            "importKey", emscripten::val("raw"), webcrypto_bytes(input_key_material),
            emscripten::val("HKDF"), emscripten::val(false), webcrypto_usages("deriveBits"));
    }

    /**
     The bits' promise. @param subtle_object `crypto.subtle`. @param imported_key The key.
     @return The promise.
    */
    [[nodiscard]] emscripten::val second(emscripten::val const& subtle_object,
                                         emscripten::val const& imported_key) const {
        auto algorithm_object = emscripten::val::object();
        algorithm_object.set("name", emscripten::val("HKDF"));
        algorithm_object.set("hash", emscripten::val(hash));
        algorithm_object.set("salt", webcrypto_bytes(salt));
        algorithm_object.set("info", webcrypto_bytes(application_info));
        return subtle_object.call<emscripten::val>("deriveBits", algorithm_object, imported_key,
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

    /** The key's promise. @param subtle_object `crypto.subtle`. @return The promise. */
    [[nodiscard]] emscripten::val first(emscripten::val const& subtle_object) const {
        return subtle_object.call<emscripten::val>(
            "importKey", emscripten::val("raw"), webcrypto_bytes(password),
            emscripten::val("PBKDF2"), emscripten::val(false), webcrypto_usages("deriveBits"));
    }

    /**
     The bits' promise. @param subtle_object `crypto.subtle`. @param imported_key The key.
     @return The promise.
    */
    [[nodiscard]] emscripten::val second(emscripten::val const& subtle_object,
                                         emscripten::val const& imported_key) const {
        auto algorithm_object = emscripten::val::object();
        algorithm_object.set("name", emscripten::val("PBKDF2"));
        algorithm_object.set("hash", emscripten::val(hash));
        algorithm_object.set("salt", webcrypto_bytes(salt));
        algorithm_object.set("iterations", emscripten::val(iterations));
        return subtle_object.call<emscripten::val>("deriveBits", algorithm_object, imported_key,
                                                   emscripten::val(bits));
    }
};

/**
 One WebCrypto call as an Asio composed operation (`async_compose`): the request's first promise
 awaited through `browser::async_await`, then, for a call of two, its second with the first's
 result (the imported key); the completion copies the resulting `ArrayBuffer` into `output_bytes`.

 Its storage is the bridge's, one wait at a time, taken from the handler's associated allocator
 and given back before the wait's completion is posted, so that nothing of that allocator
 outlives the completion; except that `browser::async_await` itself takes one block from the C
 library per promise, webcpp::asio's, outside that allocator. A `terminal` or `partial` cancellation
 through the handler's slot completes at once with `operation_aborted` (the bridge's wait completes
 and drops the promise's later settlement); `total` is not honoured, since the output is then
 zeroed.

 @tparam Executor The io_context's executor. @tparam Request The call: one of the
 `webcrypto_*_request` types.
*/
template <class Executor, class Request>
class webcrypto_operation {
public:
    /**
     The operation of `operation_request` into `output_bytes`.

     @param completion_executor The io_context's executor. @param output_bytes The output.
     @param produced_size The bytes WebCrypto gives: `output_bytes`'s size, or an HMAC's whole tag,
     which `output_bytes` takes the first bytes of. @param operation_request The call.
    */
    webcrypto_operation(Executor completion_executor, std::span<std::uint8_t> output_bytes,
                        std::size_t produced_size, Request const& operation_request)
        : executor_(std::move(completion_executor)),
          output_(output_bytes),
          produced_(produced_size),
          request_(operation_request) {}

    /**
     Starts the operation: the first promise.

     @param operation_self The composed operation.
    */
    template <class Self>
    void operator()(Self& operation_self) {
        operation_self.reset_cancellation_state(webcpp::asio::enable_partial_cancellation());
        // A copy: the wait moves `operation_self`, and this operation with it, before it reads the
        // executor.
        auto const completion_executor = executor_;
        webcpp::asio::browser::async_await(completion_executor, request_.first(subtle_crypto()),
                                           std::move(operation_self));
    }

    /**
     A promise has settled, been rejected, or been cancelled: the next promise, or the completion.

     @param operation_self The composed operation. @param completion_code The wait's error.
     @param promise_value The promise's value: the imported key, or the result's `ArrayBuffer`.
    */
    template <class Self>
    void operator()(Self& operation_self, boost::system::error_code completion_code,
                    emscripten::val const& promise_value) {
        if constexpr (Request::two_promises) {
            if (!completion_code && !second_) {
                second_ = true;
                if (operation_self.cancelled() != webcpp::asio::cancellation_type::none) {
                    operation_self.complete(fail(webcpp::asio::error::operation_aborted));
                    return;
                }
                auto const completion_executor = executor_;
                webcpp::asio::browser::async_await(completion_executor,
                                                   request_.second(subtle_crypto(), promise_value),
                                                   std::move(operation_self));
                return;
            }
        }
        if (completion_code) {
            operation_self.complete(fail(completion_code == webcpp::asio::error::operation_aborted
                                             ? completion_code
                                             : boost::system::error_code(error::backend_failure)));
            return;
        }
        operation_self.complete(copy(promise_value));
    }

private:
    // The output zeroed, with the completion's error.
    boost::system::error_code fail(boost::system::error_code failure_code) noexcept {
        secure::erase_secret(output_);
        return failure_code;
    }

    // The result's bytes into the output: an ArrayBuffer of exactly `produced_` bytes, else
    // WebCrypto answered something else, a backend failure.
    boost::system::error_code copy(emscripten::val const& promise_result) {
        if (!promise_result.instanceof(emscripten::val::global("ArrayBuffer")) ||
            promise_result["byteLength"].as<std::size_t>() != produced_) {
            return fail(error::backend_failure);
        }
        auto const result_bytes = emscripten::val::global("Uint8Array")
                                      .new_(promise_result, 0, static_cast<double>(output_.size()));
        emscripten::val(emscripten::typed_memory_view(output_.size(), output_.data()))
            .call<void>("set", result_bytes);
        return {};
    }

    Executor executor_;
    std::span<std::uint8_t> output_;
    std::size_t produced_;
    Request request_;
    bool second_ = false;
};

/**
 Whether a WebCrypto call is refused before it starts: the guards' verdict, then the executor's
 check (ruling R73), then `crypto.subtle`'s presence. The output is untouched by a guard's refusal
 and the executor's, and zeroed when WebCrypto is missing (`backend_failure`).

 @param completion_executor The io_context's executor. @param output_bytes The output.
 @param guard_result The guards' verdict. @return The refusal's error, or none.
*/
template <class Executor>
boost::system::error_code webcrypto_refusal(Executor const& completion_executor,
                                            std::span<std::uint8_t> output_bytes,
                                            boost::system::result<void> const& guard_result) {
    if (!guard_result) {
        return guard_result.error();
    }
    if (!webcrypto_executor_accepted(completion_executor)) {
        return error::invalid_parameters;
    }
    if (subtle_crypto().isUndefined()) {
        // The backend's failure: the JavaScript runtime has no WebCrypto. The output is zeroed, as
        // every backend's failure leaves it.
        secure::erase_secret(output_bytes);
        return error::backend_failure;
    }
    return {};
}

/**
 Posts a refusal to the handler's associated executor (`completion_executor` by default).

 @param completion_handler The completion handler. @param completion_executor The io_context's
 executor.
 @param refusal_code The refusal's error.
*/
template <class Handler, class Executor>
void post_webcrypto_refusal(Handler&& completion_handler, Executor const& completion_executor,
                            boost::system::error_code refusal_code) {
    auto const target_executor =
        webcpp::asio::get_associated_executor(completion_handler, completion_executor);
    webcpp::asio::post(
        target_executor,
        webcpp::asio::append(std::forward<Handler>(completion_handler), refusal_code));
}

/**
 The initiation of a WebCrypto call: @ref webcrypto_refusal, whose refusal is posted to the
 handler's associated executor (`completion_executor` by default) with its error; else the composed
 operation starts.
*/
struct webcrypto_initiation {
    /**
     Refuses or starts the call.

     @param completion_handler The completion handler. @param completion_executor The io_context's
     executor.
     @param output_bytes The output. @param produced_size The bytes WebCrypto gives.
     @param operation_request The call. @param guard_result The guards' verdict.
    */
    template <class Handler, class Executor, class Request>
    void operator()(Handler&& completion_handler, Executor const& completion_executor,
                    std::span<std::uint8_t> output_bytes, std::size_t produced_size,
                    Request const& operation_request,
                    boost::system::result<void> const& guard_result) const {
        auto const refusal_code =
            webcrypto_refusal(completion_executor, output_bytes, guard_result);
        if (refusal_code) {
            post_webcrypto_refusal(std::forward<Handler>(completion_handler), completion_executor,
                                   refusal_code);
            return;
        }
        std::decay_t<Handler> owned_handler(std::forward<Handler>(completion_handler));
        webcpp::asio::async_compose<std::decay_t<Handler>, void(boost::system::error_code)>(
            webcrypto_operation<Executor, Request>(completion_executor, output_bytes, produced_size,
                                                   operation_request),
            owned_handler, completion_executor);
    }
};

/**
 Initiates a WebCrypto call.

 @param completion_executor The io_context's executor. @param output_bytes The output.
 @param produced_size The bytes WebCrypto gives. @param operation_request The call.
 @param guard_result The guards' verdict. @param completion_token The completion token.
 @return What the completion token's `async_result` gives.
*/
template <class CompletionToken, class Executor, class Request>
auto start_webcrypto(Executor const& completion_executor, std::span<std::uint8_t> output_bytes,
                     std::size_t produced_size, Request const& operation_request,
                     boost::system::result<void> guard_result, CompletionToken& completion_token) {
    return webcpp::asio_backend::async_initiate<CompletionToken, void(boost::system::error_code)>(
        webcrypto_initiation{}, completion_token, completion_executor, output_bytes, produced_size,
        operation_request, guard_result);
}

/**
 A JavaScript `Uint8Array` that holds a secret (an HMAC key, an input keying material, Expand's
 blocks, a tag), zeroed (`fill(0)`) when it is wiped and when it is dropped: after the last call
 that reads it has settled, at the operation's end, on a refusal, and when a deferred operation is
 never launched. It moves and does not copy, so that one holder owns each buffer.
*/
class webcrypto_secret {
public:
    /** No buffer. */
    webcrypto_secret() = default;

    /** The buffer `secret_bytes`. @param secret_bytes A `Uint8Array`. */
    explicit webcrypto_secret(emscripten::val secret_bytes) noexcept
        : bytes_(std::move(secret_bytes)) {}

    /** Takes `moved_secret`'s buffer, `moved_secret` left with none. @param moved_secret The
     * holder. */
    webcrypto_secret(webcrypto_secret&& moved_secret) noexcept
        : bytes_(std::exchange(moved_secret.bytes_, emscripten::val::undefined())) {}

    /**
     Wipes this buffer, then takes `moved_secret`'s. @param moved_secret The holder. @return This
     holder.
    */
    webcrypto_secret& operator=(webcrypto_secret&& moved_secret) noexcept {
        if (this != &moved_secret) {
            wipe();
            bytes_ = std::exchange(moved_secret.bytes_, emscripten::val::undefined());
        }
        return *this;
    }

    webcrypto_secret(webcrypto_secret const&) = delete;
    webcrypto_secret& operator=(webcrypto_secret const&) = delete;

    /** Wipes the buffer. */
    ~webcrypto_secret() { wipe(); }

    /** @return The `Uint8Array`, or `undefined` when there is none. */
    [[nodiscard]] emscripten::val const& bytes() const noexcept { return bytes_; }

    /** @return The `Uint8Array`, or `undefined` when there is none. */
    [[nodiscard]] emscripten::val& bytes() noexcept { return bytes_; }

    /** Zeroes the buffer and lets it go. */
    void wipe() noexcept {
        if (!bytes_.isUndefined()) {
            bytes_.call<void>("fill", 0);
            bytes_ = emscripten::val::undefined();
        }
    }

private:
    emscripten::val bytes_ = emscripten::val::undefined();
};

#ifdef WEBCPP_HASH_DETAIL_TEST_WEBCRYPTO_MAX_GATHERED
// The test seam's value; the Doc Comment is in the #else branch, the one the reference reads.
inline constexpr std::uint64_t webcrypto_max_gathered =
    WEBCPP_HASH_DETAIL_TEST_WEBCRYPTO_MAX_GATHERED;
#else
/**
 The longest buffer the pieces are gathered into, 2^53 - 1 bytes: a typed array's length is a
 JavaScript Number, exact up to there, so that the sum of the pieces' sizes is never rounded. Pieces
 whose total, with Expand's block around the info, is longer fail with `backend_failure`, the output
 zeroed, before any buffer is made. A runtime refuses far shorter buffers, as its memory allows:
 that refusal is caught (@ref webcrypto_new_bytes) and fails likewise. The test seam
 `WEBCPP_HASH_DETAIL_TEST_WEBCRYPTO_MAX_GATHERED` lowers it, so that a test reaches the refusal.
*/
inline constexpr std::uint64_t webcrypto_max_gathered = (std::uint64_t{1} << 53U) - 1;
#endif
// Expand's block is HashLen + |info| + 1 bytes, HashLen at most 64: the bound holds its two ends.
static_assert(webcrypto_max_gathered > 64 + 1,
              "WEBCPP_HASH_DETAIL_TEST_WEBCRYPTO_MAX_GATHERED is more than 65");

/**
 A new JavaScript `Uint8Array` of `byte_length` zero bytes, or `undefined` when the runtime refuses
 it (a `RangeError`, or an out of memory, as its memory allows). The refusal is caught in
 JavaScript, before it can cross a WebAssembly frame, where it would end the program.

 @param byte_length The length, at most @ref webcrypto_max_gathered. @return The array, or
 `undefined`.
*/
inline emscripten::val webcrypto_new_bytes(double byte_length) {
    // EM_ASM supports a definition in an inline function across translation units.
    // clang-format off
    return emscripten::val::take_ownership(reinterpret_cast<emscripten::EM_VAL>(EM_ASM_PTR({
        try {
            return Emval.toHandle(new Uint8Array($0));
        } catch (error) {
            return Emval.toHandle(undefined);
        }
    }, byte_length)));
    // clang-format on
}

/**
 The pieces gathered into one JavaScript `Uint8Array` of its own `ArrayBuffer`, of `prefix_size +
 input_pieces.total_size() + suffix_size` bytes, the pieces one after another from offset
 `prefix_size` (each copied by `set` from a `typed_memory_view` of it), the rest zeros. It runs in
 the initiating call, so that no completion token keeps the list (ruling R4 of the change
 hkdf-pieces), and WebCrypto then reads no view of the program's memory, which a build with threads
 shares.

 @param input_pieces The pieces. @param prefix_size The zeros before them. @param suffix_size The
 zeros after them, the total within @ref webcrypto_max_gathered. @return The buffer, none
 (`undefined`) when the runtime refuses to make it (@ref webcrypto_new_bytes).
*/
inline webcrypto_secret webcrypto_gather(byte_pieces input_pieces, std::size_t prefix_size,
                                         std::size_t suffix_size) {
    webcrypto_secret gathered_secret(webcrypto_new_bytes(
        static_cast<double>(prefix_size + input_pieces.total_size() + suffix_size)));
    if (gathered_secret.bytes().isUndefined()) {
        return gathered_secret;
    }
    auto byte_offset = static_cast<double>(prefix_size);
    for (auto const piece_bytes : input_pieces) {
        if (!piece_bytes.empty()) {
            gathered_secret.bytes().call<void>("set",
                                               emscripten::val(emscripten::typed_memory_view(
                                                   piece_bytes.size(), piece_bytes.data())),
                                               byte_offset);
            byte_offset += static_cast<double>(piece_bytes.size());
        }
    }
    return gathered_secret;
}

/** Which steps of HKDF an operation over WebCrypto's HMAC runs. */
enum class webcrypto_hkdf_steps : std::uint8_t {
    /** HKDF-Extract alone: the pseudorandom key into the output. */
    extract,
    /** HKDF-Expand alone, from the caller's pseudorandom key. */
    expand,
    /** Both, the pseudorandom key kept in JavaScript memory between them. */
    extract_and_expand,
};

/**
 HKDF (RFC 5869) over WebCrypto's HMAC, as its operation needs it: every input already in
 JavaScript memory, gathered in the initiating call.
*/
struct webcrypto_hmac_hkdf_request {
    /** WebCrypto's name of the hash. */
    char const* hash = "";
    /** HashLen, the digest's size. */
    std::size_t digest_length = 0;
    /** The steps it runs. */
    webcrypto_hkdf_steps steps = webcrypto_hkdf_steps::extract;
    /** Extract's HMAC key: the salt, or HashLen zeros for an empty one (design D2). */
    webcrypto_secret salt;
    /** Extract's message: the input keying material's pieces, gathered. */
    webcrypto_secret input_key_material;
    /** Expand's HMAC key: the caller's (Expand alone), else Extract's tag. */
    webcrypto_secret pseudorandom_key;
    /**
     Expand's message buffer, HashLen + |info| + 1 bytes: `T(i-1) || info || i`, the info's pieces
     gathered at offset HashLen.
    */
    webcrypto_secret blocks;
    /**
     Whether every input is in JavaScript memory: false once the pieces are longer than
     @ref webcrypto_max_gathered or the runtime has refused a buffer, after which nothing more is
     gathered and the operation fails with `backend_failure`.
    */
    bool gathered = true;

    /**
     Gathers Extract's inputs: the salt (HashLen zeros for an empty one) and the input keying
     material's pieces.

     @param salt_bytes The salt. @param input_key_material_pieces The input keying material.
    */
    void gather_extract(std::span<std::uint8_t const> salt_bytes,
                        byte_pieces input_key_material_pieces) {
        if (input_key_material_pieces.total_size() > webcrypto_max_gathered) {
            gathered = false;
            return;
        }
        if (salt_bytes.empty()) {
            gather(salt, {}, digest_length, 0);
        } else {
            gather(salt, {salt_bytes}, 0, 0);
        }
        gather(input_key_material, input_key_material_pieces, 0, 0);
    }

    /**
     Gathers Expand's HMAC key, the caller's pseudorandom key (Expand alone).

     @param key_bytes The pseudorandom key.
    */
    void gather_pseudorandom_key(std::span<std::uint8_t const> key_bytes) {
        gather(pseudorandom_key, {key_bytes}, 0, 0);
    }

    /**
     Gathers Expand's message buffer around the application info's pieces; nothing once an earlier
     input was not gathered (Extract's, for `hkdf`), since the operation fails then.

     @param application_info The application info.
    */
    void gather_expand(byte_pieces application_info) {
        if (gathered &&
            application_info.total_size() > webcrypto_max_gathered - digest_length - 1) {
            gathered = false;
            return;
        }
        gather(blocks, application_info, digest_length, 1);
    }

private:
    // `input_pieces` into `target_buffer` (webcrypto_gather) while every earlier input has been
    // gathered.
    void gather(webcrypto_secret& target_buffer, byte_pieces input_pieces, std::size_t prefix_size,
                std::size_t suffix_size) {
        if (gathered) {
            target_buffer = webcrypto_gather(input_pieces, prefix_size, suffix_size);
            gathered = !target_buffer.bytes().isUndefined();
        }
    }
};

/**
 HKDF over WebCrypto's HMAC as an Asio composed operation (`async_compose`), each promise awaited
 through `browser::async_await` as @ref webcrypto_operation does: Extract is `importKey` of the
 salt, then `sign` over the input keying material, its tag the pseudorandom key; Expand is
 `importKey` of the pseudorandom key, then one `sign` per block, over the view `info || 1` of the
 message buffer for the first and over `T(i-1) || info || i` for the others, each `T(i)` copied
 into the output when its promise settles and into the buffer for the next block.

 Its state is `emscripten::val`s and the output's span, nothing of the C++ heap; its storage is the
 bridge's, one wait at a time, from the handler's associated allocator (and `browser::async_await`'s
 one C block per promise). Every JavaScript buffer that held a secret is zeroed once the promise of
 the last call that reads it has settled, and every one at the completion, on success, failure and
 cancellation. A rejected promise or a result of another size is `backend_failure`, a `terminal` or
 `partial` cancellation `operation_aborted` at once, both with the output zeroed (the blocks
 already written among it); a promise that settles after a cancellation writes nothing.

 @tparam Executor The io_context's executor.
*/
template <class Executor>
class webcrypto_hmac_hkdf_operation {
public:
    /**
     The operation of `operation_request` into `output_bytes`.

     @param completion_executor The io_context's executor. @param output_bytes The output: the
     pseudorandom key (Extract alone) or the output keying material. @param operation_request The
     inputs, gathered.
    */
    webcrypto_hmac_hkdf_operation(Executor completion_executor,
                                  std::span<std::uint8_t> output_bytes,
                                  webcrypto_hmac_hkdf_request operation_request)
        : executor_(std::move(completion_executor)),
          output_(output_bytes),
          request_(std::move(operation_request)) {}

    /**
     Starts the operation: the first `importKey`, of the salt, or of the pseudorandom key for
     Expand alone.

     @param operation_self The composed operation.
    */
    template <class Self>
    void operator()(Self& operation_self) {
        operation_self.reset_cancellation_state(webcpp::asio::enable_partial_cancellation());
        if (request_.steps == webcrypto_hkdf_steps::expand) {
            step_ = step::import_pseudorandom_key;
            await(operation_self, import_key(request_.pseudorandom_key.bytes()));
        } else {
            step_ = step::import_salt;
            await(operation_self, import_key(request_.salt.bytes()));
        }
    }

    /**
     A promise has settled, been rejected, or been cancelled: the next call, or the completion.

     @param operation_self The composed operation. @param completion_code The wait's error.
     @param promise_value The promise's value: an imported key, or a tag's `ArrayBuffer`.
    */
    template <class Self>
    void operator()(Self& operation_self, boost::system::error_code completion_code,
                    emscripten::val const& promise_value) {
        if (completion_code) {
            operation_self.complete(fail(completion_code == webcpp::asio::error::operation_aborted
                                             ? completion_code
                                             : boost::system::error_code(error::backend_failure)));
            return;
        }
        switch (step_) {
            case step::import_salt:
                request_.salt.wipe();
                key_ = promise_value;
                if (!stopped(operation_self)) {
                    step_ = step::sign_input_key_material;
                    await(operation_self, sign(request_.input_key_material.bytes()));
                }
                return;
            case step::sign_input_key_material:
                request_.input_key_material.wipe();
                if (!is_tag(promise_value)) {
                    operation_self.complete(fail(error::backend_failure));
                    return;
                }
                if (request_.steps == webcrypto_hkdf_steps::extract) {
                    webcrypto_secret tag_secret(uint8_array(promise_value));
                    copy(tag_secret.bytes(), 0, output_.size());
                    tag_secret.wipe();
                    operation_self.complete(finish());
                    return;
                }
                request_.pseudorandom_key = webcrypto_secret(uint8_array(promise_value));
                if (!stopped(operation_self)) {
                    step_ = step::import_pseudorandom_key;
                    await(operation_self, import_key(request_.pseudorandom_key.bytes()));
                }
                return;
            case step::import_pseudorandom_key:
                request_.pseudorandom_key.wipe();
                key_ = promise_value;
                if (!stopped(operation_self)) {
                    block_ = 1;
                    request_.blocks.bytes().set(counter_index(), block_);
                    step_ = step::sign_block;
                    await(operation_self,
                          sign(request_.blocks.bytes().call<emscripten::val>(
                              "subarray", static_cast<double>(request_.digest_length))));
                }
                return;
            case step::sign_block: next_block(operation_self, promise_value); return;
        }
    }

private:
    // The step whose promise the operation awaits.
    enum class step : std::uint8_t {
        import_salt,
        sign_input_key_material,
        import_pseudorandom_key,
        sign_block,
    };

    // T(block_) has settled: into the output, then the next block's sign, or the completion.
    template <class Self>
    void next_block(Self& operation_self, emscripten::val const& promise_value) {
        if (!is_tag(promise_value)) {
            operation_self.complete(fail(error::backend_failure));
            return;
        }
        webcrypto_secret tag_secret(uint8_array(promise_value));
        std::size_t const block_size = std::min(request_.digest_length, output_.size() - written_);
        copy(tag_secret.bytes(), written_, block_size);
        written_ += block_size;
        if (written_ == output_.size()) {
            tag_secret.wipe();
            operation_self.complete(finish());
            return;
        }
        request_.blocks.bytes().call<void>("set", tag_secret.bytes(), 0);
        tag_secret.wipe();
        if (!stopped(operation_self)) {
            ++block_;
            request_.blocks.bytes().set(counter_index(), block_);
            await(operation_self, sign(request_.blocks.bytes()));
        }
    }

    // Whether a cancellation has come since the last wait: then the completion, operation_aborted.
    template <class Self>
    bool stopped(Self& operation_self) {
        if (operation_self.cancelled() == webcpp::asio::cancellation_type::none) {
            return false;
        }
        operation_self.complete(fail(webcpp::asio::error::operation_aborted));
        return true;
    }

    // Awaits `pending_promise`, the operation moved into the wait.
    template <class Self>
    void await(Self& operation_self, emscripten::val pending_promise) {
        // A copy: the wait moves `operation_self`, and this operation with it, before it reads the
        // executor.
        auto const completion_executor = executor_;
        webcpp::asio::browser::async_await(completion_executor, std::move(pending_promise),
                                           std::move(operation_self));
    }

    // importKey("raw", bytes, {name: "HMAC", hash}, false, ["sign"]).
    [[nodiscard]] emscripten::val import_key(emscripten::val const& key_bytes) const {
        auto algorithm_object = emscripten::val::object();
        algorithm_object.set("name", emscripten::val("HMAC"));
        algorithm_object.set("hash", emscripten::val(request_.hash));
        return subtle_crypto().call<emscripten::val>("importKey", emscripten::val("raw"), key_bytes,
                                                     algorithm_object, emscripten::val(false),
                                                     webcrypto_usages("sign"));
    }

    // sign("HMAC", key_, data).
    [[nodiscard]] emscripten::val sign(emscripten::val const& message_data) const {
        return subtle_crypto().call<emscripten::val>("sign", emscripten::val("HMAC"), key_,
                                                     message_data);
    }

    // Whether `promise_value` is a tag: an ArrayBuffer of HashLen bytes.
    [[nodiscard]] bool is_tag(emscripten::val const& promise_value) const {
        return promise_value.instanceof(emscripten::val::global("ArrayBuffer")) &&
               promise_value["byteLength"].as<std::size_t>() == request_.digest_length;
    }

    // A Uint8Array over the ArrayBuffer `array_buffer`.
    [[nodiscard]] static emscripten::val uint8_array(emscripten::val const& array_buffer) {
        return emscripten::val::global("Uint8Array").new_(array_buffer);
    }

    // The index of the block counter in the message buffer, its last byte.
    [[nodiscard]] double counter_index() const {
        return request_.blocks.bytes()["length"].as<double>() - 1;
    }

    // The first `byte_count` bytes of `tag_value` into the output at `byte_offset`.
    void copy(emscripten::val const& tag_value, std::size_t byte_offset, std::size_t byte_count) {
        emscripten::val(emscripten::typed_memory_view(
                            byte_count, output_.subspan(byte_offset, byte_count).data()))
            .call<void>("set", tag_value.call<emscripten::val>("subarray", 0,
                                                               static_cast<double>(byte_count)));
    }

    // Every JavaScript buffer zeroed and the key let go.
    void release() noexcept {
        request_.salt.wipe();
        request_.input_key_material.wipe();
        request_.pseudorandom_key.wipe();
        request_.blocks.wipe();
        key_ = emscripten::val::undefined();
    }

    // The buffers released: the completion's success.
    [[nodiscard]] boost::system::error_code finish() noexcept {
        release();
        return {};
    }

    // The output zeroed and the buffers released, with the completion's error.
    [[nodiscard]] boost::system::error_code fail(boost::system::error_code failure_code) noexcept {
        secure::erase_secret(output_);
        release();
        return failure_code;
    }

    Executor executor_;
    std::span<std::uint8_t> output_;
    webcrypto_hmac_hkdf_request request_;
    emscripten::val key_ = emscripten::val::undefined();
    step step_ = step::import_salt;
    std::uint8_t block_ = 0;
    std::size_t written_ = 0;
};

/**
 The initiation of HKDF over WebCrypto's HMAC: @ref webcrypto_refusal, then whether every input was
 gathered (`backend_failure`, the output zeroed, else); a refusal is posted to the handler's
 associated executor, the request's buffers zeroed as it is dropped; else the composed operation
 starts.
*/
struct webcrypto_hmac_hkdf_initiation {
    /**
     Refuses or starts the operation.

     @param completion_handler The completion handler. @param completion_executor The io_context's
     executor.
     @param output_bytes The output. @param operation_request The inputs, gathered.
     @param guard_result The guards' verdict.
    */
    template <class Handler, class Executor>
    void operator()(Handler&& completion_handler, Executor const& completion_executor,
                    std::span<std::uint8_t> output_bytes,
                    webcrypto_hmac_hkdf_request operation_request,
                    boost::system::result<void> const& guard_result) const {
        auto refusal_code = webcrypto_refusal(completion_executor, output_bytes, guard_result);
        if (!refusal_code && !operation_request.gathered) {
            secure::erase_secret(output_bytes);
            refusal_code = error::backend_failure;
        }
        if (refusal_code) {
            post_webcrypto_refusal(std::forward<Handler>(completion_handler), completion_executor,
                                   refusal_code);
            return;
        }
        std::decay_t<Handler> owned_handler(std::forward<Handler>(completion_handler));
        webcpp::asio::async_compose<std::decay_t<Handler>, void(boost::system::error_code)>(
            webcrypto_hmac_hkdf_operation<Executor>(completion_executor, output_bytes,
                                                    std::move(operation_request)),
            owned_handler, completion_executor);
    }
};

/**
 The request over `Hmac`'s hash running `hkdf_steps`, with no buffer yet.

 @tparam Hmac `hmac_sha1_160`, `hmac_sha2_256`, `hmac_sha2_384` or `hmac_sha2_512`.
 @param hkdf_steps The steps. @return The request.
*/
template <class Hmac>
webcrypto_hmac_hkdf_request webcrypto_hmac_hkdf_of(webcrypto_hkdf_steps hkdf_steps) {
    // Hash2 1.92 declares no std::tuple_size for digest<N>; its size() is constexpr.
    constexpr std::size_t digest_length = typename Hmac::result_type().size();
    webcrypto_hmac_hkdf_request operation_request;
    operation_request.hash = webcrypto_hash_name<typename digest_tag_of<Hmac>::type>;
    operation_request.digest_length = digest_length;
    operation_request.steps = hkdf_steps;
    return operation_request;
}

/**
 Initiates HKDF over WebCrypto's HMAC.

 @param completion_executor The io_context's executor. @param output_bytes The output.
 @param operation_request The inputs, gathered. @param guard_result The guards' verdict.
 @param completion_token The completion token.
 @return What the completion token's `async_result` gives.
*/
template <class CompletionToken, class Executor>
auto start_webcrypto_hmac_hkdf(Executor const& completion_executor,
                               std::span<std::uint8_t> output_bytes,
                               webcrypto_hmac_hkdf_request operation_request,
                               boost::system::result<void> guard_result,
                               CompletionToken& completion_token) {
    return webcpp::asio_backend::async_initiate<CompletionToken, void(boost::system::error_code)>(
        webcrypto_hmac_hkdf_initiation{}, completion_token, completion_executor, output_bytes,
        std::move(operation_request), guard_result);
}

/**
 The asynchronous family on `backends::webcrypto` (spec 11.1): each function checks the
 synchronous function's guards and WebCrypto's limits, then the executor, then runs WebCrypto's
 call, completing as @ref webcrypto_operation does.
*/
template <>
struct async_engine<backends::webcrypto> {
private:
    // HKDF-Extract's output, the pseudorandom key: exactly the digest size, as
    // hkdf_extract_into requires of a synchronous backend's (invalid_output_size).
    template <class Hmac>
    [[nodiscard]] static boost::system::result<void> extract_size_guard(
        std::size_t key_size) noexcept {
        // Hash2 1.92 declares no std::tuple_size for digest<N>; its size() is constexpr.
        constexpr std::size_t digest_length = typename Hmac::result_type().size();
        if (key_size != digest_length) {
            return error::invalid_output_size;
        }
        return {};
    }

    // HKDF-Expand's guards, the synchronous hkdf_expand's order: RFC 5869's output size, then the
    // pseudorandom key's size (invalid_key_size).
    template <class Hmac>
    [[nodiscard]] static boost::system::result<void> expand_guards(
        std::size_t output_size, std::size_t pseudorandom_key_size) noexcept {
        // Hash2 1.92 declares no std::tuple_size for digest<N>; its size() is constexpr.
        constexpr std::size_t digest_length = typename Hmac::result_type().size();
        auto guard_result = hkdf_pieces_guards<Hmac, backends::webcrypto>(output_size, 0);
        if (guard_result && pseudorandom_key_size != digest_length) {
            return error::invalid_key_size;
        }
        return guard_result;
    }

public:
    /**
     `async_digest`: `crypto.subtle.digest`.

     @tparam Digest `digests::sha1`, `digests::sha2_256`, `digests::sha2_384` or
     `digests::sha2_512`. @param completion_executor The io_context's executor. @param output_bytes
     The digest.
     @param input_bytes The data. @param completion_token The completion token.
     @return What the completion token's `async_result` gives.
    */
    template <class Digest, class Executor, class CompletionToken>
    static auto digest(Executor const& completion_executor, std::span<std::uint8_t> output_bytes,
                       std::span<std::uint8_t const> input_bytes,
                       CompletionToken&& completion_token) {
        auto const guard_result =
            digest_guards<Digest>(output_bytes.size(), digest_options<Digest>{});
        webcrypto_digest_request const operation_request{
            .hash = webcrypto_hash_name<Digest>,
            .input = input_bytes,
        };
        return start_webcrypto(completion_executor, output_bytes, output_bytes.size(),
                               operation_request, guard_result, completion_token);
    }

    /**
     `async_hmac`: `importKey`, then `sign`; a tag shorter than the digest is its first bytes.

     @tparam Hmac `hmac_sha1_160`, `hmac_sha2_256`, `hmac_sha2_384` or `hmac_sha2_512`.
     @param completion_executor The io_context's executor. @param output_bytes The tag.
     @param key_bytes The key.
     @param input_bytes The message. @param completion_token The completion token.
     @return What the completion token's `async_result` gives.
    */
    template <class Hmac, class Executor, class CompletionToken>
    static auto hmac(Executor const& completion_executor, std::span<std::uint8_t> output_bytes,
                     std::span<std::uint8_t const> key_bytes,
                     std::span<std::uint8_t const> input_bytes,
                     CompletionToken&& completion_token) {
        using digest = digest_tag_of<Hmac>::type;
        using tag = macs::hmac<digest>;
        auto const guard_result =
            mac_guards<tag>(output_bytes.size(), key_bytes.size(), mac_options<tag>{});
        webcrypto_hmac_request const operation_request{
            .hash = webcrypto_hash_name<digest>,
            .key = key_bytes,
            .input = input_bytes,
        };
        return start_webcrypto(completion_executor, output_bytes,
                               static_cast<std::size_t>(mac_traits<tag>::max_output),
                               operation_request, guard_result, completion_token);
    }

    /**
     `async_hkdf`: `importKey`, then `deriveBits`.

     @tparam Hmac `hmac_sha1_160`, `hmac_sha2_256`, `hmac_sha2_384` or `hmac_sha2_512`.
     @param completion_executor The io_context's executor. @param output_key_material The output
     keying material.
     @param salt_bytes The salt. @param input_key_material The input keying material.
     @param application_info The application info.
     @param completion_token The completion token.
     @return What the completion token's `async_result` gives.
    */
    template <class Hmac, class Executor, class CompletionToken>
    static auto hkdf(Executor const& completion_executor,
                     std::span<std::uint8_t> output_key_material,
                     std::span<std::uint8_t const> salt_bytes,
                     std::span<std::uint8_t const> input_key_material,
                     std::span<std::uint8_t const> application_info,
                     CompletionToken&& completion_token) {
        using digest = digest_tag_of<Hmac>::type;
        auto const guard_result = hkdf_guards<Hmac, backends::webcrypto>(
            output_key_material.size(), salt_bytes.size(), input_key_material.size(),
            application_info.size());
        webcrypto_hkdf_request const operation_request{
            .hash = webcrypto_hash_name<digest>,
            .salt = salt_bytes,
            .input_key_material = input_key_material,
            .application_info = application_info,
            .bits = static_cast<std::uint32_t>(guard_result ? output_key_material.size() * 8 : 0),
        };
        return start_webcrypto(completion_executor, output_key_material, output_key_material.size(),
                               operation_request, guard_result, completion_token);
    }

    /**
     `async_hkdf` over pieces: HKDF over WebCrypto's HMAC (`importKey`, then `sign`), as
     @ref webcrypto_hmac_hkdf_operation runs it, the pieces gathered into JavaScript memory in
     the call. No cap on the application info: WebCrypto's 1,024 bytes are `deriveBits`'.

     @tparam Hmac `hmac_sha1_160`, `hmac_sha2_256`, `hmac_sha2_384` or `hmac_sha2_512`.
     @param completion_executor The io_context's executor. @param output_key_material The output
     keying material. @param salt_bytes The salt. @param input_key_material The input keying
     material's pieces. @param application_info The application info's pieces.
     @param completion_token The completion token.
     @return What the completion token's `async_result` gives.
    */
    template <class Hmac, class Executor, class CompletionToken>
    static auto hkdf(Executor const& completion_executor,
                     std::span<std::uint8_t> output_key_material,
                     std::span<std::uint8_t const> salt_bytes, byte_pieces input_key_material,
                     byte_pieces application_info, CompletionToken&& completion_token) {
        secure::timing_guard const timing_scope;
        auto const guard_result = hkdf_pieces_guards<Hmac, backends::webcrypto>(
            output_key_material.size(), salt_bytes.size());
        auto operation_request =
            webcrypto_hmac_hkdf_of<Hmac>(webcrypto_hkdf_steps::extract_and_expand);
        if (guard_result) {
            operation_request.gather_extract(salt_bytes, input_key_material);
            // Nothing when Extract's inputs were not gathered: the operation fails then.
            operation_request.gather_expand(application_info);
        }
        return start_webcrypto_hmac_hkdf(completion_executor, output_key_material,
                                         std::move(operation_request), guard_result,
                                         completion_token);
    }

    /**
     `async_hkdf_extract`, single-buffer: HKDF-Extract over WebCrypto's HMAC (`importKey` of the
     salt, then `sign`), the input keying material its one piece.

     @tparam Hmac `hmac_sha1_160`, `hmac_sha2_256`, `hmac_sha2_384` or `hmac_sha2_512`.
     @param completion_executor The io_context's executor. @param pseudorandom_key The pseudorandom
     key, of exactly the digest size. @param salt_bytes The salt. @param input_key_material The
     input keying material. @param completion_token The completion token.
     @return What the completion token's `async_result` gives.
    */
    template <class Hmac, class Executor, class CompletionToken>
    static auto hkdf_extract(Executor const& completion_executor,
                             std::span<std::uint8_t> pseudorandom_key,
                             std::span<std::uint8_t const> salt_bytes,
                             std::span<std::uint8_t const> input_key_material,
                             CompletionToken&& completion_token) {
        secure::timing_guard const timing_scope;
        auto guard_result = extract_size_guard<Hmac>(pseudorandom_key.size());
        if (guard_result) {
            guard_result = hkdf_extract_guards<backends::webcrypto>(salt_bytes.size(),
                                                                    input_key_material.size());
        }
        auto operation_request = webcrypto_hmac_hkdf_of<Hmac>(webcrypto_hkdf_steps::extract);
        if (guard_result) {
            operation_request.gather_extract(salt_bytes, {input_key_material});
        }
        return start_webcrypto_hmac_hkdf(completion_executor, pseudorandom_key,
                                         std::move(operation_request), guard_result,
                                         completion_token);
    }

    /**
     `async_hkdf_extract` over pieces: HKDF-Extract over WebCrypto's HMAC, the pieces gathered
     into JavaScript memory in the call.

     @tparam Hmac `hmac_sha1_160`, `hmac_sha2_256`, `hmac_sha2_384` or `hmac_sha2_512`.
     @param completion_executor The io_context's executor. @param pseudorandom_key The pseudorandom
     key, of exactly the digest size. @param salt_bytes The salt. @param input_key_material The
     input keying material's pieces. @param completion_token The completion token.
     @return What the completion token's `async_result` gives.
    */
    template <class Hmac, class Executor, class CompletionToken>
    static auto hkdf_extract(Executor const& completion_executor,
                             std::span<std::uint8_t> pseudorandom_key,
                             std::span<std::uint8_t const> salt_bytes,
                             byte_pieces input_key_material, CompletionToken&& completion_token) {
        secure::timing_guard const timing_scope;
        auto guard_result = extract_size_guard<Hmac>(pseudorandom_key.size());
        if (guard_result) {
            guard_result = hkdf_pieces_salt_guard<backends::webcrypto>(salt_bytes.size());
        }
        auto operation_request = webcrypto_hmac_hkdf_of<Hmac>(webcrypto_hkdf_steps::extract);
        if (guard_result) {
            operation_request.gather_extract(salt_bytes, input_key_material);
        }
        return start_webcrypto_hmac_hkdf(completion_executor, pseudorandom_key,
                                         std::move(operation_request), guard_result,
                                         completion_token);
    }

    /**
     `async_hkdf_expand`, single-buffer: HKDF-Expand over WebCrypto's HMAC (`importKey` of the
     pseudorandom key, then one `sign` per block), the application info its one piece. It keeps
     the single-buffer forms' `hkdf_max_application_info_size` (ruling R3 of the change
     hkdf-pieces), not the 1,024 bytes of `deriveBits`, which only `async_hkdf` calls.

     @tparam Hmac `hmac_sha1_160`, `hmac_sha2_256`, `hmac_sha2_384` or `hmac_sha2_512`.
     @param completion_executor The io_context's executor. @param output_key_material The output
     keying material. @param pseudorandom_key The pseudorandom key. @param application_info The
     application info. @param completion_token The completion token.
     @return What the completion token's `async_result` gives.
    */
    template <class Hmac, class Executor, class CompletionToken>
    static auto hkdf_expand(Executor const& completion_executor,
                            std::span<std::uint8_t> output_key_material,
                            std::span<std::uint8_t const> pseudorandom_key,
                            std::span<std::uint8_t const> application_info,
                            CompletionToken&& completion_token) {
        secure::timing_guard const timing_scope;
        auto guard_result =
            expand_guards<Hmac>(output_key_material.size(), pseudorandom_key.size());
        if (guard_result && application_info.size() > hkdf_max_application_info_size) {
            guard_result = error::input_too_long;
        }
        auto operation_request = webcrypto_hmac_hkdf_of<Hmac>(webcrypto_hkdf_steps::expand);
        if (guard_result) {
            operation_request.gather_pseudorandom_key(pseudorandom_key);
            operation_request.gather_expand({application_info});
        }
        return start_webcrypto_hmac_hkdf(completion_executor, output_key_material,
                                         std::move(operation_request), guard_result,
                                         completion_token);
    }

    /**
     `async_hkdf_expand` over pieces: HKDF-Expand over WebCrypto's HMAC, the pseudorandom key and
     the pieces gathered into JavaScript memory in the call; no cap on the application info.

     @tparam Hmac `hmac_sha1_160`, `hmac_sha2_256`, `hmac_sha2_384` or `hmac_sha2_512`.
     @param completion_executor The io_context's executor. @param output_key_material The output
     keying material. @param pseudorandom_key The pseudorandom key. @param application_info The
     application info's pieces. @param completion_token The completion token.
     @return What the completion token's `async_result` gives.
    */
    template <class Hmac, class Executor, class CompletionToken>
    static auto hkdf_expand(Executor const& completion_executor,
                            std::span<std::uint8_t> output_key_material,
                            std::span<std::uint8_t const> pseudorandom_key,
                            byte_pieces application_info, CompletionToken&& completion_token) {
        secure::timing_guard const timing_scope;
        auto const guard_result =
            expand_guards<Hmac>(output_key_material.size(), pseudorandom_key.size());
        auto operation_request = webcrypto_hmac_hkdf_of<Hmac>(webcrypto_hkdf_steps::expand);
        if (guard_result) {
            operation_request.gather_pseudorandom_key(pseudorandom_key);
            operation_request.gather_expand(application_info);
        }
        return start_webcrypto_hmac_hkdf(completion_executor, output_key_material,
                                         std::move(operation_request), guard_result,
                                         completion_token);
    }

    /**
     `async_pbkdf2`: `importKey`, then `deriveBits`.

     @tparam Hmac `hmac_sha1_160`, `hmac_sha2_256`, `hmac_sha2_384` or `hmac_sha2_512`; another
     refuses at compile time. @param work_executor The io_context's executor.
     @param output_bytes The derived key. @param password_bytes The password. @param salt_bytes The
     salt.
     @param iteration_count The iteration count. @param completion_token The completion token.
     @return What the completion token's `async_result` gives.
    */
    template <class Hmac, class Executor, class CompletionToken>
    static auto pbkdf2(Executor const& work_executor, std::span<std::uint8_t> output_bytes,
                       std::span<std::uint8_t const> password_bytes,
                       std::span<std::uint8_t const> salt_bytes, std::uint64_t iteration_count,
                       CompletionToken&& completion_token) {
        if constexpr (!webcrypto_hmac_v<Hmac>) {
            // clang-format off
            static_assert(always_false<Hmac>,
                          "webcpp::hash: backends::webcrypto has PBKDF2 over hmac_sha1_160, hmac_sha2_256, hmac_sha2_384 and hmac_sha2_512 alone: name a synchronous backend for the others.");
            // clang-format on
        } else {
            using digest = digest_tag_of<Hmac>::type;
            auto const guard_result = pbkdf2_guards<Hmac, backends::webcrypto>(
                output_bytes.size(), password_bytes.size(), salt_bytes.size(), iteration_count);
            // Within backend_limits once the guards pass: 2^32 - 1 iterations, (2^32 - 1) bits.
            webcrypto_pbkdf2_request const operation_request{
                .hash = webcrypto_hash_name<digest>,
                .password = password_bytes,
                .salt = salt_bytes,
                .iterations = static_cast<std::uint32_t>(guard_result ? iteration_count : 0),
                .bits = static_cast<std::uint32_t>(guard_result ? output_bytes.size() * 8 : 0),
            };
            return start_webcrypto(work_executor, output_bytes, output_bytes.size(),
                                   operation_request, guard_result, completion_token);
        }
    }
};

}  // namespace webcpp::hash::detail

#endif  // WEBCPP_TARGET_EMSCRIPTEN

#endif  // WEBCPP_HASH_BACKENDS_WEBCRYPTO_HPP
