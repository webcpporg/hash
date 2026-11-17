// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The asynchronous family (spec 11): each function an Asio asynchronous operation in webcpp::asio's
 model, initiated through `async_initiate` and completing with `void(boost::system::error_code)`,
 so that one call works with a callback, `use_awaitable`, Cobalt's `use_op`, `use_future` and
 every other completion token.

 - The cheap functions, `async_digest`, `async_hmac` and `async_hkdf`, exist on every target for
   the algorithms the browser's WebCrypto has (SHA-1, SHA-256, SHA-384, SHA-512, and HMAC and HKDF
   over them). On a synchronous backend, their default, they run it at once and complete through a
   post on the handler's associated executor, never inside the initiating call.
 - The heavy functions, `async_argon2id`, `async_argon2`, `async_scrypt` and `async_pbkdf2` on a
   synchronous backend, run on another thread: they check their guards, post the work to the
   executor the caller gives (a `webcpp::asio::thread_pool`'s), and complete on the handler's
   associated executor. They exist only where the build has threads (`WEBCPP_HASH_HAS_THREADS`);
   elsewhere each name refuses at compile time.

 The default backend of each is the synchronous function's, @ref webcpp::hash::default_backend,
 and `backends::webcrypto` is used only when the type names it, on Emscripten.

 The header needs webcpp::asio, `<library>/webcpp/asio//asio` in the program's Jamfile, which
 `<webcpp/hash.hpp>` does not bring: include it by itself.

 @code
 // An event loop's program derives a key without blocking it: the work runs on a pool's thread.
 webcpp::asio::thread_pool pool(1);
 webcpp::hash::async_argon2id(pool.get_executor(), key, password, salt,
                              webcpp::hash::argon2id_interactive,
                              webcpp::asio::bind_executor(loop.get_executor(),
                                                          [](boost::system::error_code code) {
                                                              // runs on loop's thread
                                                          }));
 @endcode

 @see "Asynchronous calls", in the guide.
*/
#ifndef WEBCPP_HASH_ASYNC_HPP
#define WEBCPP_HASH_ASYNC_HPP

#include <webcpp/hash/config.hpp>

#include <webcpp/hash/argon2.hpp>
#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/detail/wipe.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/hash/pbkdf2.hpp>
#include <webcpp/hash/scrypt.hpp>

#include <webcpp/asio/append.hpp>
#include <webcpp/asio/associated_allocator.hpp>
#include <webcpp/asio/associated_cancellation_slot.hpp>
#include <webcpp/asio/associated_executor.hpp>
#include <webcpp/asio/async_result.hpp>
#include <webcpp/asio/bind_allocator.hpp>
#include <webcpp/asio/cancellation_type.hpp>
#include <webcpp/asio/dispatch.hpp>
#include <webcpp/asio/error.hpp>
#include <webcpp/asio/executor_work_guard.hpp>
#include <webcpp/asio/post.hpp>

#include <boost/system/error_code.hpp>
#include <boost/system/result.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>
#include <utility>

namespace webcpp::hash {

/**
 The backend of the asynchronous family when a call names none: the synchronous function's,
 @ref default_backend, on every target (design D35). `backends::webcrypto` is never a default: a
 program on Emscripten names it in the type to reach the browser's WebCrypto.

 @tparam Algorithm A tag of `digests`, `macs` or `kdfs`. @tparam Hmac The hmac of a key derivation
 that takes one, else `void`; it does not change the answer.
*/
template <class Algorithm, class Hmac = void>
using default_async_backend = default_backend<Algorithm, Hmac>;

namespace detail {

/** Whether WebCrypto has the digest `Digest`: SHA-1, SHA-256, SHA-384 and SHA-512 (spec 11.2). */
template <class Digest>
inline constexpr bool webcrypto_digest_v =
    std::is_same_v<Digest, digests::sha1> || std::is_same_v<Digest, digests::sha2_256> ||
    std::is_same_v<Digest, digests::sha2_384> || std::is_same_v<Digest, digests::sha2_512>;

/** Whether WebCrypto has the HMAC of the Boost.Hash2 hmac `Hmac`, and HKDF over it. */
template <class Hmac>
inline constexpr bool webcrypto_hmac_v = webcrypto_digest_v<typename digest_tag_of<Hmac>::type>;

/** The tag of `macs` that names the HMAC of the Boost.Hash2 hmac `Hmac`. */
template <class Hmac>
using hmac_tag_of = macs::hmac<typename digest_tag_of<Hmac>::type>;

/** Whether `Backend` completes by itself, asynchronously: `backends::webcrypto` alone. */
template <class Backend>
inline constexpr bool asynchronous_backend_v = std::is_same_v<Backend, backends::webcrypto>;

#ifdef WEBCPP_TARGET_EMSCRIPTEN
/**
 The operations of a backend that completes by itself (spec 11.1): `backends::webcrypto`, whose
 header specialises it on Emscripten with the static member functions `digest<Digest>`,
 `hmac<Hmac>`, `hkdf<Hmac>` and `pbkdf2<Hmac>`, each taking the asynchronous function's arguments
 and returning its result.

 @tparam Backend `backends::webcrypto`.
*/
template <class Backend>
struct async_engine;
#else
/**
 The operations of a backend that completes by itself: `backends::webcrypto`, which exists only on
 Emscripten, so that this template refuses it elsewhere. Its members exist so that the refusal is
 the only error of the call.

 @tparam Backend `backends::webcrypto`.
*/
template <class Backend>
struct async_engine {
    static_assert(always_false<Backend>,
                  "webcpp::hash: backends::webcrypto exists only on Emscripten: name a synchronous "
                  "backend, or leave the default.");

    /** Never called: the refusal has stopped the build. */
    template <class Algorithm, class... Arguments>
    static void digest(Arguments&&... /*arguments*/) noexcept {}

    /** Never called: the refusal has stopped the build. */
    template <class Algorithm, class... Arguments>
    static void hmac(Arguments&&... /*arguments*/) noexcept {}

    /** Never called: the refusal has stopped the build. */
    template <class Algorithm, class... Arguments>
    static void hkdf(Arguments&&... /*arguments*/) noexcept {}

    /** Never called: the refusal has stopped the build. */
    template <class Algorithm, class... Arguments>
    static void pbkdf2(Arguments&&... /*arguments*/) noexcept {}
};
#endif

/**
 The error code of a synchronous function's result.

 @param done The result. @return Its error, or the empty code on success.
*/
inline boost::system::error_code code_of(boost::system::result<void> const& done) noexcept {
    return done ? boost::system::error_code{} : done.error();
}

/**
 The initiation of a cheap function on a synchronous backend: runs the function's work (its guards
 first) at once and posts the completion, with its error code, to `executor`, whence it reaches the
 handler's associated executor; the post's storage is the handler's associated allocator's.
*/
struct post_initiation {
    /**
     Runs `operation` and posts `handler` with its error code.

     @param handler The completion handler. @param executor The I/O executor.
     @param operation The synchronous function, bound to its arguments.
    */
    template <class Handler, class Executor, class Operation>
    void operator()(Handler&& handler, Executor const& executor, Operation const& operation) const {
        auto const code = code_of(operation());
        webcpp::asio::post(executor, webcpp::asio::append(std::forward<Handler>(handler), code));
    }
};

/**
 Initiates a cheap function on a synchronous backend (spec 11.2).

 @param executor The I/O executor. @param token The completion token.
 @param operation The synchronous function, bound to its arguments.
 @return What the completion token's `async_result` gives.
*/
template <class CompletionToken, class Executor, class Operation>
auto complete_by_post(Executor const& executor, CompletionToken& token, Operation operation) {
    return webcpp::asio_backend::async_initiate<CompletionToken, void(boost::system::error_code)>(
        post_initiation{}, token, executor, std::move(operation));
}

/**
 What a heavy function installs in the handler's cancellation slot, when it has one: a flag that a
 cancellation of any type sets, which the work reads on its thread before it starts and after it
 ends (spec 11.5). It lives in the slot's own storage, and holds no reference to the operation.
*/
struct cancel_flag {
    /** Set by a cancellation. */
    std::atomic<bool> cancelled{false};

    /** Sets the flag, whatever the cancellation's type. */
    void operator()(webcpp::asio::cancellation_type_t /*type*/) noexcept {
        cancelled.store(true, std::memory_order_release);
    }
};

/**
 A heavy function's work, posted to the caller's work executor: runs the synchronous function on
 that executor's thread, then dispatches the completion to the handler's associated executor
 (`work` itself by default), whose outstanding work it holds meanwhile, so that the caller's
 event loop keeps running until the completion. A cancellation before the work starts completes
 with `operation_aborted` without running it; one during the work lets it end (no C library here
 can be interrupted), then zeroes the output and completes with `operation_aborted`.

 @tparam Handler The completion handler. @tparam WorkExecutor The work executor.
 @tparam Work The synchronous function, bound to its arguments.
*/
template <class Handler, class WorkExecutor, class Work>
class heavy_operation {
public:
    /**
     Takes the handler, holds its executor's outstanding work and installs the cancellation flag.

     @param handler The completion handler. @param work The work executor.
     @param run The synchronous function, bound to its arguments. @param output The output.
    */
    heavy_operation(Handler handler, WorkExecutor const& work, Work run,
                    std::span<std::uint8_t> output)
        : handler_work_(
              webcpp::asio::make_work_guard(webcpp::asio::get_associated_executor(handler, work))),
          handler_(std::move(handler)),
          run_(std::move(run)),
          output_(output) {
        auto slot = webcpp::asio::get_associated_cancellation_slot(handler_);
        if (slot.is_connected()) {
            cancelled_ = &slot.template emplace<cancel_flag>().cancelled;
        }
    }

    /** Runs the work on the work executor's thread and dispatches the completion. */
    void operator()() {
        boost::system::error_code code;
        if (cancelled()) {
            code = webcpp::asio::error::operation_aborted;
        } else {
            code = code_of(run_());
            if (cancelled()) {
                wipe(output_);
                code = webcpp::asio::error::operation_aborted;
            }
        }
        auto const executor = handler_work_.get_executor();
        webcpp::asio::dispatch(executor, webcpp::asio::append(std::move(handler_), code));
        handler_work_.reset();
    }

private:
    [[nodiscard]] bool cancelled() const noexcept {
        return cancelled_ != nullptr && cancelled_->load(std::memory_order_acquire);
    }

    webcpp::asio::executor_work_guard<webcpp::asio::associated_executor_t<Handler, WorkExecutor>>
        handler_work_;
    Handler handler_;
    Work run_;
    std::span<std::uint8_t> output_;
    std::atomic<bool>* cancelled_ = nullptr;
};

/**
 The initiation of a heavy function (spec 11.5): its guards first, whose refusal completes through
 a post with the guard's error, the output untouched; then the work posted to the work executor,
 its storage the handler's associated allocator's.
*/
struct heavy_initiation {
    /**
     Checks the guards, then posts the work or the refusal.

     @param handler The completion handler. @param work The work executor.
     @param output The output. @param guards The guards, bound to the arguments.
     @param run The synchronous function, bound to its arguments.
    */
    template <class Handler, class WorkExecutor, class Guards, class Work>
    void operator()(Handler&& handler, WorkExecutor const& work, std::span<std::uint8_t> output,
                    Guards const& guards, Work run) const {
        auto const guarded = guards();
        if (!guarded) {
            webcpp::asio::post(
                work, webcpp::asio::append(std::forward<Handler>(handler), guarded.error()));
            return;
        }
        auto const allocator = webcpp::asio::get_associated_allocator(handler);
        using operation = heavy_operation<std::decay_t<Handler>, WorkExecutor, Work>;
        webcpp::asio::post(
            work, webcpp::asio::bind_allocator(allocator, operation(std::forward<Handler>(handler),
                                                                    work, std::move(run), output)));
    }
};

/**
 Initiates a heavy function (spec 11.5).

 @param work The work executor. @param output The output.
 @param guards The guards, bound to the arguments. @param run The synchronous function, bound to
 its arguments. @param token The completion token.
 @return What the completion token's `async_result` gives.
*/
template <class CompletionToken, class WorkExecutor, class Guards, class Work>
auto run_on_work(WorkExecutor const& work, std::span<std::uint8_t> output, Guards guards, Work run,
                 CompletionToken& token) {
    return webcpp::asio_backend::async_initiate<CompletionToken, void(boost::system::error_code)>(
        heavy_initiation{}, token, work, output, std::move(guards), std::move(run));
}

}  // namespace detail

/**
 Hashes `input` into `output` with the digest `Digest`, asynchronously (spec 11): on a synchronous
 backend, the default, at once, completing through a post on the handler's associated executor
 (`executor` by default), never inside the call.

 @code
 webcpp::hash::async_digest<webcpp::hash::digests::sha2_256>(
     loop.get_executor(), id, message, [](boost::system::error_code code) { ... });
 @endcode

 @tparam Digest `digests::sha1`, `digests::sha2_256`, `digests::sha2_384` or `digests::sha2_512`,
 the digests WebCrypto has; another refuses at compile time (`digest_of` has them all).
 @tparam Backend The backend; by default @ref default_async_backend of `Digest`, the synchronous
 default. `backends::webcrypto` only on Emscripten.
 @param executor The executor the completion is posted to.
 @param output The digest, of exactly the digest's size; the caller's until completion.
 @param input The data; the caller's until completion.
 @param token The completion token, of signature `void(boost::system::error_code)`.
 @return What the completion token's `async_result` gives. The completion's code is empty on
 success, or `digest_of`'s error, `output` untouched by a guard's refusal and zeroed by a backend's
 failure.
*/
template <class Digest, class Backend = default_async_backend<Digest>, class Executor,
          class CompletionToken>
auto async_digest(Executor const& executor, std::span<std::uint8_t> output,
                  std::span<std::uint8_t const> input, CompletionToken&& token) {
    if constexpr (!detail::webcrypto_digest_v<Digest>) {
        static_assert(detail::always_false<Digest>,
                      "webcpp::hash: async_digest takes digests::sha1, digests::sha2_256, "
                      "digests::sha2_384 or digests::sha2_512, the digests WebCrypto has: call "
                      "digest_of for the others.");
    } else if constexpr (detail::asynchronous_backend_v<Backend>) {
        return detail::async_engine<Backend>::template digest<Digest>(
            executor, output, input, std::forward<CompletionToken>(token));
    } else {
        return detail::complete_by_post(
            executor, token, [output, input] { return digest_of<Digest, Backend>(output, input); });
    }
}

/**
 The HMAC of `input` under `key` over the Boost.Hash2 hmac `Hmac`, asynchronously (spec 11), as
 @ref async_digest runs: the tag of `mac<macs::hmac<...>>` over `Hmac`'s digest.

 @tparam Hmac `hmac_sha1_160`, `hmac_sha2_256`, `hmac_sha2_384` or `hmac_sha2_512`, the hmacs
 WebCrypto has; another refuses at compile time (`mac` has them all).
 @tparam Backend The backend; by default @ref default_async_backend of the HMAC's tag, the
 synchronous default. `backends::webcrypto` only on Emscripten.
 @param executor The executor the completion is posted to.
 @param output The tag, 10 bytes up to the digest's size; the caller's until completion.
 @param key The key, of any size. @param input The message. Both the caller's until completion.
 @param token The completion token, of signature `void(boost::system::error_code)`.
 @return What the completion token's `async_result` gives. The completion's code is empty on
 success, or `mac`'s error, `output` untouched by a guard's refusal and zeroed by a backend's
 failure.
*/
template <class Hmac, class Backend = default_async_backend<detail::hmac_tag_of<Hmac>>,
          class Executor, class CompletionToken>
auto async_hmac(Executor const& executor, std::span<std::uint8_t> output,
                std::span<std::uint8_t const> key, std::span<std::uint8_t const> input,
                CompletionToken&& token) {
    if constexpr (!detail::webcrypto_hmac_v<Hmac>) {
        static_assert(detail::always_false<Hmac>,
                      "webcpp::hash: async_hmac takes hmac_sha1_160, hmac_sha2_256, "
                      "hmac_sha2_384 or hmac_sha2_512, the hmacs WebCrypto has: call mac for the "
                      "others.");
    } else if constexpr (detail::asynchronous_backend_v<Backend>) {
        return detail::async_engine<Backend>::template hmac<Hmac>(
            executor, output, key, input, std::forward<CompletionToken>(token));
    } else {
        return detail::complete_by_post(executor, token, [output, key, input] {
            return mac<detail::hmac_tag_of<Hmac>, Backend>(output, key, input);
        });
    }
}

/**
 HKDF (RFC 5869), extract and expand, asynchronously (spec 11), as @ref async_digest runs: the
 output of `hkdf<Hmac, Backend>`.

 @tparam Hmac `hmac_sha1_160`, `hmac_sha2_256`, `hmac_sha2_384` or `hmac_sha2_512`, the hmacs
 WebCrypto has HKDF over; another refuses at compile time (`hkdf` has them all).
 @tparam Backend The backend; by default @ref default_async_backend of `kdfs::hkdf`, the
 synchronous default. `backends::webcrypto` only on Emscripten.
 @param executor The executor the completion is posted to.
 @param output The output keying material, 1 to 255 times the digest size.
 @param salt The salt. @param ikm The input keying material. @param info The context, at most
 `hkdf_max_info_size` bytes. The spans are the caller's until completion.
 @param token The completion token, of signature `void(boost::system::error_code)`.
 @return What the completion token's `async_result` gives. The completion's code is empty on
 success, or `hkdf`'s error, `output` untouched by a guard's refusal and zeroed by a backend's
 failure.
*/
template <class Hmac, class Backend = default_async_backend<kdfs::hkdf, Hmac>, class Executor,
          class CompletionToken>
auto async_hkdf(Executor const& executor, std::span<std::uint8_t> output,
                std::span<std::uint8_t const> salt, std::span<std::uint8_t const> ikm,
                std::span<std::uint8_t const> info, CompletionToken&& token) {
    if constexpr (!detail::webcrypto_hmac_v<Hmac>) {
        static_assert(detail::always_false<Hmac>,
                      "webcpp::hash: async_hkdf takes hmac_sha1_160, hmac_sha2_256, "
                      "hmac_sha2_384 or hmac_sha2_512, the hmacs WebCrypto has HKDF over: call "
                      "hkdf for the others.");
    } else if constexpr (detail::asynchronous_backend_v<Backend>) {
        return detail::async_engine<Backend>::template hkdf<Hmac>(
            executor, output, salt, ikm, info, std::forward<CompletionToken>(token));
    } else {
        return detail::complete_by_post(executor, token, [output, salt, ikm, info] {
            return hkdf<Hmac, Backend>(output, salt, ikm, info);
        });
    }
}

/**
 PBKDF2 (RFC 8018), asynchronously. On a synchronous backend, the default, a heavy function (spec
 11.5): the work runs on a thread of `executor`'s context (a `webcpp::asio::thread_pool`'s) and
 completes on the handler's associated executor (`executor` by default; a program binds its event
 loop's with `bind_executor`), and it exists only where the build has threads
 (`WEBCPP_HASH_HAS_THREADS`). On `backends::webcrypto`, on Emscripten, the browser runs it: there
 `executor` is that of an `io_context` running on the calling thread, and no thread is needed.

 Cancellation through the handler's slot: before the work starts, the completion is
 `operation_aborted`; during it, the work ends, then `output` is zeroed and the completion is
 `operation_aborted`.

 @tparam Hmac The pseudorandom function, as `hmac_sha2_512`.
 @tparam Backend The backend; by default @ref default_async_backend of `kdfs::pbkdf2`, the
 synchronous default.
 @param executor The work executor, or WebCrypto's `io_context` executor.
 @param output The derived key, 1 to (2^32 - 1) times the digest size.
 @param password The password. @param salt The salt. The spans are the caller's until completion.
 @param iterations The iteration count, at least 1.
 @param token The completion token, of signature `void(boost::system::error_code)`.
 @return What the completion token's `async_result` gives. The completion's code is empty on
 success, or `pbkdf2`'s error, a guard's refusal completing through a post, `output` untouched; or
 `operation_aborted`.
*/
template <class Hmac, class Backend = default_async_backend<kdfs::pbkdf2, Hmac>, class Executor,
          class CompletionToken>
auto async_pbkdf2(Executor const& executor, std::span<std::uint8_t> output,
                  std::span<std::uint8_t const> password, std::span<std::uint8_t const> salt,
                  std::uint64_t iterations, CompletionToken&& token) {
    if constexpr (detail::asynchronous_backend_v<Backend>) {
        return detail::async_engine<Backend>::template pbkdf2<Hmac>(
            executor, output, password, salt, iterations, std::forward<CompletionToken>(token));
    } else {
#ifdef WEBCPP_HASH_HAS_THREADS
        return detail::run_on_work(
            executor, output,
            [output_size = output.size(), password_size = password.size(), salt_size = salt.size(),
             iterations] {
                if constexpr (!detail::takes_hmac<Hmac>()) {
                    return boost::system::result<void>(error::backend_failure);
                } else {
                    return detail::pbkdf2_guards<Hmac, Backend>(output_size, password_size,
                                                                salt_size, iterations);
                }
            },
            [output, password, salt, iterations] {
                return pbkdf2<Hmac, Backend>(output, password, salt, iterations);
            },
            token);
#else
        static_assert(detail::always_false<Backend>,
                      "webcpp::hash: async_pbkdf2 runs on another thread and needs a build with "
                      "threads (natively, remove WEBCPP_HASH_NO_THREADS; on Emscripten, link with "
                      "-pthread). Without threads, call pbkdf2.");
#endif
    }
}

#ifdef WEBCPP_HASH_HAS_THREADS

/**
 Argon2id (RFC 9106, one lane) on a thread of `work`'s context (spec 11.5): the guards of
 `argon2id` first, whose refusal completes through a post; then the work, posted to `work` (a
 `webcpp::asio::thread_pool`'s executor, typically); the completion on the handler's associated
 executor (`work` by default; a program binds its event loop's with `bind_executor`), so that the
 event loop never blocks. Exists only where the build has threads (`WEBCPP_HASH_HAS_THREADS`).

 Cancellation through the handler's slot: before the work starts, the completion is
 `operation_aborted`; during it, the work ends (libsodium cannot be interrupted), then `output` is
 zeroed and the completion is `operation_aborted`.

 @tparam Backend The backend; by default @ref default_backend of `kdfs::argon2id`.
 @param work The executor of the threads the work runs on.
 @param output The tag, 16 to 4,294,967,295 bytes. @param password The password.
 @param salt The salt, of `argon2id_salt_size` bytes. The spans are the caller's until completion.
 @param parameters The costs, copied.
 @param token The completion token, of signature `void(boost::system::error_code)`.
 @return What the completion token's `async_result` gives. The completion's code is empty on
 success, or `argon2id`'s error, or `operation_aborted`.
*/
template <class Backend = default_backend<kdfs::argon2id>, class WorkExecutor,
          class CompletionToken>
auto async_argon2id(WorkExecutor const& work, std::span<std::uint8_t> output,
                    std::span<std::uint8_t const> password, std::span<std::uint8_t const> salt,
                    argon2id_parameters const& parameters, CompletionToken&& token) {
    return detail::run_on_work(
        work, output,
        [output_size = output.size(), password_size = password.size(), salt_size = salt.size(),
         parameters] {
            return detail::argon2id_guards<Backend>(output_size, password_size, salt_size,
                                                    parameters);
        },
        [output, password, salt, parameters] {
            return argon2id<Backend>(output, password, salt, parameters);
        },
        token);
}

/**
 Argon2 of the variant `Variant` with every parameter (RFC 9106) on a thread of `work`'s context,
 as @ref async_argon2id runs.

 @tparam Variant `kdfs::argon2id`, `kdfs::argon2i` or `kdfs::argon2d`.
 @tparam Backend The backend; by default @ref default_backend of `Variant`.
 @param work The executor of the threads the work runs on.
 @param output The tag, 4 to 4,294,967,295 bytes. @param password The password.
 @param salt The salt, 8 to 4,294,967,295 bytes. The spans, and those of `parameters`, are the
 caller's until completion.
 @param parameters The costs, the lanes, the secret and the associated data, copied.
 @param token The completion token, of signature `void(boost::system::error_code)`.
 @return What the completion token's `async_result` gives. The completion's code is empty on
 success, or `argon2`'s error, or `operation_aborted`.
*/
template <class Variant, class Backend = default_backend<Variant>, class WorkExecutor,
          class CompletionToken>
auto async_argon2(WorkExecutor const& work, std::span<std::uint8_t> output,
                  std::span<std::uint8_t const> password, std::span<std::uint8_t const> salt,
                  argon2_parameters const& parameters, CompletionToken&& token) {
    return detail::run_on_work(
        work, output,
        [output_size = output.size(), password_size = password.size(), salt_size = salt.size(),
         parameters] {
            return detail::argon2_guards<Variant, Backend>(output_size, password_size, salt_size,
                                                           parameters);
        },
        [output, password, salt, parameters] {
            return argon2<Variant, Backend>(output, password, salt, parameters);
        },
        token);
}

/**
 scrypt (RFC 7914) on a thread of `work`'s context, as @ref async_argon2id runs.

 @tparam Backend The backend; by default @ref default_backend of `kdfs::scrypt`.
 @param work The executor of the threads the work runs on.
 @param output The derived key. @param password The password. @param salt The salt. The spans
 are the caller's until completion.
 @param parameters The costs, copied.
 @param token The completion token, of signature `void(boost::system::error_code)`.
 @return What the completion token's `async_result` gives. The completion's code is empty on
 success, or `scrypt`'s error, or `operation_aborted`.
*/
template <class Backend = default_backend<kdfs::scrypt>, class WorkExecutor, class CompletionToken>
auto async_scrypt(WorkExecutor const& work, std::span<std::uint8_t> output,
                  std::span<std::uint8_t const> password, std::span<std::uint8_t const> salt,
                  scrypt_parameters const& parameters, CompletionToken&& token) {
    return detail::run_on_work(
        work, output,
        [output_size = output.size(), password_size = password.size(), salt_size = salt.size(),
         parameters] {
            return detail::scrypt_guards<Backend>(output_size, password_size, salt_size,
                                                  parameters);
        },
        [output, password, salt, parameters] {
            return scrypt<Backend>(output, password, salt, parameters);
        },
        token);
}

#else

/**
 Argon2id on another thread, which a build without threads does not have: a call refuses at
 compile time, naming `argon2id`.

 @tparam Backend The backend. @return Nothing: the refusal has stopped the build.
*/
template <class Backend = default_backend<kdfs::argon2id>, class WorkExecutor,
          class CompletionToken>
void async_argon2id(WorkExecutor const& /*work*/, std::span<std::uint8_t> /*output*/,
                    std::span<std::uint8_t const> /*password*/,
                    std::span<std::uint8_t const> /*salt*/,
                    argon2id_parameters const& /*parameters*/, CompletionToken&& /*token*/) {
    static_assert(detail::always_false<Backend>,
                  "webcpp::hash: async_argon2id runs on another thread and needs a build with "
                  "threads (natively, remove WEBCPP_HASH_NO_THREADS; on Emscripten, link with "
                  "-pthread). Without threads, call argon2id.");
}

/**
 Argon2 on another thread, which a build without threads does not have: a call refuses at compile
 time, naming `argon2`.

 @tparam Variant The variant. @tparam Backend The backend.
 @return Nothing: the refusal has stopped the build.
*/
template <class Variant, class Backend = default_backend<Variant>, class WorkExecutor,
          class CompletionToken>
void async_argon2(WorkExecutor const& /*work*/, std::span<std::uint8_t> /*output*/,
                  std::span<std::uint8_t const> /*password*/,
                  std::span<std::uint8_t const> /*salt*/, argon2_parameters const& /*parameters*/,
                  CompletionToken&& /*token*/) {
    static_assert(detail::always_false<Backend>,
                  "webcpp::hash: async_argon2 runs on another thread and needs a build with "
                  "threads (natively, remove WEBCPP_HASH_NO_THREADS; on Emscripten, link with "
                  "-pthread). Without threads, call argon2.");
}

/**
 scrypt on another thread, which a build without threads does not have: a call refuses at compile
 time, naming `scrypt`.

 @tparam Backend The backend. @return Nothing: the refusal has stopped the build.
*/
template <class Backend = default_backend<kdfs::scrypt>, class WorkExecutor, class CompletionToken>
void async_scrypt(WorkExecutor const& /*work*/, std::span<std::uint8_t> /*output*/,
                  std::span<std::uint8_t const> /*password*/,
                  std::span<std::uint8_t const> /*salt*/, scrypt_parameters const& /*parameters*/,
                  CompletionToken&& /*token*/) {
    static_assert(detail::always_false<Backend>,
                  "webcpp::hash: async_scrypt runs on another thread and needs a build with "
                  "threads (natively, remove WEBCPP_HASH_NO_THREADS; on Emscripten, link with "
                  "-pthread). Without threads, call scrypt.");
}

#endif

}  // namespace webcpp::hash

#endif  // WEBCPP_HASH_ASYNC_HPP
