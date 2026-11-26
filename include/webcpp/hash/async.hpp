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

 - The cheap functions, `async_digest`, `async_hmac`, `async_hkdf_extract`, `async_hkdf_expand`
   and `async_hkdf`, each HKDF function also over `byte_pieces`, exist on every target for the
   algorithms the browser's WebCrypto has (SHA-1, SHA-256, SHA-384, SHA-512, and HMAC and HKDF
   over them). On a synchronous backend, their default, they run it at once and complete through a
   post on the handler's associated executor, never inside the initiating call; a form over
   pieces runs it in the call itself, before the operation is initiated, so that the pieces are
   read before the call returns, whatever the completion token.
 - The heavy functions, `async_argon2id`, `async_argon2`, `async_scrypt`, `async_bcrypt`,
   `async_bcrypt_pbkdf`, `async_bcrypt_verify` and `async_pbkdf2` on a synchronous backend, run on
   another thread: they check their guards, post the work to the executor the caller gives (a
   `webcpp::asio::thread_pool`'s), and complete on the handler's associated executor,
   `async_bcrypt_verify` with `void(boost::system::error_code, bool)`. They exist only where the
   build has threads (`WEBCPP_HASH_HAS_THREADS`); elsewhere each name refuses at compile time.

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
#include <webcpp/hash/bcrypt.hpp>
#include <webcpp/hash/byte_pieces.hpp>
#include <webcpp/hash/detail/engines.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/error.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/hash/kdf.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/hash/pbkdf2.hpp>
#include <webcpp/hash/scrypt.hpp>
#include <webcpp/secure/erase_secret.hpp>

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

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <string_view>
#include <thread>  // lint-world: std::this_thread::yield, the state's spin lock
#include <type_traits>
#include <utility>

namespace webcpp::hash {

/**
 The backend of the asynchronous family when a call names none.

 It is the synchronous function's, @ref default_backend, on every target (ruling R76, the owner's
 decision O2). `backends::webcrypto` is never a default: a program on Emscripten names it in the
 type to reach the browser's WebCrypto.

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
 `hmac<Hmac>`, `hkdf_extract<Hmac>`, `hkdf_expand<Hmac>`, `hkdf<Hmac>` and `pbkdf2<Hmac>`, each
 taking the asynchronous function's arguments (a span, or `byte_pieces` for a form over pieces)
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
    static void digest(Arguments&&... /*call_arguments*/) noexcept {}

    /** Never called: the refusal has stopped the build. */
    template <class Algorithm, class... Arguments>
    static void hmac(Arguments&&... /*call_arguments*/) noexcept {}

    /** Never called: the refusal has stopped the build. */
    template <class Algorithm, class... Arguments>
    static void hkdf_extract(Arguments&&... /*call_arguments*/) noexcept {}

    /** Never called: the refusal has stopped the build. */
    template <class Algorithm, class... Arguments>
    static void hkdf_expand(Arguments&&... /*call_arguments*/) noexcept {}

    /** Never called: the refusal has stopped the build. */
    template <class Algorithm, class... Arguments>
    static void hkdf(Arguments&&... /*call_arguments*/) noexcept {}

    /** Never called: the refusal has stopped the build. */
    template <class Algorithm, class... Arguments>
    static void pbkdf2(Arguments&&... /*call_arguments*/) noexcept {}
};
#endif

/**
 The error code of a synchronous function's result.

 @tparam Value The result's value: `void`, or `bool` for `bcrypt_verify`.
 @param call_result The result. @return Its error, or the empty code on success.
*/
template <class Value>
boost::system::error_code code_of(boost::system::result<Value> const& call_result) noexcept {
    return call_result ? boost::system::error_code{} : call_result.error();
}

/** The value a heavy operation carries to its handler beside its code: none for `void`. */
template <class Value>
struct heavy_value {
    /** The value; `Value{}` (false) until the work gives one. */
    Value value{};
};

/** No value: the completion's signature is `void(boost::system::error_code)`. */
template <>
struct heavy_value<void> {};

/**
 The completion signature of a heavy function whose synchronous function returns
 `boost::system::result<Value>`: `void(boost::system::error_code)` for `void`, else
 `void(boost::system::error_code, Value)` (`bcrypt_verify`'s `bool`).

 @tparam Value The synchronous function's value.
*/
template <class Value>
struct heavy_signature_of {
    /** `void(boost::system::error_code, Value)`. */
    using type = void(boost::system::error_code, Value);
};

/** No value: `void(boost::system::error_code)`. */
template <>
struct heavy_signature_of<void> {
    /** `void(boost::system::error_code)`. */
    using type = void(boost::system::error_code);
};

/** The completion signature of @ref heavy_signature_of. @tparam Value The value. */
template <class Value>
using heavy_signature = heavy_signature_of<Value>::type;

/**
 The value of the result of `Work`, a heavy function's synchronous function bound to its
 arguments: `void`, or `bool`.

 @tparam Work The bound function.
*/
template <class Work>
using heavy_value_of = std::invoke_result_t<Work&>::value_type;

/**
 The initiation of a cheap function on a synchronous backend: runs the function's work (its guards
 first) at once and posts the completion, with its error code, to `executor`, whence it reaches the
 handler's associated executor; the post's storage is the handler's associated allocator's.
*/
struct post_initiation {
    /**
     Runs `bound_call` and posts `completion_handler` with its error code.

     @param completion_handler The completion handler. @param completion_executor The I/O executor.
     @param bound_call The synchronous function, bound to its arguments.
    */
    template <class Handler, class Executor, class Operation>
    void operator()(Handler&& completion_handler, Executor const& completion_executor,
                    Operation const& bound_call) const {
        auto const completion_code = code_of(bound_call());
        webcpp::asio::post(
            completion_executor,
            webcpp::asio::append(std::forward<Handler>(completion_handler), completion_code));
    }
};

/**
 Initiates a cheap function on a synchronous backend (spec 11.2).

 @param completion_executor The I/O executor. @param completion_token The completion token.
 @param bound_call The synchronous function, bound to its arguments.
 @return What the completion token's `async_result` gives.
*/
template <class CompletionToken, class Executor, class Operation>
auto complete_by_post(Executor const& completion_executor, CompletionToken& completion_token,
                      Operation bound_call) {
    return webcpp::asio_backend::async_initiate<CompletionToken, void(boost::system::error_code)>(
        post_initiation{}, completion_token, completion_executor, std::move(bound_call));
}

/**
 The initiation of a form over pieces on a synchronous backend, whose work has already run: posts
 the completion, with the work's error code, to `executor`, whence it reaches the handler's
 associated executor; the post's storage is the handler's associated allocator's.
*/
struct code_initiation {
    /**
     Posts `completion_handler` with `completion_code`.

     @param completion_handler The completion handler. @param completion_executor The I/O executor.
     @param completion_code The work's error code.
    */
    template <class Handler, class Executor>
    void operator()(Handler&& completion_handler, Executor const& completion_executor,
                    boost::system::error_code completion_code) const {
        webcpp::asio::post(
            completion_executor,
            webcpp::asio::append(std::forward<Handler>(completion_handler), completion_code));
    }
};

/**
 Completes a form over pieces on a synchronous backend with the code of its work, which the caller
 has run in the initiating call (ruling R4 of the change hkdf-pieces): only the code reaches
 `async_initiate`, so that no completion token, `asio::deferred` included, keeps the pieces' list
 past the call's full-expression.

 @param completion_executor The I/O executor. @param completion_token The completion token.
 @param completion_code The work's error code.
 @return What the completion token's `async_result` gives.
*/
template <class CompletionToken, class Executor>
auto complete_with_code(Executor const& completion_executor, CompletionToken& completion_token,
                        boost::system::error_code completion_code) {
    return webcpp::asio_backend::async_initiate<CompletionToken, void(boost::system::error_code)>(
        code_initiation{}, completion_token, completion_executor, completion_code);
}

/**
 HKDF-Extract into `pseudorandom_key`, the work of `async_hkdf_extract` on a synchronous backend:
 `hkdf_extract<Hmac, Backend>` over `input_key_material` (a span, or `byte_pieces`), its result
 copied into `pseudorandom_key` and wiped.

 @tparam Hmac A Boost.Hash2 hmac over a digest. @tparam Backend A synchronous backend.
 @tparam InputKeyMaterial `std::span<std::uint8_t const>`, or `byte_pieces`.
 @param pseudorandom_key The output, of exactly the digest size.
 @param salt_bytes The salt. @param input_key_material The input keying material.
 @return Success; or `invalid_output_size` for an output of another size, then `hkdf_extract`'s
 guards' errors, `pseudorandom_key` untouched; or the backend's failure, `pseudorandom_key` zeroed.
*/
template <class Hmac, class Backend, class InputKeyMaterial>
[[nodiscard]] boost::system::result<void> hkdf_extract_into(
    std::span<std::uint8_t> pseudorandom_key, std::span<std::uint8_t const> salt_bytes,
    InputKeyMaterial input_key_material) {
    // No timing_guard here: the secret computation is hkdf_extract's, which holds the guard as its
    // first statement; this helper only checks sizes, then copies and wipes the key, work whose
    // time does not depend on the bytes. A guard here would be the first one the call enters, where
    // the asynchronous family's rule (timing_async_test) is that it is the synchronous function's.
    // Hash2 1.92 declares no std::tuple_size for digest<N>; its size() is constexpr.
    constexpr std::size_t digest_length = typename Hmac::result_type().size();
    if (pseudorandom_key.size() != digest_length) {
        return error::invalid_output_size;
    }
    if constexpr (std::is_same_v<InputKeyMaterial, byte_pieces>) {
        auto const guard_result = hkdf_pieces_salt_guard<Backend>(salt_bytes.size());
        if (!guard_result) {
            return guard_result;
        }
    } else {
        auto const guard_result =
            hkdf_extract_guards<Backend>(salt_bytes.size(), input_key_material.size());
        if (!guard_result) {
            return guard_result;
        }
    }
    auto extract_result = hkdf_extract<Hmac, Backend>(salt_bytes, input_key_material);
    if (!extract_result) {
        secure::erase_secret(pseudorandom_key);
        return extract_result.error();
    }
    std::ranges::copy(*extract_result, pseudorandom_key.begin());
    secure::erase_secret(std::span(&*extract_result, 1));
    return {};
}

/** Where a heavy operation is: waiting in the work executor's queue, running, or completed. */
enum class heavy_phase : std::uint8_t {
    /** Posted to the work executor, not started. */
    queued,
    /** Running on a thread of the work executor. */
    running,
    /** Completed, or abandoned by a work executor that destroyed it unrun. */
    finished,
};

/**
 A heavy function's operation (spec 11.5), in storage of the handler's associated allocator, as
 every Asio operation's is.

 Whoever moves the phase from `queued` produces the completion, exactly once: the job, which runs
 the synchronous function on the work executor's thread; or a cancellation before the work starts,
 on the handler's executor, which completes with `operation_aborted` at once, the output untouched
 (every type is honoured then: nothing has happened yet). Once the work runs, only `terminal` and
 `partial` are (no C library here can be interrupted: the work ends, then the output is zeroed and
 the completion is `operation_aborted`, a side effect that `total` does not allow).

 The completion runs on the handler's associated executor (`work` by default), where the slot's
 signal is emitted: it clears the cancellation slot, moves the handler out, destroys the state and
 gives its storage back to the handler's allocator, and only then calls the handler, so that
 nothing of that allocator outlives the call (Asio's rule). The job queued in the work executor
 holds the state through one atomic pointer, whose location the state records under a lock each
 time the job moves; a cancellation before the work starts takes the state back from that
 location, so that the job, which may wait behind other work for long, holds nothing of the
 handler's when the handler runs. The handler's executor has outstanding work until the
 completion, so that the caller's event loop does not return early.

 @tparam Handler The completion handler. @tparam WorkExecutor The work executor.
 @tparam Work The synchronous function, bound to its arguments.
*/
template <class Handler, class WorkExecutor, class Work>
class heavy_state {
public:
    /** The handler's associated executor, `work` by default. */
    using executor_type = webcpp::asio::associated_executor_t<Handler, WorkExecutor>;
    /** The value the handler receives beside its code: `void` (none), or `bcrypt_verify`'s bool. */
    using value_type = heavy_value_of<Work>;
    /** The handler's associated allocator, rebound to the state. */
    using allocator_type = std::allocator_traits<
        webcpp::asio::associated_allocator_t<Handler>>::template rebind_alloc<heavy_state>;

    /** Not copyable: the job and the slot reach one state. */
    heavy_state(heavy_state const&) = delete;
    /** Not movable: the job and the slot hold its address. */
    heavy_state(heavy_state&&) = delete;
    /** Not copyable: the job and the slot reach one state. */
    heavy_state& operator=(heavy_state const&) = delete;
    /** Not movable: the job and the slot hold its address. */
    heavy_state& operator=(heavy_state&&) = delete;
    /** Destroys the handler and the work's guard; the storage is freed by its owner. */
    ~heavy_state() = default;

    /**
     A new state, in storage of the handler's associated allocator.

     @param completion_handler The completion handler. @param work_executor The work executor.
     @param bound_call The synchronous function, bound to its arguments. @param output_bytes The
     output.
     @return The state.
    */
    static heavy_state* make(Handler completion_handler, WorkExecutor const& work_executor,
                             Work bound_call, std::span<std::byte> output_bytes) {
        allocator_type handler_allocator(
            webcpp::asio::get_associated_allocator(completion_handler));
        auto* const state_storage =
            std::allocator_traits<allocator_type>::allocate(handler_allocator, 1);
        try_construct(handler_allocator, state_storage, std::move(completion_handler),
                      work_executor, std::move(bound_call), output_bytes);
        return state_storage;
    }

    /** Installs the cancellation handler, when the handler's slot is connected. */
    void install_cancellation() {
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access): engaged until the completion
        auto handler_slot = webcpp::asio::get_associated_cancellation_slot(*handler_);
        if (handler_slot.is_connected()) {
            handler_slot.template emplace<cancellation>(this);
        }
    }

    /**
     Records where the job holds the state, or that it holds it no longer (null).

     @param job_location The job's atomic pointer.
    */
    void relocate(std::atomic<heavy_state*>* job_location) noexcept {
        lock();
        location_ = job_location;
        unlock();
    }

    /** The job's turn on the work executor's thread, the state taken out of the job. */
    void run_work() {
        relocate(nullptr);
        auto expected_phase = heavy_phase::queued;
        if (!phase_.compare_exchange_strong(expected_phase, heavy_phase::running,
                                            std::memory_order_acq_rel)) {
            // A cancellation won, and found the job holding the state no more: complete for it.
            complete_on_handler(webcpp::asio::error::operation_aborted);
            return;
        }
        auto const call_result = run_();
        auto completion_code = code_of(call_result);
        if constexpr (!std::is_void_v<value_type>) {
            value_.value = call_result ? *call_result : value_type{};
        }
        if (cancelled_.load(std::memory_order_acquire)) {
            secure::erase_secret(output_);
            completion_code = webcpp::asio::error::operation_aborted;
            value_ = {};
        }
        phase_.store(heavy_phase::finished, std::memory_order_release);
        complete_on_handler(completion_code);
    }

    /** The job destroyed unrun (its executor shut down): the handler is destroyed, never called. */
    void abandon() {
        relocate(nullptr);
        auto expected_phase = heavy_phase::queued;
        if (!phase_.compare_exchange_strong(expected_phase, heavy_phase::finished,
                                            std::memory_order_acq_rel)) {
            complete_on_handler(webcpp::asio::error::operation_aborted);
            return;
        }
        auto const completion_executor = handler_work_.get_executor();
        webcpp::asio::post(completion_executor, bound_completion({}, false));
    }

    /** A cancellation of type `requested_type`, on the handler's executor, where the signal is
     * emitted. */
    void cancel(webcpp::asio::cancellation_type_t requested_type) {
        auto expected_phase = heavy_phase::queued;
        if (phase_.compare_exchange_strong(expected_phase, heavy_phase::finished,
                                           std::memory_order_acq_rel)) {
            // Take the state back from the queued job; a job that has just taken it out itself
            // completes for this cancellation instead.
            bool state_taken = false;
            lock();
            if (location_ != nullptr) {
                state_taken = location_->exchange(nullptr, std::memory_order_acq_rel) != nullptr;
                location_ = nullptr;
            }
            unlock();
            if (state_taken) {
                auto const completion_executor = handler_work_.get_executor();
                webcpp::asio::post(completion_executor,
                                   bound_completion(webcpp::asio::error::operation_aborted));
            }
            return;
        }
        using webcpp::asio::cancellation_type;
        if ((requested_type & (cancellation_type::terminal | cancellation_type::partial)) !=
            cancellation_type::none) {
            cancelled_.store(true, std::memory_order_release);
        }
    }

private:
    // The handler installed in the cancellation slot; the completion clears the slot before the
    // state is destroyed.
    class cancellation {
    public:
        explicit cancellation(heavy_state* operation_state) noexcept : state_(operation_state) {}

        void operator()(webcpp::asio::cancellation_type_t requested_type) {
            state_->cancel(requested_type);
        }

    private:
        heavy_state* state_;
    };

    // The completion, on the handler's executor, its storage the handler's allocator's. It owns
    // the state: run, it frees the state and calls the handler (`invoke`), or, for a job destroyed
    // unrun, only frees it, the handler with it; destroyed without running (its executor shut down
    // or destroyed with it queued, as Asio destroys a queued operation), it frees the state and
    // the handler too, never calling it, so that nothing of the handler's allocator is left and a
    // handler that owns a promise breaks it.
    class completion {
    public:
        completion(heavy_state* operation_state, boost::system::error_code completion_code,
                   bool invoke_handler) noexcept
            : state_(operation_state), code_(completion_code), invoke_(invoke_handler) {}

        completion(completion&& moved_completion) noexcept
            : state_(std::exchange(moved_completion.state_, nullptr)),
              code_(moved_completion.code_),
              invoke_(moved_completion.invoke_) {}

        completion(completion const&) = delete;
        completion& operator=(completion const&) = delete;
        completion& operator=(completion&&) = delete;

        ~completion() {
            if (state_ != nullptr) {
                state_->destroy();
            }
        }

        void operator()() {
            auto* const operation_state = std::exchange(state_, nullptr);
            if (invoke_) {
                operation_state->complete(code_);
            } else {
                operation_state->destroy();
            }
        }

    private:
        heavy_state* state_;
        boost::system::error_code code_;
        bool invoke_;
    };

    heavy_state(Handler completion_handler, WorkExecutor const& work_executor, Work bound_call,
                std::span<std::byte> output_bytes)
        : handler_work_(webcpp::asio::make_work_guard(
              webcpp::asio::get_associated_executor(completion_handler, work_executor))),
          handler_(std::in_place, std::move(completion_handler)),
          run_(std::move(bound_call)),
          output_(output_bytes) {}

    // Constructs the state in `storage`, which is given back if the construction throws.
    static void try_construct(allocator_type& handler_allocator, heavy_state* state_storage,
                              Handler completion_handler, WorkExecutor const& work_executor,
                              Work bound_call, std::span<std::byte> output_bytes) {
        struct give_back {
            allocator_type& allocator;
            heavy_state* storage;

            ~give_back() {
                if (storage != nullptr) {
                    std::allocator_traits<allocator_type>::deallocate(allocator, storage, 1);
                }
            }
        } storage_guard{handler_allocator, state_storage};

        ::new (static_cast<void*>(state_storage)) heavy_state(
            std::move(completion_handler), work_executor, std::move(bound_call), output_bytes);
        storage_guard.storage = nullptr;
    }

    void lock() noexcept {
        while (lock_.test_and_set(std::memory_order_acquire)) {
            std::this_thread::yield();  // lint-world: to the thread holding the lock, no clock
        }
    }

    void unlock() noexcept { lock_.clear(std::memory_order_release); }

    // The completion bound to the handler's associated allocator; `invoke` false only discards.
    auto bound_completion(boost::system::error_code completion_code, bool invoke_handler = true) {
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access): engaged until the completion
        return webcpp::asio::bind_allocator(webcpp::asio::get_associated_allocator(*handler_),
                                            completion(this, completion_code, invoke_handler));
    }

    // Dispatches the completion to the handler's executor; the caller touches the state no more.
    void complete_on_handler(boost::system::error_code completion_code) {
        auto const completion_executor = handler_work_.get_executor();
        webcpp::asio::dispatch(completion_executor, bound_completion(completion_code));
    }

    // Clears the slot, takes the handler and the executor's work out, frees the state, then calls
    // the handler: nothing of the handler's allocator outlives the call.
    void complete(boost::system::error_code completion_code) {
        clear_slot();
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access): engaged until here
        Handler completion_handler(std::move(*handler_));
        auto work_guard = std::move(handler_work_);
        allocator_type handler_allocator(
            webcpp::asio::get_associated_allocator(completion_handler));
        if constexpr (std::is_void_v<value_type>) {
            release_storage(handler_allocator);
            std::move(completion_handler)(completion_code);
        } else {
            value_type const completion_value = value_.value;
            release_storage(handler_allocator);
            std::move(completion_handler)(completion_code, completion_value);
        }
        work_guard.reset();
    }

    // Clears the slot, then destroys the state, the handler with it, and gives its storage back.
    void destroy() {
        clear_slot();
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access): engaged until here
        allocator_type handler_allocator(webcpp::asio::get_associated_allocator(*handler_));
        release_storage(handler_allocator);
    }

    // Removes the cancellation handler, on the handler's executor, before the state goes.
    void clear_slot() {
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access): engaged until here
        auto handler_slot = webcpp::asio::get_associated_cancellation_slot(*handler_);
        if (handler_slot.is_connected()) {
            handler_slot.clear();
        }
    }

    // Destroys the state and gives its storage back to a copy of the handler's allocator.
    void release_storage(allocator_type& handler_allocator) {
        std::allocator_traits<allocator_type>::destroy(handler_allocator, this);
        std::allocator_traits<allocator_type>::deallocate(handler_allocator, this, 1);
    }

    std::atomic_flag lock_ = ATOMIC_FLAG_INIT;
    std::atomic<heavy_state*>* location_ = nullptr;
    std::atomic<heavy_phase> phase_{heavy_phase::queued};
    std::atomic<bool> cancelled_{false};
    webcpp::asio::executor_work_guard<executor_type> handler_work_;
    std::optional<Handler> handler_;
    Work run_;
    std::span<std::byte> output_;
    heavy_value<value_type> value_{};
};

/**
 The job a heavy function posts to the work executor: runs its state's work, or, destroyed unrun
 (the executor shut down), abandons it. Move-only. It holds the state through one atomic pointer,
 whose location it records in the state at each move, so that a cancellation before the work
 starts can take the state back: the job's own storage is the work executor's, never the
 handler's.

 @tparam State The operation's @ref heavy_state.
*/
template <class State>
class heavy_job {
public:
    /**
     Holds `operation_state`, before the state can be cancelled.

     @param operation_state The operation's state.
    */
    explicit heavy_job(State* operation_state) noexcept : state_(operation_state) {
        operation_state->relocate(&state_);
    }

    /**
     Takes `moved_job`'s hold, and records the new location; a hold taken back by a cancellation is
     null, and the state is then touched no more.

     @param moved_job The job moved from.
    */
    heavy_job(heavy_job&& moved_job) noexcept
        : state_(moved_job.state_.exchange(nullptr, std::memory_order_acq_rel)) {
        if (auto* const held_state = state_.load(std::memory_order_relaxed);
            held_state != nullptr) {
            held_state->relocate(&state_);
        }
    }

    /** Not copyable: one job holds the state once. */
    heavy_job(heavy_job const&) = delete;
    /** Not copyable: one job holds the state once. */
    heavy_job& operator=(heavy_job const&) = delete;
    /** Not assignable: a job is moved into its executor once. */
    heavy_job& operator=(heavy_job&&) = delete;

    /** Abandons the state when the job never ran and still holds it. */
    // A post that fails while a work executor destroys its queue ends the program, as an
    // exception from any of Asio's destructors does.
    // NOLINTNEXTLINE(bugprone-exception-escape): see above
    ~heavy_job() {
        if (auto* const held_state = state_.exchange(nullptr, std::memory_order_acq_rel);
            held_state != nullptr) {
            held_state->abandon();
        }
    }

    /** Runs the work on the work executor's thread, unless a cancellation took the state back. */
    void operator()() {
        if (auto* const held_state = state_.exchange(nullptr, std::memory_order_acq_rel);
            held_state != nullptr) {
            held_state->run_work();
        }
    }

private:
    std::atomic<State*> state_;
};

/**
 The initiation of a heavy function (spec 11.5): its guards first, whose refusal is posted to the
 handler's associated executor with the guard's error, the output untouched, never waiting for the
 work executor (unless the handler has no executor of its own: the work executor is then its
 executor); then the work posted to the work executor. The operation's state and its completion
 are in storage of the handler's associated allocator, all given back before the handler runs.
*/
struct heavy_initiation {
    /**
     Checks the guards, then posts the work or the refusal.

     @param completion_handler The completion handler. @param work_executor The work executor.
     @param output_bytes The output. @param bound_guards The guards, bound to the arguments.
     @param bound_call The synchronous function, bound to its arguments.
    */
    template <class Handler, class WorkExecutor, class Guards, class Work>
    void operator()(Handler&& completion_handler, WorkExecutor const& work_executor,
                    std::span<std::byte> output_bytes, Guards const& bound_guards,
                    Work bound_call) const {
        auto const guard_result = bound_guards();
        if (!guard_result) {
            auto const completion_executor =
                webcpp::asio::get_associated_executor(completion_handler, work_executor);
            if constexpr (std::is_void_v<heavy_value_of<Work>>) {
                webcpp::asio::post(completion_executor,
                                   webcpp::asio::append(std::forward<Handler>(completion_handler),
                                                        guard_result.error()));
            } else {
                webcpp::asio::post(
                    completion_executor,
                    webcpp::asio::append(std::forward<Handler>(completion_handler),
                                         guard_result.error(), heavy_value_of<Work>{}));
            }
            return;
        }
        using state = heavy_state<std::decay_t<Handler>, WorkExecutor, Work>;
        // The job holds the state from its making on, so that a failure to install the
        // cancellation or to post abandons it rather than leak it with the executor's work.
        auto* const made_state = state::make(std::forward<Handler>(completion_handler),
                                             work_executor, std::move(bound_call), output_bytes);
        heavy_job<state> queued_job(made_state);
        made_state->install_cancellation();
        webcpp::asio::post(work_executor, std::move(queued_job));
    }
};

/**
 Initiates a heavy function (spec 11.5), of the signature its synchronous function's value gives
 (@ref heavy_signature).

 @param work_executor The work executor. @param output_bytes The output's bytes, zeroed after a
 cancellation during the work; empty for `bcrypt_verify`, which has none.
 @param bound_guards The guards, bound to the arguments. @param bound_call The synchronous function,
 bound to its arguments. @param completion_token The completion token.
 @return What the completion token's `async_result` gives.
*/
template <class CompletionToken, class WorkExecutor, class Guards, class Work>
auto run_on_work(WorkExecutor const& work_executor, std::span<std::byte> output_bytes,
                 Guards bound_guards, Work bound_call, CompletionToken& completion_token) {
    return webcpp::asio_backend::async_initiate<CompletionToken,
                                                heavy_signature<heavy_value_of<Work>>>(
        heavy_initiation{}, completion_token, work_executor, output_bytes, std::move(bound_guards),
        std::move(bound_call));
}

}  // namespace detail

/**
 Hashes `input_bytes` into `output_bytes` with the digest `Digest`, asynchronously (spec 11): on a
 synchronous backend, the default, at once, completing through a post on the handler's associated
 executor
 (`completion_executor` by default), never inside the call.

 @code
 webcpp::hash::async_digest<webcpp::hash::digests::sha2_256>(
     loop.get_executor(), id, message, [](boost::system::error_code code) { ... });
 @endcode

 @tparam Digest `digests::sha1`, `digests::sha2_256`, `digests::sha2_384` or `digests::sha2_512`,
 the digests WebCrypto has; another refuses at compile time (`digest_of` has them all).
 @tparam Backend The backend; by default @ref default_async_backend of `Digest`, the synchronous
 default. `backends::webcrypto` only on Emscripten.
 @tparam Executor An Asio executor, where the completion is posted.
 @tparam CompletionToken An Asio completion token of signature `void(boost::system::error_code)`.
 @param completion_executor The executor the completion is posted to; on `backends::webcrypto`, that
 of an `io_context` run on the calling thread (see @ref async_pbkdf2), and a refusal of another goes
 to the handler's associated executor, this one unless the handler is bound to another.
 @param output_bytes The digest, of exactly the digest's size; the caller's until completion.
 @param input_bytes The data; the caller's until completion.
 @param completion_token The completion token, of signature `void(boost::system::error_code)`.
 @return What the completion token's `async_result` gives. The completion's code is empty on
 success, or `digest_of`'s error, `output_bytes` untouched by a guard's refusal and zeroed by a
 backend's failure. On `backends::webcrypto` also `invalid_parameters` (the executor),
 `output_bytes` untouched, `backend_failure` (a rejected promise, an unexpected result, no
 WebCrypto), `output_bytes` zeroed, and `operation_aborted` (a `terminal` or `partial` cancellation,
 at once), `output_bytes` zeroed.
*/
template <class Digest, class Backend = default_async_backend<Digest>, class Executor,
          class CompletionToken>
auto async_digest(Executor const& completion_executor, std::span<std::uint8_t> output_bytes,
                  std::span<std::uint8_t const> input_bytes, CompletionToken&& completion_token) {
    if constexpr (!detail::webcrypto_digest_v<Digest>) {
        static_assert(detail::always_false<Digest>,
                      "webcpp::hash: async_digest takes digests::sha1, digests::sha2_256, "
                      "digests::sha2_384 or digests::sha2_512, the digests WebCrypto has: call "
                      "digest_of for the others.");
    } else if constexpr (detail::asynchronous_backend_v<Backend>) {
        return detail::async_engine<Backend>::template digest<Digest>(
            completion_executor, output_bytes, input_bytes,
            std::forward<CompletionToken>(completion_token));
    } else {
        return detail::complete_by_post(
            completion_executor, completion_token, [output_bytes, input_bytes] {
                return digest_of<Digest, Backend>(output_bytes, input_bytes);
            });
    }
}

/**
 The HMAC of `input_bytes` under `key_bytes` over the Boost.Hash2 hmac `Hmac`, asynchronously (spec
 11), as
 @ref async_digest runs: the tag of `mac<macs::hmac<...>>` over `Hmac`'s digest.

 @tparam Hmac `hmac_sha1_160`, `hmac_sha2_256`, `hmac_sha2_384` or `hmac_sha2_512`, the hmacs
 WebCrypto has; another refuses at compile time (`mac` has them all).
 @tparam Backend The backend; by default @ref default_async_backend of the HMAC's tag, the
 synchronous default. `backends::webcrypto` only on Emscripten.
 @tparam Executor An Asio executor, where the completion is posted.
 @tparam CompletionToken An Asio completion token of signature `void(boost::system::error_code)`.
 @param completion_executor The executor the completion is posted to; on `backends::webcrypto`, that
 of an `io_context` run on the calling thread (see @ref async_pbkdf2), and a refusal of another goes
 to the handler's associated executor, this one unless the handler is bound to another.
 @param output_bytes The tag, 10 bytes up to the digest's size; the caller's until completion.
 @param key_bytes The key, of any size. @param input_bytes The message. Both the caller's until
 completion.
 @param completion_token The completion token, of signature `void(boost::system::error_code)`.
 @return What the completion token's `async_result` gives. The completion's code is empty on
 success, or `mac`'s error, `output_bytes` untouched by a guard's refusal and zeroed by a backend's
 failure. On `backends::webcrypto` also `invalid_parameters` (the executor), `output_bytes`
 untouched, `backend_failure` (a rejected promise, an unexpected result, no WebCrypto),
 `output_bytes` zeroed, and `operation_aborted` (a `terminal` or `partial` cancellation, at once),
 `output_bytes` zeroed.
*/
template <class Hmac, class Backend = default_async_backend<detail::hmac_tag_of<Hmac>>,
          class Executor, class CompletionToken>
auto async_hmac(Executor const& completion_executor, std::span<std::uint8_t> output_bytes,
                std::span<std::uint8_t const> key_bytes, std::span<std::uint8_t const> input_bytes,
                CompletionToken&& completion_token) {
    if constexpr (!detail::webcrypto_hmac_v<Hmac>) {
        static_assert(detail::always_false<Hmac>,
                      "webcpp::hash: async_hmac takes hmac_sha1_160, hmac_sha2_256, "
                      "hmac_sha2_384 or hmac_sha2_512, the hmacs WebCrypto has: call mac for the "
                      "others.");
    } else if constexpr (detail::asynchronous_backend_v<Backend>) {
        return detail::async_engine<Backend>::template hmac<Hmac>(
            completion_executor, output_bytes, key_bytes, input_bytes,
            std::forward<CompletionToken>(completion_token));
    } else {
        return detail::complete_by_post(completion_executor, completion_token,
                                        [output_bytes, key_bytes, input_bytes] {
                                            return mac<detail::hmac_tag_of<Hmac>, Backend>(
                                                output_bytes, key_bytes, input_bytes);
                                        });
    }
}

/**
 HKDF (RFC 5869), extract and expand, asynchronously (spec 11), as @ref async_digest runs: the
 output keying material of `hkdf<Hmac, Backend>`.

 @tparam Hmac `hmac_sha1_160`, `hmac_sha2_256`, `hmac_sha2_384` or `hmac_sha2_512`, the hmacs
 WebCrypto has HKDF over; another refuses at compile time (`hkdf` has them all).
 @tparam Backend The backend; by default @ref default_async_backend of `kdfs::hkdf`, the
 synchronous default. `backends::webcrypto` only on Emscripten.
 @tparam Executor An Asio executor, where the completion is posted.
 @tparam CompletionToken An Asio completion token of signature `void(boost::system::error_code)`.
 @param completion_executor The executor the completion is posted to; on `backends::webcrypto`, that
 of an `io_context` run on the calling thread (see @ref async_pbkdf2), and a refusal of another goes
 to the handler's associated executor, this one unless the handler is bound to another.
 @param output_key_material The output keying material, 1 to 255 times the digest size.
 @param salt The salt. @param input_key_material The input keying material. @param application_info
 The context, at most `hkdf_max_application_info_size` bytes; on `backends::webcrypto` at most
 1,024, WebCrypto's limit
 (`input_too_long` beyond). The spans are the caller's until completion.
 @param completion_token The completion token, of signature `void(boost::system::error_code)`.
 @return What the completion token's `async_result` gives. The completion's code is empty on
 success, or `hkdf`'s error, `output_key_material` untouched by a guard's refusal and zeroed by a
 backend's failure. On `backends::webcrypto` also `invalid_parameters` (the executor),
 `output_key_material` untouched, `backend_failure` (a rejected promise, an unexpected result, no
 WebCrypto), `output_key_material` zeroed, and `operation_aborted` (a `terminal` or `partial`
 cancellation, at once), `output_key_material` zeroed.
*/
template <class Hmac, class Backend = default_async_backend<kdfs::hkdf, Hmac>, class Executor,
          class CompletionToken>
auto async_hkdf(Executor const& completion_executor, std::span<std::uint8_t> output_key_material,
                std::span<std::uint8_t const> salt,
                std::span<std::uint8_t const> input_key_material,
                std::span<std::uint8_t const> application_info,
                CompletionToken&& completion_token) {
    if constexpr (!detail::webcrypto_hmac_v<Hmac>) {
        static_assert(detail::always_false<Hmac>,
                      "webcpp::hash: async_hkdf takes hmac_sha1_160, hmac_sha2_256, "
                      "hmac_sha2_384 or hmac_sha2_512, the hmacs WebCrypto has HKDF over: call "
                      "hkdf for the others.");
    } else if constexpr (detail::asynchronous_backend_v<Backend>) {
        return detail::async_engine<Backend>::template hkdf<Hmac>(
            completion_executor, output_key_material, salt, input_key_material, application_info,
            std::forward<CompletionToken>(completion_token));
    } else {
        return detail::complete_by_post(
            completion_executor, completion_token,
            [output_key_material, salt, input_key_material, application_info] {
                return hkdf<Hmac, Backend>(output_key_material, salt, input_key_material,
                                           application_info);
            });
    }
}

/**
 HKDF (RFC 5869), extract and expand, over pieces, asynchronously (spec 11): the output keying
 material of the `hkdf<Hmac, Backend>` over `byte_pieces`, with no cap on the application info.

 On a synchronous backend, the default, the synchronous function runs in the call itself, before
 the operation is initiated, and only its error code is posted to the handler's associated
 executor (`completion_executor` by default): the pieces and their list are read before the call
 returns, so that a braced list written at the call, whose array dies at the end of the call's
 full-expression, is safe with every completion token, `asio::deferred` and `use_awaitable`'s lazy
 awaitable included (with those, the work is done at the call, not at the launch). On
 `backends::webcrypto` the pieces are gathered into JavaScript memory in the call too.

 @code
 webcpp::hash::async_hkdf<webcpp::hash::hmac_sha2_256>(
     loop.get_executor(), key, salt, {version, suite_id, label, ikm},
     {length, version, suite_id, label, info}, [](boost::system::error_code code) { ... });
 @endcode

 @tparam Hmac `hmac_sha1_160`, `hmac_sha2_256`, `hmac_sha2_384` or `hmac_sha2_512`, the hmacs
 WebCrypto has HKDF over; another refuses at compile time (`hkdf` has them all).
 @tparam Backend The backend; by default @ref default_async_backend of `kdfs::hkdf_pieces`, the
 synchronous default. `backends::webcrypto` only on Emscripten.
 @tparam Executor An Asio executor, where the completion is posted.
 @tparam CompletionToken An Asio completion token of signature `void(boost::system::error_code)`.
 @param completion_executor The executor the completion is posted to; on `backends::webcrypto`, that
 of an `io_context` run on the calling thread (see @ref async_pbkdf2), and a refusal of another goes
 to the handler's associated executor, this one unless the handler is bound to another.
 @param output_key_material The output keying material, 1 to 255 times the digest size; the
 caller's until completion.
 @param salt The salt. @param input_key_material The input keying material's pieces.
 @param application_info The context's pieces. The salt and the pieces are read in the call.
 @param completion_token The completion token, of signature `void(boost::system::error_code)`.
 @return What the completion token's `async_result` gives. The completion's code is empty on
 success, or `hkdf`'s error over pieces, `output_key_material` untouched by a guard's refusal and
 zeroed by a backend's failure.
*/
template <class Hmac, class Backend = default_async_backend<kdfs::hkdf_pieces, Hmac>,
          class Executor, class CompletionToken>
auto async_hkdf(Executor const& completion_executor, std::span<std::uint8_t> output_key_material,
                std::span<std::uint8_t const> salt, byte_pieces input_key_material,
                byte_pieces application_info, CompletionToken&& completion_token) {
    if constexpr (!detail::webcrypto_hmac_v<Hmac>) {
        static_assert(detail::always_false<Hmac>,
                      "webcpp::hash: async_hkdf takes hmac_sha1_160, hmac_sha2_256, "
                      "hmac_sha2_384 or hmac_sha2_512, the hmacs WebCrypto has HKDF over: call "
                      "hkdf for the others.");
    } else if constexpr (detail::asynchronous_backend_v<Backend>) {
        return detail::async_engine<Backend>::template hkdf<Hmac>(
            completion_executor, output_key_material, salt, input_key_material, application_info,
            std::forward<CompletionToken>(completion_token));
    } else {
        auto const call_code = detail::code_of(
            hkdf<Hmac, Backend>(output_key_material, salt, input_key_material, application_info));
        return detail::complete_with_code(completion_executor, completion_token, call_code);
    }
}

/**
 HKDF-Extract (RFC 5869, section 2.2), asynchronously (spec 11), as @ref async_digest runs: the
 pseudorandom key of `hkdf_extract<Hmac, Backend>`, written into `pseudorandom_key`.

 @tparam Hmac `hmac_sha1_160`, `hmac_sha2_256`, `hmac_sha2_384` or `hmac_sha2_512`, the hmacs
 WebCrypto has HKDF over; another refuses at compile time (`hkdf_extract` has them all).
 @tparam Backend The backend; by default @ref default_async_backend of `kdfs::hkdf_extract`, the
 synchronous default. `backends::webcrypto` only on Emscripten.
 @tparam Executor An Asio executor, where the completion is posted.
 @tparam CompletionToken An Asio completion token of signature `void(boost::system::error_code)`.
 @param completion_executor The executor the completion is posted to; on `backends::webcrypto`, that
 of an `io_context` run on the calling thread (see @ref async_pbkdf2), and a refusal of another goes
 to the handler's associated executor, this one unless the handler is bound to another.
 @param pseudorandom_key The pseudorandom key, of exactly the digest size.
 @param salt The salt. @param input_key_material The input keying material. The spans are the
 caller's until completion.
 @param completion_token The completion token, of signature `void(boost::system::error_code)`.
 @return What the completion token's `async_result` gives. The completion's code is empty on
 success, or `invalid_output_size` for a `pseudorandom_key` of another size than the digest's, or
 `hkdf_extract`'s error, `pseudorandom_key` untouched by a guard's refusal and zeroed by a
 backend's failure.
*/
template <class Hmac, class Backend = default_async_backend<kdfs::hkdf_extract, Hmac>,
          class Executor, class CompletionToken>
auto async_hkdf_extract(Executor const& completion_executor,
                        std::span<std::uint8_t> pseudorandom_key,
                        std::span<std::uint8_t const> salt,
                        std::span<std::uint8_t const> input_key_material,
                        CompletionToken&& completion_token) {
    if constexpr (!detail::webcrypto_hmac_v<Hmac>) {
        static_assert(detail::always_false<Hmac>,
                      "webcpp::hash: async_hkdf_extract takes hmac_sha1_160, hmac_sha2_256, "
                      "hmac_sha2_384 or hmac_sha2_512, the hmacs WebCrypto has HKDF over: call "
                      "hkdf_extract for the others.");
    } else if constexpr (detail::asynchronous_backend_v<Backend>) {
        return detail::async_engine<Backend>::template hkdf_extract<Hmac>(
            completion_executor, pseudorandom_key, salt, input_key_material,
            std::forward<CompletionToken>(completion_token));
    } else {
        return detail::complete_by_post(completion_executor, completion_token,
                                        [pseudorandom_key, salt, input_key_material] {
                                            return detail::hkdf_extract_into<Hmac, Backend>(
                                                pseudorandom_key, salt, input_key_material);
                                        });
    }
}

/**
 HKDF-Extract (RFC 5869, section 2.2) over pieces, asynchronously (spec 11), as the
 @ref async_hkdf over pieces runs: the pseudorandom key of `hkdf_extract<Hmac, Backend>` over
 `byte_pieces`, written into `pseudorandom_key`, the pieces read in the call.

 @tparam Hmac `hmac_sha1_160`, `hmac_sha2_256`, `hmac_sha2_384` or `hmac_sha2_512`, the hmacs
 WebCrypto has HKDF over; another refuses at compile time (`hkdf_extract` has them all).
 @tparam Backend The backend; by default @ref default_async_backend of
 `kdfs::hkdf_extract_pieces`, the synchronous default. `backends::webcrypto` only on Emscripten.
 @tparam Executor An Asio executor, where the completion is posted.
 @tparam CompletionToken An Asio completion token of signature `void(boost::system::error_code)`.
 @param completion_executor The executor the completion is posted to; on `backends::webcrypto`, that
 of an `io_context` run on the calling thread (see @ref async_pbkdf2), and a refusal of another goes
 to the handler's associated executor, this one unless the handler is bound to another.
 @param pseudorandom_key The pseudorandom key, of exactly the digest size; the caller's until
 completion.
 @param salt The salt. @param input_key_material The input keying material's pieces. Both read in
 the call.
 @param completion_token The completion token, of signature `void(boost::system::error_code)`.
 @return What the completion token's `async_result` gives. The completion's code is empty on
 success, or `invalid_output_size` for a `pseudorandom_key` of another size than the digest's, or
 `hkdf_extract`'s error over pieces, `pseudorandom_key` untouched by a guard's refusal and zeroed
 by a backend's failure.
*/
template <class Hmac, class Backend = default_async_backend<kdfs::hkdf_extract_pieces, Hmac>,
          class Executor, class CompletionToken>
auto async_hkdf_extract(Executor const& completion_executor,
                        std::span<std::uint8_t> pseudorandom_key,
                        std::span<std::uint8_t const> salt, byte_pieces input_key_material,
                        CompletionToken&& completion_token) {
    if constexpr (!detail::webcrypto_hmac_v<Hmac>) {
        static_assert(detail::always_false<Hmac>,
                      "webcpp::hash: async_hkdf_extract takes hmac_sha1_160, hmac_sha2_256, "
                      "hmac_sha2_384 or hmac_sha2_512, the hmacs WebCrypto has HKDF over: call "
                      "hkdf_extract for the others.");
    } else if constexpr (detail::asynchronous_backend_v<Backend>) {
        return detail::async_engine<Backend>::template hkdf_extract<Hmac>(
            completion_executor, pseudorandom_key, salt, input_key_material,
            std::forward<CompletionToken>(completion_token));
    } else {
        auto const call_code = detail::code_of(
            detail::hkdf_extract_into<Hmac, Backend>(pseudorandom_key, salt, input_key_material));
        return detail::complete_with_code(completion_executor, completion_token, call_code);
    }
}

/**
 HKDF-Expand (RFC 5869, section 2.3), asynchronously (spec 11), as @ref async_digest runs: the
 output keying material of `hkdf_expand<Hmac, Backend>`.

 @tparam Hmac `hmac_sha1_160`, `hmac_sha2_256`, `hmac_sha2_384` or `hmac_sha2_512`, the hmacs
 WebCrypto has HKDF over; another refuses at compile time (`hkdf_expand` has them all).
 @tparam Backend The backend; by default @ref default_async_backend of `kdfs::hkdf_expand`, the
 synchronous default. `backends::webcrypto` only on Emscripten.
 @tparam Executor An Asio executor, where the completion is posted.
 @tparam CompletionToken An Asio completion token of signature `void(boost::system::error_code)`.
 @param completion_executor The executor the completion is posted to; on `backends::webcrypto`, that
 of an `io_context` run on the calling thread (see @ref async_pbkdf2), and a refusal of another goes
 to the handler's associated executor, this one unless the handler is bound to another.
 @param output_key_material The output keying material, 1 to 255 times the digest size.
 @param pseudorandom_key The pseudorandom key, of exactly the digest size.
 @param application_info The context, at most `hkdf_max_application_info_size` bytes. The spans
 are the caller's until completion.
 @param completion_token The completion token, of signature `void(boost::system::error_code)`.
 @return What the completion token's `async_result` gives. The completion's code is empty on
 success, or `hkdf_expand`'s error, `output_key_material` untouched by a guard's refusal and
 zeroed by a backend's failure.
*/
template <class Hmac, class Backend = default_async_backend<kdfs::hkdf_expand, Hmac>,
          class Executor, class CompletionToken>
auto async_hkdf_expand(Executor const& completion_executor,
                       std::span<std::uint8_t> output_key_material,
                       std::span<std::uint8_t const> pseudorandom_key,
                       std::span<std::uint8_t const> application_info,
                       CompletionToken&& completion_token) {
    if constexpr (!detail::webcrypto_hmac_v<Hmac>) {
        static_assert(detail::always_false<Hmac>,
                      "webcpp::hash: async_hkdf_expand takes hmac_sha1_160, hmac_sha2_256, "
                      "hmac_sha2_384 or hmac_sha2_512, the hmacs WebCrypto has HKDF over: call "
                      "hkdf_expand for the others.");
    } else if constexpr (detail::asynchronous_backend_v<Backend>) {
        return detail::async_engine<Backend>::template hkdf_expand<Hmac>(
            completion_executor, output_key_material, pseudorandom_key, application_info,
            std::forward<CompletionToken>(completion_token));
    } else {
        return detail::complete_by_post(completion_executor, completion_token,
                                        [output_key_material, pseudorandom_key, application_info] {
                                            return hkdf_expand<Hmac, Backend>(output_key_material,
                                                                              pseudorandom_key,
                                                                              application_info);
                                        });
    }
}

/**
 HKDF-Expand (RFC 5869, section 2.3) over pieces, asynchronously (spec 11), as the
 @ref async_hkdf over pieces runs: the output keying material of `hkdf_expand<Hmac, Backend>` over
 `byte_pieces`, with no cap on the application info, the pieces read in the call.

 @tparam Hmac `hmac_sha1_160`, `hmac_sha2_256`, `hmac_sha2_384` or `hmac_sha2_512`, the hmacs
 WebCrypto has HKDF over; another refuses at compile time (`hkdf_expand` has them all).
 @tparam Backend The backend; by default @ref default_async_backend of
 `kdfs::hkdf_expand_pieces`, the synchronous default. `backends::webcrypto` only on Emscripten.
 @tparam Executor An Asio executor, where the completion is posted.
 @tparam CompletionToken An Asio completion token of signature `void(boost::system::error_code)`.
 @param completion_executor The executor the completion is posted to; on `backends::webcrypto`, that
 of an `io_context` run on the calling thread (see @ref async_pbkdf2), and a refusal of another goes
 to the handler's associated executor, this one unless the handler is bound to another.
 @param output_key_material The output keying material, 1 to 255 times the digest size; the
 caller's until completion.
 @param pseudorandom_key The pseudorandom key, of exactly the digest size.
 @param application_info The context's pieces. The key and the pieces are read in the call.
 @param completion_token The completion token, of signature `void(boost::system::error_code)`.
 @return What the completion token's `async_result` gives. The completion's code is empty on
 success, or `hkdf_expand`'s error over pieces, `output_key_material` untouched by a guard's
 refusal and zeroed by a backend's failure.
*/
template <class Hmac, class Backend = default_async_backend<kdfs::hkdf_expand_pieces, Hmac>,
          class Executor, class CompletionToken>
auto async_hkdf_expand(Executor const& completion_executor,
                       std::span<std::uint8_t> output_key_material,
                       std::span<std::uint8_t const> pseudorandom_key, byte_pieces application_info,
                       CompletionToken&& completion_token) {
    if constexpr (!detail::webcrypto_hmac_v<Hmac>) {
        static_assert(detail::always_false<Hmac>,
                      "webcpp::hash: async_hkdf_expand takes hmac_sha1_160, hmac_sha2_256, "
                      "hmac_sha2_384 or hmac_sha2_512, the hmacs WebCrypto has HKDF over: call "
                      "hkdf_expand for the others.");
    } else if constexpr (detail::asynchronous_backend_v<Backend>) {
        return detail::async_engine<Backend>::template hkdf_expand<Hmac>(
            completion_executor, output_key_material, pseudorandom_key, application_info,
            std::forward<CompletionToken>(completion_token));
    } else {
        auto const call_code = detail::code_of(
            hkdf_expand<Hmac, Backend>(output_key_material, pseudorandom_key, application_info));
        return detail::complete_with_code(completion_executor, completion_token, call_code);
    }
}

/**
 PBKDF2 (RFC 8018), asynchronously.

 On a synchronous backend, the default, a heavy function (spec 11.5): the work runs on a thread of
 `work_executor`'s context (a `webcpp::asio::thread_pool`'s) and completes on the handler's
 associated executor (`work_executor` by default; a program binds its event loop's with
 `bind_executor`), and it exists only where the build has threads (`WEBCPP_HASH_HAS_THREADS`). On
 `backends::webcrypto`, on Emscripten, the browser runs it and no thread is needed: there
 `work_executor` must be that of an `io_context` run on the calling thread, whose `run` returns to
 the JavaScript event loop where WebCrypto's promise settles (ruling R73). The context is checked: a
 concrete executor of another context (a `thread_pool`'s) stops the build, and a type-erased one
 (`any_io_executor`) whose context is not an `io_context`, or whose `io_context` executor it hides
 behind another allocator or two concrete strands, completes with `invalid_parameters`, posted to
 the handler's associated executor. The calling thread is the program's duty, not checked. WebCrypto
 takes at most 2^32 - 1 iterations (`invalid_iterations`) and an output of at most (2^32 - 1) / 8
 bytes
 (`invalid_output_size`), over `hmac_sha1_160`, `hmac_sha2_256`, `hmac_sha2_384` and `hmac_sha2_512`
 alone.

 Cancellation through the handler's slot, on a synchronous backend: before the work starts, any
 type completes the operation at once with `operation_aborted`, the work never runs; during it, a
 `terminal` or `partial` one lets the work end, then `output_bytes` is zeroed and the completion is
 `operation_aborted` (a `total` one is then ignored). "At once" is on the handler's associated
 executor: for a handler without one, that is `work_executor`, so the completion waits for its
 threads; bind the handler to the event loop's executor, and emit the signal there too, never
 from another thread, as Asio's slots require. On `backends::webcrypto` a `terminal` or `partial`
 one completes at once with `operation_aborted`, `output_bytes` zeroed, while the browser's work
 runs to its end unseen; a `total` one is ignored.

 @tparam Hmac The pseudorandom function, as `hmac_sha2_512`.
 @tparam Backend The backend; by default @ref default_async_backend of `kdfs::pbkdf2`, the
 synchronous default.
 @tparam Executor An Asio executor: of the threads the work runs on, or WebCrypto's
 `io_context`'s.
 @tparam CompletionToken An Asio completion token of signature `void(boost::system::error_code)`.
 @param work_executor The work executor, or WebCrypto's `io_context` executor.
 @param output_bytes The derived key, 1 to (2^32 - 1) times the digest size.
 @param password_bytes The password. @param salt_bytes The salt. The spans are the caller's until
 completion.
 @param iteration_count The iteration count, at least 1.
 @param completion_token The completion token, of signature `void(boost::system::error_code)`.
 @return What the completion token's `async_result` gives. The completion's code is empty on
 success, or `pbkdf2`'s error, a guard's refusal completing through a post, `output_bytes`
 untouched; or `operation_aborted`. On `backends::webcrypto` also `invalid_parameters` (the
 executor), `output_bytes` untouched, and `backend_failure` (a rejected promise, an unexpected
 result, no WebCrypto), `output_bytes` zeroed.
*/
template <class Hmac, class Backend = default_async_backend<kdfs::pbkdf2, Hmac>, class Executor,
          class CompletionToken>
auto async_pbkdf2(Executor const& work_executor, std::span<std::uint8_t> output_bytes,
                  std::span<std::uint8_t const> password_bytes,
                  std::span<std::uint8_t const> salt_bytes, std::uint64_t iteration_count,
                  CompletionToken&& completion_token) {
    if constexpr (detail::asynchronous_backend_v<Backend>) {
        return detail::async_engine<Backend>::template pbkdf2<Hmac>(
            work_executor, output_bytes, password_bytes, salt_bytes, iteration_count,
            std::forward<CompletionToken>(completion_token));
    } else {
#ifdef WEBCPP_HASH_HAS_THREADS
        return detail::run_on_work(
            work_executor, std::as_writable_bytes(output_bytes),
            [output_size = output_bytes.size(), password_size = password_bytes.size(),
             salt_size = salt_bytes.size(), iteration_count] {
                if constexpr (!detail::takes_hmac<Hmac>()) {
                    return boost::system::result<void>(error::backend_failure);
                } else {
                    return detail::pbkdf2_guards<Hmac, Backend>(output_size, password_size,
                                                                salt_size, iteration_count);
                }
            },
            [output_bytes, password_bytes, salt_bytes, iteration_count] {
                return pbkdf2<Hmac, Backend>(output_bytes, password_bytes, salt_bytes,
                                             iteration_count);
            },
            completion_token);
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
 Argon2id (RFC 9106, one lane) on a thread of `work_executor`'s context (spec 11.5).

 The guards of `argon2id` first, whose refusal completes through a post; then the work, posted to
 `work_executor` (a `webcpp::asio::thread_pool`'s executor, typically); the completion on the
 handler's associated executor (`work_executor` by default; a program binds its event loop's with
 `bind_executor`), so that the event loop never blocks. Exists only where the build has threads
 (`WEBCPP_HASH_HAS_THREADS`).

 Cancellation through the handler's slot: before the work starts, any type completes the
 operation at once with `operation_aborted`, the work never runs; during it, a `terminal` or
 `partial` one lets the work end (libsodium cannot be interrupted), then `output_bytes` is zeroed
 and the completion is `operation_aborted` (a `total` one is then ignored: zeroing is a side
 effect). "At once" is on the handler's associated executor: for a handler without one, that is
 `work_executor`, so the completion waits for its threads; bind the handler to the event loop's
 executor, and emit the signal there too, never from another thread, as Asio's slots require.

 @tparam Backend The backend; by default @ref default_backend of `kdfs::argon2id`.
 @tparam WorkExecutor An Asio executor whose context runs on other threads.
 @tparam CompletionToken An Asio completion token of signature `void(boost::system::error_code)`.
 @param work_executor The executor of the threads the work runs on.
 @param output_bytes The tag, 16 to 4,294,967,295 bytes. @param password_bytes The password.
 @param salt_bytes The salt, of `argon2id_salt_size` bytes. The spans are the caller's until
 completion.
 @param cost_parameters The costs, copied.
 @param completion_token The completion token, of signature `void(boost::system::error_code)`.
 @return What the completion token's `async_result` gives. The completion's code is empty on
 success, or `argon2id`'s error, or `operation_aborted`.
*/
template <class Backend = default_backend<kdfs::argon2id>, class WorkExecutor,
          class CompletionToken>
auto async_argon2id(WorkExecutor const& work_executor, std::span<std::uint8_t> output_bytes,
                    std::span<std::uint8_t const> password_bytes,
                    std::span<std::uint8_t const> salt_bytes,
                    argon2id_parameters const& cost_parameters,
                    CompletionToken&& completion_token) {
    return detail::run_on_work(
        work_executor, std::as_writable_bytes(output_bytes),
        [output_size = output_bytes.size(), password_size = password_bytes.size(),
         salt_size = salt_bytes.size(), cost_parameters] {
            return detail::argon2id_guards<Backend>(output_size, password_size, salt_size,
                                                    cost_parameters);
        },
        [output_bytes, password_bytes, salt_bytes, cost_parameters] {
            return argon2id<Backend>(output_bytes, password_bytes, salt_bytes, cost_parameters);
        },
        completion_token);
}

/**
 Argon2 of the variant `Variant` with every parameter (RFC 9106) on a thread of `work_executor`'s
 context, as @ref async_argon2id runs.

 @tparam Variant `kdfs::argon2id`, `kdfs::argon2i` or `kdfs::argon2d`.
 @tparam Backend The backend; by default @ref default_backend of `Variant`.
 @tparam WorkExecutor An Asio executor whose context runs on other threads.
 @tparam CompletionToken An Asio completion token of signature `void(boost::system::error_code)`.
 @param work_executor The executor of the threads the work runs on.
 @param output_bytes The tag, 4 to 4,294,967,295 bytes. @param password_bytes The password.
 @param salt_bytes The salt, 8 to 4,294,967,295 bytes. The spans, and those of `cost_parameters`,
 are the caller's until completion.
 @param cost_parameters The costs, the lanes, the secret and the associated data, copied.
 @param completion_token The completion token, of signature `void(boost::system::error_code)`.
 @return What the completion token's `async_result` gives. The completion's code is empty on
 success, or `argon2`'s error, or `operation_aborted`.
*/
template <class Variant, class Backend = default_backend<Variant>, class WorkExecutor,
          class CompletionToken>
auto async_argon2(WorkExecutor const& work_executor, std::span<std::uint8_t> output_bytes,
                  std::span<std::uint8_t const> password_bytes,
                  std::span<std::uint8_t const> salt_bytes,
                  argon2_parameters const& cost_parameters, CompletionToken&& completion_token) {
    return detail::run_on_work(
        work_executor, std::as_writable_bytes(output_bytes),
        [output_size = output_bytes.size(), password_size = password_bytes.size(),
         salt_size = salt_bytes.size(), cost_parameters] {
            return detail::argon2_guards<Variant, Backend>(output_size, password_size, salt_size,
                                                           cost_parameters);
        },
        [output_bytes, password_bytes, salt_bytes, cost_parameters] {
            return argon2<Variant, Backend>(output_bytes, password_bytes, salt_bytes,
                                            cost_parameters);
        },
        completion_token);
}

/**
 scrypt (RFC 7914) on a thread of `work_executor`'s context, as @ref async_argon2id runs.

 @tparam Backend The backend; by default @ref default_backend of `kdfs::scrypt`.
 @tparam WorkExecutor An Asio executor whose context runs on other threads.
 @tparam CompletionToken An Asio completion token of signature `void(boost::system::error_code)`.
 @param work_executor The executor of the threads the work runs on.
 @param output_bytes The derived key. @param password_bytes The password. @param salt_bytes The
 salt. The spans are the caller's until completion.
 @param cost_parameters The costs, copied.
 @param completion_token The completion token, of signature `void(boost::system::error_code)`.
 @return What the completion token's `async_result` gives. The completion's code is empty on
 success, or `scrypt`'s error, or `operation_aborted`.
*/
template <class Backend = default_backend<kdfs::scrypt>, class WorkExecutor, class CompletionToken>
auto async_scrypt(WorkExecutor const& work_executor, std::span<std::uint8_t> output_bytes,
                  std::span<std::uint8_t const> password_bytes,
                  std::span<std::uint8_t const> salt_bytes,
                  scrypt_parameters const& cost_parameters, CompletionToken&& completion_token) {
    return detail::run_on_work(
        work_executor, std::as_writable_bytes(output_bytes),
        [output_size = output_bytes.size(), password_size = password_bytes.size(),
         salt_size = salt_bytes.size(), cost_parameters] {
            return detail::scrypt_guards<Backend>(output_size, password_size, salt_size,
                                                  cost_parameters);
        },
        [output_bytes, password_bytes, salt_bytes, cost_parameters] {
            return scrypt<Backend>(output_bytes, password_bytes, salt_bytes, cost_parameters);
        },
        completion_token);
}

/**
 bcrypt on a thread of `work_executor`'s context (spec 11.5), as @ref async_argon2id runs: the
 guards of `bcrypt` first, whose refusal completes through a post, `output_characters` untouched;
 then the work.

 @tparam Backend The backend; @ref default_backend of `kdfs::bcrypt` has none: the call names
 `backends::botan`.
 @tparam WorkExecutor An Asio executor whose context runs on other threads.
 @tparam CompletionToken An Asio completion token of signature `void(boost::system::error_code)`.
 @param work_executor The executor of the threads the work runs on.
 @param output_characters The string, exactly `bcrypt_hash_size` characters. @param password_bytes
 The password.
 @param salt_bytes The salt, of `bcrypt_salt_size` bytes. The spans are the caller's until
 completion.
 @param cost_parameters The cost and the version, copied.
 @param completion_token The completion token, of signature `void(boost::system::error_code)`.
 @return What the completion token's `async_result` gives. The completion's code is empty on
 success, or `bcrypt`'s error, or `operation_aborted` (a cancellation during the work zeroes
 `output_characters`).
*/
template <class Backend = default_backend<kdfs::bcrypt>, class WorkExecutor, class CompletionToken>
auto async_bcrypt(WorkExecutor const& work_executor, std::span<char> output_characters,
                  std::span<std::uint8_t const> password_bytes,
                  std::span<std::uint8_t const> salt_bytes,
                  bcrypt_parameters const& cost_parameters, CompletionToken&& completion_token) {
    return detail::run_on_work(
        work_executor, std::as_writable_bytes(output_characters),
        [output_size = output_characters.size(), password_bytes, salt_size = salt_bytes.size(),
         cost_parameters] {
            return detail::bcrypt_guards<Backend>(output_size, password_bytes, salt_size,
                                                  cost_parameters);
        },
        [output_characters, password_bytes, salt_bytes, cost_parameters] {
            return bcrypt<Backend>(output_characters, password_bytes, salt_bytes, cost_parameters);
        },
        completion_token);
}

/**
 OpenBSD's bcrypt_pbkdf on a thread of `work_executor`'s context, as @ref async_argon2id runs.

 @tparam Backend The backend; @ref default_backend of `kdfs::bcrypt_pbkdf` has none: the call
 names `backends::botan`.
 @tparam WorkExecutor An Asio executor whose context runs on other threads.
 @tparam CompletionToken An Asio completion token of signature `void(boost::system::error_code)`.
 @param work_executor The executor of the threads the work runs on.
 @param output_bytes The derived key, 1 to 1,024 bytes. @param password_bytes The password, 1 byte
 or more.
 @param salt_bytes The salt, 1 to 1,048,576 bytes. The spans are the caller's until completion.
 @param round_count The rounds, 1 or more.
 @param completion_token The completion token, of signature `void(boost::system::error_code)`.
 @return What the completion token's `async_result` gives. The completion's code is empty on
 success, or `bcrypt_pbkdf`'s error, or `operation_aborted`.
*/
template <class Backend = default_backend<kdfs::bcrypt_pbkdf>, class WorkExecutor,
          class CompletionToken>
auto async_bcrypt_pbkdf(WorkExecutor const& work_executor, std::span<std::uint8_t> output_bytes,
                        std::span<std::uint8_t const> password_bytes,
                        std::span<std::uint8_t const> salt_bytes, std::uint32_t round_count,
                        CompletionToken&& completion_token) {
    return detail::run_on_work(
        work_executor, std::as_writable_bytes(output_bytes),
        [output_size = output_bytes.size(), password_size = password_bytes.size(),
         salt_size = salt_bytes.size(), round_count] {
            return detail::bcrypt_pbkdf_guards(output_size, password_size, salt_size, round_count);
        },
        [output_bytes, password_bytes, salt_bytes, round_count] {
            return bcrypt_pbkdf<Backend>(output_bytes, password_bytes, salt_bytes, round_count);
        },
        completion_token);
}

/**
 `bcrypt_verify` on a thread of `work_executor`'s context, as @ref async_argon2id runs, completing
 with whether the password gives the string: it computes bcrypt in full, as slow as `bcrypt`
 (spec 11.5: every deliberately slow function has its heavy variant).

 @tparam Backend The backend; the call names `backends::botan`, as for @ref async_bcrypt.
 @tparam WorkExecutor An Asio executor whose context runs on other threads.
 @tparam CompletionToken An Asio completion token of signature
 `void(boost::system::error_code, bool)`.
 @param work_executor The executor of the threads the work runs on.
 @param password_bytes The password. @param encoded_hash The string, of bcrypt's form. Both are the
 caller's until completion.
 @param completion_token The completion token, of signature `void(boost::system::error_code, bool)`.
 @return What the completion token's `async_result` gives. The completion's code is empty on
 success, its `bool` then whether the password gives the string; or `bcrypt_verify`'s error, or
 `operation_aborted`, the `bool` false.
*/
template <class Backend = default_backend<kdfs::bcrypt>, class WorkExecutor, class CompletionToken>
auto async_bcrypt_verify(WorkExecutor const& work_executor,
                         std::span<std::uint8_t const> password_bytes,
                         std::string_view encoded_hash, CompletionToken&& completion_token) {
    return detail::run_on_work(
        work_executor, std::span<std::byte>{},
        [password_bytes, encoded_hash] {
            return detail::bcrypt_verify_guards<Backend>(password_bytes, encoded_hash);
        },
        [password_bytes, encoded_hash] {
            return bcrypt_verify<Backend>(password_bytes, encoded_hash);
        },
        completion_token);
}

#else

/**
 Argon2id on another thread, which a build without threads does not have: a call refuses at
 compile time, naming `argon2id`.

 @tparam Backend The backend. @return Nothing: the refusal has stopped the build.
*/
template <class Backend = default_backend<kdfs::argon2id>, class WorkExecutor,
          class CompletionToken>
void async_argon2id(WorkExecutor const& /*work_executor*/, std::span<std::uint8_t> /*output_bytes*/,
                    std::span<std::uint8_t const> /*password_bytes*/,
                    std::span<std::uint8_t const> /*salt_bytes*/,
                    argon2id_parameters const& /*cost_parameters*/,
                    CompletionToken&& /*completion_token*/) {
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
void async_argon2(WorkExecutor const& /*work_executor*/, std::span<std::uint8_t> /*output_bytes*/,
                  std::span<std::uint8_t const> /*password_bytes*/,
                  std::span<std::uint8_t const> /*salt_bytes*/,
                  argon2_parameters const& /*cost_parameters*/,
                  CompletionToken&& /*completion_token*/) {
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
void async_scrypt(WorkExecutor const& /*work_executor*/, std::span<std::uint8_t> /*output_bytes*/,
                  std::span<std::uint8_t const> /*password_bytes*/,
                  std::span<std::uint8_t const> /*salt_bytes*/,
                  scrypt_parameters const& /*cost_parameters*/,
                  CompletionToken&& /*completion_token*/) {
    static_assert(detail::always_false<Backend>,
                  "webcpp::hash: async_scrypt runs on another thread and needs a build with "
                  "threads (natively, remove WEBCPP_HASH_NO_THREADS; on Emscripten, link with "
                  "-pthread). Without threads, call scrypt.");
}

/**
 bcrypt on another thread, which a build without threads does not have: a call refuses at compile
 time, naming `bcrypt`.

 @tparam Backend The backend. @return Nothing: the refusal has stopped the build.
*/
template <class Backend = default_backend<kdfs::bcrypt>, class WorkExecutor, class CompletionToken>
void async_bcrypt(WorkExecutor const& /*work_executor*/, std::span<char> /*output_characters*/,
                  std::span<std::uint8_t const> /*password_bytes*/,
                  std::span<std::uint8_t const> /*salt_bytes*/,
                  bcrypt_parameters const& /*cost_parameters*/,
                  CompletionToken&& /*completion_token*/) {
    static_assert(detail::always_false<Backend>,
                  "webcpp::hash: async_bcrypt runs on another thread and needs a build with "
                  "threads (natively, remove WEBCPP_HASH_NO_THREADS; on Emscripten, link with "
                  "-pthread). Without threads, call bcrypt.");
}

/**
 bcrypt_pbkdf on another thread, which a build without threads does not have: a call refuses at
 compile time, naming `bcrypt_pbkdf`.

 @tparam Backend The backend. @return Nothing: the refusal has stopped the build.
*/
template <class Backend = default_backend<kdfs::bcrypt_pbkdf>, class WorkExecutor,
          class CompletionToken>
void async_bcrypt_pbkdf(WorkExecutor const& /*work_executor*/,
                        std::span<std::uint8_t> /*output_bytes*/,
                        std::span<std::uint8_t const> /*password_bytes*/,
                        std::span<std::uint8_t const> /*salt_bytes*/, std::uint32_t /*round_count*/,
                        CompletionToken&& /*completion_token*/) {
    static_assert(detail::always_false<Backend>,
                  "webcpp::hash: async_bcrypt_pbkdf runs on another thread and needs a build with "
                  "threads (natively, remove WEBCPP_HASH_NO_THREADS; on Emscripten, link with "
                  "-pthread). Without threads, call bcrypt_pbkdf.");
}

/**
 bcrypt_verify on another thread, which a build without threads does not have: a call refuses at
 compile time, naming `bcrypt_verify`.

 @tparam Backend The backend. @return Nothing: the refusal has stopped the build.
*/
template <class Backend = default_backend<kdfs::bcrypt>, class WorkExecutor, class CompletionToken>
void async_bcrypt_verify(WorkExecutor const& /*work_executor*/,
                         std::span<std::uint8_t const> /*password_bytes*/,
                         std::string_view /*encoded_hash*/,
                         CompletionToken&& /*completion_token*/) {
    static_assert(detail::always_false<Backend>,
                  "webcpp::hash: async_bcrypt_verify runs on another thread and needs a build "
                  "with threads (natively, remove WEBCPP_HASH_NO_THREADS; on Emscripten, link "
                  "with -pthread). Without threads, call bcrypt_verify.");
}

#endif

}  // namespace webcpp::hash

// backends::webcrypto's engine on Emscripten, and its limits on every target. That header includes
// this one first, so that a program may include either.
#include <webcpp/hash/backends/webcrypto.hpp>

#endif  // WEBCPP_HASH_ASYNC_HPP
