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
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <thread>
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

     @param handler The completion handler. @param work The work executor.
     @param run The synchronous function, bound to its arguments. @param output The output.
     @return The state.
    */
    static heavy_state* make(Handler handler, WorkExecutor const& work, Work run,
                             std::span<std::uint8_t> output) {
        allocator_type allocator(webcpp::asio::get_associated_allocator(handler));
        auto* const storage = std::allocator_traits<allocator_type>::allocate(allocator, 1);
        try_construct(allocator, storage, std::move(handler), work, std::move(run), output);
        return storage;
    }

    /** Installs the cancellation handler, when the handler's slot is connected. */
    void install_cancellation() {
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access): engaged until the completion
        auto slot = webcpp::asio::get_associated_cancellation_slot(*handler_);
        if (slot.is_connected()) {
            slot.template emplace<cancellation>(this);
        }
    }

    /**
     Records where the job holds the state, or that it holds it no longer (null).

     @param location The job's atomic pointer.
    */
    void relocate(std::atomic<heavy_state*>* location) noexcept {
        lock();
        location_ = location;
        unlock();
    }

    /** The job's turn on the work executor's thread, the state taken out of the job. */
    void run_work() {
        relocate(nullptr);
        auto expected = heavy_phase::queued;
        if (!phase_.compare_exchange_strong(expected, heavy_phase::running,
                                            std::memory_order_acq_rel)) {
            // A cancellation won, and found the job holding the state no more: complete for it.
            complete_on_handler(webcpp::asio::error::operation_aborted);
            return;
        }
        auto code = code_of(run_());
        if (cancelled_.load(std::memory_order_acquire)) {
            wipe(output_);
            code = webcpp::asio::error::operation_aborted;
        }
        phase_.store(heavy_phase::finished, std::memory_order_release);
        complete_on_handler(code);
    }

    /** The job destroyed unrun (its executor shut down): the handler is destroyed, never called. */
    void abandon() {
        relocate(nullptr);
        auto expected = heavy_phase::queued;
        if (!phase_.compare_exchange_strong(expected, heavy_phase::finished,
                                            std::memory_order_acq_rel)) {
            complete_on_handler(webcpp::asio::error::operation_aborted);
            return;
        }
        auto const executor = handler_work_.get_executor();
        webcpp::asio::post(executor, discard{this});
    }

    /** A cancellation of type `type`, on the handler's executor, where the signal is emitted. */
    void cancel(webcpp::asio::cancellation_type_t type) {
        auto expected = heavy_phase::queued;
        if (phase_.compare_exchange_strong(expected, heavy_phase::finished,
                                           std::memory_order_acq_rel)) {
            // Take the state back from the queued job; a job that has just taken it out itself
            // completes for this cancellation instead.
            bool taken = false;
            lock();
            if (location_ != nullptr) {
                taken = location_->exchange(nullptr, std::memory_order_acq_rel) != nullptr;
                location_ = nullptr;
            }
            unlock();
            if (taken) {
                auto const executor = handler_work_.get_executor();
                webcpp::asio::post(executor,
                                   bound_completion(webcpp::asio::error::operation_aborted));
            }
            return;
        }
        using webcpp::asio::cancellation_type;
        if ((type & (cancellation_type::terminal | cancellation_type::partial)) !=
            cancellation_type::none) {
            cancelled_.store(true, std::memory_order_release);
        }
    }

private:
    // The handler installed in the cancellation slot; the completion clears the slot before the
    // state is destroyed.
    class cancellation {
    public:
        explicit cancellation(heavy_state* state) noexcept : state_(state) {}

        void operator()(webcpp::asio::cancellation_type_t type) { state_->cancel(type); }

    private:
        heavy_state* state_;
    };

    // The completion, on the handler's executor, its storage the handler's allocator's.
    class completion {
    public:
        completion(heavy_state* state, boost::system::error_code code) noexcept
            : state_(state), code_(code) {}

        void operator()() { state_->complete(code_); }

    private:
        heavy_state* state_;
        boost::system::error_code code_;
    };

    // The end of an operation whose job was destroyed unrun: the state destroyed, the handler with
    // it, on the handler's executor, where the slot can be cleared.
    class discard {
    public:
        explicit discard(heavy_state* state) noexcept : state_(state) {}

        void operator()() { state_->destroy(); }

    private:
        heavy_state* state_;
    };

    heavy_state(Handler handler, WorkExecutor const& work, Work run, std::span<std::uint8_t> output)
        : handler_work_(
              webcpp::asio::make_work_guard(webcpp::asio::get_associated_executor(handler, work))),
          handler_(std::in_place, std::move(handler)),
          run_(std::move(run)),
          output_(output) {}

    // Constructs the state in `storage`, which is given back if the construction throws.
    static void try_construct(allocator_type& allocator, heavy_state* storage, Handler handler,
                              WorkExecutor const& work, Work run, std::span<std::uint8_t> output) {
        struct give_back {
            allocator_type& allocator;
            heavy_state* storage;

            ~give_back() {
                if (storage != nullptr) {
                    std::allocator_traits<allocator_type>::deallocate(allocator, storage, 1);
                }
            }
        } guard{allocator, storage};

        ::new (static_cast<void*>(storage))
            heavy_state(std::move(handler), work, std::move(run), output);
        guard.storage = nullptr;
    }

    void lock() noexcept {
        while (lock_.test_and_set(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
    }

    void unlock() noexcept { lock_.clear(std::memory_order_release); }

    // The completion bound to the handler's associated allocator.
    auto bound_completion(boost::system::error_code code) {
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access): engaged until the completion
        return webcpp::asio::bind_allocator(webcpp::asio::get_associated_allocator(*handler_),
                                            completion(this, code));
    }

    // Dispatches the completion to the handler's executor; the caller touches the state no more.
    void complete_on_handler(boost::system::error_code code) {
        auto const executor = handler_work_.get_executor();
        webcpp::asio::dispatch(executor, bound_completion(code));
    }

    // Clears the slot, takes the handler and the executor's work out, frees the state, then calls
    // the handler: nothing of the handler's allocator outlives the call.
    void complete(boost::system::error_code code) {
        clear_slot();
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access): engaged until here
        Handler handler(std::move(*handler_));
        auto work = std::move(handler_work_);
        allocator_type allocator(webcpp::asio::get_associated_allocator(handler));
        release_storage(allocator);
        std::move(handler)(code);
        work.reset();
    }

    // Clears the slot, then destroys the state, the handler with it, and gives its storage back.
    void destroy() {
        clear_slot();
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access): engaged until here
        allocator_type allocator(webcpp::asio::get_associated_allocator(*handler_));
        release_storage(allocator);
    }

    // Removes the cancellation handler, on the handler's executor, before the state goes.
    void clear_slot() {
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access): engaged until here
        auto slot = webcpp::asio::get_associated_cancellation_slot(*handler_);
        if (slot.is_connected()) {
            slot.clear();
        }
    }

    // Destroys the state and gives its storage back to a copy of the handler's allocator.
    void release_storage(allocator_type& allocator) {
        std::allocator_traits<allocator_type>::destroy(allocator, this);
        std::allocator_traits<allocator_type>::deallocate(allocator, this, 1);
    }

    std::atomic_flag lock_ = ATOMIC_FLAG_INIT;
    std::atomic<heavy_state*>* location_ = nullptr;
    std::atomic<heavy_phase> phase_{heavy_phase::queued};
    std::atomic<bool> cancelled_{false};
    webcpp::asio::executor_work_guard<executor_type> handler_work_;
    std::optional<Handler> handler_;
    Work run_;
    std::span<std::uint8_t> output_;
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
     Holds `state`, before the state can be cancelled.

     @param state The operation's state.
    */
    explicit heavy_job(State* state) noexcept : state_(state) { state->relocate(&state_); }

    /**
     Takes `other`'s hold, and records the new location; a hold taken back by a cancellation is
     null, and the state is then touched no more.

     @param other The job moved from.
    */
    heavy_job(heavy_job&& other) noexcept
        : state_(other.state_.exchange(nullptr, std::memory_order_acq_rel)) {
        if (auto* const held = state_.load(std::memory_order_relaxed); held != nullptr) {
            held->relocate(&state_);
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
        if (auto* const held = state_.exchange(nullptr, std::memory_order_acq_rel);
            held != nullptr) {
            held->abandon();
        }
    }

    /** Runs the work on the work executor's thread, unless a cancellation took the state back. */
    void operator()() {
        if (auto* const held = state_.exchange(nullptr, std::memory_order_acq_rel);
            held != nullptr) {
            held->run_work();
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

     @param handler The completion handler. @param work The work executor.
     @param output The output. @param guards The guards, bound to the arguments.
     @param run The synchronous function, bound to its arguments.
    */
    template <class Handler, class WorkExecutor, class Guards, class Work>
    void operator()(Handler&& handler, WorkExecutor const& work, std::span<std::uint8_t> output,
                    Guards const& guards, Work run) const {
        auto const guarded = guards();
        if (!guarded) {
            auto const executor = webcpp::asio::get_associated_executor(handler, work);
            webcpp::asio::post(
                executor, webcpp::asio::append(std::forward<Handler>(handler), guarded.error()));
            return;
        }
        using state = heavy_state<std::decay_t<Handler>, WorkExecutor, Work>;
        // The job holds the state from its making on, so that a failure to install the
        // cancellation or to post abandons it rather than leak it with the executor's work.
        auto* const made =
            state::make(std::forward<Handler>(handler), work, std::move(run), output);
        heavy_job<state> job(made);
        made->install_cancellation();
        webcpp::asio::post(work, std::move(job));
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
 @tparam Executor An Asio executor, where the completion is posted.
 @tparam CompletionToken An Asio completion token of signature `void(boost::system::error_code)`.
 @param executor The executor the completion is posted to; on `backends::webcrypto`, that of an
 `io_context` run on the calling thread (see @ref async_pbkdf2), and a refusal of another goes to
 the handler's associated executor, this one unless the handler is bound to another.
 @param output The digest, of exactly the digest's size; the caller's until completion.
 @param input The data; the caller's until completion.
 @param token The completion token, of signature `void(boost::system::error_code)`.
 @return What the completion token's `async_result` gives. The completion's code is empty on
 success, or `digest_of`'s error, `output` untouched by a guard's refusal and zeroed by a backend's
 failure. On `backends::webcrypto` also `invalid_parameters` (the executor), `output` untouched,
 `backend_failure` (a rejected promise, an unexpected result, no WebCrypto), `output` zeroed, and
 `operation_aborted` (a `terminal` or `partial` cancellation, at once), `output` zeroed.
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
 @tparam Executor An Asio executor, where the completion is posted.
 @tparam CompletionToken An Asio completion token of signature `void(boost::system::error_code)`.
 @param executor The executor the completion is posted to; on `backends::webcrypto`, that of an
 `io_context` run on the calling thread (see @ref async_pbkdf2), and a refusal of another goes to
 the handler's associated executor, this one unless the handler is bound to another.
 @param output The tag, 10 bytes up to the digest's size; the caller's until completion.
 @param key The key, of any size. @param input The message. Both the caller's until completion.
 @param token The completion token, of signature `void(boost::system::error_code)`.
 @return What the completion token's `async_result` gives. The completion's code is empty on
 success, or `mac`'s error, `output` untouched by a guard's refusal and zeroed by a backend's
 failure. On `backends::webcrypto` also `invalid_parameters` (the executor), `output` untouched,
 `backend_failure` (a rejected promise, an unexpected result, no WebCrypto), `output` zeroed, and
 `operation_aborted` (a `terminal` or `partial` cancellation, at once), `output` zeroed.
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
 @tparam Executor An Asio executor, where the completion is posted.
 @tparam CompletionToken An Asio completion token of signature `void(boost::system::error_code)`.
 @param executor The executor the completion is posted to; on `backends::webcrypto`, that of an
 `io_context` run on the calling thread (see @ref async_pbkdf2), and a refusal of another goes to
 the handler's associated executor, this one unless the handler is bound to another.
 @param output The output keying material, 1 to 255 times the digest size.
 @param salt The salt. @param ikm The input keying material. @param info The context, at most
 `hkdf_max_info_size` bytes; on `backends::webcrypto` at most 1,024, WebCrypto's limit
 (`input_too_long` beyond). The spans are the caller's until completion.
 @param token The completion token, of signature `void(boost::system::error_code)`.
 @return What the completion token's `async_result` gives. The completion's code is empty on
 success, or `hkdf`'s error, `output` untouched by a guard's refusal and zeroed by a backend's
 failure. On `backends::webcrypto` also `invalid_parameters` (the executor), `output` untouched,
 `backend_failure` (a rejected promise, an unexpected result, no WebCrypto), `output` zeroed, and
 `operation_aborted` (a `terminal` or `partial` cancellation, at once), `output` zeroed.
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
 PBKDF2 (RFC 8018), asynchronously.

 On a synchronous backend, the default, a heavy function (spec 11.5): the work runs on a thread of
 `executor`'s context (a `webcpp::asio::thread_pool`'s) and completes on the handler's associated
 executor (`executor` by default; a program binds its event loop's with `bind_executor`), and it
 exists only where the build has threads (`WEBCPP_HASH_HAS_THREADS`). On `backends::webcrypto`, on
 Emscripten, the browser runs it and no thread is needed: there `executor` must be that of an
 `io_context` run on the calling thread, whose `run` returns to the JavaScript event loop where
 WebCrypto's promise settles (ruling R73). The context is checked: a concrete executor of another
 context (a `thread_pool`'s) stops the build, and a type-erased one (`any_io_executor`) whose
 context is not an `io_context`, or whose `io_context` executor it hides behind another allocator or
 two concrete strands, completes with `invalid_parameters`, posted to the handler's associated
 executor. The calling thread is the program's duty, not checked. WebCrypto takes at most 2^32 - 1
 iterations (`invalid_iterations`) and an output of at most (2^32 - 1) / 8 bytes
 (`invalid_output_size`), over `hmac_sha1_160`, `hmac_sha2_256`, `hmac_sha2_384` and `hmac_sha2_512`
 alone.

 Cancellation through the handler's slot, on a synchronous backend: before the work starts, any
 type completes the operation at once with `operation_aborted`, the work never runs; during it, a
 `terminal` or `partial` one lets the work end, then `output` is zeroed and the completion is
 `operation_aborted` (a `total` one is then ignored). "At once" is on the handler's associated
 executor: for a handler without one, that is `executor`, so the completion waits for its
 threads; bind the handler to the event loop's executor. On `backends::webcrypto` a `terminal` or
 `partial` one completes at once with `operation_aborted`, `output` zeroed, while the browser's
 work runs to its end unseen; a `total` one is ignored.

 @tparam Hmac The pseudorandom function, as `hmac_sha2_512`.
 @tparam Backend The backend; by default @ref default_async_backend of `kdfs::pbkdf2`, the
 synchronous default.
 @tparam Executor An Asio executor: of the threads the work runs on, or WebCrypto's
 `io_context`'s.
 @tparam CompletionToken An Asio completion token of signature `void(boost::system::error_code)`.
 @param executor The work executor, or WebCrypto's `io_context` executor.
 @param output The derived key, 1 to (2^32 - 1) times the digest size.
 @param password The password. @param salt The salt. The spans are the caller's until completion.
 @param iterations The iteration count, at least 1.
 @param token The completion token, of signature `void(boost::system::error_code)`.
 @return What the completion token's `async_result` gives. The completion's code is empty on
 success, or `pbkdf2`'s error, a guard's refusal completing through a post, `output` untouched; or
 `operation_aborted`. On `backends::webcrypto` also `invalid_parameters` (the executor),
 `output` untouched, and `backend_failure` (a rejected promise, an unexpected result, no
 WebCrypto), `output` zeroed.
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
 Argon2id (RFC 9106, one lane) on a thread of `work`'s context (spec 11.5).

 The guards of `argon2id` first, whose refusal completes through a post; then the work, posted to
 `work` (a `webcpp::asio::thread_pool`'s executor, typically); the completion on the handler's
 associated executor (`work` by default; a program binds its event loop's with `bind_executor`),
 so that the event loop never blocks. Exists only where the build has threads
 (`WEBCPP_HASH_HAS_THREADS`).

 Cancellation through the handler's slot: before the work starts, any type completes the
 operation at once with `operation_aborted`, the work never runs; during it, a `terminal` or
 `partial` one lets the work end (libsodium cannot be interrupted), then `output` is zeroed and
 the completion is `operation_aborted` (a `total` one is then ignored: zeroing is a side effect).
 "At once" is on the handler's associated executor: for a handler without one, that is `work`, so
 the completion waits for its threads; bind the handler to the event loop's executor.

 @tparam Backend The backend; by default @ref default_backend of `kdfs::argon2id`.
 @tparam WorkExecutor An Asio executor whose context runs on other threads.
 @tparam CompletionToken An Asio completion token of signature `void(boost::system::error_code)`.
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
 @tparam WorkExecutor An Asio executor whose context runs on other threads.
 @tparam CompletionToken An Asio completion token of signature `void(boost::system::error_code)`.
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
 @tparam WorkExecutor An Asio executor whose context runs on other threads.
 @tparam CompletionToken An Asio completion token of signature `void(boost::system::error_code)`.
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

// backends::webcrypto's engine on Emscripten, and its limits on every target. That header includes
// this one first, so that a program may include either.
#include <webcpp/hash/backends/webcrypto.hpp>

#endif  // WEBCPP_HASH_ASYNC_HPP
