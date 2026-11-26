// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// No local name in a hash header hides a program's global. MSVC warns, C4459, at a parameter or a
// local of a header's non-template function (inline code) that has the name of a global of the
// program ("declaration of 'timing' hides global declaration"), an error at /W4 /WX, and, where a
// function template is instantiated, at its locals (14.3 and 14.5, secure's user_globals test).
// Clang and GCC never warn across namespaces, so the test is MSVC's, and on the other native
// compilers it only runs the calls. A local takes two words, the role then the kind
// (`timing_scope`, `completion_token`, `salt_bytes`), which no program names a global.
//
// Every header of another library that a hash header includes comes first, so that their own names
// are parsed before the globals exist; then a global of every one-word name a hash header gave a
// local or a parameter until each took two words (but the public HKDF functions' `salt`, which the
// change hkdf-pieces names so, and which, a function template's parameter, raises no C4459: 14.3
// and 14.5 say nothing of a template's parameters); then every public header. Every cell of every
// backend the program links is called (digests and hashers, MACs, the HKDFs over spans and over
// pieces, PBKDF2, KBKDF, SSKDF, X9.63, BLAKE2b's subkeys, Argon2, scrypt and bcrypt), and every
// asynchronous function on its default backend (bcrypt's on Botan, which is no default), which
// instantiates every template the calls reach. The parameters of detail/xkcp.hpp's C declarations,
// which have no body, raise no C4459 (14.3, with the globals `storage`, `input`, `output` and
// `length` below) and keep the C adapter's names.
//
// How the list was made: an aggregate translation unit of every header of include/, every backend
// and webcpp::asio linked, its AST dumped (clang -Xclang -ast-dump=json, filtered to webcpp::hash),
// each ParmVarDecl, VarDecl and BindingDecl inside a function of include/ whose name matches
// ^[a-z][a-z0-9]*$; again without exceptions, without threads, with the test seams
// (WEBCPP_HASH_DETAIL_TEST_*), and with Emscripten's compiler, for the code only they compile
// (backends::webcrypto's names are Emscripten's alone, and listed defensively). A name that the
// platform's C library already declares as a global (`index`, <strings.h>'s) cannot be a program's
// global there anyway: it is declared on MSVC alone.

#include <webcpp/hash/config.hpp>

#include <webcpp/asio/any_io_executor.hpp>
#include <webcpp/asio/append.hpp>
#include <webcpp/asio/associated_allocator.hpp>
#include <webcpp/asio/associated_cancellation_slot.hpp>
#include <webcpp/asio/associated_executor.hpp>
#include <webcpp/asio/async_result.hpp>
#include <webcpp/asio/bind_allocator.hpp>
#include <webcpp/asio/cancellation_state.hpp>
#include <webcpp/asio/cancellation_type.hpp>
#include <webcpp/asio/compose.hpp>
#include <webcpp/asio/dispatch.hpp>
#include <webcpp/asio/error.hpp>
#include <webcpp/asio/execution/context.hpp>
#include <webcpp/asio/executor_work_guard.hpp>
#include <webcpp/asio/io_context.hpp>
#include <webcpp/asio/post.hpp>
#include <webcpp/asio/query.hpp>
#include <webcpp/asio/strand.hpp>
#include <webcpp/config.hpp>
#include <webcpp/secure/erase_secret.hpp>
#include <webcpp/secure/timing_guard.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/blake2.hpp>
#include <boost/hash2/digest.hpp>
#include <boost/hash2/fnv1a.hpp>
#include <boost/hash2/has_constant_size.hpp>
#include <boost/hash2/hash_append.hpp>
#include <boost/hash2/hmac.hpp>
#include <boost/hash2/legacy/murmur3.hpp>
#include <boost/hash2/legacy/spooky2.hpp>
#include <boost/hash2/md5.hpp>
#include <boost/hash2/ripemd.hpp>
#include <boost/hash2/sha1.hpp>
#include <boost/hash2/sha2.hpp>
#include <boost/hash2/sha3.hpp>
#include <boost/hash2/siphash.hpp>
#include <boost/hash2/xxh3.hpp>
#include <boost/hash2/xxhash.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/error_category.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/result.hpp>
#include <boost/throw_exception.hpp>

#include <bearssl_hash.h>
#include <bearssl_hmac.h>
#include <bearssl_kdf.h>
#include <blake3.h>
#include <openssl/core.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <sodium/core.h>
#include <sodium/crypto_auth_hmacsha256.h>
#include <sodium/crypto_auth_hmacsha512.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_hash_sha256.h>
#include <sodium/crypto_hash_sha3.h>
#include <sodium/crypto_hash_sha512.h>
#include <sodium/crypto_kdf_blake2b.h>
#include <sodium/crypto_kdf_hkdf_sha256.h>
#include <sodium/crypto_kdf_hkdf_sha512.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_pwhash_argon2i.h>
#include <sodium/crypto_pwhash_argon2id.h>
#include <sodium/crypto_pwhash_scryptsalsa208sha256.h>
#include <sodium/crypto_shorthash_siphash24.h>
#include <sodium/crypto_xof_shake128.h>
#include <sodium/crypto_xof_shake256.h>
#include <sodium/crypto_xof_turboshake128.h>
#include <sodium/crypto_xof_turboshake256.h>
#include <sodium/randombytes.h>
#ifdef WEBCPP_HASH_HAS_BOTAN
#include <botan/bcrypt.h>
#include <botan/exceptn.h>
#include <botan/hash.h>
#include <botan/kdf.h>
#include <botan/mac.h>
#include <botan/pwdhash.h>
#include <botan/rng.h>
#include <botan/xof.h>
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <climits>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <type_traits>
#include <utility>

// NOLINTBEGIN(readability-redundant-declaration): clang-tidy takes Boost's dependent
// `...::value` for a declaration of `value`
extern int const absorbed, algorithm, allocator, bits, buffer, byte, bytes, c, characters, checked,
    code, computed, context, cost, crypto, data, decimal, deeper, derive, derived, digest, done,
    ended, executor, expected, extracted, finished, gathered, generator, guard, guarded, guards,
    handler, hash, hashed, held, imported, initialised, inner, input, invoke, iterations, job,
    joined, key, keyed, kind, label, length, limits, location, mac, made, name, named, nested,
    nonce, object, offset, operation, options, other, outcome, output, owned, parameters, part,
    password, piece, pieces, prefix, produced, promise, raised, ready, refusal, request, rest,
    result, room, rounds, run, salt, same, secret, self, served, size, sized, slice, slot, started,
    state, steps, storage, subtle, succeeded, suffix, tag, taken, target, tens, timing, token,
    total, type, units, update, updated, usage, usages, used, value, version, whole, work, written,
    zero;
#ifdef _MSC_VER
extern int const index;
#endif
// NOLINTEND(readability-redundant-declaration)

#include <webcpp/hash.hpp>
#include <webcpp/hash/async.hpp>
#include <webcpp/hash/backends/webcrypto.hpp>

// In webcpp::test, `hash::` names webcpp::hash before the global `hash` above.
namespace webcpp::test {
namespace {

namespace digests = hash::digests;
namespace kdfs = hash::kdfs;
namespace macs = hash::macs;

// Every tag of `digests`, of `macs`, every hmac of hmac.hpp, and argon2's variants.
using every_digest =
    std::tuple<digests::md5, digests::sha1, digests::sha2_224, digests::sha2_256, digests::sha2_384,
               digests::sha2_512, digests::sha2_512_224, digests::sha2_512_256, digests::sha3_224,
               digests::sha3_256, digests::sha3_384, digests::sha3_512, digests::shake_128,
               digests::shake_256, digests::keccak_224, digests::keccak_256, digests::keccak_384,
               digests::keccak_512, digests::cshake_128, digests::cshake_256, digests::kt128,
               digests::kt256, digests::turboshake_128, digests::turboshake_256,
               digests::tuplehash_128, digests::tuplehash_256, digests::parallelhash_128,
               digests::parallelhash_256, digests::blake2b, digests::blake2s_256, digests::blake3,
               digests::ripemd_160, digests::md5_sha1, digests::sm3, digests::streebog_256,
               digests::streebog_512, digests::whirlpool, digests::skein_512>;
using every_mac = std::tuple<
    macs::hmac<digests::md5>, macs::hmac<digests::sha1>, macs::hmac<digests::sha2_224>,
    macs::hmac<digests::sha2_256>, macs::hmac<digests::sha2_384>, macs::hmac<digests::sha2_512>,
    macs::hmac<digests::sha2_512_224>, macs::hmac<digests::sha2_512_256>,
    macs::hmac<digests::sha3_224>, macs::hmac<digests::sha3_256>, macs::hmac<digests::sha3_384>,
    macs::hmac<digests::sha3_512>, macs::hmac<digests::ripemd_160>, macs::hmac<digests::blake2b>,
    macs::hmac<digests::blake2s_256>, macs::hmac<digests::keccak_224>,
    macs::hmac<digests::keccak_256>, macs::hmac<digests::keccak_384>,
    macs::hmac<digests::keccak_512>, macs::hmac<digests::md5_sha1>, macs::hmac<digests::sm3>,
    macs::hmac<digests::streebog_256>, macs::hmac<digests::streebog_512>,
    macs::hmac<digests::whirlpool>, macs::hmac<digests::skein_512>, macs::kmac_128, macs::kmac_256,
    macs::siphash_2_4, macs::siphash_2_4x, macs::blake2b_mac, macs::blake2s_mac>;
using every_hmac =
    std::tuple<hash::hmac_md5_128, hash::hmac_sha1_160, hash::hmac_sha2_224, hash::hmac_sha2_256,
               hash::hmac_sha2_384, hash::hmac_sha2_512, hash::hmac_sha2_512_224,
               hash::hmac_sha2_512_256, hash::hmac_sha3_224, hash::hmac_sha3_256,
               hash::hmac_sha3_384, hash::hmac_sha3_512, hash::hmac_ripemd_128,
               hash::hmac_ripemd_160, hash::hmac_blake2b_512, hash::hmac_blake2s_256>;
using every_argon2 = std::tuple<kdfs::argon2d, kdfs::argon2i, kdfs::argon2id>;
using every_backend =
    std::tuple<hash::backends::hash2, hash::backends::xkcp, hash::backends::blake3,
               hash::backends::sodium, hash::backends::bearssl, hash::backends::openssl,
               hash::backends::botan>;

/** Calls `each_call.template operator()<Tag>()` for each tag of `Tags`. */
template <class Tags, class Each>
void for_each_tag(Each const& each_call) {
    [&each_call]<class... Tag>(std::tuple<Tag...>*) {
        (each_call.template operator()<Tag>(), ...);
    }(static_cast<Tags*>(nullptr));
}

/** Whether the program links `Backend` and it has `Tag` (over `Key`). */
template <class Backend, class Tag, class Key = void>
inline constexpr bool cell_v =
    hash::detail::linked_v<Backend> && hash::backend_has_v<Backend, Tag, Key>;

/** `Size` bytes, each its index plus `first_byte`. */
template <std::size_t Size>
constexpr std::array<std::uint8_t, Size> counted_bytes(std::uint8_t first_byte) {
    std::array<std::uint8_t, Size> counted_array{};
    for (std::size_t byte_index = 0; byte_index < Size; ++byte_index) {
        counted_array[byte_index] = static_cast<std::uint8_t>(first_byte + byte_index);
    }
    return counted_array;
}

inline constexpr std::array<std::uint8_t, 32> test_key = counted_bytes<32>(1);
inline constexpr std::array<std::uint8_t, 16> test_salt = counted_bytes<16>(101);
inline constexpr std::array<std::uint8_t, 24> test_input{9, 8, 7, 6, 5, 4, 3, 2, 1};

/** The pieces of `test_input`, one of them empty. */
std::array<std::span<std::uint8_t const>, 3> test_pieces() {
    std::span<std::uint8_t const> const input_span(test_input);
    return {input_span.first(5), std::span<std::uint8_t const>{}, input_span.subspan(5)};
}

/** `digest_of` and a hasher round of `Digest` on `Backend`, unkeyed, and keyed for BLAKE2b. */
template <class Digest, class Backend>
void call_digest() {
    using traits = hash::detail::digest_traits<Digest>;
    // The default options, but ParallelHash's block size, which has no default.
    auto const digest_choice = [] {
        hash::digest_options<Digest> chosen_options{};
        if constexpr (requires { chosen_options.block_size; }) {
            chosen_options.block_size = 8;
        }
        return chosen_options;
    }();
    std::array<std::uint8_t, 64> output_buffer{};
    auto const output_size = static_cast<std::size_t>(std::min({
        traits::max_output(digest_choice),
        hash::detail::digest_engine<Backend, Digest>::max_output,
        std::uint64_t{64},
    }));
    auto const output_span = std::span(output_buffer).first(output_size);
    static_cast<void>(hash::digest_of<Digest, Backend>(output_span, test_input, digest_choice));
    auto made_hasher = hash::hasher<Digest, Backend>::make(digest_choice);
    if (made_hasher) {
        static_cast<void>(made_hasher->update(test_input));
        static_cast<void>(made_hasher->finish(output_span));
    }
    if constexpr (std::is_same_v<Digest, digests::blake2b>) {
        hash::digest_options<Digest> const keyed_choice{.key = test_key};
        static_cast<void>(hash::digest_of<Digest, Backend>(output_span, test_input, keyed_choice));
        static_cast<void>(hash::hasher<Digest, Backend>::make(keyed_choice));
    }
}

/** `mac` of `Mac` on `Backend`, under the shortest key the backend takes. */
template <class Mac, class Backend>
void call_mac() {
    using traits = hash::detail::mac_traits<Mac>;
    using engine = hash::detail::mac_engine<Backend, Mac>;
    std::array<std::uint8_t, 64> output_buffer{};
    auto const output_span =
        std::span(output_buffer)
            .first(static_cast<std::size_t>(std::min(traits::max_output, std::uint64_t{64})));
    auto key_size = static_cast<std::size_t>(traits::min_key);
    while (!engine::accepts(hash::mac_options<Mac>{}, key_size, output_span.size()) &&
           key_size < test_key.size()) {
        ++key_size;
    }
    static_cast<void>(
        hash::mac<Mac, Backend>(output_span, std::span(test_key).first(key_size), test_input));
}

/** Whether `Backend` has a key derivation over `Hmac`. */
template <class Backend, class Hmac>
inline constexpr bool hmac_family_v =
    cell_v<Backend, kdfs::hkdf_extract, Hmac> || cell_v<Backend, kdfs::hkdf_expand, Hmac> ||
    cell_v<Backend, kdfs::hkdf, Hmac> || cell_v<Backend, kdfs::hkdf_extract_pieces, Hmac> ||
    cell_v<Backend, kdfs::hkdf_expand_pieces, Hmac> || cell_v<Backend, kdfs::hkdf_pieces, Hmac> ||
    cell_v<Backend, kdfs::pbkdf2, Hmac> || cell_v<Backend, kdfs::kbkdf_hmac, Hmac>;

/** Every key derivation over `Hmac` that `Backend` has: the HKDFs, PBKDF2 and KBKDF. */
template <class Hmac, class Backend>
void call_hmac_family() {
    if constexpr (hmac_family_v<Backend, Hmac>) {
        std::array<std::uint8_t, 42> output_buffer{};
        std::array<std::uint8_t, 64> key_buffer{};
        auto const pseudorandom_key =
            std::span(key_buffer).first(typename Hmac::result_type().size());
        auto const piece_array = test_pieces();
        if constexpr (cell_v<Backend, kdfs::hkdf_extract, Hmac>) {
            static_cast<void>(hash::hkdf_extract<Hmac, Backend>(test_salt, test_key));
        }
        if constexpr (cell_v<Backend, kdfs::hkdf_expand, Hmac>) {
            static_cast<void>(
                hash::hkdf_expand<Hmac, Backend>(output_buffer, pseudorandom_key, test_input));
        }
        if constexpr (cell_v<Backend, kdfs::hkdf, Hmac>) {
            static_cast<void>(
                hash::hkdf<Hmac, Backend>(output_buffer, test_salt, test_key, test_input));
        }
        if constexpr (cell_v<Backend, kdfs::hkdf_extract_pieces, Hmac>) {
            static_cast<void>(hash::hkdf_extract<Hmac, Backend>(test_salt, piece_array));
        }
        if constexpr (cell_v<Backend, kdfs::hkdf_expand_pieces, Hmac>) {
            static_cast<void>(
                hash::hkdf_expand<Hmac, Backend>(output_buffer, pseudorandom_key, piece_array));
        }
        if constexpr (cell_v<Backend, kdfs::hkdf_pieces, Hmac>) {
            static_cast<void>(
                hash::hkdf<Hmac, Backend>(output_buffer, test_salt, piece_array, piece_array));
        }
        if constexpr (cell_v<Backend, kdfs::pbkdf2, Hmac>) {
            static_cast<void>(hash::pbkdf2<Hmac, Backend>(output_buffer, test_key, test_salt, 1));
        }
        if constexpr (cell_v<Backend, kdfs::kbkdf_hmac, Hmac>) {
            static_cast<void>(hash::kbkdf<Hmac, Backend>(output_buffer, test_key));
        }
    }
}

/** Every cell of `Backend`. */
template <class Backend>
void call_every_cell() {
    if constexpr (hash::detail::linked_v<Backend>) {
        for_each_tag<every_digest>([]<class Digest> {
            if constexpr (cell_v<Backend, Digest>) {
                call_digest<Digest, Backend>();
            }
        });
        for_each_tag<every_mac>([]<class Mac> {
            if constexpr (cell_v<Backend, Mac>) {
                call_mac<Mac, Backend>();
            }
        });
        for_each_tag<every_hmac>([]<class Hmac> { call_hmac_family<Hmac, Backend>(); });
        std::array<std::uint8_t, 32> output_buffer{};
        if constexpr (cell_v<Backend, kdfs::blake2b_subkey>) {
            std::array<std::uint8_t, 8> const context_bytes{'c', 't', 'x', '_', 't', 'e', 's', 't'};
            static_cast<void>(
                hash::blake2b_subkey<Backend>(output_buffer, test_key, 7, context_bytes));
        }
        if constexpr (cell_v<Backend, kdfs::sskdf>) {
            static_cast<void>(
                hash::sskdf<digests::sha2_256, Backend>(output_buffer, test_key, test_input));
        }
        if constexpr (cell_v<Backend, kdfs::x963kdf>) {
            static_cast<void>(
                hash::x963kdf<digests::sha2_256, Backend>(output_buffer, test_key, test_input));
        }
        if constexpr (cell_v<Backend, kdfs::argon2id>) {
            static_cast<void>(hash::argon2id<Backend>(output_buffer, test_key, test_salt,
                                                      {.passes = 1, .memory = 8192}));
        }
        for_each_tag<every_argon2>([&output_buffer]<class Variant> {
            if constexpr (cell_v<Backend, Variant, hash::argon2_parameters>) {
                static_cast<void>(hash::argon2<Variant, Backend>(
                    output_buffer, test_key, test_salt, {.passes = 3, .memory_kibibytes = 8}));
            }
        });
        if constexpr (cell_v<Backend, kdfs::scrypt>) {
            static_cast<void>(
                hash::scrypt<Backend>(output_buffer, test_key, test_salt,
                                      {.cost = 16, .block_size = 1, .parallelism = 1}));
        }
        if constexpr (cell_v<Backend, kdfs::bcrypt>) {
            std::array<char, hash::bcrypt_hash_size> hash_characters{};
            static_cast<void>(
                hash::bcrypt<Backend>(hash_characters, test_key, test_salt, {.cost = 4}));
            static_cast<void>(hash::bcrypt_verify<Backend>(
                test_key, std::string_view(hash_characters.data(), hash_characters.size())));
        }
        if constexpr (cell_v<Backend, kdfs::bcrypt_pbkdf>) {
            static_cast<void>(hash::bcrypt_pbkdf<Backend>(output_buffer, test_key, test_salt, 1));
        }
    }
}

/** Every asynchronous function, on its default backend, each completing on `context_object`. */
void call_every_async(asio::io_context& context_object) {
    auto const io_executor = context_object.get_executor();
    std::array<std::uint8_t, 32> output_buffer{};
    std::array<std::uint8_t, 32> key_buffer{};
    auto const piece_array = test_pieces();
    auto const on_done = [](boost::system::error_code const&) {};
    hash::async_digest<digests::sha2_256>(io_executor, output_buffer, test_input, on_done);
    hash::async_hmac<hash::hmac_sha2_256>(io_executor, output_buffer, test_key, test_input,
                                          on_done);
    hash::async_hkdf<hash::hmac_sha2_256>(io_executor, output_buffer, test_salt, test_key,
                                          test_input, on_done);
    hash::async_hkdf<hash::hmac_sha2_256>(io_executor, output_buffer, test_salt, piece_array,
                                          piece_array, on_done);
    hash::async_hkdf_extract<hash::hmac_sha2_256>(io_executor, key_buffer, test_salt, test_key,
                                                  on_done);
    hash::async_hkdf_extract<hash::hmac_sha2_256>(io_executor, key_buffer, test_salt, piece_array,
                                                  on_done);
    hash::async_hkdf_expand<hash::hmac_sha2_256>(io_executor, output_buffer, key_buffer, test_input,
                                                 on_done);
    hash::async_hkdf_expand<hash::hmac_sha2_256>(io_executor, output_buffer, key_buffer,
                                                 piece_array, on_done);
#ifdef WEBCPP_HASH_HAS_THREADS
    hash::async_pbkdf2<hash::hmac_sha2_256>(io_executor, output_buffer, test_key, test_salt, 1,
                                            on_done);
    hash::async_argon2id(io_executor, output_buffer, test_key, test_salt,
                         {.passes = 1, .memory = 8192}, on_done);
    hash::async_argon2<kdfs::argon2id>(io_executor, output_buffer, test_key, test_salt,
                                       {.passes = 3, .memory_kibibytes = 8}, on_done);
    hash::async_scrypt(io_executor, output_buffer, test_key, test_salt,
                       {.cost = 16, .block_size = 1, .parallelism = 1}, on_done);
#ifdef WEBCPP_HASH_HAS_BOTAN
    std::array<char, hash::bcrypt_hash_size> hash_characters{};
    using hash::backends::botan;
    hash::async_bcrypt<botan>(io_executor, hash_characters, test_key, test_salt, {.cost = 4},
                              on_done);
    hash::async_bcrypt_pbkdf<botan>(io_executor, output_buffer, test_key, test_salt, 1, on_done);
    hash::async_bcrypt_verify<botan>(io_executor, test_key, std::string_view("not a bcrypt string"),
                                     [](boost::system::error_code const&, bool) {});
#endif
#endif
    context_object.poll();  // every completion is posted, none waits on I/O or a timer
}

}  // namespace
}  // namespace webcpp::test

int main() {
    namespace test = webcpp::test;
    []<class... Backend>(std::tuple<Backend...>*) {
        (test::call_every_cell<Backend>(), ...);
    }(static_cast<test::every_backend*>(nullptr));
    webcpp::asio::io_context context_object;
    test::call_every_async(context_object);
    return webcpp::test::exit_status(boost::report_errors());
}
