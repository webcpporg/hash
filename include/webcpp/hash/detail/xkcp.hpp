// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The functions of webcpp::hash's adapter over XKCP (`libs/hash/src/xkcp_adapter.c`,
 compiled into `/third_party//xkcp`): no XKCP header reaches a program's translation unit.

 Keccak-p[1600]: four functions over a state of 25 lanes of 64 bits, the layout of XKCP's
 `KeccakP1600_plain64_state`; every `offset + length` is at most 200, the state's size in
 bytes.

 XKCP's high-level interfaces: the sponge, FIPS 202's `Keccak_Hash` (SHA-3, SHAKE and Keccak),
 TurboSHAKE, KangarooTwelve, and SP 800-185's cSHAKE, KMAC, TupleHash and ParallelHash, each in
 four phases, `initialize`, `update`, `final` and `squeeze`, named
 `webcpp_hash_xkcp_<interface>_<phase>`; TupleHash and ParallelHash also end with
 `final_length`, which takes the output length at the end. An instance lives in the caller's
 storage, the `xkcp_<kind>_storage` below, opaque to it: its size, in `detail/xkcp_storage.h`, is
 the native maximum of XKCP's structure (smaller on wasm32, where `size_t` is 4 bytes), which the
 adapter's static assertions check on every target. A storage is used for one instance from its
 `initialize` on, and wiped by its owner when done. Every length is in bytes; every function returns
 XKCP's answer, 0 on success and nonzero on a refusal (a phase out of order, a parameter XKCP does
 not take). SP 800-185's and `Keccak_Hash`'s lengths are bits in a `size_t`: the adapter passes
 input and squeezed output in chunks, and refuses a key, function name, customisation, tuple element
 or fixed output longer than `SIZE_MAX / 8` bytes. A pointer may be null when its length is zero.
*/
#ifndef WEBCPP_HASH_DETAIL_XKCP_HPP
#define WEBCPP_HASH_DETAIL_XKCP_HPP

#include <webcpp/hash/detail/xkcp_storage.h>
#include <webcpp/hash/config.hpp>

#include <array>
#include <cstddef>
#include <cstdint>

namespace webcpp::hash::detail {

/** The storage of a `KeccakWidth1600_SpongeInstance`: `webcpp_hash_xkcp_sponge_words` words. */
using xkcp_sponge_storage = std::array<std::uint64_t, webcpp_hash_xkcp_sponge_words>;

/** The storage of a `Keccak_HashInstance`: `webcpp_hash_xkcp_keccak_hash_words` words. */
using xkcp_keccak_hash_storage = std::array<std::uint64_t, webcpp_hash_xkcp_keccak_hash_words>;

/** The storage of a `TurboSHAKE_Instance`: `webcpp_hash_xkcp_turboshake_words` words. */
using xkcp_turboshake_storage = std::array<std::uint64_t, webcpp_hash_xkcp_turboshake_words>;

/** The storage of a `KangarooTwelve_Instance`: `webcpp_hash_xkcp_kangarootwelve_words` words. */
using xkcp_kangarootwelve_storage =
    std::array<std::uint64_t, webcpp_hash_xkcp_kangarootwelve_words>;

/** The storage of a `cSHAKE_Instance`: `webcpp_hash_xkcp_cshake_words` words. */
using xkcp_cshake_storage = std::array<std::uint64_t, webcpp_hash_xkcp_cshake_words>;

/** The storage of a `KMAC_Instance`: `webcpp_hash_xkcp_kmac_words` words. */
using xkcp_kmac_storage = std::array<std::uint64_t, webcpp_hash_xkcp_kmac_words>;

/** The storage of a `TupleHash_Instance`: `webcpp_hash_xkcp_tuplehash_words` words. */
using xkcp_tuplehash_storage = std::array<std::uint64_t, webcpp_hash_xkcp_tuplehash_words>;

/** The storage of a `ParallelHash_Instance`: `webcpp_hash_xkcp_parallelhash_words` words. */
using xkcp_parallelhash_storage = std::array<std::uint64_t, webcpp_hash_xkcp_parallelhash_words>;

/**
 Whether `Storage` is exactly `Words` words of `std::uint64_t`, at their alignment: the room the
 adapter's C static assertions check each XKCP structure against (`detail/xkcp_storage.h`).

 @tparam Storage A storage type of this header.
 @tparam Words Its number of words in `detail/xkcp_storage.h`.
*/
template <class Storage, std::size_t Words>
inline constexpr bool holds_words_v =
    sizeof(Storage) == Words * sizeof(std::uint64_t) && alignof(Storage) == alignof(std::uint64_t);
static_assert(holds_words_v<xkcp_sponge_storage, webcpp_hash_xkcp_sponge_words>);
static_assert(holds_words_v<xkcp_keccak_hash_storage, webcpp_hash_xkcp_keccak_hash_words>);
static_assert(holds_words_v<xkcp_turboshake_storage, webcpp_hash_xkcp_turboshake_words>);
static_assert(holds_words_v<xkcp_kangarootwelve_storage, webcpp_hash_xkcp_kangarootwelve_words>);
static_assert(holds_words_v<xkcp_cshake_storage, webcpp_hash_xkcp_cshake_words>);
static_assert(holds_words_v<xkcp_kmac_storage, webcpp_hash_xkcp_kmac_words>);
static_assert(holds_words_v<xkcp_tuplehash_storage, webcpp_hash_xkcp_tuplehash_words>);
static_assert(holds_words_v<xkcp_parallelhash_storage, webcpp_hash_xkcp_parallelhash_words>);

}  // namespace webcpp::hash::detail

extern "C" {

/**
 Sets the 25 lanes at `permutation_state` to zero (XKCP's `KeccakP1600_Initialize`).

 @param permutation_state The state.
*/
void webcpp_hash_xkcp_initialize(std::uint64_t* permutation_state);

/**
 Adds, by exclusive or, the `byte_length` bytes at `data_bytes` to the state's bytes from
 `byte_offset` (XKCP's `KeccakP1600_AddBytes`).

 @param permutation_state The state.
 @param data_bytes The bytes.
 @param byte_offset The first byte of the state they are added to.
 @param byte_length Their number.
*/
void webcpp_hash_xkcp_add_bytes(std::uint64_t* permutation_state, unsigned char const* data_bytes,
                                std::size_t byte_offset, std::size_t byte_length);

/**
 Applies Keccak-f[1600], 24 rounds, to the state (XKCP's `KeccakP1600_Permute_24rounds`).

 @param permutation_state The state.
*/
void webcpp_hash_xkcp_permute(std::uint64_t* permutation_state);

/**
 Copies the state's `byte_length` bytes from `byte_offset` to `data_bytes` (XKCP's
 `KeccakP1600_ExtractBytes`).

 @param permutation_state The state.
 @param data_bytes Where the bytes go.
 @param byte_offset The first byte of the state copied.
 @param byte_length Their number.
*/
void webcpp_hash_xkcp_extract_bytes(std::uint64_t const* permutation_state,
                                    unsigned char* data_bytes, std::size_t byte_offset,
                                    std::size_t byte_length);

/**
 Starts XKCP's Keccak sponge (`KeccakWidth1600_SpongeInitialize`).

 @param storage The instance's storage, an `xkcp_sponge_storage`.
 @param rate The rate in bits, a multiple of 8.
 @param capacity The capacity in bits; `rate + capacity` is 1600.
 @return 0, or nonzero when XKCP refuses the rate and capacity.
*/
int webcpp_hash_xkcp_sponge_initialize(std::uint64_t* storage, unsigned int rate,
                                       unsigned int capacity);

/**
 Absorbs bytes (`KeccakWidth1600_SpongeAbsorb`).

 @param storage The instance's storage.
 @param input The bytes.
 @param length Their number.
 @return 0, or nonzero once the sponge squeezes.
*/
int webcpp_hash_xkcp_sponge_update(std::uint64_t* storage, unsigned char const* input,
                                   std::size_t length);

/**
 Absorbs the delimited suffix and the padding (`KeccakWidth1600_SpongeAbsorbLastFewBits`).

 @param storage The instance's storage.
 @param delimited_suffix The suffix's bits followed by a 1, nonzero (0x01 for Keccak, 0x06 for
 SHA-3, 0x1F for SHAKE).
 @return 0, or nonzero for a suffix of 0 or once the sponge squeezes.
*/
int webcpp_hash_xkcp_sponge_final(std::uint64_t* storage, unsigned char delimited_suffix);

/**
 Squeezes output bytes (`KeccakWidth1600_SpongeSqueeze`), after `final`.

 @param storage The instance's storage.
 @param output Where the bytes go.
 @param length Their number.
 @return 0.
*/
int webcpp_hash_xkcp_sponge_squeeze(std::uint64_t* storage, unsigned char* output,
                                    std::size_t length);

/**
 Starts FIPS 202's hash (`Keccak_HashInitialize`): SHA3-n is rate `1600 - 2n`, capacity
 `2n`, `n / 8` bytes and suffix 0x06; SHAKE128 and SHAKE256 rates 1344 and 1088, output 0 and
 suffix 0x1F; Keccak-n as SHA3-n with suffix 0x01.

 @param storage The instance's storage, an `xkcp_keccak_hash_storage`.
 @param rate The rate in bits.
 @param capacity The capacity in bits; `rate + capacity` is 1600.
 @param output_length The bytes `final` writes, 0 for an output read by `squeeze` alone.
 @param delimited_suffix The suffix's bits followed by a 1, nonzero.
 @return 0, or nonzero when XKCP refuses a parameter or the output is over `UINT_MAX / 8`.
*/
int webcpp_hash_xkcp_keccak_hash_initialize(std::uint64_t* storage, unsigned int rate,
                                            unsigned int capacity, std::size_t output_length,
                                            unsigned char delimited_suffix);

/**
 Absorbs bytes (`Keccak_HashUpdate`).

 @param storage The instance's storage.
 @param input The bytes.
 @param length Their number.
 @return 0, or nonzero after `final`.
*/
int webcpp_hash_xkcp_keccak_hash_update(std::uint64_t* storage, unsigned char const* input,
                                        std::size_t length);

/**
 Ends the input and writes the fixed output (`Keccak_HashFinal`).

 @param storage The instance's storage.
 @param output Where `initialize`'s `output_length` bytes go (none when it was 0).
 @return 0, or nonzero when called twice.
*/
int webcpp_hash_xkcp_keccak_hash_final(std::uint64_t* storage, unsigned char* output);

/**
 Squeezes more output bytes (`Keccak_HashSqueeze`), after `final`.

 @param storage The instance's storage.
 @param output Where the bytes go.
 @param length Their number.
 @return 0.
*/
int webcpp_hash_xkcp_keccak_hash_squeeze(std::uint64_t* storage, unsigned char* output,
                                         std::size_t length);

/**
 Starts TurboSHAKE (`TurboSHAKE_Initialize`).

 @param storage The instance's storage, an `xkcp_turboshake_storage`.
 @param capacity 256 for TurboSHAKE128, 512 for TurboSHAKE256.
 @return 0, or nonzero for a capacity XKCP refuses.
*/
int webcpp_hash_xkcp_turboshake_initialize(std::uint64_t* storage, unsigned int capacity);

/**
 Absorbs bytes (`TurboSHAKE_Absorb`).

 @param storage The instance's storage.
 @param input The bytes.
 @param length Their number.
 @return 0, or nonzero after `final`.
*/
int webcpp_hash_xkcp_turboshake_update(std::uint64_t* storage, unsigned char const* input,
                                       std::size_t length);

/**
 Absorbs the domain separation byte and the padding (`TurboSHAKE_AbsorbDomainSeparationByte`).
 XKCP takes any nonzero byte; RFC 9861 allows 0x01 to 0x7F, which the caller checks.

 @param storage The instance's storage.
 @param domain The domain separation byte.
 @return 0, or nonzero for a byte of 0 or when called twice.
*/
int webcpp_hash_xkcp_turboshake_final(std::uint64_t* storage, unsigned char domain);

/**
 Squeezes output bytes (`TurboSHAKE_Squeeze`), after `final`.

 @param storage The instance's storage.
 @param output Where the bytes go.
 @param length Their number.
 @return 0.
*/
int webcpp_hash_xkcp_turboshake_squeeze(std::uint64_t* storage, unsigned char* output,
                                        std::size_t length);

/**
 Starts KangarooTwelve (`KangarooTwelve_Initialize`).

 @param storage The instance's storage, an `xkcp_kangarootwelve_storage`.
 @param security_level 128 for KT128, 256 for KT256.
 @param output_length The bytes `final` writes, 0 for an output read by `squeeze` alone.
 @return 0, or nonzero for another security level.
*/
int webcpp_hash_xkcp_kangarootwelve_initialize(std::uint64_t* storage, int security_level,
                                               std::size_t output_length);

/**
 Absorbs bytes of the message (`KangarooTwelve_Update`).

 @param storage The instance's storage.
 @param input The bytes.
 @param length Their number.
 @return 0, or nonzero after `final`.
*/
int webcpp_hash_xkcp_kangarootwelve_update(std::uint64_t* storage, unsigned char const* input,
                                           std::size_t length);

/**
 Absorbs the customisation string, ends the input and writes the fixed output
 (`KangarooTwelve_Final`): KangarooTwelve takes its customisation here, not at `initialize`.

 @param storage The instance's storage.
 @param output Where `initialize`'s `output_length` bytes go (none when it was 0).
 @param customisation The customisation string C.
 @param customisation_length Its length.
 @return 0, or nonzero when called twice.
*/
int webcpp_hash_xkcp_kangarootwelve_final(std::uint64_t* storage, unsigned char* output,
                                          unsigned char const* customisation,
                                          std::size_t customisation_length);

/**
 Squeezes more output bytes (`KangarooTwelve_Squeeze`), after `final`.

 @param storage The instance's storage.
 @param output Where the bytes go.
 @param length Their number.
 @return 0, or nonzero before `final` (a length of 0 does nothing and returns 0).
*/
int webcpp_hash_xkcp_kangarootwelve_squeeze(std::uint64_t* storage, unsigned char* output,
                                            std::size_t length);

/**
 Starts cSHAKE128 (`cSHAKE128_Initialize`); with an empty function name and
 customisation it is SHAKE128.

 @param storage The instance's storage, an `xkcp_cshake_storage`.
 @param output_length The bytes `final` writes, 0 for the XOF form read by `squeeze`.
 @param function_name The function name N.
 @param function_name_length Its length.
 @param customisation The customisation string S.
 @param customisation_length Its length.
 @return 0, or nonzero when a length is over `SIZE_MAX / 8`.
*/
int webcpp_hash_xkcp_cshake128_initialize(std::uint64_t* storage, std::size_t output_length,
                                          unsigned char const* function_name,
                                          std::size_t function_name_length,
                                          unsigned char const* customisation,
                                          std::size_t customisation_length);

/**
 Absorbs bytes (`cSHAKE128_Update`).

 @param storage The instance's storage.
 @param input The bytes.
 @param length Their number.
 @return 0, or nonzero after `final`.
*/
int webcpp_hash_xkcp_cshake128_update(std::uint64_t* storage, unsigned char const* input,
                                      std::size_t length);

/**
 Ends the input and writes the fixed output (`cSHAKE128_Final`).

 @param storage The instance's storage.
 @param output Where `initialize`'s `output_length` bytes go (none when it was 0).
 @return 0, or nonzero when called twice.
*/
int webcpp_hash_xkcp_cshake128_final(std::uint64_t* storage, unsigned char* output);

/**
 Squeezes output bytes of the XOF form (`cSHAKE128_Squeeze`), after `final` with an
 `output_length` of 0.

 @param storage The instance's storage.
 @param output Where the bytes go.
 @param length Their number.
 @return 0, or nonzero before `final` (a length of 0 does nothing and returns 0).
*/
int webcpp_hash_xkcp_cshake128_squeeze(std::uint64_t* storage, unsigned char* output,
                                       std::size_t length);

/**
 Starts cSHAKE256 (`cSHAKE256_Initialize`); with an empty function name and
 customisation it is SHAKE256.

 @param storage The instance's storage, an `xkcp_cshake_storage`.
 @param output_length The bytes `final` writes, 0 for the XOF form read by `squeeze`.
 @param function_name The function name N.
 @param function_name_length Its length.
 @param customisation The customisation string S.
 @param customisation_length Its length.
 @return 0, or nonzero when a length is over `SIZE_MAX / 8`.
*/
int webcpp_hash_xkcp_cshake256_initialize(std::uint64_t* storage, std::size_t output_length,
                                          unsigned char const* function_name,
                                          std::size_t function_name_length,
                                          unsigned char const* customisation,
                                          std::size_t customisation_length);

/**
 Absorbs bytes (`cSHAKE256_Update`).

 @param storage The instance's storage.
 @param input The bytes.
 @param length Their number.
 @return 0, or nonzero after `final`.
*/
int webcpp_hash_xkcp_cshake256_update(std::uint64_t* storage, unsigned char const* input,
                                      std::size_t length);

/**
 Ends the input and writes the fixed output (`cSHAKE256_Final`).

 @param storage The instance's storage.
 @param output Where `initialize`'s `output_length` bytes go (none when it was 0).
 @return 0, or nonzero when called twice.
*/
int webcpp_hash_xkcp_cshake256_final(std::uint64_t* storage, unsigned char* output);

/**
 Squeezes output bytes of the XOF form (`cSHAKE256_Squeeze`), after `final` with an
 `output_length` of 0.

 @param storage The instance's storage.
 @param output Where the bytes go.
 @param length Their number.
 @return 0, or nonzero before `final` (a length of 0 does nothing and returns 0).
*/
int webcpp_hash_xkcp_cshake256_squeeze(std::uint64_t* storage, unsigned char* output,
                                       std::size_t length);

/**
 Starts KMAC128 (`KMAC128_Initialize`).

 @param storage The instance's storage, an `xkcp_kmac_storage`.
 @param key The key K, of any length.
 @param key_length Its length.
 @param output_length The tag's bytes `final` writes, 0 for KMACXOF128 read by `squeeze`.
 @param customisation The customisation string S.
 @param customisation_length Its length.
 @return 0, or nonzero when a length is over `SIZE_MAX / 8`.
*/
int webcpp_hash_xkcp_kmac128_initialize(std::uint64_t* storage, unsigned char const* key,
                                        std::size_t key_length, std::size_t output_length,
                                        unsigned char const* customisation,
                                        std::size_t customisation_length);

/**
 Absorbs bytes (`KMAC128_Update`).

 @param storage The instance's storage.
 @param input The bytes.
 @param length Their number.
 @return 0, or nonzero after `final`.
*/
int webcpp_hash_xkcp_kmac128_update(std::uint64_t* storage, unsigned char const* input,
                                    std::size_t length);

/**
 Ends the input and writes the fixed output (`KMAC128_Final`).

 @param storage The instance's storage.
 @param output Where `initialize`'s `output_length` bytes go (none when it was 0).
 @return 0, or nonzero when called twice.
*/
int webcpp_hash_xkcp_kmac128_final(std::uint64_t* storage, unsigned char* output);

/**
 Squeezes output bytes of the XOF form (`KMAC128_Squeeze`), after `final` with an
 `output_length` of 0.

 @param storage The instance's storage.
 @param output Where the bytes go.
 @param length Their number.
 @return 0, or nonzero before `final` (a length of 0 does nothing and returns 0).
*/
int webcpp_hash_xkcp_kmac128_squeeze(std::uint64_t* storage, unsigned char* output,
                                     std::size_t length);

/**
 Starts KMAC256 (`KMAC256_Initialize`).

 @param storage The instance's storage, an `xkcp_kmac_storage`.
 @param key The key K, of any length.
 @param key_length Its length.
 @param output_length The tag's bytes `final` writes, 0 for KMACXOF256 read by `squeeze`.
 @param customisation The customisation string S.
 @param customisation_length Its length.
 @return 0, or nonzero when a length is over `SIZE_MAX / 8`.
*/
int webcpp_hash_xkcp_kmac256_initialize(std::uint64_t* storage, unsigned char const* key,
                                        std::size_t key_length, std::size_t output_length,
                                        unsigned char const* customisation,
                                        std::size_t customisation_length);

/**
 Absorbs bytes (`KMAC256_Update`).

 @param storage The instance's storage.
 @param input The bytes.
 @param length Their number.
 @return 0, or nonzero after `final`.
*/
int webcpp_hash_xkcp_kmac256_update(std::uint64_t* storage, unsigned char const* input,
                                    std::size_t length);

/**
 Ends the input and writes the fixed output (`KMAC256_Final`).

 @param storage The instance's storage.
 @param output Where `initialize`'s `output_length` bytes go (none when it was 0).
 @return 0, or nonzero when called twice.
*/
int webcpp_hash_xkcp_kmac256_final(std::uint64_t* storage, unsigned char* output);

/**
 Squeezes output bytes of the XOF form (`KMAC256_Squeeze`), after `final` with an
 `output_length` of 0.

 @param storage The instance's storage.
 @param output Where the bytes go.
 @param length Their number.
 @return 0, or nonzero before `final` (a length of 0 does nothing and returns 0).
*/
int webcpp_hash_xkcp_kmac256_squeeze(std::uint64_t* storage, unsigned char* output,
                                     std::size_t length);

/**
 Starts TupleHash128 (`TupleHash128_Initialize`).

 @param storage The instance's storage, an `xkcp_tuplehash_storage`.
 @param output_length The bytes `final` writes, 0 for TupleHashXOF128 read by `squeeze`.
 @param customisation The customisation string S.
 @param customisation_length Its length.
 @return 0, or nonzero when a length is over `SIZE_MAX / 8`.
*/
int webcpp_hash_xkcp_tuplehash128_initialize(std::uint64_t* storage, std::size_t output_length,
                                             unsigned char const* customisation,
                                             std::size_t customisation_length);

/**
 Absorbs bytes (`TupleHash128_Update`).

 @param storage The instance's storage.
 @param input The bytes.
 @param length Their number.
 @return 0, or nonzero after `final`.
*/
int webcpp_hash_xkcp_tuplehash128_update(std::uint64_t* storage, unsigned char const* input,
                                         std::size_t length);

/**
 Ends the input and writes the fixed output (`TupleHash128_Final`).

 @param storage The instance's storage.
 @param output Where `initialize`'s `output_length` bytes go (none when it was 0).
 @return 0, or nonzero when called twice.
*/
int webcpp_hash_xkcp_tuplehash128_final(std::uint64_t* storage, unsigned char* output);

/**
 Ends the input with the output length L given now, in place of `initialize`'s
 `output_length` (`TupleHash128_Final`): SP 800-185 encodes L after the input, so that a caller that
 learns it last, as `hasher::finish` does, starts with an `output_length` of 0 and states it
 here.

 @param storage The instance's storage.
 @param output Where the `output_length` bytes go (none when it is 0).
 @param output_length L in bytes; 0 for TupleHashXOF128, read by `squeeze`.
 @return 0, or nonzero once the input has ended (after `final` or `final_length`) or for an
 `output_length` over `SIZE_MAX / 8`.
*/
int webcpp_hash_xkcp_tuplehash128_final_length(std::uint64_t* storage, unsigned char* output,
                                               std::size_t output_length);

/**
 Squeezes output bytes of the XOF form (`TupleHash128_Squeeze`), after `final` with an
 `output_length` of 0.

 @param storage The instance's storage.
 @param output Where the bytes go.
 @param length Their number.
 @return 0, or nonzero before `final` (a length of 0 does nothing and returns 0).
*/
int webcpp_hash_xkcp_tuplehash128_squeeze(std::uint64_t* storage, unsigned char* output,
                                          std::size_t length);

/**
 Starts TupleHash256 (`TupleHash256_Initialize`).

 @param storage The instance's storage, an `xkcp_tuplehash_storage`.
 @param output_length The bytes `final` writes, 0 for TupleHashXOF256 read by `squeeze`.
 @param customisation The customisation string S.
 @param customisation_length Its length.
 @return 0, or nonzero when a length is over `SIZE_MAX / 8`.
*/
int webcpp_hash_xkcp_tuplehash256_initialize(std::uint64_t* storage, std::size_t output_length,
                                             unsigned char const* customisation,
                                             std::size_t customisation_length);

/**
 Absorbs bytes (`TupleHash256_Update`).

 @param storage The instance's storage.
 @param input The bytes.
 @param length Their number.
 @return 0, or nonzero after `final`.
*/
int webcpp_hash_xkcp_tuplehash256_update(std::uint64_t* storage, unsigned char const* input,
                                         std::size_t length);

/**
 Ends the input and writes the fixed output (`TupleHash256_Final`).

 @param storage The instance's storage.
 @param output Where `initialize`'s `output_length` bytes go (none when it was 0).
 @return 0, or nonzero when called twice.
*/
int webcpp_hash_xkcp_tuplehash256_final(std::uint64_t* storage, unsigned char* output);

/**
 Ends the input with the output length L given now, in place of `initialize`'s
 `output_length` (`TupleHash256_Final`): SP 800-185 encodes L after the input, so that a caller that
 learns it last, as `hasher::finish` does, starts with an `output_length` of 0 and states it
 here.

 @param storage The instance's storage.
 @param output Where the `output_length` bytes go (none when it is 0).
 @param output_length L in bytes; 0 for TupleHashXOF256, read by `squeeze`.
 @return 0, or nonzero once the input has ended (after `final` or `final_length`) or for an
 `output_length` over `SIZE_MAX / 8`.
*/
int webcpp_hash_xkcp_tuplehash256_final_length(std::uint64_t* storage, unsigned char* output,
                                               std::size_t output_length);

/**
 Squeezes output bytes of the XOF form (`TupleHash256_Squeeze`), after `final` with an
 `output_length` of 0.

 @param storage The instance's storage.
 @param output Where the bytes go.
 @param length Their number.
 @return 0, or nonzero before `final` (a length of 0 does nothing and returns 0).
*/
int webcpp_hash_xkcp_tuplehash256_squeeze(std::uint64_t* storage, unsigned char* output,
                                          std::size_t length);

/**
 Starts ParallelHash128 (`ParallelHash128_Initialize`).

 @param storage The instance's storage, an `xkcp_parallelhash_storage`.
 @param block_size The block size B in bytes: XKCP takes a power of two of at least 8 (the
 lane's size) and refuses any other.
 @param output_length The bytes `final` writes, 0 for ParallelHashXOF128 read by `squeeze`.
 @param customisation The customisation string S.
 @param customisation_length Its length.
 @return 0, or nonzero for a block size XKCP refuses or a length over `SIZE_MAX / 8`.
*/
int webcpp_hash_xkcp_parallelhash128_initialize(std::uint64_t* storage, std::size_t block_size,
                                                std::size_t output_length,
                                                unsigned char const* customisation,
                                                std::size_t customisation_length);

/**
 Absorbs bytes (`ParallelHash128_Update`).

 @param storage The instance's storage.
 @param input The bytes.
 @param length Their number.
 @return 0, or nonzero after `final`.
*/
int webcpp_hash_xkcp_parallelhash128_update(std::uint64_t* storage, unsigned char const* input,
                                            std::size_t length);

/**
 Ends the input and writes the fixed output (`ParallelHash128_Final`).

 @param storage The instance's storage.
 @param output Where `initialize`'s `output_length` bytes go (none when it was 0).
 @return 0, or nonzero when called twice.
*/
int webcpp_hash_xkcp_parallelhash128_final(std::uint64_t* storage, unsigned char* output);

/**
 Ends the input with the output length L given now, in place of `initialize`'s
 `output_length` (`ParallelHash128_Final`): SP 800-185 encodes L after the input, so that a caller
 that learns it last, as `hasher::finish` does, starts with an `output_length` of 0 and states it
 here.

 @param storage The instance's storage.
 @param output Where the `output_length` bytes go (none when it is 0).
 @param output_length L in bytes; 0 for ParallelHashXOF128, read by `squeeze`.
 @return 0, or nonzero once the input has ended (after `final` or `final_length`) or for an
 `output_length` over `SIZE_MAX / 8`.
*/
int webcpp_hash_xkcp_parallelhash128_final_length(std::uint64_t* storage, unsigned char* output,
                                                  std::size_t output_length);

/**
 Squeezes output bytes of the XOF form (`ParallelHash128_Squeeze`), after `final` with an
 `output_length` of 0.

 @param storage The instance's storage.
 @param output Where the bytes go.
 @param length Their number.
 @return 0, or nonzero before `final` (a length of 0 does nothing and returns 0).
*/
int webcpp_hash_xkcp_parallelhash128_squeeze(std::uint64_t* storage, unsigned char* output,
                                             std::size_t length);

/**
 Starts ParallelHash256 (`ParallelHash256_Initialize`).

 @param storage The instance's storage, an `xkcp_parallelhash_storage`.
 @param block_size The block size B in bytes: XKCP takes a power of two of at least 8 (the
 lane's size) and refuses any other.
 @param output_length The bytes `final` writes, 0 for ParallelHashXOF256 read by `squeeze`.
 @param customisation The customisation string S.
 @param customisation_length Its length.
 @return 0, or nonzero for a block size XKCP refuses or a length over `SIZE_MAX / 8`.
*/
int webcpp_hash_xkcp_parallelhash256_initialize(std::uint64_t* storage, std::size_t block_size,
                                                std::size_t output_length,
                                                unsigned char const* customisation,
                                                std::size_t customisation_length);

/**
 Absorbs bytes (`ParallelHash256_Update`).

 @param storage The instance's storage.
 @param input The bytes.
 @param length Their number.
 @return 0, or nonzero after `final`.
*/
int webcpp_hash_xkcp_parallelhash256_update(std::uint64_t* storage, unsigned char const* input,
                                            std::size_t length);

/**
 Ends the input and writes the fixed output (`ParallelHash256_Final`).

 @param storage The instance's storage.
 @param output Where `initialize`'s `output_length` bytes go (none when it was 0).
 @return 0, or nonzero when called twice.
*/
int webcpp_hash_xkcp_parallelhash256_final(std::uint64_t* storage, unsigned char* output);

/**
 Ends the input with the output length L given now, in place of `initialize`'s
 `output_length` (`ParallelHash256_Final`): SP 800-185 encodes L after the input, so that a caller
 that learns it last, as `hasher::finish` does, starts with an `output_length` of 0 and states it
 here.

 @param storage The instance's storage.
 @param output Where the `output_length` bytes go (none when it is 0).
 @param output_length L in bytes; 0 for ParallelHashXOF256, read by `squeeze`.
 @return 0, or nonzero once the input has ended (after `final` or `final_length`) or for an
 `output_length` over `SIZE_MAX / 8`.
*/
int webcpp_hash_xkcp_parallelhash256_final_length(std::uint64_t* storage, unsigned char* output,
                                                  std::size_t output_length);

/**
 Squeezes output bytes of the XOF form (`ParallelHash256_Squeeze`), after `final` with an
 `output_length` of 0.

 @param storage The instance's storage.
 @param output Where the bytes go.
 @param length Their number.
 @return 0, or nonzero before `final` (a length of 0 does nothing and returns 0).
*/
int webcpp_hash_xkcp_parallelhash256_squeeze(std::uint64_t* storage, unsigned char* output,
                                             std::size_t length);
}

#endif  // WEBCPP_HASH_DETAIL_XKCP_HPP
