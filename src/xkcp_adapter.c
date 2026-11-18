/* Copyright (c) 2026 WebCpp.org
 *
 * Distributed under the Boost Software License, Version 1.0. (See
 * accompanying file LICENSE_1_0.txt or copy at
 * https://www.boost.org/LICENSE_1_0.txt)
 *
 * webcpp::hash's adapter over XKCP: functions of webcpp's own names, so that no XKCP header,
 * and with them XKCP's config.h, reaches a program's translation unit
 * (include/webcpp/hash/detail/xkcp.hpp declares them).
 *
 * Keccak-p[1600]: the state is the caller's 25 lanes of 64 bits, the layout of
 * KeccakP1600_plain64_state. offset + length never exceeds 200, the state's size: the callers
 * are keccak_256's members, which the unsigned int casts rely on.
 *
 * The high-level interfaces (the sponge, FIPS 202's Keccak_Hash, TurboSHAKE, KangarooTwelve,
 * and SP 800-185's cSHAKE, KMAC, TupleHash and ParallelHash): each instance lives in the
 * caller's storage of 64-bit words, opaque to it, whose size per kind is
 * detail/xkcp_storage.h's WEBCPP_HASH_XKCP_*_WORDS, the numbers detail/xkcp.hpp allocates;
 * static assertions stop the build on any target or pin where XKCP's structure outgrows it
 * or needs a stricter alignment. Every length is in bytes and every function returns XKCP's
 * answer, 0 on success. SP 800-185 and Keccak_Hash count lengths in bits in a size_t: input
 * and squeezed output are passed in chunks of at most SIZE_MAX / 8 bytes, and a key, name,
 * customisation, tuple element or fixed output longer than that is refused (1) before XKCP
 * is called. A null pointer with a length of zero is passed as a pointer to an empty byte
 * string. */
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include <webcpp/hash/detail/xkcp_storage.h>

#include "KangarooTwelve.h"
#include "KeccakHash.h"
#include "KeccakP-1600-SnP.h"
#include "KeccakSponge.h"
#include "SP800-185.h"
#include "TurboSHAKE.h"

void webcpp_hash_xkcp_initialize(uint64_t* state) {
    KeccakP1600_Initialize((KeccakP1600_plain64_state*)state);
}

void webcpp_hash_xkcp_add_bytes(uint64_t* state, const unsigned char* data, size_t offset,
                                size_t length) {
    KeccakP1600_AddBytes((KeccakP1600_plain64_state*)state, data, (unsigned int)offset,
                         (unsigned int)length);
}

void webcpp_hash_xkcp_permute(uint64_t* state) {
    KeccakP1600_Permute_24rounds((KeccakP1600_plain64_state*)state);
}

void webcpp_hash_xkcp_extract_bytes(const uint64_t* state, unsigned char* data, size_t offset,
                                    size_t length) {
    KeccakP1600_ExtractBytes((const KeccakP1600_plain64_state*)state, data, (unsigned int)offset,
                             (unsigned int)length);
}

/* That type fits in that many words of uint64_t, at their alignment: _Static_assert where the
 * dialect has it (C11), else an array whose size is negative when it does not, which MSVC's
 * C without /std:c11 also stops on. */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define WEBCPP_HASH_XKCP_FITS(type, words)                                                  \
    _Static_assert(                                                                         \
        sizeof(type) <= (words) * sizeof(uint64_t) && _Alignof(type) <= _Alignof(uint64_t), \
        #type " outgrows webcpp's storage: raise " #words " in detail/xkcp_storage.h")
#else
#define WEBCPP_HASH_XKCP_FITS(type, words)                                                      \
    typedef char webcpp_hash_xkcp_##type##_outgrows_its_storage                                 \
        [(sizeof(type) <= (words) * sizeof(uint64_t) && __alignof(type) <= __alignof(uint64_t)) \
             ? 1                                                                                \
             : -1]
#endif

WEBCPP_HASH_XKCP_FITS(KeccakWidth1600_SpongeInstance, WEBCPP_HASH_XKCP_SPONGE_WORDS);
WEBCPP_HASH_XKCP_FITS(Keccak_HashInstance, WEBCPP_HASH_XKCP_KECCAK_HASH_WORDS);
WEBCPP_HASH_XKCP_FITS(TurboSHAKE_Instance, WEBCPP_HASH_XKCP_TURBOSHAKE_WORDS);
WEBCPP_HASH_XKCP_FITS(KangarooTwelve_Instance, WEBCPP_HASH_XKCP_KANGAROOTWELVE_WORDS);
WEBCPP_HASH_XKCP_FITS(cSHAKE_Instance, WEBCPP_HASH_XKCP_CSHAKE_WORDS);
WEBCPP_HASH_XKCP_FITS(KMAC_Instance, WEBCPP_HASH_XKCP_KMAC_WORDS);
WEBCPP_HASH_XKCP_FITS(TupleHash_Instance, WEBCPP_HASH_XKCP_TUPLEHASH_WORDS);
WEBCPP_HASH_XKCP_FITS(ParallelHash_Instance, WEBCPP_HASH_XKCP_PARALLELHASH_WORDS);

/* The most bytes whose length in bits a size_t holds. */
#define WEBCPP_HASH_XKCP_BIT_CHUNK (SIZE_MAX / 8)

static const unsigned char webcpp_hash_xkcp_no_bytes[1] = {0};

static const unsigned char* webcpp_hash_xkcp_bytes(const unsigned char* data) {
    return data != NULL ? data : webcpp_hash_xkcp_no_bytes;
}

/* The sponge: KeccakWidth1600_Sponge*. */

int webcpp_hash_xkcp_sponge_initialize(uint64_t* storage, unsigned int rate,
                                       unsigned int capacity) {
    return KeccakWidth1600_SpongeInitialize((KeccakWidth1600_SpongeInstance*)storage, rate,
                                            capacity);
}

int webcpp_hash_xkcp_sponge_update(uint64_t* storage, const unsigned char* input, size_t length) {
    return KeccakWidth1600_SpongeAbsorb((KeccakWidth1600_SpongeInstance*)storage,
                                        webcpp_hash_xkcp_bytes(input), length);
}

int webcpp_hash_xkcp_sponge_final(uint64_t* storage, unsigned char delimited_suffix) {
    return KeccakWidth1600_SpongeAbsorbLastFewBits((KeccakWidth1600_SpongeInstance*)storage,
                                                   delimited_suffix);
}

int webcpp_hash_xkcp_sponge_squeeze(uint64_t* storage, unsigned char* output, size_t length) {
    if (length == 0) {
        return 0;
    }
    return KeccakWidth1600_SpongeSqueeze((KeccakWidth1600_SpongeInstance*)storage, output, length);
}

/* FIPS 202's Keccak_Hash*: SHA-3, SHAKE and Keccak by their rate, capacity and suffix. */

int webcpp_hash_xkcp_keccak_hash_initialize(uint64_t* storage, unsigned int rate,
                                            unsigned int capacity, size_t output_length,
                                            unsigned char delimited_suffix) {
    if (output_length > UINT_MAX / 8) {
        return 1;
    }
    return Keccak_HashInitialize((Keccak_HashInstance*)storage, rate, capacity,
                                 (unsigned int)(output_length * 8), delimited_suffix);
}

int webcpp_hash_xkcp_keccak_hash_update(uint64_t* storage, const unsigned char* input,
                                        size_t length) {
    input = webcpp_hash_xkcp_bytes(input);
    do {
        size_t const chunk =
            length < WEBCPP_HASH_XKCP_BIT_CHUNK ? length : WEBCPP_HASH_XKCP_BIT_CHUNK;
        if (Keccak_HashUpdate((Keccak_HashInstance*)storage, input, chunk * 8) != 0) {
            return 1;
        }
        input += chunk;
        length -= chunk;
    } while (length != 0);
    return 0;
}

int webcpp_hash_xkcp_keccak_hash_final(uint64_t* storage, unsigned char* output) {
    return Keccak_HashFinal((Keccak_HashInstance*)storage, output);
}

int webcpp_hash_xkcp_keccak_hash_squeeze(uint64_t* storage, unsigned char* output, size_t length) {
    while (length != 0) {
        size_t const chunk =
            length < WEBCPP_HASH_XKCP_BIT_CHUNK ? length : WEBCPP_HASH_XKCP_BIT_CHUNK;
        if (Keccak_HashSqueeze((Keccak_HashInstance*)storage, output, chunk * 8) != 0) {
            return 1;
        }
        output += chunk;
        length -= chunk;
    }
    return 0;
}

/* TurboSHAKE*: capacity 256 for TurboSHAKE128, 512 for TurboSHAKE256. */

int webcpp_hash_xkcp_turboshake_initialize(uint64_t* storage, unsigned int capacity) {
    return TurboSHAKE_Initialize((TurboSHAKE_Instance*)storage, capacity);
}

int webcpp_hash_xkcp_turboshake_update(uint64_t* storage, const unsigned char* input,
                                       size_t length) {
    return TurboSHAKE_Absorb((TurboSHAKE_Instance*)storage, webcpp_hash_xkcp_bytes(input), length);
}

int webcpp_hash_xkcp_turboshake_final(uint64_t* storage, unsigned char domain) {
    return TurboSHAKE_AbsorbDomainSeparationByte((TurboSHAKE_Instance*)storage, domain);
}

int webcpp_hash_xkcp_turboshake_squeeze(uint64_t* storage, unsigned char* output, size_t length) {
    if (length == 0) {
        return 0;
    }
    return TurboSHAKE_Squeeze((TurboSHAKE_Instance*)storage, output, length);
}

/* KangarooTwelve_*: security level 128 for KT128, 256 for KT256. */

int webcpp_hash_xkcp_kangarootwelve_initialize(uint64_t* storage, int security_level,
                                               size_t output_length) {
    return KangarooTwelve_Initialize((KangarooTwelve_Instance*)storage, security_level,
                                     output_length);
}

int webcpp_hash_xkcp_kangarootwelve_update(uint64_t* storage, const unsigned char* input,
                                           size_t length) {
    return KangarooTwelve_Update((KangarooTwelve_Instance*)storage, webcpp_hash_xkcp_bytes(input),
                                 length);
}

int webcpp_hash_xkcp_kangarootwelve_final(uint64_t* storage, unsigned char* output,
                                          const unsigned char* customisation,
                                          size_t customisation_length) {
    return KangarooTwelve_Final((KangarooTwelve_Instance*)storage, output,
                                webcpp_hash_xkcp_bytes(customisation), customisation_length);
}

int webcpp_hash_xkcp_kangarootwelve_squeeze(uint64_t* storage, unsigned char* output,
                                            size_t length) {
    if (length == 0) {
        return 0;
    }
    return KangarooTwelve_Squeeze((KangarooTwelve_Instance*)storage, output, length);
}

/* SP 800-185. Each function of 128 and 256 bits: its update and squeeze in chunks, its
 * final as XKCP's. */

#define WEBCPP_HASH_XKCP_SP800_185_PHASES(name, xkcp, instance)                            \
    int webcpp_hash_xkcp_##name##_update(uint64_t* storage, const unsigned char* input,    \
                                         size_t length) {                                  \
        input = webcpp_hash_xkcp_bytes(input);                                             \
        do {                                                                               \
            size_t const chunk =                                                           \
                length < WEBCPP_HASH_XKCP_BIT_CHUNK ? length : WEBCPP_HASH_XKCP_BIT_CHUNK; \
            if (xkcp##_Update((instance*)storage, input, chunk * 8) != 0) {                \
                return 1;                                                                  \
            }                                                                              \
            input += chunk;                                                                \
            length -= chunk;                                                               \
        } while (length != 0);                                                             \
        return 0;                                                                          \
    }                                                                                      \
                                                                                           \
    int webcpp_hash_xkcp_##name##_final(uint64_t* storage, unsigned char* output) {        \
        return xkcp##_Final((instance*)storage, output);                                   \
    }                                                                                      \
                                                                                           \
    int webcpp_hash_xkcp_##name##_squeeze(uint64_t* storage, unsigned char* output,        \
                                          size_t length) {                                 \
        while (length != 0) {                                                              \
            size_t const chunk =                                                           \
                length < WEBCPP_HASH_XKCP_BIT_CHUNK ? length : WEBCPP_HASH_XKCP_BIT_CHUNK; \
            if (xkcp##_Squeeze((instance*)storage, output, chunk * 8) != 0) {              \
                return 1;                                                                  \
            }                                                                              \
            output += chunk;                                                               \
            length -= chunk;                                                               \
        }                                                                                  \
        return 0;                                                                          \
    }

/* cSHAKE: function name N and customisation S; an output length of 0 is the XOF. */
#define WEBCPP_HASH_XKCP_CSHAKE(name, xkcp)                                                        \
    int webcpp_hash_xkcp_##name##_initialize(                                                      \
        uint64_t* storage, size_t output_length, const unsigned char* function_name,               \
        size_t function_name_length, const unsigned char* customisation,                           \
        size_t customisation_length) {                                                             \
        if (output_length > WEBCPP_HASH_XKCP_BIT_CHUNK ||                                          \
            function_name_length > WEBCPP_HASH_XKCP_BIT_CHUNK ||                                   \
            customisation_length > WEBCPP_HASH_XKCP_BIT_CHUNK) {                                   \
            return 1;                                                                              \
        }                                                                                          \
        return xkcp##_Initialize((cSHAKE_Instance*)storage, output_length * 8,                     \
                                 webcpp_hash_xkcp_bytes(function_name), function_name_length * 8,  \
                                 webcpp_hash_xkcp_bytes(customisation), customisation_length * 8); \
    }                                                                                              \
    WEBCPP_HASH_XKCP_SP800_185_PHASES(name, xkcp, cSHAKE_Instance)

/* KMAC: key K and customisation S; an output length of 0 is KMACXOF. */
#define WEBCPP_HASH_XKCP_KMAC(name, xkcp)                                                          \
    int webcpp_hash_xkcp_##name##_initialize(                                                      \
        uint64_t* storage, const unsigned char* key, size_t key_length, size_t output_length,      \
        const unsigned char* customisation, size_t customisation_length) {                         \
        if (key_length > WEBCPP_HASH_XKCP_BIT_CHUNK ||                                             \
            output_length > WEBCPP_HASH_XKCP_BIT_CHUNK ||                                          \
            customisation_length > WEBCPP_HASH_XKCP_BIT_CHUNK) {                                   \
            return 1;                                                                              \
        }                                                                                          \
        return xkcp##_Initialize((KMAC_Instance*)storage, webcpp_hash_xkcp_bytes(key),             \
                                 key_length * 8, output_length * 8,                                \
                                 webcpp_hash_xkcp_bytes(customisation), customisation_length * 8); \
    }                                                                                              \
    WEBCPP_HASH_XKCP_SP800_185_PHASES(name, xkcp, KMAC_Instance)

/* TupleHash: customisation S; each update is one element of the tuple, so it is not cut in
 * chunks; an output length of 0 is TupleHashXOF. SP 800-185 encodes the output length L only
 * after the last element: final_length gives L there, for a caller that learns it after
 * initialize (webcpp's hasher), by setting the two members TupleHash_Final reads (the
 * instance's and its cSHAKE's) before calling it; it refuses once the input has ended, so that
 * no member of an ended instance changes. The tests check it against NIST's samples. */
#define WEBCPP_HASH_XKCP_TUPLEHASH(name, xkcp)                                                     \
    int webcpp_hash_xkcp_##name##_initialize(uint64_t* storage, size_t output_length,              \
                                             const unsigned char* customisation,                   \
                                             size_t customisation_length) {                        \
        if (output_length > WEBCPP_HASH_XKCP_BIT_CHUNK ||                                          \
            customisation_length > WEBCPP_HASH_XKCP_BIT_CHUNK) {                                   \
            return 1;                                                                              \
        }                                                                                          \
        return xkcp##_Initialize((TupleHash_Instance*)storage, output_length * 8,                  \
                                 webcpp_hash_xkcp_bytes(customisation), customisation_length * 8); \
    }                                                                                              \
                                                                                                   \
    int webcpp_hash_xkcp_##name##_update(uint64_t* storage, const unsigned char* element,          \
                                         size_t length) {                                          \
        TupleElement tuple_element;                                                                \
        if (length > WEBCPP_HASH_XKCP_BIT_CHUNK) {                                                 \
            return 1;                                                                              \
        }                                                                                          \
        tuple_element.input = webcpp_hash_xkcp_bytes(element);                                     \
        tuple_element.inputBitLen = length * 8;                                                    \
        return xkcp##_Update((TupleHash_Instance*)storage, &tuple_element, 1);                     \
    }                                                                                              \
                                                                                                   \
    int webcpp_hash_xkcp_##name##_final(uint64_t* storage, unsigned char* output) {                \
        return xkcp##_Final((TupleHash_Instance*)storage, output);                                 \
    }                                                                                              \
                                                                                                   \
    int webcpp_hash_xkcp_##name##_final_length(uint64_t* storage, unsigned char* output,           \
                                               size_t output_length) {                             \
        TupleHash_Instance* const instance = (TupleHash_Instance*)storage;                         \
        if (output_length > WEBCPP_HASH_XKCP_BIT_CHUNK || instance->csi.phase != ABSORBING) {      \
            return 1;                                                                              \
        }                                                                                          \
        instance->outputBitLen = output_length * 8;                                                \
        instance->csi.fixedOutputLength = output_length * 8;                                       \
        return xkcp##_Final(instance, output);                                                     \
    }                                                                                              \
                                                                                                   \
    int webcpp_hash_xkcp_##name##_squeeze(uint64_t* storage, unsigned char* output,                \
                                          size_t length) {                                         \
        while (length != 0) {                                                                      \
            size_t const chunk =                                                                   \
                length < WEBCPP_HASH_XKCP_BIT_CHUNK ? length : WEBCPP_HASH_XKCP_BIT_CHUNK;         \
            if (xkcp##_Squeeze((TupleHash_Instance*)storage, output, chunk * 8) != 0) {            \
                return 1;                                                                          \
            }                                                                                      \
            output += chunk;                                                                       \
            length -= chunk;                                                                       \
        }                                                                                          \
        return 0;                                                                                  \
    }

/* ParallelHash: block size B in bytes and customisation S; an output length of 0 is
 * ParallelHashXOF. final_length gives L after the input, as TupleHash's does, through the one
 * member ParallelHash_Final reads. */
#define WEBCPP_HASH_XKCP_PARALLELHASH(name, xkcp)                                                  \
    int webcpp_hash_xkcp_##name##_initialize(                                                      \
        uint64_t* storage, size_t block_size, size_t output_length,                                \
        const unsigned char* customisation, size_t customisation_length) {                         \
        if (output_length > WEBCPP_HASH_XKCP_BIT_CHUNK ||                                          \
            customisation_length > WEBCPP_HASH_XKCP_BIT_CHUNK) {                                   \
            return 1;                                                                              \
        }                                                                                          \
        return xkcp##_Initialize((ParallelHash_Instance*)storage, block_size, output_length * 8,   \
                                 webcpp_hash_xkcp_bytes(customisation), customisation_length * 8); \
    }                                                                                              \
                                                                                                   \
    int webcpp_hash_xkcp_##name##_final_length(uint64_t* storage, unsigned char* output,           \
                                               size_t output_length) {                             \
        ParallelHash_Instance* const instance = (ParallelHash_Instance*)storage;                   \
        if (output_length > WEBCPP_HASH_XKCP_BIT_CHUNK || instance->phase != ABSORBING) {          \
            return 1;                                                                              \
        }                                                                                          \
        instance->fixedOutputLength = output_length * 8;                                           \
        return xkcp##_Final(instance, output);                                                     \
    }                                                                                              \
    WEBCPP_HASH_XKCP_SP800_185_PHASES(name, xkcp, ParallelHash_Instance)

WEBCPP_HASH_XKCP_CSHAKE(cshake128, cSHAKE128)
WEBCPP_HASH_XKCP_CSHAKE(cshake256, cSHAKE256)
WEBCPP_HASH_XKCP_KMAC(kmac128, KMAC128)
WEBCPP_HASH_XKCP_KMAC(kmac256, KMAC256)
WEBCPP_HASH_XKCP_TUPLEHASH(tuplehash128, TupleHash128)
WEBCPP_HASH_XKCP_TUPLEHASH(tuplehash256, TupleHash256)
WEBCPP_HASH_XKCP_PARALLELHASH(parallelhash128, ParallelHash128)
WEBCPP_HASH_XKCP_PARALLELHASH(parallelhash256, ParallelHash256)
