# Working on hash

webcpp's rules apply here: read the superproject's
[CODING-GUIDELINES.md](../../CODING-GUIDELINES.md)
(<https://github.com/webcpporg/webcpp/blob/main/CODING-GUIDELINES.md>) and its
[AGENTS.md](../../AGENTS.md)
(<https://github.com/webcpporg/webcpp/blob/main/AGENTS.md>) first. This file holds only what is
specific to hash.

## What hash is

- **webcpp's own library** (`"port-of": null`), a wrapper: Boost.Hash2's algorithms by alias, and
  C libraries (XKCP, BLAKE3, libsodium, BearSSL, OpenSSL) behind backends.
- **Two constructions of webcpp's own, and no primitive:** HKDF and PBKDF2 over Boost.Hash2's
  `hmac<H>` (`backends::hash2`), and Keccak-256's sponge over XKCP's permutation.
- **Oracles.** Boost.Hash2 and the other backends' agreement on random inputs, and the standards'
  own vectors, are the evidence.

## Cautions

- Every C library is upstream code, unchanged except where CODING-GUIDELINES.md chapter 5 rule 1
  allows a security fix on the mirror's `webcpp` branch (BearSSL: 32381d6, ECDSA's nonce
  decoding); a moved pin carries that commit. A moved pin is a change of its own (rule 12).
- A test is declared through `hash-run` in `test/Jamfile`, which runs it with exceptions and
  without.
- Every function that computes on a key, a password or a key derivation's secret input holds
  `secure::timing_guard` (webcpp::secure's, `<webcpp/secure/timing_guard.hpp>`) as its first
  statement (`timing{engaged}` where the arguments decide whether the call is keyed); unkeyed
  digests and Boost.Hash2's types by alias hold none. A new keyed function, or a keyed cell that
  `doc/capabilities.json` gains (a MAC, a key derivation, a password hash, on any backend), holds
  the guard and gets its call in that backend's `test/timing_coverage_<backend>_test.cpp`, which
  fails until it does. The seam support (`test/support/timing_seam.hpp`) counts hash's own guards
  by their file, under `include/webcpp/hash/`, in `timing_entries`, and every guard in
  `timing_all_entries`.
- Every wipe of a secret or of a failed output is `secure::erase_secret` over a span
  (`<webcpp/secure/erase_secret.hpp>`); a test sees each one through secure's seam
  `WEBCPP_SECURE_TEST_WIPE_RECORD` (`test/support/wipe_record.hpp`). hash depends on config and
  secure, no other webcpp library.
- `include/webcpp/hash/detail/canary.h` is a C header: it is in neither the headers-alone list nor
  `meta/include-boundaries.json`.
