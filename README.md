# hash

hash is one entry point for hashing and key derivation in a C++20 program, on every target
[webcpp](https://github.com/webcpporg/webcpp) has: native (Linux, macOS, Windows with MSVC), wasip2,
wasip3 and Emscripten. Boost.Hash2's algorithms and `hmac` are re-exported by alias; Keccak-256,
BLAKE3, Argon2id, scrypt, bcrypt and the key derivations of NIST SP 800-108, SP 800-56C and ANSI
X9.63 run on C and C++ libraries; HKDF and PBKDF2 run on a backend of the program's choice. The
families `digest_of`, `hasher`, `mac` and `argon2` reach the digests, MACs and Argon2 through a tag
and a backend: Boost.Hash2, XKCP, BLAKE3, libsodium, BearSSL, OpenSSL or Botan (with exceptions).
Every synchronous function reports failure as a value and allocates nothing in webcpp's own code;
`<webcpp/hash/async.hpp>` gives the slow functions and the ones the browser's WebCrypto has an
asynchronous form over webcpp::asio.

The guide (`doc/hash.adoc`) teaches each family of functions with two comparison tables, an example
program of `example/` per section and its pitfalls, then three applications from end to end; its
tables and `doc/llms.txt` are generated from `doc/capabilities.json` and the measured data by
`tools/hash/doc_tables.py`. Each function and tag has one default backend, the same on every
target: HKDF and PBKDF2 run on `backends::hash2`; Argon2id and scrypt on `backends::sodium` unless
the call names `backends::openssl`; a family's tag on the first of `backends::hash2`,
`backends::xkcp`, `backends::blake3` and `backends::sodium` that has it; `kbkdf`, `sskdf` and
`x963kdf` have no default and run on `backends::openssl` or `backends::botan`, named in the call,
and bcrypt on `backends::botan` alone. `backends::bearssl`, `backends::openssl` and
`backends::botan` are never a default. The measured table, `doc/measurements.json`, is a
reference measured on 2026-11-16 that decides nothing. `NOTICE.md` keeps the notice of the
documentation it adapts.

## Building and testing

hash lives in the superproject's `libs/hash`. From the root of a webcpp checkout, each lane
builds from scratch:

```
b2 -a --build-dir=bin/lane-native libs/hash/test libs/hash/example
b2 -a --build-dir=bin/lane-wasip2 toolset=clang-wasip2 testing.launcher=tools/boost/asio-wasip2/run.sh libs/hash/test libs/hash/example
b2 -a --build-dir=bin/lane-wasip3 toolset=clang-wasip3 testing.launcher=tools/boost/asio-wasip3/run.sh libs/hash/test libs/hash/example
b2 -a --build-dir=bin/lane-emscripten toolset=emscripten libs/hash/test libs/hash/example
b2 -a --build-dir=bin/lane-gcc-15 toolset=gcc-15 libs/hash/test libs/hash/example
```

One own lane runs outside those: `c-suites` builds the C libraries' own test programs on every
target:

```
b2 -a --build-dir=bin/lane-c-suites libs/hash/test/c_suites//c-suites
```

The user Jamfiles of the library (each line of the specification's section 5.1, as a user
writes it) are built with b2 as a user runs it by `python3 tools/test/hash_jamfiles_test.py`.

A program names `/webcpp/hash//hash` and the C library of each part it uses.

## Documentation

The page is published at <https://webcpporg.github.io/libs/hash/>.

## Licence

hash is under the Boost Software License, Version 1.0 (`LICENSE_1_0.txt`). The C libraries keep
their own licences.
