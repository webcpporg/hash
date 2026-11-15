# hash

hash is one entry point for hashing and key derivation in a C++20 program, on every target
[webcpp](https://github.com/webcpporg/webcpp) has: native (Linux, macOS, Windows with MSVC),
wasip2, wasip3 and Emscripten. Boost.Hash2's algorithms and `hmac` are re-exported by alias;
Keccak-256, BLAKE3, Argon2id and scrypt run on C libraries; HKDF and PBKDF2 run on a backend of
the program's choice. Every function is synchronous, reports failure as a value and allocates
nothing in webcpp's own code.

Nothing but the library's skeleton is built so far: the configuration header, the test rule and
the documentation's outline.

## Building and testing

hash lives in the superproject's `libs/hash`. From the root of a webcpp checkout, each lane
builds from scratch:

```
b2 -a --build-dir=bin/lane-native libs/hash/test libs/hash/example
b2 -a --build-dir=bin/lane-wasip2 toolset=clang-wasip2 testing.launcher=tools/boost/asio-wasip2/run.sh libs/hash/test libs/hash/example
b2 -a --build-dir=bin/lane-wasip3 toolset=clang-wasip3 testing.launcher=tools/boost/asio-wasip3/run.sh libs/hash/test libs/hash/example
b2 -a --build-dir=bin/lane-emscripten toolset=emscripten libs/hash/test libs/hash/example
```

A program names `/webcpp/hash//hash` and the C library of each part it uses.

## Documentation

The page is published at <https://webcpporg.github.io/libs/hash/>.

## Licence

hash is under the Boost Software License, Version 1.0 (`LICENSE_1_0.txt`). The C libraries keep
their own licences.
