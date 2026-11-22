# Notices

hash is under the Boost Software License, Version 1.0 (`LICENSE_1_0.txt`). Parts of its
documentation adapt other projects' text, whose notices follow.

## libsodium's documentation

The sections of `doc/` that say they adapt libsodium's documentation (on SipHash in
`doc/macs.adoc`, on HKDF in `doc/kdfs.adoc`, and on Argon2 and scrypt in
`doc/password_hashing.adoc`) adapt [libsodium-doc](https://github.com/jedisct1/libsodium-doc) at
commit `6d1ea27b79b853b2a04f09ae9e1a8231c90e3b56`: its pages `hashing/short-input_hashing.md`,
`key_derivation/hkdf.md`, `password_hashing/default_phf.md` and `password_hashing/scrypt.md`.
Its licence, kept as it is:

```
Copyright (c) 2014-2026, Frank Denis <github@pureftpd.org>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

## Botan's documentation

The sections of `doc/` that say they adapt Botan's documentation (on Streebog and Whirlpool in
`doc/digests.adoc`, and on bcrypt in `doc/password_hashing.adoc`) adapt the documentation of
[Botan](https://github.com/randombit/botan) 3.14.1, at commit
`01af88c039fcfaedc418b1af4d6d3a139674e591`: its pages `doc/api_ref/hash.rst`,
`doc/deprecated.rst` and `doc/api_ref/passhash.rst`. Its licence, kept as it is:

```
Copyright (C) 1999-2026 The Botan Authors
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions, and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions, and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
```

## Sources cited, never copied

The guide cites the RFCs, NIST's publications, the other standards and the projects it names, each
by its address, for their facts, and copies none of their text. Wikipedia's articles and
noble-hashes' README served as models of style alone; nothing of either is copied.
