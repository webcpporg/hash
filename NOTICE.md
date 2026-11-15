# Notices

hash is under the Boost Software License, Version 1.0 (`LICENSE_1_0.txt`). Parts of its
documentation adapt another project's text, whose notice follows.

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

## Sources cited, never copied

The guide cites the RFCs, NIST's publications, the other standards and the projects it names, each
by its address, for their facts, and copies none of their text. Wikipedia's articles and
noble-hashes' README served as models of style alone; nothing of either is copied.
