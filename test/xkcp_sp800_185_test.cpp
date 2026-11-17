// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// NIST SP 800-185's functions on backends::xkcp: cSHAKE through digest_of and hasher, KMAC and
// KMACXOF through mac, TupleHash and TupleHashXOF through hasher (one update per element of the
// tuple) and digest_of (a tuple of one element), ParallelHash and ParallelHashXOF through
// digest_of and hasher; their options (cSHAKE's function name and customisation, KMAC's,
// TupleHash's and ParallelHash's customisation and extendable-output form, ParallelHash's block
// size) and their guards.
//
// - Every sample of NIST's example files for SP 800-185, each value copied from the file named
//   with its sample below and checked twice: against XKCP's own copy of the samples
//   (tests/UnitTests/testSP800-185.c, which leaves out ParallelHash's block size of 12) and
//   against an implementation of SP 800-185 over Keccak-f[1600] written from the standards,
//   independent of XKCP, which reproduces all 40 samples. ParallelHash's samples 3 and 6 use a
//   block size of 12, which XKCP does not take: on backends::xkcp they are
//   unsupported_by_backend, counted.
//   https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/cSHAKE_samples.pdf
//   https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMAC_samples.pdf
//   https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMACXOF_samples.pdf
//   https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TupleHash_samples.pdf
//   https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TupleHashXOF_samples.pdf
//   https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/ParallelHash_samples.pdf
//   https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/ParallelHashXOF_samples.pdf
// - webcpp's own cases, each value from that independent implementation (a Python script written
//   for this test from SP 800-185's text over its own Keccak-f[1600], whose sponge agrees with
//   Python's hashlib on SHA3-256 and SHAKE, and which reproduces NIST's 40 samples; kept beside
//   the plan's Task 32 report as task-32-sp800185.py, not in the repository):
//   a function name, an
//   output past the rate, the tuple of one element, the empty tuple and the tuple of one empty
//   element, a ParallelHash with a last block shorter than the others, an empty KMAC key.
// - cSHAKE with no function name and no customisation is SHAKE (SP 800-185, section 3.3).
//
// Each digest is taken in one call and through a hasher at several splits of its input.

#include <webcpp/hash/backends/xkcp.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/mac.hpp>
#include <webcpp/test/exit_status.hpp>

#include "require.hpp"
#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace {

namespace hash = webcpp::hash;
namespace digests = webcpp::hash::digests;
namespace macs = webcpp::hash::macs;
namespace test = webcpp::test;
using webcpp::hash::backends::xkcp;
using bytes = std::vector<std::uint8_t>;

// One sample of NIST's files: the function ("cSHAKE", "KMAC", "KMACXOF", "TupleHash",
// "TupleHashXOF", "ParallelHash", "ParallelHashXOF"), its security strength and number in its
// file, and its inputs and output in hex (strings as text). A tuple's elements are not empty.
struct sample {
    std::string_view kind;
    int security = 0;
    int number = 0;
    std::string_view key;
    std::string_view data;
    std::array<std::string_view, 3> tuple{};
    std::size_t block_size = 0;
    std::string_view function_name;
    std::string_view customisation;
    std::string_view output;
};

std::vector<sample> const& nist_samples() {
    static std::vector<sample> const all{
        {
            .kind = "cSHAKE",
            .security = 128,
            .number = 1,
            .key = "",
            .data = "00010203",
            .block_size = 0,
            .function_name = "",
            .customisation = "Email Signature",
            .output = "c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5",
        },
        {
            .kind = "cSHAKE",
            .security = 128,
            .number = 2,
            .key = "",
            .data =
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627"
                "28292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
                "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f7071727374757677"
                "78797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7",
            .block_size = 0,
            .function_name = "",
            .customisation = "Email Signature",
            .output = "c5221d50e4f822d96a2e8881a961420f294b7b24fe3d2094baed2c6524cc166b",
        },
        {
            .kind = "cSHAKE",
            .security = 256,
            .number = 3,
            .key = "",
            .data = "00010203",
            .block_size = 0,
            .function_name = "",
            .customisation = "Email Signature",
            .output =
                "d008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd164020e2be0560858"
                "d9c00c037e34a96937c561a74c412bb4c746469527281c8c",
        },
        {
            .kind = "cSHAKE",
            .security = 256,
            .number = 4,
            .key = "",
            .data =
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627"
                "28292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
                "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f7071727374757677"
                "78797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7",
            .block_size = 0,
            .function_name = "",
            .customisation = "Email Signature",
            .output =
                "07dc27b11e51fbac75bc7b3c1d983e8b4b85fb1defaf218912ac86430273091727f42b17ed1df63e"
                "8ec118f04b23633c1dfb1574c8fb55cb45da8e25afb092bb",
        },
        {
            .kind = "KMAC",
            .security = 128,
            .number = 1,
            .key = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            .data = "00010203",
            .block_size = 0,
            .function_name = "",
            .customisation = "",
            .output = "e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e",
        },
        {
            .kind = "KMAC",
            .security = 128,
            .number = 2,
            .key = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            .data = "00010203",
            .block_size = 0,
            .function_name = "",
            .customisation = "My Tagged Application",
            .output = "3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5",
        },
        {
            .kind = "KMAC",
            .security = 128,
            .number = 3,
            .key = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            .data =
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627"
                "28292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
                "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f7071727374757677"
                "78797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7",
            .block_size = 0,
            .function_name = "",
            .customisation = "My Tagged Application",
            .output = "1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230",
        },
        {
            .kind = "KMAC",
            .security = 256,
            .number = 4,
            .key = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            .data = "00010203",
            .block_size = 0,
            .function_name = "",
            .customisation = "My Tagged Application",
            .output =
                "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a"
                "351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd",
        },
        {
            .kind = "KMAC",
            .security = 256,
            .number = 5,
            .key = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            .data =
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627"
                "28292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
                "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f7071727374757677"
                "78797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7",
            .block_size = 0,
            .function_name = "",
            .customisation = "",
            .output =
                "75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691589d27cf5e15369c"
                "bbff8b9a4c2eb17800855d0235ff635da82533ec6b759b69",
        },
        {
            .kind = "KMAC",
            .security = 256,
            .number = 6,
            .key = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            .data =
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627"
                "28292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
                "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f7071727374757677"
                "78797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7",
            .block_size = 0,
            .function_name = "",
            .customisation = "My Tagged Application",
            .output =
                "b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d970fbacfde50033ae"
                "a585f1a2708510c32d07880801bd182898fe476876fc8965",
        },
        {
            .kind = "KMACXOF",
            .security = 128,
            .number = 1,
            .key = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            .data = "00010203",
            .block_size = 0,
            .function_name = "",
            .customisation = "",
            .output = "cd83740bbd92ccc8cf032b1481a0f4460e7ca9dd12b08a0c4031178bacd6ec35",
        },
        {
            .kind = "KMACXOF",
            .security = 128,
            .number = 2,
            .key = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            .data = "00010203",
            .block_size = 0,
            .function_name = "",
            .customisation = "My Tagged Application",
            .output = "31a44527b4ed9f5c6101d11de6d26f0620aa5c341def41299657fe9df1a3b16c",
        },
        {
            .kind = "KMACXOF",
            .security = 128,
            .number = 3,
            .key = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            .data =
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627"
                "28292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
                "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f7071727374757677"
                "78797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7",
            .block_size = 0,
            .function_name = "",
            .customisation = "My Tagged Application",
            .output = "47026c7cd793084aa0283c253ef658490c0db61438b8326fe9bddf281b83ae0f",
        },
        {
            .kind = "KMACXOF",
            .security = 256,
            .number = 4,
            .key = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            .data = "00010203",
            .block_size = 0,
            .function_name = "",
            .customisation = "My Tagged Application",
            .output =
                "1755133f1534752aad0748f2c706fb5c784512cab835cd15676b16c0c6647fa96faa7af634a0bf8f"
                "f6df39374fa00fad9a39e322a7c92065a64eb1fb0801eb2b",
        },
        {
            .kind = "KMACXOF",
            .security = 256,
            .number = 5,
            .key = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            .data =
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627"
                "28292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
                "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f7071727374757677"
                "78797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7",
            .block_size = 0,
            .function_name = "",
            .customisation = "",
            .output =
                "ff7b171f1e8a2b24683eed37830ee797538ba8dc563f6da1e667391a75edc02ca633079f81ce12a2"
                "5f45615ec89972031d18337331d24ceb8f8ca8e6a19fd98b",
        },
        {
            .kind = "KMACXOF",
            .security = 256,
            .number = 6,
            .key = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            .data =
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627"
                "28292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
                "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f7071727374757677"
                "78797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7",
            .block_size = 0,
            .function_name = "",
            .customisation = "My Tagged Application",
            .output =
                "d5be731c954ed7732846bb59dbe3a8e30f83e77a4bff4459f2f1c2b4ecebb8ce67ba01c62e8ab857"
                "8d2d499bd1bb276768781190020a306a97de281dcc30305d",
        },
        {
            .kind = "TupleHash",
            .security = 128,
            .number = 1,
            .key = "",
            .data = "",
            .tuple = {"000102", "101112131415"},
            .block_size = 0,
            .function_name = "",
            .customisation = "",
            .output = "c5d8786c1afb9b82111ab34b65b2c0048fa64e6d48e263264ce1707d3ffc8ed1",
        },
        {
            .kind = "TupleHash",
            .security = 128,
            .number = 2,
            .key = "",
            .data = "",
            .tuple = {"000102", "101112131415"},
            .block_size = 0,
            .function_name = "",
            .customisation = "My Tuple App",
            .output = "75cdb20ff4db1154e841d758e24160c54bae86eb8c13e7f5f40eb35588e96dfb",
        },
        {
            .kind = "TupleHash",
            .security = 128,
            .number = 3,
            .key = "",
            .data = "",
            .tuple = {"000102", "101112131415", "202122232425262728"},
            .block_size = 0,
            .function_name = "",
            .customisation = "My Tuple App",
            .output = "e60f202c89a2631eda8d4c588ca5fd07f39e5151998deccf973adb3804bb6e84",
        },
        {
            .kind = "TupleHash",
            .security = 256,
            .number = 4,
            .key = "",
            .data = "",
            .tuple = {"000102", "101112131415"},
            .block_size = 0,
            .function_name = "",
            .customisation = "",
            .output =
                "cfb7058caca5e668f81a12a20a2195ce97a925f1dba3e7449a56f82201ec607311ac2696b1ab5ea2"
                "352df1423bde7bd4bb78c9aed1a853c78672f9eb23bbe194",
        },
        {
            .kind = "TupleHash",
            .security = 256,
            .number = 5,
            .key = "",
            .data = "",
            .tuple = {"000102", "101112131415"},
            .block_size = 0,
            .function_name = "",
            .customisation = "My Tuple App",
            .output =
                "147c2191d5ed7efd98dbd96d7ab5a11692576f5fe2a5065f3e33de6bba9f3aa1c4e9a068a289c61c"
                "95aab30aee1e410b0b607de3620e24a4e3bf9852a1d4367e",
        },
        {
            .kind = "TupleHash",
            .security = 256,
            .number = 6,
            .key = "",
            .data = "",
            .tuple = {"000102", "101112131415", "202122232425262728"},
            .block_size = 0,
            .function_name = "",
            .customisation = "My Tuple App",
            .output =
                "45000be63f9b6bfd89f54717670f69a9bc763591a4f05c50d68891a744bcc6e7d6d5b5e82c018da9"
                "99ed35b0bb49c9678e526abd8e85c13ed254021db9e790ce",
        },
        {
            .kind = "TupleHashXOF",
            .security = 128,
            .number = 1,
            .key = "",
            .data = "",
            .tuple = {"000102", "101112131415"},
            .block_size = 0,
            .function_name = "",
            .customisation = "",
            .output = "2f103cd7c32320353495c68de1a8129245c6325f6f2a3d608d92179c96e68488",
        },
        {
            .kind = "TupleHashXOF",
            .security = 128,
            .number = 2,
            .key = "",
            .data = "",
            .tuple = {"000102", "101112131415"},
            .block_size = 0,
            .function_name = "",
            .customisation = "My Tuple App",
            .output = "3fc8ad69453128292859a18b6c67d7ad85f01b32815e22ce839c49ec374e9b9a",
        },
        {
            .kind = "TupleHashXOF",
            .security = 128,
            .number = 3,
            .key = "",
            .data = "",
            .tuple = {"000102", "101112131415", "202122232425262728"},
            .block_size = 0,
            .function_name = "",
            .customisation = "My Tuple App",
            .output = "900fe16cad098d28e74d632ed852f99daab7f7df4d99e775657885b4bf76d6f8",
        },
        {
            .kind = "TupleHashXOF",
            .security = 256,
            .number = 4,
            .key = "",
            .data = "",
            .tuple = {"000102", "101112131415"},
            .block_size = 0,
            .function_name = "",
            .customisation = "",
            .output =
                "03ded4610ed6450a1e3f8bc44951d14fbc384ab0efe57b000df6b6df5aae7cd568e77377daf13f37"
                "ec75cf5fc598b6841d51dd207c991cd45d210ba60ac52eb9",
        },
        {
            .kind = "TupleHashXOF",
            .security = 256,
            .number = 5,
            .key = "",
            .data = "",
            .tuple = {"000102", "101112131415"},
            .block_size = 0,
            .function_name = "",
            .customisation = "My Tuple App",
            .output =
                "6483cb3c9952eb20e830af4785851fc597ee3bf93bb7602c0ef6a65d741aeca7e63c3b128981aa05"
                "c6d27438c79d2754bb1b7191f125d6620fca12ce658b2442",
        },
        {
            .kind = "TupleHashXOF",
            .security = 256,
            .number = 6,
            .key = "",
            .data = "",
            .tuple = {"000102", "101112131415", "202122232425262728"},
            .block_size = 0,
            .function_name = "",
            .customisation = "My Tuple App",
            .output =
                "0c59b11464f2336c34663ed51b2b950bec743610856f36c28d1d088d8a2446284dd09830a6a178dc"
                "752376199fae935d86cfdee5913d4922dfd369b66a53c897",
        },
        {
            .kind = "ParallelHash",
            .security = 128,
            .number = 1,
            .key = "",
            .data = "000102030405060710111213141516172021222324252627",
            .block_size = 8,
            .function_name = "",
            .customisation = "",
            .output = "ba8dc1d1d979331d3f813603c67f72609ab5e44b94a0b8f9af46514454a2b4f5",
        },
        {
            .kind = "ParallelHash",
            .security = 128,
            .number = 2,
            .key = "",
            .data = "000102030405060710111213141516172021222324252627",
            .block_size = 8,
            .function_name = "",
            .customisation = "Parallel Data",
            .output = "fc484dcb3f84dceedc353438151bee58157d6efed0445a81f165e495795b7206",
        },
        {
            .kind = "ParallelHash",
            .security = 128,
            .number = 3,
            .key = "",
            .data =
                "000102030405060708090a0b101112131415161718191a1b202122232425262728292a2b30313233"
                "3435363738393a3b404142434445464748494a4b505152535455565758595a5b",
            .block_size = 12,
            .function_name = "",
            .customisation = "Parallel Data",
            .output = "f7fd5312896c6685c828af7e2adb97e393e7f8d54e3c2ea4b95e5aca3796e8fc",
        },
        {
            .kind = "ParallelHash",
            .security = 256,
            .number = 1,
            .key = "",
            .data = "000102030405060710111213141516172021222324252627",
            .block_size = 8,
            .function_name = "",
            .customisation = "",
            .output =
                "bc1ef124da34495e948ead207dd9842235da432d2bbc54b4c110e64c451105531b7f2a3e0ce055c0"
                "2805e7c2de1fb746af97a1dd01f43b824e31b87612410429",
        },
        {
            .kind = "ParallelHash",
            .security = 256,
            .number = 2,
            .key = "",
            .data = "000102030405060710111213141516172021222324252627",
            .block_size = 8,
            .function_name = "",
            .customisation = "Parallel Data",
            .output =
                "cdf15289b54f6212b4bc270528b49526006dd9b54e2b6add1ef6900dda3963bb33a72491f236969c"
                "a8afaea29c682d47a393c065b38e29fae651a2091c833110",
        },
        {
            .kind = "ParallelHash",
            .security = 256,
            .number = 3,
            .key = "",
            .data =
                "000102030405060708090a0b101112131415161718191a1b202122232425262728292a2b30313233"
                "3435363738393a3b404142434445464748494a4b505152535455565758595a5b",
            .block_size = 12,
            .function_name = "",
            .customisation = "Parallel Data",
            .output =
                "69d0fcb764ea055dd09334bc6021cb7e4b61348dff375da262671cdec3effa8d1b4568a6cce16b1c"
                "ad946ddde27f6ce2b8dee4cd1b24851ebf00eb90d43813e9",
        },
        {
            .kind = "ParallelHashXOF",
            .security = 128,
            .number = 1,
            .key = "",
            .data = "000102030405060710111213141516172021222324252627",
            .block_size = 8,
            .function_name = "",
            .customisation = "",
            .output = "fe47d661e49ffe5b7d999922c062356750caf552985b8e8ce6667f2727c3c8d3",
        },
        {
            .kind = "ParallelHashXOF",
            .security = 128,
            .number = 2,
            .key = "",
            .data = "000102030405060710111213141516172021222324252627",
            .block_size = 8,
            .function_name = "",
            .customisation = "Parallel Data",
            .output = "ea2a793140820f7a128b8eb70a9439f93257c6e6e79b4a540d291d6dae7098d7",
        },
        {
            .kind = "ParallelHashXOF",
            .security = 128,
            .number = 3,
            .key = "",
            .data =
                "000102030405060708090a0b101112131415161718191a1b202122232425262728292a2b30313233"
                "3435363738393a3b404142434445464748494a4b505152535455565758595a5b",
            .block_size = 12,
            .function_name = "",
            .customisation = "Parallel Data",
            .output = "0127ad9772ab904691987fcc4a24888f341fa0db2145e872d4efd255376602f0",
        },
        {
            .kind = "ParallelHashXOF",
            .security = 256,
            .number = 1,
            .key = "",
            .data = "000102030405060710111213141516172021222324252627",
            .block_size = 8,
            .function_name = "",
            .customisation = "",
            .output =
                "c10a052722614684144d28474850b410757e3cba87651ba167a5cbddff7f466675fbf84bcae7378a"
                "c444be681d729499afca667fb879348bfdda427863c82f1c",
        },
        {
            .kind = "ParallelHashXOF",
            .security = 256,
            .number = 2,
            .key = "",
            .data = "000102030405060710111213141516172021222324252627",
            .block_size = 8,
            .function_name = "",
            .customisation = "Parallel Data",
            .output =
                "538e105f1a22f44ed2f5cc1674fbd40be803d9c99bf5f8d90a2c8193f3fe6ea768e5c1a20987e2c9"
                "c65febed03887a51d35624ed12377594b5585541dc377efc",
        },
        {
            .kind = "ParallelHashXOF",
            .security = 256,
            .number = 3,
            .key = "",
            .data =
                "000102030405060708090a0b101112131415161718191a1b202122232425262728292a2b30313233"
                "3435363738393a3b404142434445464748494a4b505152535455565758595a5b",
            .block_size = 12,
            .function_name = "",
            .customisation = "Parallel Data",
            .output =
                "6b3e790b330c889a204c2fbc728d809f19367328d852f4002dc829f73afd6bcefb7fe5b607b13a80"
                "1c0be5c1170bdb794e339458fdb0e62a6af3d42558970249",
        },
    };
    return all;
}

bytes text_bytes(std::string_view text) {
    return {text.begin(), text.end()};
}

bool failed_with(boost::system::result<void> const& outcome, hash::error expected) {
    return outcome.has_error() && outcome.error() == expected;
}

// The splits of an input of size n in three pieces that each digest is also taken at.
std::vector<std::pair<std::size_t, std::size_t>> splits(std::size_t n) {
    return {{0, n}, {n / 3, 2 * n / 3}, {1, n / 2}, {n / 2, n / 2}, {n, n}};
}

// Whether Digest is TupleHash's, whose hasher takes one element of the tuple per update.
template <class Digest>
constexpr bool is_tuplehash = std::is_same_v<Digest, digests::tuplehash_128> ||
                              std::is_same_v<Digest, digests::tuplehash_256>;

// Digest on xkcp over input, of size bytes, in one call and at every split through a hasher
// (TupleHash's: in one update, its tuple's one element): each against expected.
template <class Digest>
void expect_digest(bytes const& input, hash::digest_options<Digest> const& options,
                   std::string_view expected, std::string const& what) {
    bytes once(expected.size() / 2);
    BOOST_TEST((hash::digest_of<Digest, xkcp>(once, input, options).has_value()));
    if (!BOOST_TEST_EQ(test::to_hex(once), expected)) {
        std::cerr << "  digest_of: " << what << '\n';
    }
    std::span<std::uint8_t const> const all(input);
    if constexpr (is_tuplehash<Digest>) {
        auto hashing = hash::hasher<Digest, xkcp>::make(options);
        test::require(BOOST_TEST(hashing.has_value()));
        BOOST_TEST(hashing->update(all).has_value());
        bytes whole(expected.size() / 2);
        BOOST_TEST(hashing->finish(whole).has_value());
        if (!BOOST_TEST_EQ(test::to_hex(whole), expected)) {
            std::cerr << "  hasher, one element: " << what << '\n';
        }
        return;
    }
    for (auto const& [first, second] : splits(input.size())) {
        auto hashing = hash::hasher<Digest, xkcp>::make(options);
        test::require(BOOST_TEST(hashing.has_value()));
        BOOST_TEST(hashing->update(all.first(first)).has_value());
        BOOST_TEST(hashing->update(all.subspan(first, second - first)).has_value());
        BOOST_TEST(hashing->update(all.subspan(second)).has_value());
        bytes pieces(expected.size() / 2);
        BOOST_TEST(hashing->finish(pieces).has_value());
        if (!BOOST_TEST_EQ(test::to_hex(pieces), expected)) {
            std::cerr << "  hasher split at " << first << ", " << second << ": " << what << '\n';
        }
    }
}

// A tuple's hash on xkcp through a hasher, one update per element.
template <class Digest>
std::string tuple_hash(std::vector<bytes> const& elements,
                       hash::digest_options<Digest> const& options, std::size_t size) {
    auto hashing = hash::hasher<Digest, xkcp>::make(options);
    test::require(BOOST_TEST(hashing.has_value()));
    for (auto const& element : elements) {
        BOOST_TEST(hashing->update(element).has_value());
    }
    bytes output(size);
    BOOST_TEST(hashing->finish(output).has_value());
    return test::to_hex(output);
}

// The tag of Mac on xkcp.
template <class Mac>
std::string mac_of(bytes const& key, bytes const& input, hash::mac_options<Mac> const& options,
                   std::size_t size) {
    bytes output(size);
    BOOST_TEST((hash::mac<Mac, xkcp>(output, key, input, options).has_value()));
    return test::to_hex(output);
}

// The name of a sample in a failure's report.
std::string name_of(sample const& s) {
    return std::string(s.kind) + std::to_string(s.security) + " sample #" +
           std::to_string(s.number);
}

// How many samples of each kind ran, and how many ParallelHash ones XKCP refused.
struct counts {
    int cshake = 0;
    int kmac = 0;
    int tuplehash = 0;
    int parallelhash = 0;
    int refused_block_size = 0;
};

template <class CShake>
void run_cshake(sample const& s) {
    auto const name = text_bytes(s.function_name);
    auto const customisation = text_bytes(s.customisation);
    expect_digest<CShake>(test::from_hex(s.data),
                          {.function_name = name, .customisation = customisation}, s.output,
                          name_of(s));
}

template <class Kmac>
void run_kmac(sample const& s, bool xof) {
    auto const customisation = text_bytes(s.customisation);
    auto const tag =
        mac_of<Kmac>(test::from_hex(s.key), test::from_hex(s.data),
                     {.customisation = customisation, .xof = xof}, s.output.size() / 2);
    if (!BOOST_TEST_EQ(tag, s.output)) {
        std::cerr << "  " << name_of(s) << '\n';
    }
}

template <class TupleHash>
void run_tuplehash(sample const& s, bool xof) {
    std::vector<bytes> elements;
    for (auto const element : s.tuple) {
        if (!element.empty()) {
            elements.push_back(test::from_hex(element));
        }
    }
    BOOST_TEST(elements.size() == 2 || elements.size() == 3);
    auto const customisation = text_bytes(s.customisation);
    auto const value = tuple_hash<TupleHash>(elements, {.customisation = customisation, .xof = xof},
                                             s.output.size() / 2);
    if (!BOOST_TEST_EQ(value, s.output)) {
        std::cerr << "  " << name_of(s) << '\n';
    }
}

// A ParallelHash sample: run when XKCP takes its block size, else refused before any work.
template <class ParallelHash>
void run_parallelhash(sample const& s, bool xof, counts& counted) {
    auto const customisation = text_bytes(s.customisation);
    hash::digest_options<ParallelHash> const options{
        .block_size = s.block_size,
        .customisation = customisation,
        .xof = xof,
    };
    if (s.block_size == 12) {
        bytes output(s.output.size() / 2, 0xAA);
        BOOST_TEST(failed_with(
            hash::digest_of<ParallelHash, xkcp>(output, test::from_hex(s.data), options),
            hash::error::unsupported_by_backend));
        BOOST_TEST(output == bytes(output.size(), 0xAA));
        auto const started = hash::hasher<ParallelHash, xkcp>::make(options);
        BOOST_TEST(started.has_error() && started.error() == hash::error::unsupported_by_backend);
        ++counted.refused_block_size;
        return;
    }
    expect_digest<ParallelHash>(test::from_hex(s.data), options, s.output, name_of(s));
}

void check_nist_samples() {
    BOOST_TEST_EQ(nist_samples().size(), 40U);
    counts counted;
    for (auto const& s : nist_samples()) {
        bool const at128 = s.security == 128;
        bool const xof = s.kind.ends_with("XOF");
        if (s.kind == "cSHAKE") {
            at128 ? run_cshake<digests::cshake_128>(s) : run_cshake<digests::cshake_256>(s);
            ++counted.cshake;
        } else if (s.kind.starts_with("KMAC")) {
            at128 ? run_kmac<macs::kmac_128>(s, xof) : run_kmac<macs::kmac_256>(s, xof);
            ++counted.kmac;
        } else if (s.kind.starts_with("TupleHash")) {
            at128 ? run_tuplehash<digests::tuplehash_128>(s, xof)
                  : run_tuplehash<digests::tuplehash_256>(s, xof);
            ++counted.tuplehash;
        } else if (s.kind.starts_with("ParallelHash")) {
            at128 ? run_parallelhash<digests::parallelhash_128>(s, xof, counted)
                  : run_parallelhash<digests::parallelhash_256>(s, xof, counted);
            ++counted.parallelhash;
        }
    }
    BOOST_TEST_EQ(counted.cshake, 4);
    BOOST_TEST_EQ(counted.kmac, 12);
    BOOST_TEST_EQ(counted.tuplehash, 12);
    BOOST_TEST_EQ(counted.parallelhash, 12);
    BOOST_TEST_EQ(counted.refused_block_size, 4);
}

// The bytes i % 251 for i from 0 to size - 1.
bytes pattern(std::size_t size) {
    bytes out(size);
    for (std::size_t i = 0; i < size; ++i) {
        out[i] = static_cast<std::uint8_t>(i % 251);
    }
    return out;
}

// webcpp's own cases, each value from the independent implementation.
void check_own_cases() {
    auto const abc = text_bytes("abc");
    auto const webcpp = text_bytes("webcpp");
    auto const email = text_bytes("Email Signature");

    // A function name; an output past two rates of cSHAKE256 (136 bytes), whose first 64 bytes
    // are NIST's cSHAKE sample #4.
    expect_digest<digests::cshake_128>(
        abc, {.function_name = webcpp},
        "5ca6ca715cd75dd43f9f847b348eda5dceabb0f4aa712fd946bb7a0bcc45f3a5", "cSHAKE128 N=webcpp");
    expect_digest<digests::cshake_256>(
        pattern(200), {.customisation = email},
        "07dc27b11e51fbac75bc7b3c1d983e8b4b85fb1defaf218912ac86430273091727f42b17ed1df63e8ec118f04b"
        "23633c1dfb1574c8fb55cb45da8e25afb092bbda604fe5c6ac1cdd0735ef8167d797e88703dc78f33898d4535"
        "3ff59fced6702af2b64099f50461cd5a787cedfca60c03e6cec108a0f01f02609097ce64554197edbc53c2f1dc"
        "abf74270679928e948a279f95c8ad49a8c9082fca8fee432d7e194cc4a5dd0bfa2154f1c00390555a9a62de449"
        "aa4ee999cf29b707ccec2d262ad2b6aa4c134d07b50552e947e67abeb3eed06c92cfe9c88c3f4a21b1d641729b"
        "fac748dc2aaf0ffcb17e7c6706d4b35d0708487d46b489d922ef3dcc67e7f75343b4b6ae7f2a15198155dbc4b3"
        "49844767aefc7b0395bfb526b1e8de79d208c7f24270fab74738f92291273",
        "cSHAKE256 past two rates");

    // TupleHash: digest_of hashes the tuple of one element, its input; a hasher with one update
    // gives the same. The empty tuple and the tuple of one empty element differ.
    expect_digest<digests::tuplehash_128>(
        abc, {.xof = false}, "873195cadfea6bc6a71cdd903da87afb49fd232d71db817c3abcad48ad8a7898",
        "TupleHash128 of (abc)");
    BOOST_TEST_EQ(tuple_hash<digests::tuplehash_128>({abc}, {}, 32),
                  "873195cadfea6bc6a71cdd903da87afb49fd232d71db817c3abcad48ad8a7898");
    BOOST_TEST_EQ(tuple_hash<digests::tuplehash_128>({}, {}, 32),
                  "786aa3d4fcaadf0aa723a4818a1a72de2330d613e5de7ae4eb6cb4cdd26adba2");
    BOOST_TEST_EQ(tuple_hash<digests::tuplehash_128>({bytes{}}, {}, 32),
                  "549330469327c593eb95b1d467c48e5781939e135e10632c804ef8a69c73281c");
    BOOST_TEST_EQ(tuple_hash<digests::tuplehash_256>({}, {}, 64),
                  "3afbba494aedd16073746e9a04ac28c3e7b023fed42bcb1935d26b0ce9ed212703448a3b08b8656b"
                  "d32e5fdd3ebe72fb7575ab1eefa93b84286556bead103a0a");
    expect_digest<digests::tuplehash_128>(
        abc, {.xof = true},
        "d66f622e7bb2129ec60f161dd3e2842b612bdbfee5c80043a24561edd70cdbf79fc4f44363a81c1c1782d42e32"
        "c2d8102355224058a3f8bce12367d43e33b8452f6b07c5b4c1fd0df451b4fc3c5a6f55af7cd4c6d80433de39f6"
        "d1367cee67e2cee829cf4f2346371923b8f267b66b0d30337ffaa6daf4522ebc891e32e667555593ea557fb803"
        "22433d32dfc0172b9a79a4261a07b9430bbbf55580a8f2b5608e6d12725aae79f2873461c5d092a6a50e977a27"
        "9e48eed9c5f8fcd1df71e73dafc7cc9fd96b0cca",
        "TupleHashXOF128 of (abc), 200 bytes");

    // ParallelHash: 100 bytes in blocks of 16, the last of 4; 1000 bytes in blocks of 64.
    expect_digest<digests::parallelhash_128>(
        pattern(100), {.block_size = 16},
        "ff2e361d1103b5d32d85aa9115ab5f3802553022d1ff8de5000f69f6e6c76603", "ParallelHash128 B=16");
    expect_digest<digests::parallelhash_256>(
        pattern(1000), {.block_size = 64, .customisation = webcpp, .xof = true},
        "c42df5427f9f61acf501c07c8e6c407ad190d33d145cabc7ad435cbfe78ca074caddcd0af2c2e3c882cb50f7b4"
        "bd8fd084164518c958b6b7e6472a7f7dcc538a6a5e2b82ac8202118def8a0fb5b26dd970814698cf56af373b0f"
        "159c08d8e07771100733",
        "ParallelHashXOF256 B=64");

    // KMAC: an empty key; KMAC256 and KMACXOF256 of 200 bytes, which differ.
    BOOST_TEST_EQ(mac_of<macs::kmac_128>({}, abc, {}, 32),
                  "bad8c820c19c56d72b2dd4955b9bfab692d925dad1b6a65075ba60fd6f739e4a");
    BOOST_TEST_EQ(
        mac_of<macs::kmac_256>(pattern(32), abc, {.customisation = webcpp}, 200),
        "c4d07022e7fb46de43f50bbcca9172ce887d4eebcc5c800feee82c12248a01a735aa370b7f90090958a6a566f5"
        "4bff1265c7246238c49a9f78532484a7a91dde4a504126f24b52f2f871ca52c591ee1eead6b7aa07c5cd1e5dff"
        "142f9f1a52296f7bc1ebe12e57064ba4f35227bf6c13fd3930d72118eb8f9f00e6c534c95ae8c752b35d02ec72"
        "8065d08bbc3e94bff55a8423358f52c57778f8d44ecac3cf4a8701c11dd8eae1d3fd7a708adc4efbe089d5a0ef"
        "426b1ee829bbc3aee99efe562f8ddf3e8df10d32");
    BOOST_TEST_EQ(
        mac_of<macs::kmac_256>(pattern(32), abc, {.customisation = webcpp, .xof = true}, 200),
        "0cb9c7bdd1a07ed9ad36c838037b3db103add02f040d1fa412b9601db99a648cc15849a59608a5d223513aeb07"
        "65b52c29ef8e0a99b56a3a9e26c75d4654be88c0bcf25a4960a1457655db1aac34657299fe424de4f8aeeaaa75"
        "0facd3d03dfe98aade39ce518b8a2956e7ab1132e5b5dad3a7f33828a1adb9df9618c8520206a1b205fbfa29c3"
        "9571ccfd7deefa20cc0213df7a7afcd6f90f4a0402ab11721d4b8d6039842bcd464dfa25cf341bdd06c778cf6b"
        "4bb65f6b282dd531246897e15eda75dbfd2f47a8");
}

// cSHAKE with no function name and no customisation is SHAKE (SP 800-185, section 3.3), here
// against digests::shake_128 and shake_256 on the same backend; and the default backend of the
// SP 800-185 tags is xkcp, so a call that names none gives the same values.
void check_shake_and_defaults() {
    for (std::size_t const size : {0U, 1U, 135U, 136U, 168U, 169U, 500U}) {
        auto const input = pattern(size);
        bytes cshake(300);
        bytes shake(300);
        BOOST_TEST((hash::digest_of<digests::cshake_128, xkcp>(cshake, input).has_value()));
        BOOST_TEST((hash::digest_of<digests::shake_128, xkcp>(shake, input).has_value()));
        BOOST_TEST(cshake == shake);
        BOOST_TEST((hash::digest_of<digests::cshake_256, xkcp>(cshake, input).has_value()));
        BOOST_TEST((hash::digest_of<digests::shake_256, xkcp>(shake, input).has_value()));
        BOOST_TEST(cshake == shake);
    }
    auto const abc = text_bytes("abc");
    bytes output(32);
    BOOST_TEST((hash::digest_of<digests::tuplehash_128>(output, abc).has_value()));
    BOOST_TEST_EQ(test::to_hex(output),
                  "873195cadfea6bc6a71cdd903da87afb49fd232d71db817c3abcad48ad8a7898");
    BOOST_TEST((hash::mac<macs::kmac_128>(output, bytes{}, abc).has_value()));
    BOOST_TEST_EQ(test::to_hex(output),
                  "bad8c820c19c56d72b2dd4955b9bfab692d925dad1b6a65075ba60fd6f739e4a");
}

// ParallelHash's block size of 0 is invalid_parameters on every backend, one XKCP does not take
// (not a power of two of at least 8) unsupported_by_backend, the output untouched either way.
void check_block_sizes() {
    auto const input = pattern(40);
    for (std::size_t const block_size : {0U, 1U, 4U, 12U, 24U, 1000U}) {
        bytes output(32, 0xAA);
        auto const expected =
            block_size == 0 ? hash::error::invalid_parameters : hash::error::unsupported_by_backend;
        BOOST_TEST(failed_with(hash::digest_of<digests::parallelhash_128, xkcp>(
                                   output, input, {.block_size = block_size}),
                               expected));
        BOOST_TEST(output == bytes(32, 0xAA));
        auto const started =
            hash::hasher<digests::parallelhash_256>::make({.block_size = block_size});
        BOOST_TEST(started.has_error() && started.error() == expected);
    }
    for (std::size_t const block_size : {8U, 16U, 32U, 1024U}) {
        bytes output(32);
        BOOST_TEST((hash::digest_of<digests::parallelhash_256, xkcp>(output, input,
                                                                     {.block_size = block_size})
                        .has_value()));
    }
}

// An empty output, or a KMAC tag under 4 bytes, is invalid_output_size.
void check_short_outputs() {
    auto const input = pattern(40);
    bytes none;
    BOOST_TEST(failed_with(hash::digest_of<digests::cshake_128, xkcp>(none, input),
                           hash::error::invalid_output_size));
    BOOST_TEST(failed_with(hash::digest_of<digests::tuplehash_256, xkcp>(none, input),
                           hash::error::invalid_output_size));
    BOOST_TEST(failed_with(hash::digest_of<digests::parallelhash_128, xkcp>(
                               none, input, {.block_size = 8, .xof = true}),
                           hash::error::invalid_output_size));
    BOOST_TEST(failed_with(hash::mac<macs::kmac_256, xkcp>(none, bytes(32), input),
                           hash::error::invalid_output_size));
    // KMAC's tag is at least 32 bits (SP 800-185, section 8.4.2), in both forms.
    bytes short_tag(3, 0xAA);
    BOOST_TEST(failed_with(hash::mac<macs::kmac_128, xkcp>(short_tag, bytes(16), input),
                           hash::error::invalid_output_size));
    BOOST_TEST(failed_with(hash::mac<macs::kmac_256>(short_tag, bytes(32), input, {.xof = true}),
                           hash::error::invalid_output_size));
    BOOST_TEST(short_tag == bytes(3, 0xAA));
    bytes shortest(4);
    BOOST_TEST((hash::mac<macs::kmac_128, xkcp>(shortest, bytes(16), input).has_value()));
}

// The fixed-length and the XOF forms of TupleHash, ParallelHash and KMAC differ at the same
// length.
void check_forms() {
    auto const input = pattern(40);
    bytes fixed(32);
    bytes xof(32);
    BOOST_TEST((hash::digest_of<digests::tuplehash_128, xkcp>(fixed, input).has_value()));
    BOOST_TEST(
        (hash::digest_of<digests::tuplehash_128, xkcp>(xof, input, {.xof = true}).has_value()));
    BOOST_TEST(fixed != xof);
    BOOST_TEST((hash::digest_of<digests::parallelhash_128, xkcp>(fixed, input, {.block_size = 8})
                    .has_value()));
    BOOST_TEST((
        hash::digest_of<digests::parallelhash_128, xkcp>(xof, input, {.block_size = 8, .xof = true})
            .has_value()));
    BOOST_TEST(fixed != xof);
    BOOST_TEST((hash::mac<macs::kmac_128, xkcp>(fixed, bytes(16), input).has_value()));
    BOOST_TEST((hash::mac<macs::kmac_128, xkcp>(xof, bytes(16), input, {.xof = true}).has_value()));
    BOOST_TEST(fixed != xof);
}

// The fixed form's length is the output's: a hasher started before it is known gives the value of
// digest_of at each length, once; its result is final.
void check_length_at_finish() {
    auto const input = pattern(40);
    for (std::size_t const size : {1U, 32U, 200U}) {
        bytes once(size);
        BOOST_TEST((hash::digest_of<digests::parallelhash_256, xkcp>(once, input, {.block_size = 8})
                        .has_value()));
        auto hashing = hash::hasher<digests::parallelhash_256, xkcp>::make({.block_size = 8});
        test::require(BOOST_TEST(hashing.has_value()));
        BOOST_TEST(hashing->update(input).has_value());
        bytes pieces(size);
        BOOST_TEST(hashing->finish(pieces).has_value());
        BOOST_TEST(once == pieces);
        BOOST_TEST(failed_with(hashing->finish(pieces), hash::error::invalid_state));
        BOOST_TEST(failed_with(hashing->update(input), hash::error::invalid_state));
    }
}

}  // namespace

int main() {
    check_nist_samples();
    check_own_cases();
    check_shake_and_defaults();
    check_block_sizes();
    check_short_outputs();
    check_forms();
    check_length_at_finish();
    return webcpp::test::exit_status(boost::report_errors());
}
