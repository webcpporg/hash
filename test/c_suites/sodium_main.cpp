// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The main of each of libsodium's own tests. Upstream's cmptest.h writes <name>.res in the working
// directory and compares it with <name>.exp under TEST_SRCDIR, which it forces to /test-data on
// Emscripten; its main, which the Jamfile renames to sodium_test_main, is run here, from the
// directory of results the build made for this test and this target, TEST_NAME's directory in
// WEBCPP_SODIUM_RESULTS: the working directory natively and on WASI, where wasmtime is given
// WEBCPP_SODIUM_RESULTS; on Emscripten, whose program links NODEFS (<webcpp-node-raw-fs>off), the
// host's WEBCPP_SODIUM_RESULTS is mounted at its own path and libsodium's test directory at
// /test-data. A run that leaves no <name>.res fails: cmptest.h's main would then have compared
// nothing.

// The Jamfile renames cmptest.h's main to sodium_test_main for every source of the program; no
// header of this one sees the macro.
#undef main

#include <webcpp/test/exit_status.hpp>

#include <cstdio>

#ifdef _WIN32
#include <direct.h>
#else
#include <unistd.h>
#endif

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#endif

// The directory of this test's results.
#define WEBCPP_SODIUM_DIRECTORY WEBCPP_SODIUM_RESULTS "/" TEST_NAME

extern "C" int sodium_test_main(void);

namespace {

// Makes the directory of results the working directory; false when it cannot.
bool enter_results() {
#ifdef __EMSCRIPTEN__
    EM_ASM(
        {
            FS.mkdir('/test-data');
            FS.mount(NODEFS, {root : UTF8ToString($0)}, '/test-data');
            FS.mkdirTree(UTF8ToString($1));
            FS.mount(NODEFS, {root : UTF8ToString($1)}, UTF8ToString($1));
        },
        WEBCPP_SODIUM_TESTS, WEBCPP_SODIUM_RESULTS);
#endif
#ifdef _WIN32
    return _chdir(WEBCPP_SODIUM_DIRECTORY) == 0;
#else
    return chdir(WEBCPP_SODIUM_DIRECTORY) == 0;
#endif
}

}  // namespace

int main() {
    if (!enter_results()) {
        std::perror("chdir(" WEBCPP_SODIUM_DIRECTORY ")");
        return webcpp::test::exit_status(1);
    }
    // A <name>.res of an earlier run must not stand for this one's.
    // NOLINTNEXTLINE(cert-err33-c): the file is absent on a first run, which is no failure
    std::remove(TEST_NAME ".res");
    int const status = sodium_test_main();
    std::FILE* const written = std::fopen(TEST_NAME ".res", "r");
    if (written == nullptr) {
        // NOLINTNEXTLINE(cert-err33-c): the test fails either way
        std::fputs("sodium: " TEST_NAME " wrote no " TEST_NAME ".res in " WEBCPP_SODIUM_DIRECTORY
                   "\n",
                   stderr);
        return webcpp::test::exit_status(1);
    }
    // NOLINTNEXTLINE(cert-err33-c): opened only to know that it exists
    std::fclose(written);
    return webcpp::test::exit_status(status);
}
