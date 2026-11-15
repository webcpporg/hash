/* Copyright (c) 2026 WebCpp.org
 *
 * Distributed under the Boost Software License, Version 1.0. (See
 * accompanying file LICENSE_1_0.txt or copy at
 * https://www.boost.org/LICENSE_1_0.txt)
 *
 * A stand-in for cmptest.h's main that succeeds and writes no <name>.res: sodium_main.cpp must
 * fail its run. */
int sodium_test_main(void);

int sodium_test_main(void) {
    return 0;
}
