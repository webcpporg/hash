/* Copyright (c) 2026 WebCpp.org
 *
 * Distributed under the Boost Software License, Version 1.0. (See
 * accompanying file LICENSE_1_0.txt or copy at
 * https://www.boost.org/LICENSE_1_0.txt)
 *
 * BLAKE3's own test program, c/main.c at the pin, unmodified, compiled with its main renamed
 * webcpp_blake3_main and its standard input and output routed to blake3_c_suite.cpp, which
 * calls it once per run as c/test.py runs c/blake3: fread reads the run's input, printf and
 * fprintf write into the run's buffers. The headers main.c includes come first, so that the
 * renames reach main.c's own code alone. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blake3.h"
#include "blake3_impl.h"

size_t webcpp_blake3_fread(void* buffer, size_t size, size_t count, FILE* stream);
int webcpp_blake3_printf(const char* format, ...);
int webcpp_blake3_fprintf(FILE* stream, const char* format, ...);
int webcpp_blake3_main(int argc, char** argv);

#define main webcpp_blake3_main
#define fread webcpp_blake3_fread
#define printf webcpp_blake3_printf
#define fprintf webcpp_blake3_fprintf

/* Found on the include path that /third_party//blake3 gives, third_party/libs/blake3/c. */
#include "main.c"
