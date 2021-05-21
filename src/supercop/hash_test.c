/*
 * Copyright (C) 2021 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

/* Very basic test harness for verifying that a SUPERCOP hash algorithm
 * can be compiled and also generates KAT vectors for it on stdout. */

#include "api.h"
#include "crypto_hash.h"
#include <stdio.h>
#include <string.h>

static void set_vec(unsigned char *vec, unsigned size)
{
    unsigned index;
    for (index = 0; index < size; ++index)
        vec[index] = (unsigned char)index;
}

static void print_vec(const char *name, const unsigned char *vec, unsigned size)
{
    printf("%s = ", name);
    while (size > 0) {
        printf("%02X", vec[0]);
        ++vec;
        --size;
    }
    printf("\n");
}

static int gen_kat_hash(unsigned mlen)
{
    unsigned char hash[CRYPTO_BYTES];
    unsigned char m[mlen];
    int result;

    set_vec(m, mlen);

    memset(hash, 0xAA, CRYPTO_BYTES);
    result = crypto_hash(hash, m, mlen);
    if (result != 0)
        return 0;

    print_vec("Msg", m, mlen);
    print_vec("MD", hash, CRYPTO_BYTES);

    return 1;
}

int main(int argc, char *argv[])
{
    unsigned mlen;
    unsigned count = 1;
    int exit_val = 0;
    (void)argc;
    (void)argv;
    for (mlen = 0; mlen <= 1024; ++mlen) {
        printf("Count = %u\n", count++);
        if (!gen_kat_hash(mlen)) {
            fprintf(stderr, "vector %u failed\n", count - 1);
            exit_val = 1;
        }
        printf("\n");
    }
    return exit_val;
}
