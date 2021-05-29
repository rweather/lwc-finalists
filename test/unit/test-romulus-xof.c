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

/* Cross-check the Romulus-H XOF implementation in the library
 * with a very simple implementation here. */

#include "romulus-xof.h"
#include "test-cipher.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Simple implementation of Romulus-H in XOF mode */
static void simple_romulus_xof
    (unsigned char *out, size_t outlen, const unsigned char *in,
     size_t inlen, unsigned counter)
{
    romulus_hash_state_t hash;
    unsigned char h[ROMULUS_HASH_SIZE];
    size_t len, padlen;
    while (outlen > 0) {
        /* How much data should we generate this time around? */
        len = outlen;
        if (len > ROMULUS_HASH_SIZE)
            len = ROMULUS_HASH_SIZE;

        /* Compute Hash(M || padding || [counter]) */
        romulus_hash_init(&hash);
        romulus_hash_update(&hash, in, inlen);
        padlen = (inlen % ROMULUS_HASH_SIZE);
        memset(h, 0, sizeof(h));
        h[ROMULUS_HASH_SIZE - 1] = (unsigned char)padlen;
        romulus_hash_update(&hash, h + padlen, ROMULUS_HASH_SIZE - padlen);
        h[0] = (unsigned char)(counter >> 24);
        h[1] = (unsigned char)(counter >> 16);
        h[2] = (unsigned char)(counter >> 8);
        h[3] = (unsigned char)counter;
        ++counter;
        romulus_hash_update(&hash, h, 4);
        romulus_hash_finalize(&hash, h);

        /* Extract the next block of data */
        memcpy(out, h, len);
        out += len;
        outlen -= len;
    }
}

void test_romulus_xof(void)
{
    static unsigned char const in[7] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };
    unsigned char *out1;
    unsigned char *out2;
    romulus_xof_state_t xof;
    unsigned offset;
    size_t size = 16384;
    unsigned long start_counter = 0x01020304;

    printf("Romulus-H XOF:\n");

    /* Allocate buffers to hold the generated output */
    out1 = malloc(size);
    out2 = malloc(size);
    if (!out1 || !out2)
        exit(1);

    /* Generate the output that we expect */
    simple_romulus_xof(out1, size, in, sizeof(in), 0);

    /* Test the all-in-one generation of the output */
    printf("    All in one ... ");
    fflush(stdout);
    romulus_xof(out2, in, sizeof(in));
    if (!test_memcmp(out2, out1, ROMULUS_HASH_SIZE)) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    /* Test incremental generation of the output in block-sized quantities */
    printf("    Incremental blocks ... ");
    fflush(stdout);
    romulus_xof_init(&xof);
    romulus_xof_absorb(&xof, in, sizeof(in));
    for (offset = 0; offset < size; offset += 32)
        romulus_xof_squeeze(&xof, out2 + offset, 32);
    if (!test_memcmp(out2, out1, size)) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    /* Test incremental generation of the output in byte-sized quantities */
    printf("    Incremental bytes ... ");
    fflush(stdout);
    romulus_xof_init(&xof);
    romulus_xof_absorb(&xof, in, sizeof(in));
    for (offset = 0; offset < size; ++offset)
        romulus_xof_squeeze(&xof, out2 + offset, 1);
    if (!test_memcmp(out2, out1, size)) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    /* Generate data starting a long way into the sequence to check
     * that the counter values are encoded in big endian correctly */
    printf("    Fast forward ... ");
    fflush(stdout);
    simple_romulus_xof(out1, size, in, sizeof(in), start_counter);
    romulus_xof_init(&xof);
    romulus_xof_absorb(&xof, in, sizeof(in));
    romulus_xof_squeeze(&xof, out2, 32); /* Generate first block and discard */
    xof.mgf1_count = start_counter; /* Fast forward the counter */
    for (offset = 0; offset < size; offset += 32)
        romulus_xof_squeeze(&xof, out2 + offset, 32);
    if (!test_memcmp(out2, out1, size)) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    /* Clean up and exit */
    free(out1);
    free(out2);
    printf("\n");
}
