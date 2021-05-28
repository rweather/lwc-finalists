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

#include "internal-grain128.h"
#include "test-cipher.h"
#include <stdio.h>
#include <string.h>

/* Test vectors for Grain-128 generated with the Grain-128AEAD reference code */
static unsigned char const grain_1_key[16] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
};
static unsigned char const grain_1_nonce[12] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc
};
static unsigned char const grain_1_lfsr[16] = {
    0x70, 0xf3, 0xdd, 0xb7, 0x5b, 0x34, 0x8d, 0x66,
    0xe8, 0xb9, 0x6f, 0x41, 0xa9, 0x34, 0x31, 0xbf,
};
static unsigned char const grain_1_nfsr[16] = {
    0xcc, 0xa1, 0x23, 0x4a, 0x23, 0x5a, 0x1b, 0x24,
    0xf9, 0x34, 0x5b, 0xc6, 0xd2, 0x43, 0x2f, 0x4d,
};
static unsigned char const grain_1_accum[8] = {
    0x4d, 0x23, 0xc5, 0x85, 0x3d, 0x24, 0xba, 0x5c,
};
static unsigned char const grain_1_sr[8] = {
    0x70, 0x05, 0xc0, 0xe9, 0x14, 0x29, 0x32, 0x23,
};

static void grain128_to_bytes
    (unsigned char *out, const uint32_t *in, unsigned count)
{
    while (count > 0) {
        be_store_word32(out, *in);
        out += 4;
        ++in;
        --count;
    }
}

static void grain128_to_bytes_64
    (unsigned char *out, const uint64_t *in, unsigned count)
{
    while (count > 0) {
        be_store_word64(out, *in);
        out += 8;
        ++in;
        --count;
    }
}

void test_grain128(void)
{
    grain128_state_t state;
    unsigned char bytes[16];
    int failure;

    printf("Grain-128:\n");

    printf("    Test Vector ... ");
    fflush(stdout);
    grain128_setup(&state, grain_1_key, grain_1_nonce);
    grain128_to_bytes(bytes, state.lfsr, 4);
    failure =  test_memcmp(bytes, grain_1_lfsr, sizeof(grain_1_lfsr));
    grain128_to_bytes(bytes, state.nfsr, 4);
    failure |= test_memcmp(bytes, grain_1_nfsr, sizeof(grain_1_nfsr));
    grain128_to_bytes_64(bytes, &state.accum, 1);
    failure |= test_memcmp(bytes, grain_1_accum, sizeof(grain_1_accum));
    grain128_to_bytes_64(bytes, &state.sr, 1);
    failure |= test_memcmp(bytes, grain_1_sr, sizeof(grain_1_sr));
    if (!failure) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    printf("\n");
}
