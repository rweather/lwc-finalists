/*
 * Copyright (C) 2020 Southern Storm Software, Pty Ltd.
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

#include "internal-tinyjambu.h"
#include "internal-tinyjambu-m.h"
#include "test-cipher.h"
#include <stdio.h>
#include <string.h>

/* Test vectors for TinyJAMBU generated with the reference code */
static uint32_t const tinyjambu_input[] = {
    0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c
};
static uint32_t const tinyjambu_key_1[] = {
    0x33221100, 0x77665544, 0xbbaa9988, 0xffeeddcc
};
static uint32_t const tinyjambu_output_1[] = {
    0xd9025b75, 0xdea7c711, 0xc42bfe5c, 0x361e5016
};
static uint32_t const tinyjambu_key_2[] = {
    0x33221100, 0x77665544, 0xbbaa9988, 0xffeeddcc,
    0x9687b4a5, 0xd2c3f0e1, 0x1e0f3c2d, 0x5a4b7869
};
static uint32_t const tinyjambu_output_2[] = {
    0xf066f253, 0xa8cf13ed, 0xd46f2eb9, 0xbd4c5e4a
};
static uint32_t const tinyjambu_key_3[] = {
    0x33221100, 0x77665544, 0xbbaa9988, 0xffeeddcc,
    0x9687b4a5, 0xd2c3f0e1
};
static uint32_t const tinyjambu_output_3[] = {
    0xeb03d4da, 0x14894342, 0xb0d7ba4d, 0x025b53a6
};

static void invert_key(uint32_t *out, const uint32_t *in, unsigned count)
{
    while (count > 0) {
        *out++ = ~(*in++);
        --count;
    }
}

void test_tinyjambu(void)
{
    uint32_t state[TINY_JAMBU_STATE_SIZE];
    uint32_t invkey[8];
    mask_uint32_t masked_state[TINY_JAMBU_MASKED_STATE_SIZE];
    mask_uint32_t masked_key[12];

    printf("TinyJAMBU:\n");

    printf("    Test Vector 1 ... ");
    fflush(stdout);
    memcpy(state, tinyjambu_input, sizeof(tinyjambu_input));
    invert_key(invkey, tinyjambu_key_1, 4);
    tiny_jambu_permutation_128(state, invkey, TINYJAMBU_ROUNDS(1024));
    if (!test_memcmp((const unsigned char *)state,
                     (const unsigned char *)tinyjambu_output_1,
                     sizeof(tinyjambu_output_1))) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    printf("    Test Vector 2 ... ");
    fflush(stdout);
    memcpy(state, tinyjambu_input, sizeof(tinyjambu_input));
    invert_key(invkey, tinyjambu_key_2, 8);
    tiny_jambu_permutation_256(state, invkey, TINYJAMBU_ROUNDS(1280));
    if (!test_memcmp((const unsigned char *)state,
                     (const unsigned char *)tinyjambu_output_2,
                     sizeof(tinyjambu_output_2))) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    printf("    Test Vector 3 ... ");
    fflush(stdout);
    memcpy(state, tinyjambu_input, sizeof(tinyjambu_input));
    invert_key(invkey, tinyjambu_key_3, 6);
    tiny_jambu_permutation_192(state, invkey, TINYJAMBU_ROUNDS(1152));
    if (!test_memcmp((const unsigned char *)state,
                     (const unsigned char *)tinyjambu_output_3,
                     sizeof(tinyjambu_output_3))) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    printf("    Masked Test Vector 1 ... ");
    fflush(stdout);
    mask_input(masked_state[0], tinyjambu_input[0]);
    mask_input(masked_state[1], tinyjambu_input[1]);
    mask_input(masked_state[2], tinyjambu_input[2]);
    mask_input(masked_state[3], tinyjambu_input[3]);
    invert_key(invkey, tinyjambu_key_1, 4);
    mask_input(masked_key[0], invkey[0]);
    mask_input(masked_key[1], invkey[1]);
    mask_input(masked_key[2], invkey[2]);
    mask_input(masked_key[3], invkey[3]);
    tiny_jambu_permutation_masked
        (masked_state, masked_key, 4, TINYJAMBU_MASKED_ROUNDS(1024));
    state[0] = mask_output(masked_state[0]);
    state[1] = mask_output(masked_state[1]);
    state[2] = mask_output(masked_state[2]);
    state[3] = mask_output(masked_state[3]);
    if (!test_memcmp((const unsigned char *)state,
                     (const unsigned char *)tinyjambu_output_1,
                     sizeof(tinyjambu_output_1))) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    printf("    Masked Test Vector 2 ... ");
    fflush(stdout);
    mask_input(masked_state[0], tinyjambu_input[0]);
    mask_input(masked_state[1], tinyjambu_input[1]);
    mask_input(masked_state[2], tinyjambu_input[2]);
    mask_input(masked_state[3], tinyjambu_input[3]);
    invert_key(invkey, tinyjambu_key_2, 8);
    mask_input(masked_key[0], invkey[0]);
    mask_input(masked_key[1], invkey[1]);
    mask_input(masked_key[2], invkey[2]);
    mask_input(masked_key[3], invkey[3]);
    mask_input(masked_key[4], invkey[4]);
    mask_input(masked_key[5], invkey[5]);
    mask_input(masked_key[6], invkey[6]);
    mask_input(masked_key[7], invkey[7]);
    tiny_jambu_permutation_masked
        (masked_state, masked_key, 8, TINYJAMBU_MASKED_ROUNDS(1280));
    state[0] = mask_output(masked_state[0]);
    state[1] = mask_output(masked_state[1]);
    state[2] = mask_output(masked_state[2]);
    state[3] = mask_output(masked_state[3]);
    if (!test_memcmp((const unsigned char *)state,
                     (const unsigned char *)tinyjambu_output_2,
                     sizeof(tinyjambu_output_2))) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    printf("    Masked Test Vector 3 ... ");
    fflush(stdout);
    mask_input(masked_state[0], tinyjambu_input[0]);
    mask_input(masked_state[1], tinyjambu_input[1]);
    mask_input(masked_state[2], tinyjambu_input[2]);
    mask_input(masked_state[3], tinyjambu_input[3]);
    invert_key(invkey, tinyjambu_key_3, 6);
    mask_input(masked_key[0], invkey[0]);
    mask_input(masked_key[1], invkey[1]);
    mask_input(masked_key[2], invkey[2]);
    mask_input(masked_key[3], invkey[3]);
    mask_input(masked_key[4], invkey[4]);
    mask_input(masked_key[5], invkey[5]);
    mask_input(masked_key[6], invkey[0]);
    mask_input(masked_key[7], invkey[1]);
    mask_input(masked_key[8], invkey[2]);
    mask_input(masked_key[9], invkey[3]);
    mask_input(masked_key[10], invkey[4]);
    mask_input(masked_key[11], invkey[5]);
    tiny_jambu_permutation_masked
        (masked_state, masked_key, 12, TINYJAMBU_MASKED_ROUNDS(1152));
    state[0] = mask_output(masked_state[0]);
    state[1] = mask_output(masked_state[1]);
    state[2] = mask_output(masked_state[2]);
    state[3] = mask_output(masked_state[3]);
    if (!test_memcmp((const unsigned char *)state,
                     (const unsigned char *)tinyjambu_output_3,
                     sizeof(tinyjambu_output_3))) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    printf("\n");
}
