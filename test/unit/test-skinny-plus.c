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

#include "internal-skinny-plus.h"
#include "skinny-plus-bc.h"
#include "test-cipher.h"
#include <stdio.h>
#include <string.h>

/* Information blocks for the SKINNY-128-384+ block cipher */
static block_cipher_t const skinny_plus = {
    "SKINNY-128-384+",
    sizeof(skinny_plus_key_schedule_t),
    (block_cipher_init_t)skinny_plus_init,
    (block_cipher_encrypt_t)skinny_plus_encrypt,
    (block_cipher_decrypt_t)skinny_plus_decrypt
};

/* Test vectors for SKINNY-128-384+ */
static block_cipher_test_vector_128_t const skinny_plus_1 = {
    "Test Vector",
    {0xdf, 0x88, 0x95, 0x48, 0xcf, 0xc7, 0xea, 0x52,    /* key */
     0xd2, 0x96, 0x33, 0x93, 0x01, 0x79, 0x74, 0x49,
     0xab, 0x58, 0x8a, 0x34, 0xa4, 0x7f, 0x1a, 0xb2,
     0xdf, 0xe9, 0xc8, 0x29, 0x3f, 0xbe, 0xa9, 0xa5,
     0xab, 0x1a, 0xfa, 0xc2, 0x61, 0x10, 0x12, 0xcd,
     0x8c, 0xef, 0x95, 0x26, 0x18, 0xc3, 0xeb, 0xe8},
    48,                                                 /* key_len */
    {0xa3, 0x99, 0x4b, 0x66, 0xad, 0x85, 0xa3, 0x45,    /* plaintext */
     0x9f, 0x44, 0xe9, 0x2b, 0x08, 0xf5, 0x50, 0xcb},
    {0xff, 0x38, 0xd1, 0xd2, 0x4c, 0x86, 0x4c, 0x43,    /* ciphertext */
     0x52, 0xa8, 0x53, 0x69, 0x0f, 0xe3, 0x6e, 0x5e}
};

/* Alternative version of SKINNY-128-384 where everything is tweakable */
static void tk_full_skinny_plus_init
    (unsigned char ks[48], const unsigned char *key)
{
    memcpy(ks, key, 48);
}
static block_cipher_t const skinny_plus_tk_full = {
    "SKINNY-128-384-TK-FULL+",
    48,
    (block_cipher_init_t)tk_full_skinny_plus_init,
    (block_cipher_encrypt_t)skinny_plus_encrypt_tk_full,
    (block_cipher_decrypt_t)skinny_plus_decrypt_tk_full
};

/* Number of blocks to use when testing parallel encryption */
#define NUM_BLOCKS 13

/* Test single and parallel versions of SKINNY-128-384+ encryption */
typedef void (*skinny_plus_parallel_func_t)
    (const skinny_128_384_plus_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, size_t len);
static void skinny_plus_ecb_parallel
    (const skinny_128_384_plus_key_schedule_t *ks,
     skinny_plus_parallel_func_t func,
     unsigned char *output, const unsigned char *input)
{
    unsigned char multiple_input[SKINNY_128_384_PLUS_BLOCK_SIZE * NUM_BLOCKS];
    unsigned char multiple_output[SKINNY_128_384_PLUS_BLOCK_SIZE * NUM_BLOCKS];
    unsigned index;

    /* Process multiple blocks */
    for (index = 0; index < NUM_BLOCKS; ++index) {
        memcpy(multiple_input + index * SKINNY_128_384_PLUS_BLOCK_SIZE,
               input, SKINNY_128_384_PLUS_BLOCK_SIZE);
    }
    memset(multiple_output, 0xAA, sizeof(multiple_output));
    (*func)(ks, multiple_output, multiple_input, sizeof(multiple_input));

    /* Process a single block */
    (*func)(ks, output, input, SKINNY_128_384_PLUS_BLOCK_SIZE);

    /* Check that the multiple block version produced the same output */
    for (index = 0; index < NUM_BLOCKS; ++index) {
        if (memcmp(multiple_output + index * SKINNY_128_384_PLUS_BLOCK_SIZE,
                   output, SKINNY_128_384_PLUS_BLOCK_SIZE) != 0) {
            /* Destroy the regular output to cause the test to fail */
            memset(output, 0x55, SKINNY_128_384_PLUS_BLOCK_SIZE);
            break;
        }
    }
}

/* Test single and parallel versions of SKINNY-128-384+ encryption with TK1 */
typedef void (*skinny_plus_parallel_tk1_func_t)
    (skinny_128_384_plus_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, const unsigned char *tk1, size_t len);
static void skinny_plus_ecb_tk1_parallel
    (skinny_128_384_plus_key_schedule_t *ks,
     skinny_plus_parallel_tk1_func_t func,
     unsigned char *output, const unsigned char *input)
{
    unsigned char multiple_input[SKINNY_128_384_PLUS_BLOCK_SIZE * NUM_BLOCKS];
    unsigned char multiple_output[SKINNY_128_384_PLUS_BLOCK_SIZE * NUM_BLOCKS];
    unsigned char multiple_tk1[SKINNY_128_384_PLUS_BLOCK_SIZE * NUM_BLOCKS];
    unsigned char saved_tk1[SKINNY_128_384_PLUS_BLOCK_SIZE];
    unsigned index;

    /* Process multiple blocks */
    memcpy(saved_tk1, ks->TK1, SKINNY_128_384_PLUS_BLOCK_SIZE);
    for (index = 0; index < NUM_BLOCKS; ++index) {
        memcpy(multiple_input + index * SKINNY_128_384_PLUS_BLOCK_SIZE,
               input, SKINNY_128_384_PLUS_BLOCK_SIZE);
        memcpy(multiple_tk1 + index * SKINNY_128_384_PLUS_BLOCK_SIZE,
               ks->TK1, SKINNY_128_384_PLUS_BLOCK_SIZE);
    }
    memset(multiple_output, 0xAA, sizeof(multiple_output));
    memset(ks->TK1, 0x55, sizeof(ks->TK1));
    (*func)(ks, multiple_output, multiple_input, multiple_tk1,
            sizeof(multiple_input));

    /* Process a single block */
    (*func)(ks, output, input, multiple_tk1, SKINNY_128_384_PLUS_BLOCK_SIZE);
    memcpy(ks->TK1, saved_tk1, SKINNY_128_384_PLUS_BLOCK_SIZE);

    /* Check that the multiple block version produced the same output */
    for (index = 0; index < NUM_BLOCKS; ++index) {
        if (memcmp(multiple_output + index * SKINNY_128_384_PLUS_BLOCK_SIZE,
                   output, SKINNY_128_384_PLUS_BLOCK_SIZE) != 0) {
            /* Destroy the regular output to cause the test to fail */
            memset(output, 0x55, SKINNY_128_384_PLUS_BLOCK_SIZE);
            break;
        }
    }
}

/* Information block for the parallel encryption API for SKINNY-128-384+ */
static void skinny_plus_ecb_encrypt_wrapper
    (const skinny_128_384_plus_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    skinny_plus_ecb_parallel
        (ks, skinny_128_384_plus_ecb_encrypt, output, input);
}
static void skinny_plus_ecb_decrypt_wrapper
    (const skinny_128_384_plus_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    skinny_plus_ecb_parallel
        (ks, skinny_128_384_plus_ecb_decrypt, output, input);
}
static block_cipher_t const skinny_plus_parallel = {
    "SKINNY-128-384+ Parallel",
    sizeof(skinny_128_384_plus_key_schedule_t),
    (block_cipher_init_t)skinny_128_384_plus_setup_key,
    (block_cipher_encrypt_t)skinny_plus_ecb_encrypt_wrapper,
    (block_cipher_decrypt_t)skinny_plus_ecb_decrypt_wrapper
};

/* Information block for the parallel encryption API for SKINNY-128-384+ */
static void skinny_plus_tk1_setup_wrapper
    (skinny_128_384_plus_key_schedule_t *ks, const unsigned char *k)
{
    skinny_128_384_plus_setup_tk23(ks, k + 16, k + 32);
    memcpy(ks->TK1, k, 16);
}
static void skinny_plus_ecb_tk1_encrypt_wrapper
    (skinny_128_384_plus_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    skinny_plus_ecb_tk1_parallel
        (ks, skinny_128_384_plus_ecb_encrypt_tk1, output, input);
}
static void skinny_plus_ecb_tk1_decrypt_wrapper
    (skinny_128_384_plus_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    skinny_plus_ecb_tk1_parallel
        (ks, skinny_128_384_plus_ecb_decrypt_tk1, output, input);
}
static block_cipher_t const skinny_plus_parallel_tk1 = {
    "SKINNY-128-384+ Parallel TK1",
    sizeof(skinny_128_384_plus_key_schedule_t),
    (block_cipher_init_t)skinny_plus_tk1_setup_wrapper,
    (block_cipher_encrypt_t)skinny_plus_ecb_tk1_encrypt_wrapper,
    (block_cipher_decrypt_t)skinny_plus_ecb_tk1_decrypt_wrapper
};

/* Information block for the parallel full encryption API for SKINNY-128-384+ */
static void skinny_plus_full_setup_wrapper
    (unsigned char *ks, const unsigned char *k)
{
    memcpy(ks, k, SKINNY_128_384_PLUS_KEY_SIZE);
}
static void skinny_plus_ecb_full_encrypt_wrapper
    (const skinny_128_384_plus_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    skinny_plus_ecb_parallel
        (ks, (skinny_plus_parallel_func_t)skinny_128_384_plus_expand_and_encrypt, output, input);
}
static void skinny_plus_ecb_full_decrypt_wrapper
    (const skinny_128_384_plus_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    skinny_plus_ecb_parallel
        (ks, (skinny_plus_parallel_func_t)skinny_128_384_plus_expand_and_decrypt, output, input);
}
static block_cipher_t const skinny_plus_parallel_full = {
    "SKINNY-128-384+ Parallel Full",
    SKINNY_128_384_PLUS_KEY_SIZE,
    (block_cipher_init_t)skinny_plus_full_setup_wrapper,
    (block_cipher_encrypt_t)skinny_plus_ecb_full_encrypt_wrapper,
    (block_cipher_decrypt_t)skinny_plus_ecb_full_decrypt_wrapper
};

void test_skinny128(void)
{
    test_block_cipher_start(&skinny_plus);
    test_block_cipher_128(&skinny_plus, &skinny_plus_1);
    test_block_cipher_end(&skinny_plus);

    test_block_cipher_start(&skinny_plus_tk_full);
    test_block_cipher_128(&skinny_plus_tk_full, &skinny_plus_1);
    test_block_cipher_end(&skinny_plus_tk_full);

    test_block_cipher_start(&skinny_plus_parallel);
    test_block_cipher_128(&skinny_plus_parallel, &skinny_plus_1);
    test_block_cipher_end(&skinny_plus_parallel);

    test_block_cipher_start(&skinny_plus_parallel_tk1);
    test_block_cipher_128(&skinny_plus_parallel_tk1, &skinny_plus_1);
    test_block_cipher_end(&skinny_plus_parallel_tk1);

    test_block_cipher_start(&skinny_plus_parallel_full);
    test_block_cipher_128(&skinny_plus_parallel_full, &skinny_plus_1);
    test_block_cipher_end(&skinny_plus_parallel_full);
}
