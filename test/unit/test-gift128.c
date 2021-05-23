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

#include "internal-gift128.h"
#include "internal-gift128-m.h"
#include "internal-util.h"
#include "gift-bc.h"
#include "test-cipher.h"
#include <stdio.h>
#include <string.h>

/* Wrapper around the "preloaded" version to convert the test vectors
 * from big-endian byte order to host byte order and back again */
static void gift128b_encrypt_wrapper
    (const gift128b_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t out[4];
    uint32_t in[4];
    in[0] = be_load_word32(input);
    in[1] = be_load_word32(input + 4);
    in[2] = be_load_word32(input + 8);
    in[3] = be_load_word32(input + 12);
    gift128b_encrypt_preloaded(ks, out, in);
    be_store_word32(output, out[0]);
    be_store_word32(output + 4, out[1]);
    be_store_word32(output + 8, out[2]);
    be_store_word32(output + 12, out[3]);
}
static void gift128b_decrypt_wrapper
    (const gift128b_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t out[4];
    uint32_t in[4];
    in[0] = be_load_word32(input);
    in[1] = be_load_word32(input + 4);
    in[2] = be_load_word32(input + 8);
    in[3] = be_load_word32(input + 12);
    gift128b_decrypt_preloaded(ks, out, in);
    be_store_word32(output, out[0]);
    be_store_word32(output + 4, out[1]);
    be_store_word32(output + 8, out[2]);
    be_store_word32(output + 12, out[3]);
}

/* Information block for the GIFT-128 block cipher (bit-sliced version) */
static block_cipher_t const gift128b = {
    "GIFT-128-b",
    sizeof(gift128b_key_schedule_t),
    (block_cipher_init_t)gift128b_init,
    (block_cipher_encrypt_t)gift128b_encrypt_wrapper,
    (block_cipher_decrypt_t)gift128b_decrypt_wrapper
};

/* Wrapper around the "preloaded" version to convert the test vectors
 * from big-endian byte order to host byte order and back again */
static void gift128b_encrypt_masked_wrapper
    (const gift128b_masked_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    mask_uint32_t out[4];
    mask_uint32_t in[4];
    mask_input(in[0], be_load_word32(input));
    mask_input(in[1], be_load_word32(input + 4));
    mask_input(in[2], be_load_word32(input + 8));
    mask_input(in[3], be_load_word32(input + 12));
    gift128b_encrypt_preloaded_masked(ks, out, in);
    be_store_word32(output, mask_output(out[0]));
    be_store_word32(output + 4, mask_output(out[1]));
    be_store_word32(output + 8, mask_output(out[2]));
    be_store_word32(output + 12, mask_output(out[3]));
}
static void gift128b_decrypt_masked_wrapper
    (const gift128b_masked_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    mask_uint32_t out[4];
    mask_uint32_t in[4];
    mask_input(in[0], be_load_word32(input));
    mask_input(in[1], be_load_word32(input + 4));
    mask_input(in[2], be_load_word32(input + 8));
    mask_input(in[3], be_load_word32(input + 12));
    gift128b_decrypt_preloaded_masked(ks, out, in);
    be_store_word32(output, mask_output(out[0]));
    be_store_word32(output + 4, mask_output(out[1]));
    be_store_word32(output + 8, mask_output(out[2]));
    be_store_word32(output + 12, mask_output(out[3]));
}

/* Information block for the masked GIFT-128 block cipher (bit-sliced) */
static block_cipher_t const gift128b_masked = {
    "GIFT-128-b-masked",
    sizeof(gift128b_masked_key_schedule_t),
    (block_cipher_init_t)gift128b_init_masked,
    (block_cipher_encrypt_t)gift128b_encrypt_masked_wrapper,
    (block_cipher_decrypt_t)gift128b_decrypt_masked_wrapper
};

/* Number of blocks to use when testing parallel encryption */
#define GIFT128_NUM_BLOCKS 13

/* Test single and parallel versions of GIFT-128 encryption or decryption */
typedef void (*gift128_parallel_func_t)
    (const gift128_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, size_t len);
static void gift128_ecb_parallel
    (const gift128_key_schedule_t *ks, gift128_parallel_func_t func,
     unsigned char *output, const unsigned char *input)
{
    unsigned char multiple_input[GIFT128_BLOCK_SIZE * GIFT128_NUM_BLOCKS];
    unsigned char multiple_output[GIFT128_BLOCK_SIZE * GIFT128_NUM_BLOCKS];
    unsigned index;

    /* Process multiple blocks */
    for (index = 0; index < GIFT128_NUM_BLOCKS; ++index) {
        memcpy(multiple_input + index * GIFT128_BLOCK_SIZE,
               input, GIFT128_BLOCK_SIZE);
    }
    memset(multiple_output, 0xAA, sizeof(multiple_output));
    (*func)(ks, multiple_output, multiple_input, sizeof(multiple_input));

    /* Process a single block */
    (*func)(ks, output, input, GIFT128_BLOCK_SIZE);

    /* Check that the multiple block version produced the same output */
    for (index = 0; index < GIFT128_NUM_BLOCKS; ++index) {
        if (memcmp(multiple_output + index * GIFT128_BLOCK_SIZE,
                   output, GIFT128_BLOCK_SIZE) != 0) {
            /* Destroy the regular output to cause the test to fail */
            memset(output, 0x55, GIFT128_BLOCK_SIZE);
            break;
        }
    }
}

/* Information block for the GIFT-128 big-endian raw API */
static void gift128_ecb_encrypt_wrapper
    (const gift128_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    gift128_ecb_parallel(ks, gift128_ecb_encrypt, output, input);
}
static void gift128_ecb_decrypt_wrapper
    (const gift128_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    gift128_ecb_parallel(ks, gift128_ecb_decrypt, output, input);
}
static block_cipher_t const gift128_raw_be = {
    "GIFT-128-raw-be",
    sizeof(gift128_key_schedule_t),
    (block_cipher_init_t)gift128_setup_key,
    (block_cipher_encrypt_t)gift128_ecb_encrypt_wrapper,
    (block_cipher_decrypt_t)gift128_ecb_decrypt_wrapper
};

/* Information block for the GIFT-128 little-endian raw API */
static void gift128_le_ecb_encrypt_wrapper
    (const gift128_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    gift128_ecb_parallel(ks, gift128_le_ecb_encrypt, output, input);
}
static void gift128_le_ecb_decrypt_wrapper
    (const gift128_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    gift128_ecb_parallel(ks, gift128_le_ecb_decrypt, output, input);
}
static block_cipher_t const gift128_raw_le = {
    "GIFT-128-raw-le",
    sizeof(gift128_key_schedule_t),
    (block_cipher_init_t)gift128_le_setup_key,
    (block_cipher_encrypt_t)gift128_le_ecb_encrypt_wrapper,
    (block_cipher_decrypt_t)gift128_le_ecb_decrypt_wrapper
};

/* Information block for the GIFT-128 bit-sliced raw API */
static void gift128b_ecb_encrypt_wrapper
    (const gift128_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    gift128_ecb_parallel(ks, gift128b_ecb_encrypt, output, input);
}
static void gift128b_ecb_decrypt_wrapper
    (const gift128_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    gift128_ecb_parallel(ks, gift128b_ecb_decrypt, output, input);
}
static block_cipher_t const gift128_raw_bitsliced = {
    "GIFT-128-raw-bitsliced",
    sizeof(gift128_key_schedule_t),
    (block_cipher_init_t)gift128b_setup_key,
    (block_cipher_encrypt_t)gift128b_ecb_encrypt_wrapper,
    (block_cipher_decrypt_t)gift128b_ecb_decrypt_wrapper
};

/* Test vectors for GIFT-128 (bit-sliced version) from the GIFT-COFB spec:
 * https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/round-2/spec-doc-rnd2/gift-cofb-spec-round2.pdf */
static block_cipher_test_vector_128_t const gift128b_1 = {
    "Test Vector 1",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* key */
     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
    16,                                                 /* key_len */
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* plaintext */
     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
    {0xA9, 0x4A, 0xF7, 0xF9, 0xBA, 0x18, 0x1D, 0xF9,    /* ciphertext */
     0xB2, 0xB0, 0x0E, 0xB7, 0xDB, 0xFA, 0x93, 0xDF}
};
static block_cipher_test_vector_128_t const gift128b_2 = {
    "Test Vector 2",
    {0xE0, 0x84, 0x1F, 0x8F, 0xB9, 0x07, 0x83, 0x13,    /* key */
     0x6A, 0xA8, 0xB7, 0xF1, 0x92, 0xF5, 0xC4, 0x74},
    16,                                                 /* key_len */
    {0xE4, 0x91, 0xC6, 0x65, 0x52, 0x20, 0x31, 0xCF,    /* plaintext */
     0x03, 0x3B, 0xF7, 0x1B, 0x99, 0x89, 0xEC, 0xB3},
    {0x33, 0x31, 0xEF, 0xC3, 0xA6, 0x60, 0x4F, 0x95,    /* ciphertext */
     0x99, 0xED, 0x42, 0xB7, 0xDB, 0xC0, 0x2A, 0x38}
};
/* Test vectors for GIFT-128b generated with the fixslicing reference code */
static block_cipher_test_vector_128_t const gift128b_3 = {
    "Test Vector 3",
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* key */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    16,                                                 /* key_len */
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* plaintext */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x5e, 0x8e, 0x3a, 0x2e, 0x16, 0x97, 0xa7, 0x7d,    /* ciphertext */
     0xcc, 0x0b, 0x89, 0xdc, 0xd9, 0x7a, 0x64, 0xee}
};
static block_cipher_test_vector_128_t const gift128b_4 = {
    "Test Vector 4",
    {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,    /* key */
     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
    16,                                                 /* key_len */
    {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,    /* plaintext */
     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
    {0x22, 0x58, 0x14, 0x37, 0xe5, 0xe9, 0x61, 0xef,    /* ciphertext */
     0x6d, 0x12, 0x50, 0x46, 0xc5, 0xf2, 0x07, 0x88}
};
static block_cipher_test_vector_128_t const gift128b_5 = {
    "Test Vector 5",
    {0xd0, 0xf5, 0xc5, 0x9a, 0x77, 0x00, 0xd3, 0xe7,    /* key */
     0x99, 0x02, 0x8f, 0xa9, 0xf9, 0x0a, 0xd8, 0x37},
    16,                                                 /* key_len */
    {0xe3, 0x9c, 0x14, 0x1f, 0xa5, 0x7d, 0xba, 0x43,    /* plaintext */
     0xf0, 0x8a, 0x85, 0xb6, 0xa9, 0x1f, 0x86, 0xc1},
    {0xda, 0x1d, 0xc8, 0x87, 0x38, 0x23, 0xe3, 0x25,    /* ciphertext */
     0xc4, 0xb4, 0xa7, 0x7c, 0x1a, 0x73, 0x33, 0x0e}
};

/* Test vectors for GIFT-128 for the original big-endian nibble version */
static block_cipher_test_vector_128_t const gift128_be_1 = {
    "Test Vector 1",
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* key */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    16,                                                 /* key_len */
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* plaintext */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0xcd, 0x0b, 0xd7, 0x38, 0x38, 0x8a, 0xd3, 0xf6,    /* ciphertext */
     0x68, 0xb1, 0x5a, 0x36, 0xce, 0xb6, 0xff, 0x92}
};
static block_cipher_test_vector_128_t const gift128_be_2 = {
    "Test Vector 2",
    {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,    /* key */
     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
    16,                                                 /* key_len */
    {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,    /* plaintext */
     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
    {0x84, 0x22, 0x24, 0x1a, 0x6d, 0xbf, 0x5a, 0x93,    /* ciphertext */
     0x46, 0xaf, 0x46, 0x84, 0x09, 0xee, 0x01, 0x52}
};
static block_cipher_test_vector_128_t const gift128_be_3 = {
    "Test Vector 3",
    {0xd0, 0xf5, 0xc5, 0x9a, 0x77, 0x00, 0xd3, 0xe7,    /* key */
     0x99, 0x02, 0x8f, 0xa9, 0xf9, 0x0a, 0xd8, 0x37},
    16,                                                 /* key_len */
    {0xe3, 0x9c, 0x14, 0x1f, 0xa5, 0x7d, 0xba, 0x43,    /* plaintext */
     0xf0, 0x8a, 0x85, 0xb6, 0xa9, 0x1f, 0x86, 0xc1},
    {0x13, 0xed, 0xe6, 0x7c, 0xbd, 0xcc, 0x3d, 0xbf,    /* ciphertext */
     0x40, 0x0a, 0x62, 0xd6, 0x97, 0x72, 0x65, 0xea}
};

/* Test vectors for GIFT-128 (nibble-based version) that were generated
 * with the GIFT-128 implementation in the HYENA submission, which has a
 * different byte order than the original GIFT-128 paper but is otherwise
 * equivalent to it */
static block_cipher_test_vector_128_t const gift128_le_1 = {
    "Test Vector 1",
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* key */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    16,                                                 /* key_len */
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* plaintext */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x92, 0xff, 0xb6, 0xce, 0x36, 0x5a, 0xb1, 0x68,    /* ciphertext */
     0xf6, 0xd3, 0x8a, 0x38, 0x38, 0xd7, 0x0b, 0xcd}
};
static block_cipher_test_vector_128_t const gift128_le_2 = {
    "Test Vector 2",
    {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,    /* key */
     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
    16,                                                 /* key_len */
    {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,    /* plaintext */
     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
    {0xeb, 0xda, 0xda, 0xa8, 0xbc, 0x83, 0xd5, 0x16,    /* ciphertext */
     0xd5, 0x0a, 0x45, 0x6e, 0xf8, 0x0e, 0x7f, 0x72}
};
static block_cipher_test_vector_128_t const gift128_le_3 = {
    "Test Vector 3",
    {0xd0, 0xf5, 0xc5, 0x9a, 0x77, 0x00, 0xd3, 0xe7,    /* key */
     0x99, 0x02, 0x8f, 0xa9, 0xf9, 0x0a, 0xd8, 0x37},
    16,                                                 /* key_len */
    {0xe3, 0x9c, 0x14, 0x1f, 0xa5, 0x7d, 0xba, 0x43,    /* plaintext */
     0xf0, 0x8a, 0x85, 0xb6, 0xa9, 0x1f, 0x86, 0xc1},
    {0xb2, 0x3e, 0x1f, 0xb4, 0xfd, 0xd8, 0xc0, 0x88,    /* ciphertext */
     0xd3, 0x72, 0xe8, 0xbe, 0xf3, 0x43, 0x06, 0x02}
};

void test_gift128(void)
{
    test_block_cipher_start(&gift128b);
    test_block_cipher_128(&gift128b, &gift128b_1);
    test_block_cipher_128(&gift128b, &gift128b_2);
    test_block_cipher_128(&gift128b, &gift128b_3);
    test_block_cipher_128(&gift128b, &gift128b_4);
    test_block_cipher_128(&gift128b, &gift128b_5);
    test_block_cipher_end(&gift128b);

    test_block_cipher_start(&gift128_raw_be);
    test_block_cipher_128(&gift128_raw_be, &gift128_be_1);
    test_block_cipher_128(&gift128_raw_be, &gift128_be_2);
    test_block_cipher_128(&gift128_raw_be, &gift128_be_3);
    test_block_cipher_end(&gift128_raw_be);

    test_block_cipher_start(&gift128_raw_le);
    test_block_cipher_128(&gift128_raw_le, &gift128_le_1);
    test_block_cipher_128(&gift128_raw_le, &gift128_le_2);
    test_block_cipher_128(&gift128_raw_le, &gift128_le_3);
    test_block_cipher_end(&gift128_raw_le);

    test_block_cipher_start(&gift128_raw_bitsliced);
    test_block_cipher_128(&gift128_raw_bitsliced, &gift128b_1);
    test_block_cipher_128(&gift128_raw_bitsliced, &gift128b_2);
    test_block_cipher_128(&gift128_raw_bitsliced, &gift128b_3);
    test_block_cipher_128(&gift128_raw_bitsliced, &gift128b_4);
    test_block_cipher_128(&gift128_raw_bitsliced, &gift128b_5);
    test_block_cipher_end(&gift128_raw_bitsliced);
}

void test_gift128_masked(void)
{
    test_block_cipher_start(&gift128b_masked);
    test_block_cipher_128(&gift128b_masked, &gift128b_1);
    test_block_cipher_128(&gift128b_masked, &gift128b_2);
    test_block_cipher_128(&gift128b_masked, &gift128b_3);
    test_block_cipher_128(&gift128b_masked, &gift128b_4);
    test_block_cipher_128(&gift128b_masked, &gift128b_5);
    test_block_cipher_end(&gift128b_masked);
}
