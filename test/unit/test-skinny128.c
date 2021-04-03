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

#include "internal-skinny128.h"
#include "test-cipher.h"
#include <stdio.h>
#include <string.h>

/* Information blocks for the SKINNY-128 block cipher variants */
static block_cipher_t const skinny128_384 = {
    "SKINNY-128-384",
    sizeof(skinny_128_384_key_schedule_t),
    (block_cipher_init_t)skinny_128_384_init,
    (block_cipher_encrypt_t)skinny_128_384_encrypt,
    (block_cipher_decrypt_t)0
};

/* Test vectors for SKINNY-128 from https://eprint.iacr.org/2016/660.pdf */
static block_cipher_test_vector_128_t const skinny128_384_1 = {
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
    {0x94, 0xec, 0xf5, 0x89, 0xe2, 0x01, 0x7c, 0x60,    /* ciphertext */
     0x1b, 0x38, 0xc6, 0x34, 0x6a, 0x10, 0xdc, 0xfa}
};

/* Alternative version of SKINNY-128-384 where TK2 is also tweakable */
static unsigned char TK2[16];
static void tk2_skinny_128_384_init
    (skinny_128_384_key_schedule_t *ks, const unsigned char *key)
{
    unsigned char tk[48];
    memcpy(tk, key, 48);
    memset(tk + 16, 0, 16);
    memcpy(TK2, key + 16, 16);
    skinny_128_384_init(ks, tk);
}
static void tk2_skinny_128_384_encrypt
    (const skinny_128_384_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    skinny_128_384_key_schedule_t ks2 = *ks;
    skinny_128_384_encrypt_tk2(&ks2, output, input, TK2);
}
static block_cipher_t const skinny128_384_tk2 = {
    "SKINNY-128-384-TK2",
    sizeof(skinny_128_384_key_schedule_t),
    (block_cipher_init_t)tk2_skinny_128_384_init,
    (block_cipher_encrypt_t)tk2_skinny_128_384_encrypt,
    (block_cipher_decrypt_t)0
};

/* Alternative version of SKINNY-128-384 where everything is tweakable */
static void tk_full_skinny_128_384_init
    (unsigned char ks[48], const unsigned char *key)
{
    memcpy(ks, key, 48);
}
static block_cipher_t const skinny128_384_tk_full = {
    "SKINNY-128-384-TK-FULL",
    48,
    (block_cipher_init_t)tk_full_skinny_128_384_init,
    (block_cipher_encrypt_t)skinny_128_384_encrypt_tk_full,
    (block_cipher_decrypt_t)0
};

void test_skinny128(void)
{
    test_block_cipher_start(&skinny128_384);
    test_block_cipher_128(&skinny128_384, &skinny128_384_1);
    test_block_cipher_end(&skinny128_384);

    test_block_cipher_start(&skinny128_384_tk2);
    test_block_cipher_128(&skinny128_384_tk2, &skinny128_384_1);
    test_block_cipher_end(&skinny128_384_tk2);

    test_block_cipher_start(&skinny128_384_tk_full);
    test_block_cipher_128(&skinny128_384_tk_full, &skinny128_384_1);
    test_block_cipher_end(&skinny128_384_tk_full);
}
