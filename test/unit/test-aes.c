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

#include "internal-aes.h"
#include "internal-util.h"
#include "test-cipher.h"
#include <stdio.h>

/* Information block for the AES-128 block cipher */
static block_cipher_t const aes128_cipher = {
    "AES-128",
    sizeof(aes_key_schedule_t),
    (block_cipher_init_t)aes_128_init,
    (block_cipher_encrypt_t)aes_ecb_encrypt,
    (block_cipher_decrypt_t)0
};

/* Information block for the AES-192 block cipher */
static block_cipher_t const aes192_cipher = {
    "AES-192",
    sizeof(aes_key_schedule_t),
    (block_cipher_init_t)aes_192_init,
    (block_cipher_encrypt_t)aes_ecb_encrypt,
    (block_cipher_decrypt_t)0
};

/* Information block for the AES-256 block cipher */
static block_cipher_t const aes256_cipher = {
    "AES-256",
    sizeof(aes_key_schedule_t),
    (block_cipher_init_t)aes_256_init,
    (block_cipher_encrypt_t)aes_ecb_encrypt,
    (block_cipher_decrypt_t)0
};

/* Test vectors for AES from the FIPS specification */
static block_cipher_test_vector_128_t const testVectorAES128 = {
    "Test Vector",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* key */
     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
    16,                                                 /* key_len */
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,    /* plaintext */
     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
    {0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30,    /* ciphertext */
     0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A}
};
static block_cipher_test_vector_128_t const testVectorAES192 = {
    "Test Vector",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* key */
     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17},
    24,                                                 /* key_len */
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,    /* plaintext */
     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
    {0xDD, 0xA9, 0x7C, 0xA4, 0x86, 0x4C, 0xDF, 0xE0,    /* ciphertext */
     0x6E, 0xAF, 0x70, 0xA0, 0xEC, 0x0D, 0x71, 0x91}
};
static block_cipher_test_vector_128_t const testVectorAES256 = {
    "Test Vector",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* key */
     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
     0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F},
    32,                                                 /* key_len */
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,    /* plaintext */
     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
    {0x8E, 0xA2, 0xB7, 0xCA, 0x51, 0x67, 0x45, 0xBF,    /* ciphertext */
     0xEA, 0xFC, 0x49, 0x90, 0x4B, 0x49, 0x60, 0x89}
};

void test_aes(void)
{
    test_block_cipher_start(&aes128_cipher);
    test_block_cipher_128(&aes128_cipher, &testVectorAES128);
    test_block_cipher_end(&aes128_cipher);

    test_block_cipher_start(&aes192_cipher);
    test_block_cipher_128(&aes192_cipher, &testVectorAES192);
    test_block_cipher_end(&aes192_cipher);

    test_block_cipher_start(&aes256_cipher);
    test_block_cipher_128(&aes256_cipher, &testVectorAES256);
    test_block_cipher_end(&aes256_cipher);
}
