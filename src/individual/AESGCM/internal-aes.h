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

#ifndef LW_INTERNAL_AES_H
#define LW_INTERNAL_AES_H

/**
 * \file internal-aes.h
 * \brief AES block cipher.
 *
 * This version of AES is intended for performing comparisons with the
 * other candidates in the Lightweight Cryptography Competition.
 *
 * Note: This implementation is not constant cache.  Internally it uses
 * lookup tables for the AES S-box and MixColumns operation.  This means
 * that it has similar behaviour to other "fast" 32-bit software
 * implementations of AES but is not suitable for use where memory
 * cache attacks are a concern.
 */

#include "internal-util.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the AES block in bytes.
 */
#define AES_BLOCK_SIZE 16

/**
 * \brief Size of the AES-128 key in bytes.
 */
#define AES128_KEY_SIZE 16

/**
 * \brief Size of the AES-192 key in bytes.
 */
#define AES192_KEY_SIZE 24

/**
 * \brief Size of the AES-256 key in bytes.
 */
#define AES256_KEY_SIZE 32

/**
 * \brief Number of round keys for the AES key schedule.
 *
 * This is sized for AES-256.  There will be some wasted space for
 * AES-128 and AES-192.
 */
#define AES_ROUND_KEYS 60

/**
 * \brief Structure of the key schedule for AES.
 */
typedef struct
{
    /** Pre-computed round keys for AES */
    uint32_t k[AES_ROUND_KEYS];

    /** Number of rounds to perform */
    uint32_t rounds;

} aes_key_schedule_t;

/**
 * \brief Initializes the key schedule for AES-128.
 *
 * \param ks Points to the key schedule to initialize.
 * \param key Points to the key data.
 */
void aes_128_init(aes_key_schedule_t *ks, const unsigned char *key);

/**
 * \brief Initializes the key schedule for AES-192.
 *
 * \param ks Points to the key schedule to initialize.
 * \param key Points to the key data.
 */
void aes_192_init(aes_key_schedule_t *ks, const unsigned char *key);

/**
 * \brief Initializes the key schedule for AES-256.
 *
 * \param ks Points to the key schedule to initialize.
 * \param key Points to the key data.
 */
void aes_256_init(aes_key_schedule_t *ks, const unsigned char *key);

/**
 * \brief Encrypts a 128-bit block with AES in ECB mode.
 *
 * \param ks Points to the AES key schedule.
 * \param output Output buffer which must be at least 16 bytes in length.
 * \param input Input buffer which must be at least 16 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 */
void aes_ecb_encrypt
    (const aes_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input);

#ifdef __cplusplus
}
#endif

#endif
