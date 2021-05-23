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

#ifndef LW_INTERNAL_GIFT128_H
#define LW_INTERNAL_GIFT128_H

/**
 * \file internal-gift128.h
 * \brief GIFT-128 block cipher.
 *
 * This version of GIFT-128 implements a cutdown form of the bit-sliced
 * representation of GIFT-128 that is used by GIFT-COFB.
 *
 * Only initialization and block encryption are supported, and the
 * encryption function assumes that the input data was already converted
 * from big endian to host byte order by the caller.
 *
 * References: https://eprint.iacr.org/2017/622.pdf,
 * https://eprint.iacr.org/2020/412.pdf,
 * https://giftcipher.github.io/gift/
 */

#include <stddef.h>
#include <stdint.h>
#include "internal-gift128-config.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of a GIFT-128 block in bytes.
 */
#define GIFT128_BLK_SIZE 16

/**
 * \var GIFT128_ROUND_KEYS
 * \brief Number of round keys for the GIFT-128 key schedule.
 */
#if GIFT128_VARIANT == GIFT128_VARIANT_TINY
#define GIFT128_ROUND_KEYS 4
#elif GIFT128_VARIANT == GIFT128_VARIANT_SMALL
#define GIFT128_ROUND_KEYS 20
#else
#define GIFT128_ROUND_KEYS 80
#endif

/**
 * \brief Structure of the key schedule for GIFT-128 (bit-sliced).
 */
typedef struct
{
    /** Pre-computed round keys for bit-sliced GIFT-128 */
    uint32_t k[GIFT128_ROUND_KEYS];

} gift128b_key_schedule_t;

/**
 * \brief Initializes the key schedule for GIFT-128 (bit-sliced).
 *
 * \param ks Points to the key schedule to initialize.
 * \param key Points to the 16 bytes of the key data.
 */
void gift128b_init(gift128b_key_schedule_t *ks, const unsigned char *key);

/**
 * \brief Encrypts a 128-bit block with GIFT-128 (bit-sliced and pre-loaded).
 *
 * \param ks Points to the GIFT-128 key schedule.
 * \param output Output buffer which must be at least 16 bytes in length.
 * \param input Input buffer which must be at least 16 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 *
 * This function assumes that the input has already been pre-loaded from
 * big-endian into host byte order in the supplied word array.  The output
 * is delivered in the same way.
 */
void gift128b_encrypt_preloaded
    (const gift128b_key_schedule_t *ks, uint32_t output[4],
     const uint32_t input[4]);

/**
 * \brief Decrypts a 128-bit block with GIFT-128 (bit-sliced and pre-loaded).
 *
 * \param ks Points to the GIFT-128 key schedule.
 * \param output Output buffer which must be at least 16 bytes in length.
 * \param input Input buffer which must be at least 16 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place decryption.
 *
 * This function assumes that the input has already been pre-loaded from
 * big-endian into host byte order in the supplied word array.  The output
 * is delivered in the same way.
 */
void gift128b_decrypt_preloaded
    (const gift128b_key_schedule_t *ks, uint32_t output[4],
     const uint32_t input[4]);

/**
 * \brief Converts the GIFT-128 nibble-based representation into word-based.
 *
 * \param block Block to convert from nibble-based to word-based.
 *
 * \sa gift128_words_to_nibbles()
 */
void gift128_nibbles_to_words(uint32_t block[4]);

/**
 * \brief Converts the GIFT-128 word-based representation into nibble-based.
 *
 * \param block Block to convert from word-based to nibble-based.
 *
 * \sa gift128_nibbles_to_words()
 */
void gift128_words_to_nibbles(uint32_t block[4]);

#ifdef __cplusplus
}
#endif

#endif
