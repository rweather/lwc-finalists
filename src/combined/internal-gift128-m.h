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

#ifndef LW_INTERNAL_GIFT128_M_H
#define LW_INTERNAL_GIFT128_M_H

/**
 * \file internal-gift128-m.h
 * \brief Masked version of the GIFT-128 block cipher.
 */

#include "internal-masking.h"
#include "internal-gift128-config.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of a GIFT-128 block in bytes.
 */
#define GIFT128_MASKED_BLOCK_SIZE 16

/**
 * \var GIFT128_MASKED_ROUND_KEYS
 * \brief Number of round keys for the GIFT-128 key schedule.
 */
#if GIFT128_VARIANT == GIFT128_VARIANT_TINY
#define GIFT128_MASKED_ROUND_KEYS 4
#elif GIFT128_VARIANT == GIFT128_VARIANT_SMALL
#define GIFT128_MASKED_ROUND_KEYS 20
#else
#define GIFT128_MASKED_ROUND_KEYS 80
#endif

/**
 * \brief Structure of the key schedule for masked GIFT-128 (bit-sliced).
 */
typedef struct
{
    /** Pre-computed round keys for bit-sliced GIFT-128 */
    mask_uint32_t k[GIFT128_MASKED_ROUND_KEYS];

} gift128b_masked_key_schedule_t;

/**
 * \brief Initializes the key schedule for masked GIFT-128 (bit-sliced).
 *
 * \param ks Points to the key schedule to initialize.
 * \param key Points to the 16 bytes of the key data.
 */
void gift128b_init_masked
    (gift128b_masked_key_schedule_t *ks, const unsigned char *key);

/**
 * \brief Encrypts a block with masked GIFT-128 (bit-sliced and pre-loaded).
 *
 * \param ks Points to the masked GIFT-128 key schedule.
 * \param output Output buffer which must be at least 16 bytes in length.
 * \param input Input buffer which must be at least 16 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 *
 * This version assumes that the input has already been pre-loaded from
 * big-endian into host byte order in the supplied word array.  The output
 * is delivered in the same way.
 */
void gift128b_encrypt_preloaded_masked
    (const gift128b_masked_key_schedule_t *ks, mask_uint32_t output[4],
     const mask_uint32_t input[4]);

#ifdef __cplusplus
}
#endif

#endif
