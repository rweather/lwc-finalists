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

#ifndef LW_INTERNAL_GHASH_H
#define LW_INTERNAL_GHASH_H

/**
 * \file internal-ghash.h
 * \brief GHASH algorithm for supporting GCM mode.
 *
 * Note: This implementation is not constant cache.  Internally it uses
 * lookup tables for multiplication in the GF(2^128) field.  This means
 * that it has similar behaviour to other fast but memory-efficient
 * software implementations of GHASH but is not suitable for use where
 * memory cache attacks are a concern.
 */

#include "internal-util.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \def GHASH_SHOUP_4BIT
 * \brief Define to 1 to use Shoup's 4-bit method for GF(2^128) multiplications,
 * or define to 0 to use a simpler but slower bit-by-bit method.
 */
#if defined(__AVR__)
#define GHASH_SHOUP_4BIT 0
#else
#define GHASH_SHOUP_4BIT 1
#endif

/**
 * \brief Representation of a value in the GF(2^128) field.
 */
typedef struct
{
    uint64_t c[2];          /**< Components of the 128-bit value */

} gf128_value_t;

/**
 * \brief State information for GHASH.
 */
typedef struct
{
#if GHASH_SHOUP_4BIT
    gf128_value_t H[16];    /**< Precomputed hash keys for 0..15 */
#else
    gf128_value_t H;        /**< Hash key */
#endif
    uint8_t Y[16];          /**< Current value of the hash */
    uint32_t posn;          /**< Position within Y for the next input byte */

} ghash_state_t;

/**
 * \brief Initializes the GHASH state.
 *
 * \param state GHASH state to be initialized.
 * \param key 128-bit key.
 */
void ghash_init(ghash_state_t *state, const unsigned char *key);

/**
 * \brief Updates a GHASH state with more data.
 *
 * \param state GHASH state to be updated.
 * \param data Points to the input data.
 * \param size Number of bytes of input data.
 */
void ghash_update(ghash_state_t *state, const unsigned char *data, size_t size);

/**
 * \brief Pads a GHASH state with zeroes to the next block boundary.
 *
 * \param state GHASH state to be padded.
 */
void ghash_pad(ghash_state_t *state);

/**
 * \brief Finalizes a GHASH state.
 *
 * \param state GHASH state to be finalized.
 * \param hash Points to the output hash value, which is 16 bytes in length.
 */
void ghash_finalize(ghash_state_t *state, unsigned char *hash);

#ifdef __cplusplus
}
#endif

#endif
