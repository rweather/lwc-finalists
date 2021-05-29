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

#ifndef LWCRYPTO_ROMULUS_XOF_H
#define LWCRYPTO_ROMULUS_XOF_H

#include "romulus-hash.h"

/**
 * \file romulus-xof.h
 * \brief Extensible Output Function (XOF) based on Romulus-H.
 *
 * Romulus-H is a hash algorithm based on the block cipher SKINNY-128-384+,
 * using the MDPH construction.  We combine it with the mask generation
 * function MGF1 to create an XOF mode.
 *
 * The XOF output is generated with the sequence Hash(M || [0]),
 * Hash(M || [1]), Hash(M || [2]), etc.  "M" is the message input
 * padded to a 32 byte block boundary using the same padding
 * scheme as Romulus-H.  [0], [1], [2], etc are 32-bit integers
 * encoded in big-endian.
 *
 * The application should not generate more than 32 * 2<sup>32</sup>
 * bytes (or 128 GiB) of output because after that the MGF1 counter
 * will wrap around and start generating the same output again.
 *
 * References: https://romulusae.github.io/romulus/,
 * https://www.ietf.org/rfc/rfc2437.html
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief State information for Romulus-H XOF mode.
 */
typedef struct
{
    romulus_hash_state_t hash;  /**< Hash state for Romulus-H */
    unsigned char out[ROMULUS_HASH_SIZE]; /**< Squeezed output buffer */
    unsigned long mgf1_count;   /**< MGF1 counter value */

} romulus_xof_state_t;

/**
 * \brief Hashes a block of input data with Romulus-H in XOF mode.
 *
 * \param out Buffer to receive the hash output which must be at least
 * ROMULUS_HASH_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 *
 * \sa romulus_xof_init(), romulus_xof_absorb(), romulus_xof_squeeze()
 */
int romulus_xof
    (unsigned char *out, const unsigned char *in, size_t inlen);

/**
 * \brief Initializes the state for a Romulus-H XOF mode.
 *
 * \param state XOF state to be initialized.
 *
 * \sa romulus_xof_update(), romulus_xof_squeeze(), romulus_xof()
 */
void romulus_xof_init(romulus_xof_state_t *state);

/**
 * \brief Absorbs more input data into a Romulus-H XOF state.
 *
 * \param state XOF state to be updated.
 * \param in Points to the input data to be absorbed into the state.
 * \param inlen Length of the input data to be absorbed into the state.
 *
 * \sa romulus_xof_init(), romulus_xof_squeeze()
 */
void romulus_xof_absorb
    (romulus_xof_state_t *state, const unsigned char *in, size_t inlen);

/**
 * \brief Returns the final hash value from a Romulus-H hashing operation.
 *
 * \param state XOF state to squeeze data from.
 * \param out Buffer to receive the squeezed dara.
 * \param outlen Number of bytes to squeeze from the XOF state.
 *
 * \sa romulus_xof_init(), romulus_xof_update()
 */
void romulus_xof_squeeze
    (romulus_xof_state_t *state, unsigned char *out, size_t outlen);

#ifdef __cplusplus
}
#endif

#endif
