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

#ifndef LWCRYPTO_ROMULUS_KMAC_H
#define LWCRYPTO_ROMULUS_KMAC_H

#include "romulus-xof.h"

/**
 * \file romulus-kmac.h
 * \brief Keyed Message Authentication Code (KMAC) based on Romulus-H.
 *
 * The KMAC mode provides a method to authenticate a sequence of bytes
 * using Romulus-H in hashing mode.  The output is essentially equivalent to
 * hashing the key followed by the data.
 *
 * NIST SP 800-185 is an extension of the XOF modes SHAKE128 and SHAKE256.
 * The nearest equivalent for us is Romulus-H-XOF.  We use the same encoding
 * as NIST SP 800-185 to provide domain separation between the key and data.
 *
 * References: NIST SP 800-185
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Default size of the output for Romulus-H-KMAC.
 */
#define ROMULUS_KMAC_SIZE ROMULUS_HASH_SIZE

/**
 * \brief State information for the Romulus-H-KMAC incremental mode.
 */
typedef romulus_xof_state_t romulus_kmac_state_t;

/**
 * \brief Computes a KMAC value using the Romulus-H hash algorithm.
 *
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 * \param in Points to the data to authenticate.
 * \param inlen Number of bytes of data to authenticate.
 * \param custom Points to the customization string.
 * \param customlen Number of bytes in the customization string.
 * \param out Buffer to receive the output KMAC value.
 * \param outlen Length of the output KMAC value.
 *
 * The customization string allows the application to perform domain
 * separation between different uses of the KMAC algorithm.
 */
void romulus_kmac
    (const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen,
     const unsigned char *custom, size_t customlen,
     unsigned char *out, size_t outlen);

/**
 * \brief Initializes an incremental KMAC state using the Romulus-H
 * hash algorithm.
 *
 * \param state Points to the state to be initialized.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 * \param custom Points to the customization string.
 * \param customlen Number of bytes in the customization string.
 *
 * \sa romulus_kmac_update(), romulus_kmac_squeeze()
 */
void romulus_kmac_init
    (romulus_kmac_state_t *state, const unsigned char *key, size_t keylen,
     const unsigned char *custom, size_t customlen);

/**
 * \brief Absorbs more input data into an incremental Romulus-H-KMAC state.
 *
 * \param state KMAC state to be updated.
 * \param in Points to the input data to be absorbed into the state.
 * \param inlen Length of the input data to be absorbed into the state.
 *
 * \sa romulus_kmac_init(), romulus_kmac_squeeze()
 */
void romulus_kmac_absorb
    (romulus_kmac_state_t *state, const unsigned char *in, size_t inlen);

/**
 * \brief Sets the desired output length for an incremental Romulus-H-KMAC state.
 *
 * \param state KMAC state to squeeze the output data from after the
 * desired output length has been set.
 * \param outlen Desired output length, or zero for arbitrary-length output.
 *
 * \sa romulus_kmac_squeeze()
 */
void romulus_kmac_set_output_length
    (romulus_kmac_state_t *state, size_t outlen);

/**
 * \brief Squeezes output data from an incremental Romulus-H-KMAC state.
 *
 * \param state KMAC state to squeeze the output data from.
 * \param out Points to the output buffer to receive the squeezed data.
 * \param outlen Number of bytes of data to squeeze out of the state.
 *
 * The application should call romulus_kmac_set_output_length() before
 * this function to set the desired output length.  If that function
 * has not been called, then this function will assume that the application
 * wants arbitrary-length output.
 *
 * \sa romulus_kmac_init(), romulus_kmac_update(), romulus_kmac_finalize()
 */
void romulus_kmac_squeeze
    (romulus_kmac_state_t *state, unsigned char *out, size_t outlen);

/**
 * \brief Squeezes fixed-length data from an incremental Romulus-H-KMAC
 * state and finalizes the KMAC process.
 *
 * \param state KMAC state to squeeze the output data from.
 * \param out Points to the output buffer to receive the
 * ROMULUS_KMAC_SIZE bytes of squeezed data.
 *
 * This function combines the effect of romulus_kmac_set_output_length()
 * and romulus_kmac_squeeze() for convenience.
 *
 * \sa romulus_kmac_squeeze(), romulus_kmac_set_output_length()
 */
void romulus_kmac_finalize
    (romulus_kmac_state_t *state, unsigned char out[ROMULUS_KMAC_SIZE]);

#ifdef __cplusplus
}
#endif

#endif
