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

#ifndef LWCRYPTO_XOODYAK_KMAC_H
#define LWCRYPTO_XOODYAK_KMAC_H

#include "xoodyak-hash.h"
#include <stddef.h>

/**
 * \file xoodyak-kmac.h
 * \brief Keyed Message Authentication Code (KMAC) based on Xoodyak.
 *
 * The KMAC mode provides a method to authenticate a sequence of bytes
 * using Xoodyak in hashing mode.  The output is essentially equivalent to
 * hashing the key followed by the data.
 *
 * NIST SP 800-185 is an extension of the XOF modes SHAKE128 and SHAKE256.
 * The nearest equivalent for us is Xoodyak-XOF.  We use the same encoding
 * as NIST SP 800-185 to provide domain separation between the key and data.
 *
 * References: NIST SP 800-185
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Default size of the output for Xoodyak-KMAC.
 */
#define XOODYAK_KMAC_SIZE XOODYAK_HASH_SIZE

/**
 * \brief State information for the Xoodyak-KMAC incremental mode.
 */
typedef xoodyak_hash_state_t xoodyak_kmac_state_t;

/**
 * \brief Computes a KMAC value using the Xoodyak hash algorithm.
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
void xoodyak_kmac
    (const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen,
     const unsigned char *custom, size_t customlen,
     unsigned char *out, size_t outlen);

/**
 * \brief Initializes an incremental KMAC state using the Xoodyak
 * hash algorithm.
 *
 * \param state Points to the state to be initialized.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 * \param custom Points to the customization string.
 * \param customlen Number of bytes in the customization string.
 *
 * \sa xoodyak_kmac_update(), xoodyak_kmac_squeeze()
 */
void xoodyak_kmac_init
    (xoodyak_kmac_state_t *state, const unsigned char *key, size_t keylen,
     const unsigned char *custom, size_t customlen);

/**
 * \brief Absorbs more input data into an incremental Xoodyak-KMAC state.
 *
 * \param state KMAC state to be updated.
 * \param in Points to the input data to be absorbed into the state.
 * \param inlen Length of the input data to be absorbed into the state.
 *
 * \sa xoodyak_kmac_init(), xoodyak_kmac_squeeze()
 */
void xoodyak_kmac_absorb
    (xoodyak_kmac_state_t *state, const unsigned char *in, size_t inlen);

/**
 * \brief Sets the desired output length for an incremental Xoodyak-KMAC state.
 *
 * \param state KMAC state to squeeze the output data from after the
 * desired output length has been set.
 * \param outlen Desired output length, or zero for arbitrary-length output.
 *
 * \sa xoodyak_kmac_squeeze()
 */
void xoodyak_kmac_set_output_length
    (xoodyak_kmac_state_t *state, size_t outlen);

/**
 * \brief Squeezes output data from an incremental Xoodyak-KMAC state.
 *
 * \param state KMAC state to squeeze the output data from.
 * \param out Points to the output buffer to receive the squeezed data.
 * \param outlen Number of bytes of data to squeeze out of the state.
 *
 * The application should call xoodyak_kmac_set_output_length() before
 * this function to set the desired output length.  If that function
 * has not been called, then this function will assume that the application
 * wants arbitrary-length output.
 *
 * \sa xoodyak_kmac_init(), xoodyak_kmac_update(), xoodyak_kmac_finalize()
 */
void xoodyak_kmac_squeeze
    (xoodyak_kmac_state_t *state, unsigned char *out, size_t outlen);

/**
 * \brief Squeezes fixed-length data from an incremental Xoodyak-KMAC
 * state and finalizes the KMAC process.
 *
 * \param state KMAC state to squeeze the output data from.
 * \param out Points to the output buffer to receive the
 * XOODYAK_KMAC_SIZE bytes of squeezed data.
 *
 * This function combines the effect of xoodyak_kmac_set_output_length()
 * and xoodyak_kmac_squeeze() for convenience.
 *
 * \sa xoodyak_kmac_squeeze(), xoodyak_kmac_set_output_length()
 */
void xoodyak_kmac_finalize
    (xoodyak_kmac_state_t *state, unsigned char out[XOODYAK_KMAC_SIZE]);

#ifdef __cplusplus
}
#endif

#endif
