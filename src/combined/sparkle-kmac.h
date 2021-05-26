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

#ifndef LWCRYPTO_SPARKLE_KMAC_H
#define LWCRYPTO_SPARKLE_KMAC_H

#include "sparkle-hash.h"

/**
 * \file sparkle-kmac.h
 * \brief Keyed Message Authentication Code (KMAC) based on XOEsch256.
 *
 * The KMAC mode provides a method to authenticate a sequence of bytes
 * using XOEsch256 or XOEsch384 in XOF mode.  The output is essentially
 * equivalent to hashing the key followed by the data.
 *
 * NIST SP 800-185 is an extension of the XOF modes SHAKE128 and SHAKE256.
 * The nearest equivalent for us is XOEsch256-XOF.  We use the same encoding
 * as NIST SP 800-185 to provide domain separation between the key and data.
 *
 * References: NIST SP 800-185
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Default size of the output for XOEsch256-KMAC.
 */
#define ESCH_256_KMAC_SIZE ESCH_256_HASH_SIZE

/**
 * \brief Default size of the output for XOEsch384-KMAC.
 */
#define ESCH_384_KMAC_SIZE ESCH_384_HASH_SIZE

/**
 * \brief State information for the XOEsch256-KMAC incremental mode.
 */
typedef esch_256_hash_state_t esch_256_kmac_state_t;

/**
 * \brief Computes a KMAC value using the XOEsch256 XOF mode.
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
void esch_256_kmac
    (const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen,
     const unsigned char *custom, size_t customlen,
     unsigned char *out, size_t outlen);

/**
 * \brief Initializes an incremental KMAC state using the XOEsch256 XOF mode.
 *
 * \param state Points to the state to be initialized.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 * \param custom Points to the customization string.
 * \param customlen Number of bytes in the customization string.
 *
 * \sa esch_256_kmac_update(), esch_256_kmac_squeeze()
 */
void esch_256_kmac_init
    (esch_256_kmac_state_t *state, const unsigned char *key, size_t keylen,
     const unsigned char *custom, size_t customlen);

/**
 * \brief Absorbs more input data into an incremental XOEsch256-KMAC state.
 *
 * \param state KMAC state to be updated.
 * \param in Points to the input data to be absorbed into the state.
 * \param inlen Length of the input data to be absorbed into the state.
 *
 * \sa esch_256_kmac_init(), esch_256_kmac_squeeze()
 */
void esch_256_kmac_absorb
    (esch_256_kmac_state_t *state, const unsigned char *in, size_t inlen);

/**
 * \brief Sets the desired output length for an incremental
 * XOEsch256-KMAC state.
 *
 * \param state KMAC state to squeeze the output data from after the
 * desired output length has been set.
 * \param outlen Desired output length, or zero for arbitrary-length output.
 *
 * \sa esch_256_kmac_squeeze()
 */
void esch_256_kmac_set_output_length
    (esch_256_kmac_state_t *state, size_t outlen);

/**
 * \brief Squeezes output data from an incremental XOEsch256-KMAC state.
 *
 * \param state KMAC state to squeeze the output data from.
 * \param out Points to the output buffer to receive the squeezed data.
 * \param outlen Number of bytes of data to squeeze out of the state.
 *
 * The application should call esch_256_kmac_set_output_length() before
 * this function to set the desured output length.  If that function
 * has not been called, then this function will assume that the application
 * wants arbitrary-length output.
 *
 * \sa esch_256_kmac_init(), esch_256_kmac_update(), esch_256_kmac_finalize()
 */
void esch_256_kmac_squeeze
    (esch_256_kmac_state_t *state, unsigned char *out, size_t outlen);

/**
 * \brief Squeezes fixed-length data from an incremental XOEsch256-KMAC
 * state and finalizes the KMAC process.
 *
 * \param state KMAC state to squeeze the output data from.
 * \param out Points to the output buffer to receive the
 * ESCH_256_KMAC_SIZE bytes of squeezed data.
 *
 * This function combines the effect of esch_256_kmac_set_output_length()
 * and esch_256_kmac_squeeze() for convenience.
 *
 * \sa esch_256_kmac_squeeze(), esch_256_kmac_set_output_length()
 */
void esch_256_kmac_finalize
    (esch_256_kmac_state_t *state, unsigned char out[ESCH_256_KMAC_SIZE]);

/**
 * \brief State information for the XOEsch384-KMAC incremental mode.
 */
typedef esch_384_hash_state_t esch_384_kmac_state_t;

/**
 * \brief Computes a KMAC value using the XOEsch384 XOF mode.
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
void esch_384_kmac
    (const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen,
     const unsigned char *custom, size_t customlen,
     unsigned char *out, size_t outlen);

/**
 * \brief Initializes an incremental KMAC state using the XOEsch384 XOF mode.
 *
 * \param state Points to the state to be initialized.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 * \param custom Points to the customization string.
 * \param customlen Number of bytes in the customization string.
 *
 * \sa esch_384_kmac_update(), esch_384_kmac_squeeze()
 */
void esch_384_kmac_init
    (esch_384_kmac_state_t *state, const unsigned char *key, size_t keylen,
     const unsigned char *custom, size_t customlen);

/**
 * \brief Absorbs more input data into an incremental XOEsch384-KMAC state.
 *
 * \param state KMAC state to be updated.
 * \param in Points to the input data to be absorbed into the state.
 * \param inlen Length of the input data to be absorbed into the state.
 *
 * \sa esch_384_kmac_init(), esch_384_kmac_squeeze()
 */
void esch_384_kmac_absorb
    (esch_384_kmac_state_t *state, const unsigned char *in, size_t inlen);

/**
 * \brief Sets the desired output length for an incremental
 * XOEsch384-KMAC state.
 *
 * \param state KMAC state to squeeze the output data from after the
 * desired output length has been set.
 * \param outlen Desired output length, or zero for arbitrary-length output.
 *
 * \sa esch_384_kmac_squeeze()
 */
void esch_384_kmac_set_output_length
    (esch_384_kmac_state_t *state, size_t outlen);

/**
 * \brief Squeezes output data from an incremental XOEsch384-KMAC state.
 *
 * \param state KMAC state to squeeze the output data from.
 * \param out Points to the output buffer to receive the squeezed data.
 * \param outlen Number of bytes of data to squeeze out of the state.
 *
 * The application should call esch_384_kmac_set_output_length() before
 * this function to set the desured output length.  If that function
 * has not been called, then this function will assume that the application
 * wants arbitrary-length output.
 *
 * \sa esch_384_kmac_init(), esch_384_kmac_update(), esch_384_kmac_finalize()
 */
void esch_384_kmac_squeeze
    (esch_384_kmac_state_t *state, unsigned char *out, size_t outlen);

/**
 * \brief Squeezes fixed-length data from an incremental XOEsch384-KMAC
 * state and finalizes the KMAC process.
 *
 * \param state KMAC state to squeeze the output data from.
 * \param out Points to the output buffer to receive the
 * ESCH_384_KMAC_SIZE bytes of squeezed data.
 *
 * This function combines the effect of esch_384_kmac_set_output_length()
 * and esch_384_kmac_squeeze() for convenience.
 *
 * \sa esch_384_kmac_squeeze(), esch_384_kmac_set_output_length()
 */
void esch_384_kmac_finalize
    (esch_384_kmac_state_t *state, unsigned char out[ESCH_384_KMAC_SIZE]);

#ifdef __cplusplus
}
#endif

#endif
