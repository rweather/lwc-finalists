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

#ifndef LWCRYPTO_PHOTON_BEETLE_HMAC_H
#define LWCRYPTO_PHOTON_BEETLE_HMAC_H

#include "photon-beetle-hash.h"
#include <stddef.h>

/**
 * \file photon-beetle-hmac.h
 * \brief Hashed Message Authentication Code (HMAC) based on
 * PHOTON-Beetle-Hash.
 *
 * The HMAC mode provides a method to authenticate a sequence of bytes
 * using PHOTON-Beetle-Hash as the underlying digest algorithm.
 *
 * HMAC uses an underlying block size to pad the key data.
 * The PHOTON-Beetle-Hash block absorption rates of 16 and 4 bytes
 * are too short so we use the HMAC-SHA-256 block size of 64 instead.
 *
 * \note The KMAC construction is preferable for sponge-based hash
 * algorithms as it is simpler and more efficient.  HMAC mode is
 * provided for drop-in compatibility with existing designs.
 *
 * Reference: https://tools.ietf.org/html/rfc2104
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Default size of the output for PHOTON-Beetle-HMAC.
 */
#define PHOTON_BEETLE_HMAC_SIZE PHOTON_BEETLE_HASH_SIZE

/**
 * \brief State information for the PHOTON-Beetle-HMAC incremental mode.
 */
typedef photon_beetle_hash_state_t photon_beetle_hmac_state_t;

/**
 * \brief Computes a HMAC value using PHOTON-Beetle-Hash.
 *
 * \param out Buffer to receive the output HMAC value; must be at least
 * PHOTON_BEETLE_HMAC_SIZE bytes in length.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 * \param in Points to the data to authenticate.
 * \param inlen Number of bytes of data to authenticate.
 */
void photon_beetle_hmac
    (unsigned char *out,
     const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen);

/**
 * \brief Initializes an incremental HMAC state using PHOTON-Beetle-Hash.
 *
 * \param state Points to the state to be initialized.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 *
 * The \a key needs to be preserved until the photon_beetle_hmac_finalize() call
 * to provide the outer HMAC hashing key.
 *
 * \sa photon_beetle_hmac_update(), photon_beetle_hmac_finalize()
 */
void photon_beetle_hmac_init
    (photon_beetle_hmac_state_t *state,
     const unsigned char *key, size_t keylen);

/**
 * \brief Updates an incremental PHOTON-Beetle-HMAC state with more input data.
 *
 * \param state HMAC state to be updated.
 * \param in Points to the input data to be incorporated into the state.
 * \param inlen Length of the input data to be incorporated into the state.
 *
 * \sa photon_beetle_hmac_init(), photon_beetle_hmac_finalize()
 */
void photon_beetle_hmac_update
    (photon_beetle_hmac_state_t *state,
     const unsigned char *in, size_t inlen);

/**
 * \brief Finalizes an incremental PHOTON-Beetle-HMAC state.
 *
 * \param state HMAC state to squeeze the output data from.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 * \param out Points to the output buffer to receive the HMAC value;
 * must be at least PHOTON_BEETLE_HMAC_SIZE bytes in length.
 *
 * \sa photon_beetle_hmac_init(), photon_beetle_hmac_update()
 */
void photon_beetle_hmac_finalize
    (photon_beetle_hmac_state_t *state,
     const unsigned char *key, size_t keylen,
     unsigned char *out);

#ifdef __cplusplus
}
#endif

#endif
