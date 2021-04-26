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

#ifndef LWCRYPTO_XOODYAK_HMAC_H
#define LWCRYPTO_XOODYAK_HMAC_H

#include "xoodyak-hash.h"
#include <stddef.h>

/**
 * \file xoodyak-hmac.h
 * \brief Hashed Message Authentication Code (HMAC) based on Xoodyak-Hash.
 *
 * The HMAC mode provides a method to authenticate a sequence of bytes
 * using Xoodyak-Hash as the underlying digest algorithm.
 *
 * HMAC uses an underlying block size to pad the key data.
 * The Xoodyak-Hash block absorption rate of 16 bytes is too short
 * so we use the HMAC-SHA-256 block size of 64 instead.
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
 * \brief Default size of the output for Xoodyak-HMAC.
 */
#define XOODYAK_HMAC_SIZE XOODYAK_HASH_SIZE

/**
 * \brief State information for the Xoodyak-HMAC incremental mode.
 */
typedef xoodyak_hash_state_t xoodyak_hmac_state_t;

/**
 * \brief Computes a HMAC value using Xoodyak-Hash.
 *
 * \param out Buffer to receive the output HMAC value; must be at least
 * XOODYAK_HMAC_SIZE bytes in length.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 * \param in Points to the data to authenticate.
 * \param inlen Number of bytes of data to authenticate.
 */
void xoodyak_hmac
    (unsigned char *out,
     const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen);

/**
 * \brief Initializes an incremental HMAC state using Xoodyak-Hash.
 *
 * \param state Points to the state to be initialized.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 *
 * The \a key needs to be preserved until the xoodyak_hmac_finalize() call
 * to provide the outer HMAC hashing key.
 *
 * \sa xoodyak_hmac_update(), xoodyak_hmac_finalize()
 */
void xoodyak_hmac_init
    (xoodyak_hmac_state_t *state, const unsigned char *key, size_t keylen);

/**
 * \brief Updates an incremental Xoodyak-HMAC state with more input data.
 *
 * \param state HMAC state to be updated.
 * \param in Points to the input data to be incorporated into the state.
 * \param inlen Length of the input data to be incorporated into the state.
 *
 * \sa xoodyak_hmac_init(), xoodyak_hmac_finalize()
 */
void xoodyak_hmac_update
    (xoodyak_hmac_state_t *state, const unsigned char *in, size_t inlen);

/**
 * \brief Finalizes an incremental Xoodyak-HMAC state.
 *
 * \param state HMAC state to squeeze the output data from.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 * \param out Points to the output buffer to receive the HMAC value;
 * must be at least XOODYAK_HMAC_SIZE bytes in length.
 *
 * \sa xoodyak_hmac_init(), xoodyak_hmac_update()
 */
void xoodyak_hmac_finalize
    (xoodyak_hmac_state_t *state, const unsigned char *key, size_t keylen,
     unsigned char *out);

#ifdef __cplusplus
}
#endif

#endif
