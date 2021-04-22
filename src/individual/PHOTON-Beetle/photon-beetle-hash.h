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

#ifndef LWCRYPTO_PHOTON_BEETLE_HASH_H
#define LWCRYPTO_PHOTON_BEETLE_HASH_H

/**
 * \file photon-beetle-hash.h
 * \brief PHOTON-Beetle hash algorithm.
 *
 * PHOTON-Beetle-Hash has a 256-bit hash output.  The initial data is
 * handled as a 16 byte block, and then the remaining bytes are processed
 * in 4 byte blocks.
 *
 * References: https://www.isical.ac.in/~lightweight/beetle/
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the hash output for PHOTON-Beetle-HASH.
 */
#define PHOTON_BEETLE_HASH_SIZE 32

/**
 * \brief State information for the PHOTON-Beetle-HASH incremental mode.
 */
typedef union
{
    struct {
        unsigned char state[32]; /**< Current hash state */
        unsigned char posn;      /**< Position within current block */
        unsigned char rate;      /**< Rate of absorption for current block */
        unsigned char first;     /**< Non-zero for the first block */
    } s;                         /**< State */
    unsigned long long align;    /**< For alignment of this structure */

} photon_beetle_hash_state_t;

/**
 * \brief Hashes a block of input data with PHOTON-Beetle-HASH to
 * generate a hash value.
 *
 * \param out Buffer to receive the hash output which must be at least
 * PHOTON_BEETLE_HASH_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 *
 * \sa photon_beetle_hash_init()
 */
int photon_beetle_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen);

/**
 * \brief Initializes the state for a Photon-Beetle-HASH hashing operation.
 *
 * \param state Hash state to be initialized.
 *
 * \sa photon_beetle_hash_update(), photon_beetle_hash_finalize(),
 * photon_beetle_hash()
 */
void photon_beetle_hash_init(photon_beetle_hash_state_t *state);

/**
 * \brief Updates a Photon-Beetle-HASH state with more input data.
 *
 * \param state Hash state to be updated.
 * \param in Points to the input data to be incorporated into the state.
 * \param inlen Length of the input data to be incorporated into the state.
 *
 * \sa photon_beetle_hash_init(), photon_beetle_hash_finalize()
 */
void photon_beetle_hash_update
    (photon_beetle_hash_state_t *state, const unsigned char *in,
     unsigned long long inlen);

/**
 * \brief Returns the final hash value from a Photon-Beetle-HASH
 * hashing operation.
 *
 * \param state Hash state to be finalized.
 * \param out Buffer to receive the hash output which must be at least
 * PHOTON_BEETLE_HASH_SIZE bytes in length.
 *
 * \sa photon_beetle_hash_init(), photon_beetle_hash_update()
 */
void photon_beetle_hash_finalize
    (photon_beetle_hash_state_t *state, unsigned char *out);

#ifdef __cplusplus
}
#endif

#endif
