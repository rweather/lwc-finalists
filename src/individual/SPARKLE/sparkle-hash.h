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

#ifndef LWCRYPTO_SPARKLE_HASH_H
#define LWCRYPTO_SPARKLE_HASH_H

/**
 * \file sparkle-hash.h
 * \brief Hash algorithms based on the SPARKLE permutation.
 *
 * SPARKLE is a family of encryption and hash algorithms that are based
 * around the SPARKLE permutation.  There are three versions of the
 * permutation with 256-bit, 384-bit, and 512-bit state sizes.
 * The hash algorithms in the family are:
 *
 * \li Esch256 hash algorithm with a 256-bit digest output.  This is the
 * primary hash algorithm in the family.
 * \li Esch384 hash algorithm with a 384-bit digest output.
 *
 * References: https://www.cryptolux.org/index.php/Sparkle
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the hash output for Esch256.
 */
#define ESCH_256_HASH_SIZE 32

/**
 * \brief Size of the hash output for Esch384.
 */
#define ESCH_384_HASH_SIZE 48

/**
 * \brief State information for the Esch256 incremental hash mode.
 */
typedef union
{
    struct {
        unsigned char state[48];    /**< Current hash state */
        unsigned char block[16];    /**< Partial input data block */
        unsigned char count;        /**< Number of bytes in the current block */
    } s;                            /**< State */
    unsigned long long align;       /**< For alignment of this structure */

} esch_256_hash_state_t;

/**
 * \brief State information for the Esch384 incremental hash mode.
 */
typedef union
{
    struct {
        unsigned char state[64];    /**< Current hash state */
        unsigned char block[16];    /**< Partial input data block */
        unsigned char count;        /**< Number of bytes in the current block */
    } s;                            /**< State */
    unsigned long long align;       /**< For alignment of this structure */

} esch_384_hash_state_t;

/**
 * \brief Hashes a block of input data with Esch256 to generate a hash value.
 *
 * \param out Buffer to receive the hash output which must be at least
 * ESCH_256_HASH_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 */
int esch_256_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen);

/**
 * \brief Initializes the state for an Esch256 hashing operation.
 *
 * \param state Hash state to be initialized.
 *
 * \sa esch_256_hash_update(), esch_256_hash_finalize(), esch_256_hash()
 */
void esch_256_hash_init(esch_256_hash_state_t *state);

/**
 * \brief Updates an Esch256 state with more input data.
 *
 * \param state Hash state to be updated.
 * \param in Points to the input data to be incorporated into the state.
 * \param inlen Length of the input data to be incorporated into the state.
 *
 * \sa esch_256_hash_init(), esch_256_hash_finalize()
 */
void esch_256_hash_update
    (esch_256_hash_state_t *state, const unsigned char *in,
     unsigned long long inlen);

/**
 * \brief Returns the final hash value from an Esch256 hashing operation.
 *
 * \param state Hash state to be finalized.
 * \param out Points to the output buffer to receive the 32-byte hash value.
 *
 * \sa esch_256_hash_init(), esch_256_hash_update()
 */
void esch_256_hash_finalize
    (esch_256_hash_state_t *state, unsigned char *out);

/**
 * \brief Hashes a block of input data with Esch384 to generate a hash value.
 *
 * \param out Buffer to receive the hash output which must be at least
 * ESCH_384_HASH_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 */
int esch_384_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen);

/**
 * \brief Initializes the state for an Esch384 hashing operation.
 *
 * \param state Hash state to be initialized.
 *
 * \sa esch_384_hash_update(), esch_384_hash_finalize(), esch_384_hash()
 */
void esch_384_hash_init(esch_384_hash_state_t *state);

/**
 * \brief Updates an Esch384 state with more input data.
 *
 * \param state Hash state to be updated.
 * \param in Points to the input data to be incorporated into the state.
 * \param inlen Length of the input data to be incorporated into the state.
 *
 * \sa esch_384_hash_init(), esch_384_hash_finalize()
 */
void esch_384_hash_update
    (esch_384_hash_state_t *state, const unsigned char *in,
     unsigned long long inlen);

/**
 * \brief Returns the final hash value from an Esch384 hashing operation.
 *
 * \param state Hash state to be finalized.
 * \param out Points to the output buffer to receive the 48-byte hash value.
 *
 * \sa esch_384_hash_init(), esch_384_hash_update()
 */
void esch_384_hash_finalize
    (esch_384_hash_state_t *state, unsigned char *out);

#ifdef __cplusplus
}
#endif

#endif