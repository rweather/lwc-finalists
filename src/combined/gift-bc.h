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

#ifndef LWCRYPTO_GIFT_BC_H
#define LWCRYPTO_GIFT_BC_H

#include <stddef.h>
#include <stdint.h>

/**
 * \file gift-bc.h
 * \brief GIFT-128 block cipher.
 *
 * This API provides access to the raw GIFT-128 block cipher ECB operation
 * to help applications implement higher-level modes around the cipher.
 *
 * Three versions of the GIFT-128 key setup, encryption, and decryption
 * functions are provided with different prefixes:
 *
 * \li <tt>gift128</tt> - Nibble-based GIFT-128 with big endian byte order
 * for the key and big endian nibble order for the message blocks.
 * This is the version of GIFT-128 from the original paper.
 * \li <tt>gift128_le</tt> - Nibble-based GIFT-128 with little endian
 * byte order for the key and little endian nibble order for the message blocks.
 * This version is used in some AEAD modes that are built around GIFT-128.
 * \li <tt>gift128b</tt> - Bit-sliced GIFT-128 with big endian byte order
 * for the key and message blocks.  This version is used by GIFT-COFB
 * and is the fastest version of the three.
 *
 * Internally the first two versions are implemented on top of the third,
 * with the byte and nibble order re-arranged on input and output.
 *
 * The ECB encryption and decryption functions can take multiple blocks as
 * input which allows the back end to process multiple blocks in parallel
 * on architectures with SIMD instructions.  The function
 * gift128_get_parallel_size() returns the best number of bytes to
 * process in a parallel request.  The input should be divided up into
 * blocks of this size if possible.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the key for GIFT-128.
 */
#define GIFT128_KEY_SIZE 16

/**
 * \brief Size of a single message block for GIFT-128.
 */
#define GIFT128_BLOCK_SIZE 16

/**
 * \brief Structure of an expanded GIFT-128 key schedule.
 *
 * \note This structure is sized to hold the largest possible key schedule
 * in the back end implementation.  The actual schedule may be smaller than
 * this if a memory-constrained back end is in use.  The function
 * gift128_get_key_schedule_size() can be used to dynamically allocate a
 * memory buffer of the correct size.
 */
typedef struct
{
    uint32_t k[80];     /**< Round keys */

} gift128_key_schedule_t;

/**
 * \brief Gets the actual size of the GIFT-128 key schedule in the back end.
 *
 * \return The actual size of the key schedule.
 */
size_t gift128_get_key_schedule_size(void);

/**
 * \brief Gets the best size to use for parallel encryption and decryption.
 *
 * \return The best size in bytes to use for processing blocks in parallel.
 * If the back end does not support parallel block processing, then this
 * function will return GIFT128_BLOCK_SIZE.
 */
size_t gift128_get_parallel_size(void);

/**
 * \brief Sets up a key schedule for the original version of GIFT-128.
 *
 * \param ks Points to the key schedule object to set up.
 * \param k Points to the GIFT128_KEY_SIZE bytes of the key.
 *
 * \sa gift128_ecb_encrypt(), gift128_ecb_decrypt(), gift128_free_schedule()
 */
void gift128_setup_key
    (gift128_key_schedule_t *ks, const unsigned char *k);

/**
 * \brief Encrypts a 128-bit block with the original version of GIFT-128.
 *
 * \param ks Points to the GIFT-128 key schedule.
 * \param output Output buffer which must be at least \a len bytes in length.
 * \param input Input buffer which must be at least \a len bytes in length.
 * \param len Number of bytes to encrypt, which should be a multiple of
 * GIFT128_BLOCK_SIZE bytes.  If not, the last partial block will be ignored.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 *
 * \sa gift128_ecb_decrypt(), gift128_setup_key()
 */
void gift128_ecb_encrypt
    (const gift128_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, size_t len);

/**
 * \brief Decrypts a 128-bit block with the original version of GIFT-128.
 *
 * \param ks Points to the GIFT-128 key schedule.
 * \param output Output buffer which must be at least \a len bytes in length.
 * \param input Input buffer which must be at least \a len bytes in length.
 * \param len Number of bytes to decrypt, which should be a multiple of
 * GIFT128_BLOCK_SIZE bytes.  If not, the last partial block will be ignored.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place decryption.
 *
 * \sa gift128_ecb_encrypt(), gift128_setup_key()
 */
void gift128_ecb_decrypt
    (const gift128_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, size_t len);

/**
 * \brief Sets up a key schedule for the little-endian version of GIFT-128.
 *
 * \param ks Points to the key schedule object to set up.
 * \param k Points to the GIFT128_KEY_SIZE bytes of the key.
 *
 * \sa gift128_le_ecb_encrypt(), gift128_le_ecb_decrypt(),
 * gift128_free_schedule()
 */
void gift128_le_setup_key
    (gift128_key_schedule_t *ks, const unsigned char *k);

/**
 * \brief Encrypts a 128-bit block with the little-endian version of GIFT-128.
 *
 * \param ks Points to the GIFT-128 key schedule.
 * \param output Output buffer which must be at least \a len bytes in length.
 * \param input Input buffer which must be at least \a len bytes in length.
 * \param len Number of bytes to encrypt, which should be a multiple of
 * GIFT128_BLOCK_SIZE bytes.  If not, the last partial block will be ignored.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 *
 * \sa gift128_le_ecb_decrypt(), gift128_le_setup_key()
 */
void gift128_le_ecb_encrypt
    (const gift128_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, size_t len);

/**
 * \brief Decrypts a 128-bit block with the little-endian version of GIFT-128.
 *
 * \param ks Points to the GIFT-128 key schedule.
 * \param output Output buffer which must be at least \a len bytes in length.
 * \param input Input buffer which must be at least \a len bytes in length.
 * \param len Number of bytes to decrypt, which should be a multiple of
 * GIFT128_BLOCK_SIZE bytes.  If not, the last partial block will be ignored.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place decryption.
 *
 * \sa gift128_le_ecb_encrypt(), gift128_le_setup_key()
 */
void gift128_le_ecb_decrypt
    (const gift128_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, size_t len);

/**
 * \brief Sets up a key schedule for the bit-sliced version of GIFT-128.
 *
 * \param ks Points to the key schedule object to set up.
 * \param k Points to the GIFT128_KEY_SIZE bytes of the key.
 *
 * \sa gift128b_ecb_encrypt(), gift128b_ecb_decrypt(), gift128_free_schedule()
 */
void gift128b_setup_key
    (gift128_key_schedule_t *ks, const unsigned char *k);

/**
 * \brief Encrypts a 128-bit block with the bit-sliced version of GIFT-128.
 *
 * \param ks Points to the GIFT-128 key schedule.
 * \param output Output buffer which must be at least \a len bytes in length.
 * \param input Input buffer which must be at least \a len bytes in length.
 * \param len Number of bytes to encrypt, which should be a multiple of
 * GIFT128_BLOCK_SIZE bytes.  If not, the last partial block will be ignored.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 *
 * \sa gift128b_ecb_decrypt(), gift128b_setup_key()
 */
void gift128b_ecb_encrypt
    (const gift128_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, size_t len);

/**
 * \brief Decrypts a 128-bit block with the bit-sliced version of GIFT-128.
 *
 * \param ks Points to the GIFT-128 key schedule.
 * \param output Output buffer which must be at least \a len bytes in length.
 * \param input Input buffer which must be at least \a len bytes in length.
 * \param len Number of bytes to decrypt, which should be a multiple of
 * GIFT128_BLOCK_SIZE bytes.  If not, the last partial block will be ignored.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place decryption.
 *
 * \sa gift128b_ecb_encrypt(), gift128b_setup_key()
 */
void gift128b_ecb_decrypt
    (const gift128_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, size_t len);

/**
 * \brief Frees a GIFT-128 key schedule and destroys any sensitive data.
 *
 * \param ks Points to the key schedule object.
 *
 * Normally this will simply clear the \a ks object to all zeroes as the
 * caller is responsible for deallocating the memory used by \a ks.
 * It is still a good idea to call this function when the key schedule
 * is no longer required because future back ends might allocate
 * dynamic memory for large key schedules in the key setup functions.
 *
 * \sa gift128_setup_key(), gift128_le_setup_key(), gift128b_setup_key()
 */
void gift128_free_schedule(gift128_key_schedule_t *ks);

#ifdef __cplusplus
}
#endif

#endif
