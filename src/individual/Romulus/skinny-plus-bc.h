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

#ifndef LWCRYPTO_SKINNY_PLUS_BC_H
#define LWCRYPTO_SKINNY_PLUS_BC_H

#include <stddef.h>
#include <stdint.h>

/**
 * \file skinny-plus-bc.h
 * \brief SKINNY-128-384+ block cipher.
 *
 * This API provides access to the raw SKINNY-128-384+ block cipher ECB
 * operation to help applications implement higher-level modes around
 * the cipher.
 *
 * The ECB encryption and decryption functions can take multiple blocks as
 * input which allows the back end to process multiple blocks in parallel
 * on architectures with SIMD instructions.  The function
 * skinny_128_384_plus_get_parallel_size() returns the best number of
 * bytes to process in a parallel request.  The input should be divided
 * up into blocks of this size if possible.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the key for SKINNY-128-384+.
 */
#define SKINNY_128_384_PLUS_KEY_SIZE 48

/**
 * \brief Size of a single message block for SKINNY-128-384+
 */
#define SKINNY_128_384_PLUS_BLOCK_SIZE 16

/**
 * \brief Structure of an expanded SKINNY-128-384+ key schedule.
 *
 * The TK1 field can be modified freely by the application between
 * calls to the encryption and decryption functions.  The rest of
 * the structure should be treated as opaque.
 *
 * \note This structure is sized to hold the largest possible key schedule
 * in the back end implementation.  The actual schedule may be smaller than
 * this if a memory-constrained back end is in use.  The function
 * skinny_128_384_plus_get_key_schedule_size() can be used to dynamically
 * allocate a memory buffer of the correct size.
 */
typedef struct
{
    uint8_t TK1[16];    /**< TK1 value */
    uint32_t k[160];    /**< Round keys for TK2 and TK3 */

} skinny_128_384_plus_key_schedule_t;

/**
 * \brief Gets the actual size of the SKINNY-128-384+ key schedule
 * in the back end.
 *
 * \return The actual size of the key schedule.
 */
size_t skinny_128_384_plus_get_key_schedule_size(void);

/**
 * \brief Gets the best size to use for parallel encryption and decryption.
 *
 * \return The best size in bytes to use for processing blocks in parallel.
 * If the back end does not support parallel block processing, then this
 * function will return SKINNY_128_384_PLUS_BLOCK_SIZE.
 */
size_t skinny_128_384_plus_get_parallel_size(void);

/**
 * \brief Sets up a key schedule for SKINNY-128-384+.
 *
 * \param ks Points to the key schedule object to set up.
 * \param k Points to the SKINNY_128_384_PLUS_KEY_SIZE bytes of the key.
 *
 * \sa skinny_128_384_plus_ecb_encrypt(), skinny_128_384_plus_ecb_decrypt(),
 * skinny_128_384_plus_free_schedule(), skinny_128_384_plus_setup_tk23()
 */
void skinny_128_384_plus_setup_key
    (skinny_128_384_plus_key_schedule_t *ks,
     const unsigned char k[SKINNY_128_384_PLUS_KEY_SIZE]);

/**
 * \brief Sets up the TK2 and TK3 parts of the key schedule for
 * SKINNY-128-384+ without TK1.
 *
 * \param ks Points to the key schedule to initialize.
 * \param tk2 Points to the 16 bytes of key data for TK2.
 * \param tk3 Points to the 16 bytes of key data for TK3.
 *
 * It is assumed that the application will fill in the TK1 field within
 * \a ks when it needs to encrypt or decrypt.
 *
 * \sa skinny_128_384_plus_ecb_encrypt(), skinny_128_384_plus_ecb_decrypt(),
 * skinny_128_384_plus_free_schedule(), skinny_128_384_plus_setup_key()
 */
void skinny_128_384_plus_setup_tk23
    (skinny_128_384_plus_key_schedule_t *ks, const unsigned char *tk2,
     const unsigned char *tk3);

/**
 * \brief Encrypts an array of 128-bit blocks with SKINNY-128-384+.
 *
 * \param ks Points to the SKINNY-128-384+ key schedule.
 * \param output Output buffer which must be at least \a len bytes in length.
 * \param input Input buffer which must be at least \a len bytes in length.
 * \param len Number of bytes to encrypt, which should be a multiple of
 * SKINNY_128_384_PLUS_BLOCK_SIZE bytes.  If not, the last partial block
 * will be ignored.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 *
 * \sa skinny_128_384_plus_ecb_decrypt(), skinny_128_384_plus_setup_key()
 */
void skinny_128_384_plus_ecb_encrypt
    (const skinny_128_384_plus_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, size_t len);

/**
 * \brief Encrypts an array of 128-bit blocks with SKINNY-128-384+.
 *
 * \param ks Points to the SKINNY-128-384+ key schedule.
 * \param output Output buffer which must be at least \a len bytes in length.
 * \param input Input buffer which must be at least \a len bytes in length.
 * \param len Number of bytes to decrypt, which should be a multiple of
 * SKINNY_128_384_PLUS_BLOCK_SIZE bytes.  If not, the last partial block
 * will be ignored.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place decryption.
 *
 * \sa skinny_128_384_plus_ecb_encrypt(), skinny_128_384_plus_setup_key()
 */
void skinny_128_384_plus_ecb_decrypt
    (const skinny_128_384_plus_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, size_t len);

/**
 * \brief Encrypts an array of 128-bit blocks with SKINNY-128-384+
 * where the TK1 values vary from block to block.
 *
 * \param ks Points to the SKINNY-128-384+ key schedule.
 * \param output Output buffer which must be at least \a len bytes in length.
 * \param input Input buffer which must be at least \a len bytes in length.
 * \param tk1 Points to the TK1 values for the blocks, which must be at
 * least \a len bytes in length.
 * \param len Number of bytes to encrypt, which should be a multiple of
 * SKINNY_128_384_PLUS_BLOCK_SIZE bytes.  If not, the last partial block
 * will be ignored.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 *
 * This function may modify the TK1 field of \a ks by copying successive
 * blocks from \a tk1 to \a ks during encryption.  The application should
 * assume that the TK1 field of \a ks has been destroyed after this
 * function is called.
 *
 * \sa skinny_128_384_plus_ecb_encrypt()
 */
void skinny_128_384_plus_ecb_encrypt_tk1
    (skinny_128_384_plus_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, const unsigned char *tk1, size_t len);

/**
 * \brief Decrypts an array of 128-bit blocks with SKINNY-128-384+
 * where the TK1 values vary from block to block.
 *
 * \param ks Points to the SKINNY-128-384+ key schedule.
 * \param output Output buffer which must be at least \a len bytes in length.
 * \param input Input buffer which must be at least \a len bytes in length.
 * \param tk1 Points to the TK1 values for the blocks, which must be at
 * least \a len bytes in length.
 * \param len Number of bytes to encrypt, which should be a multiple of
 * SKINNY_128_384_PLUS_BLOCK_SIZE bytes.  If not, the last partial block
 * will be ignored.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place decryption.
 *
 * This function may modify the TK1 field of \a ks by copying successive
 * blocks from \a tk1 to \a ks during decryption.  The application should
 * assume that the TK1 field of \a ks has been destroyed after this
 * function is called.
 *
 * \sa skinny_128_384_plus_ecb_decrypt()
 */
void skinny_128_384_plus_ecb_decrypt_tk1
    (skinny_128_384_plus_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, const unsigned char *tk1, size_t len);

/**
 * \brief Frees a SKINNY-128-384+ key schedule and destroys any sensitive data.
 *
 * \param ks Points to the key schedule object.
 *
 * Normally this will simply clear the \a ks object to all zeroes as the
 * caller is responsible for deallocating the memory used by \a ks.
 * It is still a good idea to call this function when the key schedule
 * is no longer required because future back ends might allocate
 * dynamic memory for large key schedules in the key setup functions.
 *
 * \sa skinny_128_384_plus_setup_key(), skinny_128_384_plus_setup_tk23()
 */
void skinny_128_384_plus_free_schedule(skinny_128_384_plus_key_schedule_t *ks);

/**
 * \brief Expands the key schedule and encrypts an array of blocks with
 * SKINNY-128-384+.
 *
 * \param k Points to the SKINNY_128_384_PLUS_KEY_SIZE bytes of the key.
 * \param output Output buffer which must be at least \a len bytes in length.
 * \param input Input buffer which must be at least \a len bytes in length.
 * \param len Number of bytes to encrypt, which should be a multiple of
 * SKINNY_128_384_PLUS_BLOCK_SIZE bytes.  If not, the last partial block
 * will be ignored.
 *
 * This function is intended for encrypting blocks where the entire
 * 48 bytes of the key change from request to request.
 *
 * \sa skinny_128_384_plus_expand_and_decrypt()
 */
void skinny_128_384_plus_expand_and_encrypt
    (const unsigned char k[SKINNY_128_384_PLUS_KEY_SIZE],
     unsigned char *output, const unsigned char *input, size_t len);

/**
 * \brief Expands the key schedule and decrypts an array of blocks with
 * SKINNY-128-384+.
 *
 * \param k Points to the SKINNY_128_384_PLUS_KEY_SIZE bytes of the key.
 * \param output Output buffer which must be at least \a len bytes in length.
 * \param input Input buffer which must be at least \a len bytes in length.
 * \param len Number of bytes to encrypt, which should be a multiple of
 * SKINNY_128_384_PLUS_BLOCK_SIZE bytes.  If not, the last partial block
 * will be ignored.
 *
 * This function is intended for decrypting blocks where the entire
 * 48 bytes of the key change from request to request.
 *
 * \sa skinny_128_384_plus_expand_and_encrypt()
 */
void skinny_128_384_plus_expand_and_decrypt
    (const unsigned char k[SKINNY_128_384_PLUS_KEY_SIZE],
     unsigned char *output, const unsigned char *input, size_t len);

#ifdef __cplusplus
}
#endif

#endif
