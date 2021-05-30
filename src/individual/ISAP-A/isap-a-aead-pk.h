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

#ifndef LWCRYPTO_ISAP_A_AEAD_PK_H
#define LWCRYPTO_ISAP_A_AEAD_PK_H

#include "isap-a-aead.h"

/**
 * \file isap-a-aead-pk.h
 * \brief ISAP-A authenticated encryption algorithm with pre-computed keys.
 *
 * This version of ISAP-A provides an alternative API where the keys are
 * expanded ahead of time.  This is intended to limit leakage of information
 * about the key bits.  The key is loaded once during a session rather
 * than repeatedly each time encryption or decryption is performed.
 *
 * If a device has a long-lived key, then the pre-computed key could be
 * stored in ROM or flash memory and thus avoid leakage of loading
 * the key bits at runtime.
 *
 * References: https://isap.iaik.tugraz.at/
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Pre-computed key information for ISAP-A-128A.
 */
typedef struct
{
    unsigned char ke[40];   /**< Pre-computed key for encryption */
    unsigned char ka[40];   /**< Pre-computed key for authentication */

} isap_ascon_128a_key_t;

/**
 * \brief Pre-computed key information for ISAP-A-128.
 */
typedef struct
{
    unsigned char ke[40];   /**< Pre-computed key for encryption */
    unsigned char ka[40];   /**< Pre-computed key for authentication */

} isap_ascon_128_key_t;

/**
 * \brief Initializes a pre-computed key for ISAP-A-128A.
 *
 * \param pk Points to the object to receive the pre-computed key value.
 * \param k Points to the 16 bytes of the key.
 *
 * \return 0 on success, or a negative value if there was an error in
 * the parameters.
 *
 * \sa isap_ascon_128a_aead_pk_encrypt(), isap_ascon_128a_aead_pk_decrypt()
 */
int isap_ascon_128a_aead_pk_init
    (isap_ascon_128a_key_t *pk, const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with ISAP-A-128A and
 * pre-computed keys.
 *
 * \param c Buffer to receive the output.
 * \param clen On exit, set to the length of the output which includes
 * the ciphertext and the 16 byte authentication tag.
 * \param m Buffer that contains the plaintext message to encrypt.
 * \param mlen Length of the plaintext message in bytes.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param pk Points to the pre-computed key value.
 *
 * \return 0 on success, or a negative value if there was an error in
 * the parameters.
 *
 * \sa isap_ascon_128a_aead_pk_decrypt(), isap_ascon_128a_aead_pk_init()
 */
int isap_ascon_128a_aead_pk_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const isap_ascon_128a_key_t *pk);

/**
 * \brief Decrypts and authenticates a packet with ISAP-A-128A and
 * pre-computed keys.
 *
 * \param m Buffer to receive the plaintext message on output.
 * \param mlen Receives the length of the plaintext message on output.
 * \param c Buffer that contains the ciphertext and authentication
 * tag to decrypt.
 * \param clen Length of the input data in bytes, which includes the
 * ciphertext and the 16 byte authentication tag.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param pk Points to the pre-computed key value.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa isap_ascon_128a_aead_pk_encrypt(), isap_ascon_128a_aead_pk_init()
 */
int isap_ascon_128a_aead_pk_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const isap_ascon_128a_key_t *pk);

/**
 * \brief Initializes a pre-computed key for ISAP-A-128.
 *
 * \param pk Points to the object to receive the pre-computed key value.
 * \param k Points to the 16 bytes of the key.
 *
 * \return 0 on success, or a negative value if there was an error in
 * the parameters.
 *
 * \sa isap_ascon_128_aead_pk_encrypt(), isap_ascon_128_aead_pk_decrypt()
 */
int isap_ascon_128_aead_pk_init
    (isap_ascon_128_key_t *pk, const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with ISAP-A-128 and
 * pre-computed keys.
 *
 * \param c Buffer to receive the output.
 * \param clen On exit, set to the length of the output which includes
 * the ciphertext and the 16 byte authentication tag.
 * \param m Buffer that contains the plaintext message to encrypt.
 * \param mlen Length of the plaintext message in bytes.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param pk Points to the pre-computed key value.
 *
 * \return 0 on success, or a negative value if there was an error in
 * the parameters.
 *
 * \sa isap_ascon_128_aead_pk_decrypt(), isap_ascon_128_aead_pk_init()
 */
int isap_ascon_128_aead_pk_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const isap_ascon_128_key_t *pk);

/**
 * \brief Decrypts and authenticates a packet with ISAP-A-128 and
 * pre-computed keys.
 *
 * \param m Buffer to receive the plaintext message on output.
 * \param mlen Receives the length of the plaintext message on output.
 * \param c Buffer that contains the ciphertext and authentication
 * tag to decrypt.
 * \param clen Length of the input data in bytes, which includes the
 * ciphertext and the 16 byte authentication tag.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param pk Points to the pre-computed key value.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa isap_ascon_128_aead_pk_encrypt(), isap_ascon_128_aead_pk_init()
 */
int isap_ascon_128_aead_pk_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const isap_ascon_128_key_t *pk);

#ifdef __cplusplus
}
#endif

#endif
