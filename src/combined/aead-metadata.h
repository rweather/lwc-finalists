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

#ifndef LWCRYPTO_AEAD_METADATA_H
#define LWCRYPTO_AEAD_METADATA_H

#include <stddef.h>

/**
 * \file aead-metadata.h
 * \brief Metadata defintions for AEAD and hashing schemes.
 *
 * This module provides metadata about the other implementations that
 * is useful for testing and benchmarking frameworks, but isn't part
 * of the main code for the algorithms.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Encrypts and authenticates a packet with an AEAD scheme.
 *
 * \param c Buffer to receive the output.
 * \param clen On exit, set to the length of the output which includes
 * the ciphertext and the authentication tag.
 * \param m Buffer that contains the plaintext message to encrypt.
 * \param mlen Length of the plaintext message in bytes.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet.
 * \param k Points to the key to use to encrypt the packet.
 *
 * \return 0 on success, or a negative value if there was an error in
 * the parameters.
 */
typedef int (*aead_cipher_encrypt_t)
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with an AEAD scheme.
 *
 * \param m Buffer to receive the plaintext message on output.
 * \param mlen Receives the length of the plaintext message on output.
 * \param c Buffer that contains the ciphertext and authentication
 * tag to decrypt.
 * \param clen Length of the input data in bytes, which includes the
 * ciphertext and the authentication tag.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet.
 * \param k Points to the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 */
typedef int (*aead_cipher_decrypt_t)
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Initializes a pre-computed key for an AEAD scheme.
 *
 * \param pk Points to the object to receive the pre-computed key value.
 * \param k Points to the bytes of the key.
 *
 * \return 0 on success, or a negative value if there was an error in
 * the parameters.
 */
typedef int (*aead_cipher_pk_init_t)
    (unsigned char *pk, const unsigned char *k);

/**
 * \brief Hashes a block of input data.
 *
 * \param out Buffer to receive the hash output.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 */
typedef int (*aead_hash_t)
    (unsigned char *out, const unsigned char *in, size_t inlen);

/**
 * \brief Initializes the state for a hashing operation.
 *
 * \param state Hash state to be initialized.
 */
typedef void (*aead_hash_init_t)(void *state);

/**
 * \brief Updates a hash state with more input data.
 *
 * \param state Hash state to be updated.
 * \param in Points to the input data to be incorporated into the state.
 * \param inlen Length of the input data to be incorporated into the state.
 */
typedef void (*aead_hash_update_t)
    (void *state, const unsigned char *in, size_t inlen);

/**
 * \brief Returns the final hash value from a hashing operation.
 *
 * \param Hash state to be finalized.
 * \param out Points to the output buffer to receive the hash value.
 */
typedef void (*aead_hash_finalize_t)(void *state, unsigned char *out);

/**
 * \brief Aborbs more input data into an XOF state.
 *
 * \param state XOF state to be updated.
 * \param in Points to the input data to be absorbed into the state.
 * \param inlen Length of the input data to be absorbed into the state.
 *
 * \sa ascon_xof_init(), ascon_xof_squeeze()
 */
typedef void (*aead_xof_absorb_t)
    (void *state, const unsigned char *in, size_t inlen);

/**
 * \brief Squeezes output data from an XOF state.
 *
 * \param state XOF state to squeeze the output data from.
 * \param out Points to the output buffer to receive the squeezed data.
 * \param outlen Number of bytes of data to squeeze out of the state.
 */
typedef void (*aead_xof_squeeze_t)
    (void *state, unsigned char *out, size_t outlen);

/**
 * \brief No special AEAD features.
 */
#define AEAD_FLAG_NONE              0x0000

/**
 * \brief The natural byte order of the AEAD cipher is little-endian.
 *
 * If this flag is not present, then the natural byte order of the
 * AEAD cipher should be assumed to be big-endian.
 *
 * The natural byte order may be useful when formatting packet sequence
 * numbers as nonces.  The application needs to know whether the sequence
 * number should be packed into the leading or trailing bytes of the nonce.
 */
#define AEAD_FLAG_LITTLE_ENDIAN     0x0001

/**
 * \brief The AEAD mode provides side-channel protection for the key.
 */
#define AEAD_FLAG_SC_PROTECT_KEY    0x0002

/**
 * \brief The AEAD mode provides side-channel protection for all block
 * operations.
 */
#define AEAD_FLAG_SC_PROTECT_ALL    0x0004

/**
 * \brief Algorithm is very slow in software, so performance frameworks
 * may want to use a different testing approach to avoid taking too long.
 */
#define AEAD_FLAG_SLOW              0x0008

/**
 * \brief Algorithm uses masking to protect sensitive material.
 */
#define AEAD_FLAG_MASKED            0x0010

/**
 * \brief Meta-information about an AEAD cipher.
 */
typedef struct
{
    const char *name;               /**< Name of the cipher */
    unsigned key_len;               /**< Length of the key in bytes */
    unsigned nonce_len;             /**< Length of the nonce in bytes */
    unsigned tag_len;               /**< Length of the tag in bytes */
    unsigned flags;                 /**< Flags for extra features */
    aead_cipher_encrypt_t encrypt;  /**< AEAD encryption function */
    aead_cipher_decrypt_t decrypt;  /**< AEAD decryption function */
    unsigned pk_state_len;          /**< Length of the pre-computed state */
    aead_cipher_pk_init_t pk_init;  /**< AEAD pre-computed init function */

} aead_cipher_t;

/**
 * \brief Meta-information about a hash algorithm that is related to an AEAD.
 *
 * Regular hash algorithms should provide the "hash", "init", "update",
 * and "finalize" functions.  Extensible Output Functions (XOF's) should
 * proivde the "hash", "init", "absorb", and "squeeze" functions.
 */
typedef struct
{
    const char *name;           /**< Name of the hash algorithm */
    size_t state_size;          /**< Size of the incremental state structure */
    unsigned hash_len;          /**< Length of the hash in bytes */
    unsigned flags;             /**< Flags for extra features */
    aead_hash_t hash;           /**< All in one hashing function */
    aead_hash_init_t init;      /**< Incremental hash/XOF init function */
    aead_hash_update_t update;  /**< Incremental hash update function */
    aead_hash_finalize_t finalize; /**< Incremental hash finalize function */
    aead_xof_absorb_t absorb;   /**< Incremental XOF absorb function */
    aead_xof_squeeze_t squeeze; /**< Incremental XOF squeeze function */

} aead_hash_algorithm_t;

/*------------------------ AES-GCM ------------------------*/

/**
 * \brief Meta-information block for the AES-128-GCM cipher.
 */
extern aead_cipher_t const aesgcm128_cipher;

/**
 * \brief Meta-information block for the AES-192-GCM cipher.
 */
extern aead_cipher_t const aesgcm192_cipher;

/**
 * \brief Meta-information block for the AES-256-GCM cipher.
 */
extern aead_cipher_t const aesgcm256_cipher;

/*------------------------- ASCON -------------------------*/

/**
 * \brief Meta-information block for the ASCON-128 cipher.
 */
extern aead_cipher_t const ascon128_cipher;

/**
 * \brief Meta-information block for the ASCON-128a cipher.
 */
extern aead_cipher_t const ascon128a_cipher;

/**
 * \brief Meta-information block for the ASCON-80pq cipher.
 */
extern aead_cipher_t const ascon80pq_cipher;

/**
 * \brief Meta-information block for the ASCON-HASH algorithm.
 */
extern aead_hash_algorithm_t const ascon_hash_algorithm;

/**
 * \brief Meta-information block for the ASCON-HASHA algorithm.
 */
extern aead_hash_algorithm_t const ascon_hasha_algorithm;

/**
 * \brief Meta-information block for the ASCON-XOF algorithm.
 */
extern aead_hash_algorithm_t const ascon_xof_algorithm;

/**
 * \brief Meta-information block for the ASCON-XOFA algorithm.
 */
extern aead_hash_algorithm_t const ascon_xofa_algorithm;

/**
 * \brief Meta-information block for the masked ASCON-128 cipher.
 */
extern aead_cipher_t const ascon128_masked_cipher;

/**
 * \brief Meta-information block for the masked ASCON-128a cipher.
 */
extern aead_cipher_t const ascon128a_masked_cipher;

/**
 * \brief Meta-information block for the masked ASCON-80pq cipher.
 */
extern aead_cipher_t const ascon80pq_masked_cipher;

/**
 * \brief Meta-information block for the ASCON-128-SIV cipher.
 */
extern aead_cipher_t const ascon128_siv_cipher;

/**
 * \brief Meta-information block for the ASCON-128a-SIV cipher.
 */
extern aead_cipher_t const ascon128a_siv_cipher;

/**
 * \brief Meta-information block for the ASCON-80pq-SIV cipher.
 */
extern aead_cipher_t const ascon80pq_siv_cipher;

/*----------------------- Elephant ------------------------*/

/**
 * \brief Meta-information block for the Delirium cipher.
 */
extern aead_cipher_t const delirium_cipher;

/**
 * \brief Meta-information block for the Dumbo cipher.
 */
extern aead_cipher_t const dumbo_cipher;

/**
 * \brief Meta-information block for the Jumbo cipher.
 */
extern aead_cipher_t const jumbo_cipher;

/*----------------------- GIFT-COFB -----------------------*/

/**
 * \brief Meta-information block for the GIFT-COFB cipher.
 */
extern aead_cipher_t const gift_cofb_cipher;

/**
 * \brief Meta-information block for the masked GIFT-COFB cipher.
 */
extern aead_cipher_t const gift_cofb_masked_cipher;

/*--------------------- Grain128-AEAD ---------------------*/

/**
 * \brief Meta-information block for the Grain-128AEAD cipher.
 */
extern aead_cipher_t const grain128_aead_cipher;

/*-------------------------- ISAP -------------------------*/

/**
 * \brief Meta-information block for the ISAP-K-128A cipher.
 */
extern aead_cipher_t const isap_keccak_128a_cipher;

/**
 * \brief Meta-information block for the ISAP-A-128A cipher.
 */
extern aead_cipher_t const isap_ascon_128a_cipher;

/**
 * \brief Meta-information block for the ISAP-K-128 cipher.
 */
extern aead_cipher_t const isap_keccak_128_cipher;

/**
 * \brief Meta-information block for the ISAP-A-128 cipher.
 */
extern aead_cipher_t const isap_ascon_128_cipher;

/**
 * \brief Meta-information block for the pre-computed ISAP-K-128A cipher.
 */
extern aead_cipher_t const isap_keccak_128a_pk_cipher;

/**
 * \brief Meta-information block for the pre-computed ISAP-A-128A cipher.
 */
extern aead_cipher_t const isap_ascon_128a_pk_cipher;

/**
 * \brief Meta-information block for the pre-computed ISAP-K-128 cipher.
 */
extern aead_cipher_t const isap_keccak_128_pk_cipher;

/**
 * \brief Meta-information block for the pre-computed ISAP-A-128 cipher.
 */
extern aead_cipher_t const isap_ascon_128_pk_cipher;

/*--------------------- PHOTON-Beetle ---------------------*/

/**
 * \brief Meta-information block for the PHOTON-Beetle-AEAD-ENC-128 cipher.
 */
extern aead_cipher_t const photon_beetle_128_cipher;

/**
 * \brief Meta-information block for the PHOTON-Beetle-AEAD-ENC-32 cipher.
 */
extern aead_cipher_t const photon_beetle_32_cipher;

/**
 * \brief Meta-information block for the PHOTON-Beetle-HASH algorithm.
 */
extern aead_hash_algorithm_t const photon_beetle_hash_algorithm;

/*------------------------ Romulus ------------------------*/

/**
 * \brief Meta-information block for the Romulus-N cipher.
 */
extern aead_cipher_t const romulus_n_cipher;

/**
 * \brief Meta-information block for the Romulus-M cipher.
 */
extern aead_cipher_t const romulus_m_cipher;

/**
 * \brief Meta-information block for the Romulus-T cipher.
 */
extern aead_cipher_t const romulus_t_cipher;

/**
 * \brief Meta-information block for the Romulus-H hash algorithm.
 */
extern aead_hash_algorithm_t const romulus_hash_algorithm;

/**
 * \brief Meta-information block for the Romulus-H based XOF algorithm.
 */
extern aead_hash_algorithm_t const romulus_xof_algorithm;

/*------------------------ SPARKLE ------------------------*/

/**
 * \brief Meta-information block for the Schwaemm256-128 cipher.
 */
extern aead_cipher_t const schwaemm_256_128_cipher;

/**
 * \brief Meta-information block for the Schwaemm192-192 cipher.
 */
extern aead_cipher_t const schwaemm_192_192_cipher;

/**
 * \brief Meta-information block for the Schwaemm128-128 cipher.
 */
extern aead_cipher_t const schwaemm_128_128_cipher;

/**
 * \brief Meta-information block for the Schwaemm256-256 cipher.
 */
extern aead_cipher_t const schwaemm_256_256_cipher;

/**
 * \brief Meta-information block for the Esch256 hash algorithm.
 */
extern aead_hash_algorithm_t const esch_256_hash_algorithm;

/**
 * \brief Meta-information block for the Esch384 hash algorithm.
 */
extern aead_hash_algorithm_t const esch_384_hash_algorithm;

/**
 * \brief Meta-information block for the XOEsch256 XOF algorithm.
 */
extern aead_hash_algorithm_t const esch_256_xof_algorithm;

/**
 * \brief Meta-information block for the XOEsch384 XOF algorithm.
 */
extern aead_hash_algorithm_t const esch_384_xof_algorithm;

/*----------------------- TinyJAMBU -----------------------*/

/**
 * \brief Meta-information block for the TinyJAMBU-128 cipher.
 */
extern aead_cipher_t const tiny_jambu_128_cipher;

/**
 * \brief Meta-information block for the TinyJAMBU-192 cipher.
 */
extern aead_cipher_t const tiny_jambu_192_cipher;

/**
 * \brief Meta-information block for the TinyJAMBU-256 cipher.
 */
extern aead_cipher_t const tiny_jambu_256_cipher;

/**
 * \brief Meta-information block for the masked TinyJAMBU-128 cipher.
 */
extern aead_cipher_t const tiny_jambu_128_masked_cipher;

/**
 * \brief Meta-information block for the masked TinyJAMBU-192 cipher.
 */
extern aead_cipher_t const tiny_jambu_192_masked_cipher;

/**
 * \brief Meta-information block for the masked TinyJAMBU-256 cipher.
 */
extern aead_cipher_t const tiny_jambu_256_masked_cipher;

/*------------------------ Xoodyak ------------------------*/

/**
 * \brief Meta-information block for the Xoodyak cipher.
 */
extern aead_cipher_t const xoodyak_cipher;

/**
 * \brief Meta-information block for the Xoodyak hash algorithm.
 */
extern aead_hash_algorithm_t const xoodyak_hash_algorithm;

/**
 * \brief Meta-information block for the masked Xoodyak cipher.
 */
extern aead_cipher_t const xoodyak_masked_cipher;

#ifdef __cplusplus
}
#endif

#endif
