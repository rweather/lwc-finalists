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

#ifndef LWCRYPTO_ASCON_H
#define LWCRYPTO_ASCON_H

/**
 * \file ascon128.h
 * \brief ASCON-128 encryption algorithm and related family members.
 *
 * The ASCON family consists of several related algorithms:
 *
 * \li ASCON-128 with a 128-bit key, a 128-bit nonce, a 128-bit authentication
 * tag, and a block rate of 64 bits.
 * \li ASCON-128a with a 128-bit key, a 128-bit nonce, a 128-bit authentication
 * tag, and a block rate of 128 bits.  This is faster than ASCON-128 but may
 * not be as secure.
 * \li ASCON-80pq with a 160-bit key, a 128-bit nonce, a 128-bit authentication
 * tag, and a block rate of 64 bits.  This is similar to ASCON-128 but has a
 * 160-bit key instead which may be more resistant against quantum computers.
 * \li ASCON-HASH with a 256-bit hash output.
 *
 * References: https://ascon.iaik.tugraz.at/
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the key for ASCON-128 and ASCON-128a.
 */
#define ASCON128_KEY_SIZE 16

/**
 * \brief Size of the nonce for ASCON-128 and ASCON-128a.
 */
#define ASCON128_NONCE_SIZE 16

/**
 * \brief Size of the authentication tag for ASCON-128 and ASCON-128a.
 */
#define ASCON128_TAG_SIZE 16

/**
 * \brief Size of the key for ASCON-80pq.
 */
#define ASCON80PQ_KEY_SIZE 20

/**
 * \brief Size of the nonce for ASCON-80pq.
 */
#define ASCON80PQ_NONCE_SIZE 16

/**
 * \brief Size of the authentication tag for ASCON-80pq.
 */
#define ASCON80PQ_TAG_SIZE 16

/**
 * \brief Size of the hash output for ASCON-HASH.
 */
#define ASCON_HASH_SIZE 32

/**
 * \brief State information for ASCON-HASH and ASCON-XOF incremental modes.
 */
typedef union
{
    struct {
        unsigned char state[40]; /**< Current hash state */
        unsigned char count;     /**< Number of bytes in the current block */
        unsigned char mode;      /**< Hash mode: 0 for absorb, 1 for squeeze */
    } s;                         /**< State */
    unsigned long long align;    /**< For alignment of this structure */

} ascon_hash_state_t;

/**
 * \brief Encrypts and authenticates a packet with ASCON-128.
 *
 * \param c Buffer to receive the output.
 * \param clen On exit, set to the length of the output which includes
 * the ciphertext and the 16 byte authentication tag.
 * \param m Buffer that contains the plaintext message to encrypt.
 * \param mlen Length of the plaintext message in bytes.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param nsec Secret nonce - not used by this algorithm.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param k Points to the 16 bytes of the key to use to encrypt the packet.
 *
 * \return 0 on success, or a negative value if there was an error in
 * the parameters.
 *
 * \sa ascon128_aead_decrypt()
 */
int ascon128_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with ASCON-128.
 *
 * \param m Buffer to receive the plaintext message on output.
 * \param mlen Receives the length of the plaintext message on output.
 * \param nsec Secret nonce - not used by this algorithm.
 * \param c Buffer that contains the ciphertext and authentication
 * tag to decrypt.
 * \param clen Length of the input data in bytes, which includes the
 * ciphertext and the 16 byte authentication tag.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param k Points to the 16 bytes of the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa ascon128_aead_encrypt()
 */
int ascon128_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with ASCON-128a.
 *
 * \param c Buffer to receive the output.
 * \param clen On exit, set to the length of the output which includes
 * the ciphertext and the 16 byte authentication tag.
 * \param m Buffer that contains the plaintext message to encrypt.
 * \param mlen Length of the plaintext message in bytes.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param nsec Secret nonce - not used by this algorithm.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param k Points to the 16 bytes of the key to use to encrypt the packet.
 *
 * \return 0 on success, or a negative value if there was an error in
 * the parameters.
 *
 * \sa ascon128a_aead_decrypt()
 */
int ascon128a_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with ASCON-128a.
 *
 * \param m Buffer to receive the plaintext message on output.
 * \param mlen Receives the length of the plaintext message on output.
 * \param nsec Secret nonce - not used by this algorithm.
 * \param c Buffer that contains the ciphertext and authentication
 * tag to decrypt.
 * \param clen Length of the input data in bytes, which includes the
 * ciphertext and the 16 byte authentication tag.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param k Points to the 16 bytes of the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa ascon128a_aead_encrypt()
 */
int ascon128a_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with ASCON-80pq.
 *
 * \param c Buffer to receive the output.
 * \param clen On exit, set to the length of the output which includes
 * the ciphertext and the 16 byte authentication tag.
 * \param m Buffer that contains the plaintext message to encrypt.
 * \param mlen Length of the plaintext message in bytes.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param nsec Secret nonce - not used by this algorithm.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param k Points to the 20 bytes of the key to use to encrypt the packet.
 *
 * \return 0 on success, or a negative value if there was an error in
 * the parameters.
 *
 * \sa ascon80pq_aead_decrypt()
 */
int ascon80pq_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with ASCON-80pq.
 *
 * \param m Buffer to receive the plaintext message on output.
 * \param mlen Receives the length of the plaintext message on output.
 * \param nsec Secret nonce - not used by this algorithm.
 * \param c Buffer that contains the ciphertext and authentication
 * tag to decrypt.
 * \param clen Length of the input data in bytes, which includes the
 * ciphertext and the 16 byte authentication tag.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param k Points to the 20 bytes of the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa ascon80pq_aead_encrypt()
 */
int ascon80pq_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Hashes a block of input data with ASCON-HASH.
 *
 * \param out Buffer to receive the hash output which must be at least
 * ASCON_HASH_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 *
 * \sa ascon_hash_init(), ascon_hash_absorb(), ascon_hash_squeeze()
 */
int ascon_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen);

/**
 * \brief Initializes the state for an ASCON-HASH hashing operation.
 *
 * \param state Hash state to be initialized.
 *
 * \sa ascon_hash_update(), ascon_hash_finalize(), ascon_hash()
 */
void ascon_hash_init(ascon_hash_state_t *state);

/**
 * \brief Updates an ASCON-HASH state with more input data.
 *
 * \param state Hash state to be updated.
 * \param in Points to the input data to be incorporated into the state.
 * \param inlen Length of the input data to be incorporated into the state.
 *
 * \sa ascon_hash_init(), ascon_hash_finalize()
 */
void ascon_hash_update
    (ascon_hash_state_t *state, const unsigned char *in,
     unsigned long long inlen);

/**
 * \brief Returns the final hash value from an ASCON-HASH hashing operation.
 *
 * \param state Hash state to be finalized.
 * \param out Points to the output buffer to receive the 32-byte hash value.
 *
 * \sa ascon_hash_init(), ascon_hash_update()
 */
void ascon_hash_finalize
    (ascon_hash_state_t *state, unsigned char *out);

/**
 * \brief Hashes a block of input data with ASCON-XOF and generates a
 * fixed-length 32 byte output.
 *
 * \param out Buffer to receive the hash output which must be at least
 * ASCON_HASH_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 *
 * Use ascon_xof_squeeze() instead if you need variable-length XOF ouutput.
 *
 * \sa ascon_xof_init(), ascon_xof_absorb(), ascon_xof_squeeze()
 */
int ascon_xof
    (unsigned char *out, const unsigned char *in, unsigned long long inlen);

/**
 * \brief Initializes the state for an ASCON-XOF hashing operation.
 *
 * \param state Hash state to be initialized.
 *
 * \sa ascon_xof_absorb(), ascon_xof_squeeze(), ascon_xof()
 */
void ascon_xof_init(ascon_hash_state_t *state);

/**
 * \brief Aborbs more input data into an ASCON-XOF state.
 *
 * \param state Hash state to be updated.
 * \param in Points to the input data to be absorbed into the state.
 * \param inlen Length of the input data to be absorbed into the state.
 *
 * \sa ascon_xof_init(), ascon_xof_squeeze()
 */
void ascon_xof_absorb
    (ascon_hash_state_t *state, const unsigned char *in,
     unsigned long long inlen);

/**
 * \brief Squeezes output data from an ASCON-XOF state.
 *
 * \param state Hash state to squeeze the output data from.
 * \param out Points to the output buffer to receive the squeezed data.
 * \param outlen Number of bytes of data to squeeze out of the state.
 *
 * \sa ascon_xof_init(), ascon_xof_update()
 */
void ascon_xof_squeeze
    (ascon_hash_state_t *state, unsigned char *out, unsigned long long outlen);

#ifdef __cplusplus
}
#endif

#endif
