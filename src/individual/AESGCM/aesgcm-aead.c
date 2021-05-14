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

#include "aesgcm-aead.h"
#include "internal-aes.h"
#include "internal-ghash.h"
#include <string.h>

/**
 * \brief Encrypts and authenticates a packet with AES-GCM.
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
 * be 12 bytes in length.
 * \param ks Points to the key schedule.
 *
 * \return 0 on success, or a negative value if there was an error in
 * the parameters.
 */
static int aesgcm_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const aes_key_schedule_t *ks)
{
    size_t offset;
    ghash_state_t ghash;
    unsigned char counter[AES_BLOCK_SIZE];
    unsigned char block[AES_BLOCK_SIZE];
    uint32_t count = 1;

    /* Set the length of the returned ciphertext */
    *clen = mlen + AESGCM_TAG_SIZE;

    /* Set up the counter prefix based on the nonce */
    memcpy(counter, npub, 12);

    /* Encrypt a block of zeroes to create the hashing key */
    memset(block, 0, sizeof(block));
    aes_ecb_encrypt(ks, block, block);
    ghash_init(&ghash, block);

    /* Absorb the associated data into the hash */
    ghash_update(&ghash, ad, adlen);
    ghash_pad(&ghash);

    /* Encrypt the plaintext in counter mode */
    offset = 0;
    while ((offset + AES_BLOCK_SIZE) <= mlen) {
        ++count;
        be_store_word32(counter + 12, count);
        aes_ecb_encrypt(ks, block, counter);
        lw_xor_block_2_src(c + offset, m + offset, block, AES_BLOCK_SIZE);
        offset += AES_BLOCK_SIZE;
    }
    if (offset < mlen) {
        size_t temp = mlen - offset;
        ++count;
        be_store_word32(counter + 12, count);
        aes_ecb_encrypt(ks, block, counter);
        lw_xor_block_2_src(c + offset, m + offset, block, temp);
    }

    /* Absorb the ciphertext into the hash */
    ghash_update(&ghash, c, mlen);
    ghash_pad(&ghash);

    /* Absorb the size of the associated data and plaintext in bits */
    be_store_word64(block, adlen * 8ULL);
    be_store_word64(block + 8, mlen * 8ULL);
    ghash_update(&ghash, block, sizeof(block));

    /* Finalize the hash to create the tag */
    be_store_word32(counter + 12, 1);
    aes_ecb_encrypt(ks, block, counter);
    ghash_finalize(&ghash, counter);
    lw_xor_block_2_src(c + mlen, block, counter, AESGCM_TAG_SIZE);
    return 0;
}

/**
 * \brief Decrypts and authenticates a packet with AES-GCM.
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
 * be 12 bytes in length.
 * \param ks Points to the key schedule.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 */
static int aesgcm_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const aes_key_schedule_t *ks)
{
    size_t offset;
    ghash_state_t ghash;
    unsigned char counter[AES_BLOCK_SIZE];
    unsigned char block[AES_BLOCK_SIZE];
    uint32_t count = 1;

    /* Set the length of the returned plaintext */
    if (clen < AESGCM_TAG_SIZE)
        return -1;
    clen -= AESGCM_TAG_SIZE;
    *mlen = clen;

    /* Set up the counter prefix based on the nonce */
    memcpy(counter, npub, 12);

    /* Encrypt a block of zeroes to create the hashing key */
    memset(block, 0, sizeof(block));
    aes_ecb_encrypt(ks, block, block);
    ghash_init(&ghash, block);

    /* Absorb the associated data into the hash */
    ghash_update(&ghash, ad, adlen);
    ghash_pad(&ghash);

    /* Absorb the ciphertext into the hash prior to decryption */
    ghash_update(&ghash, c, clen);
    ghash_pad(&ghash);

    /* Decrypt the ciphertext in counter mode */
    offset = 0;
    while ((offset + AES_BLOCK_SIZE) <= clen) {
        ++count;
        be_store_word32(counter + 12, count);
        aes_ecb_encrypt(ks, block, counter);
        lw_xor_block_2_src(m + offset, c + offset, block, AES_BLOCK_SIZE);
        offset += AES_BLOCK_SIZE;
    }
    if (offset < clen) {
        size_t temp = clen - offset;
        ++count;
        be_store_word32(counter + 12, count);
        aes_ecb_encrypt(ks, block, counter);
        lw_xor_block_2_src(m + offset, c + offset, block, temp);
    }

    /* Absorb the size of the associated data and plaintext in bits */
    be_store_word64(block, adlen * 8ULL);
    be_store_word64(block + 8, clen * 8ULL);
    ghash_update(&ghash, block, sizeof(block));

    /* Finalize the hash and check the tag */
    be_store_word32(counter + 12, 1);
    aes_ecb_encrypt(ks, block, counter);
    ghash_finalize(&ghash, counter);
    lw_xor_block(block, counter, AESGCM_TAG_SIZE);
    return aead_check_tag(m, *mlen, block, c + clen, AESGCM_TAG_SIZE);
}

int aesgcm128_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    aes_key_schedule_t ks;
    aes_128_init(&ks, k);
    return aesgcm_aead_encrypt(c, clen, m, mlen, ad, adlen, npub, &ks);
}

int aesgcm128_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    aes_key_schedule_t ks;
    aes_128_init(&ks, k);
    return aesgcm_aead_decrypt(m, mlen, c, clen, ad, adlen, npub, &ks);
}

int aesgcm192_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    aes_key_schedule_t ks;
    aes_192_init(&ks, k);
    return aesgcm_aead_encrypt(c, clen, m, mlen, ad, adlen, npub, &ks);
}

int aesgcm192_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    aes_key_schedule_t ks;
    aes_192_init(&ks, k);
    return aesgcm_aead_decrypt(m, mlen, c, clen, ad, adlen, npub, &ks);
}

int aesgcm256_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    aes_key_schedule_t ks;
    aes_256_init(&ks, k);
    return aesgcm_aead_encrypt(c, clen, m, mlen, ad, adlen, npub, &ks);
}

int aesgcm256_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    aes_key_schedule_t ks;
    aes_256_init(&ks, k);
    return aesgcm_aead_decrypt(m, mlen, c, clen, ad, adlen, npub, &ks);
}
