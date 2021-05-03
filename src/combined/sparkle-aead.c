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

#include "sparkle-aead.h"
#include "internal-sparkle.h"
#include <string.h>

/**
 * \def DOMAIN(value)
 * \brief Build a domain separation value as a 32-bit word.
 *
 * \param value The base value.
 * \return The domain separation value as a 32-bit word.
 */
#if defined(LW_UTIL_LITTLE_ENDIAN)
#define DOMAIN(value) (((uint32_t)(value)) << 24)
#else
#define DOMAIN(value) (value)
#endif

/**
 * \brief Rate at which bytes are processed by Schwaemm256-128.
 */
#define SCHWAEMM_256_128_RATE 32

/**
 * \brief Pointer to the left of the state for Schwaemm256-128.
 */
#define SCHWAEMM_256_128_LEFT(s) ((unsigned char *)&(s[0]))

/**
 * \brief Pointer to the right of the state for Schwaemm256-128.
 */
#define SCHWAEMM_256_128_RIGHT(s) \
    (SCHWAEMM_256_128_LEFT(s) + SCHWAEMM_256_128_RATE)

/**
 * \brief Perform the rho1 and rate whitening steps for Schwaemm256-128.
 *
 * \param s SPARKLE-384 state.
 */
#define schwaemm_256_128_rho(s) \
    do { \
        uint32_t t = s[0]; \
        s[0] = s[4] ^ s[8]; \
        s[4] ^= t   ^ s[8]; \
        t = s[1]; \
        s[1] = s[5] ^ s[9]; \
        s[5] ^= t   ^ s[9]; \
        t = s[2]; \
        s[2] = s[6] ^ s[10]; \
        s[6] ^= t   ^ s[10]; \
        t = s[3]; \
        s[3] = s[7] ^ s[11]; \
        s[7] ^= t   ^ s[11]; \
    } while (0)

/**
 * \brief Authenticates the associated data for Schwaemm256-128.
 *
 * \param s SPARKLE-384 state.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data; must be >= 1.
 */
static void schwaemm_256_128_authenticate
    (uint32_t s[SPARKLE_384_STATE_SIZE],
     const unsigned char *ad, size_t adlen)
{
    while (adlen > SCHWAEMM_256_128_RATE) {
        schwaemm_256_128_rho(s);
        lw_xor_block((unsigned char *)s, ad, SCHWAEMM_256_128_RATE);
        sparkle_384(s, 7);
        ad += SCHWAEMM_256_128_RATE;
        adlen -= SCHWAEMM_256_128_RATE;
    }
    if (adlen == SCHWAEMM_256_128_RATE) {
        s[11] ^= DOMAIN(0x05);
        schwaemm_256_128_rho(s);
        lw_xor_block((unsigned char *)s, ad, SCHWAEMM_256_128_RATE);
    } else {
        unsigned temp = (unsigned)adlen;
        s[11] ^= DOMAIN(0x04);
        schwaemm_256_128_rho(s);
        lw_xor_block((unsigned char *)s, ad, temp);
        ((unsigned char *)s)[temp] ^= 0x80;
    }
    sparkle_384(s, 11);
}

int schwaemm_256_128_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    uint32_t s[SPARKLE_384_STATE_SIZE];
    uint8_t block[SCHWAEMM_256_128_RATE];

    /* Set the length of the returned ciphertext */
    *clen = mlen + SCHWAEMM_256_128_TAG_SIZE;

    /* Initialize the state with the nonce and the key */
    memcpy(SCHWAEMM_256_128_LEFT(s), npub, SCHWAEMM_256_128_NONCE_SIZE);
    memcpy(SCHWAEMM_256_128_RIGHT(s), k, SCHWAEMM_256_128_KEY_SIZE);
    sparkle_384(s, 11);

    /* Process the associated data */
    if (adlen > 0)
        schwaemm_256_128_authenticate(s, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    if (mlen > 0) {
        while (mlen > SCHWAEMM_256_128_RATE) {
            lw_xor_block_2_src
                (block, (unsigned char *)s, m, SCHWAEMM_256_128_RATE);
            schwaemm_256_128_rho(s);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_256_128_RATE);
            sparkle_384(s, 7);
            memcpy(c, block, SCHWAEMM_256_128_RATE);
            c += SCHWAEMM_256_128_RATE;
            m += SCHWAEMM_256_128_RATE;
            mlen -= SCHWAEMM_256_128_RATE;
        }
        if (mlen == SCHWAEMM_256_128_RATE) {
            lw_xor_block_2_src
                (block, (unsigned char *)s, m, SCHWAEMM_256_128_RATE);
            s[11] ^= DOMAIN(0x07);
            schwaemm_256_128_rho(s);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_256_128_RATE);
            memcpy(c, block, SCHWAEMM_256_128_RATE);
        } else {
            unsigned temp = (unsigned)mlen;
            lw_xor_block_2_src(block, (unsigned char *)s, m, temp);
            s[11] ^= DOMAIN(0x06);
            schwaemm_256_128_rho(s);
            lw_xor_block((unsigned char *)s, m, temp);
            ((unsigned char *)s)[temp] ^= 0x80;
            memcpy(c, block, temp);
        }
        sparkle_384(s, 11);
        c += mlen;
    }

    /* Generate the authentication tag */
    lw_xor_block_2_src
        (c, SCHWAEMM_256_128_RIGHT(s), k, SCHWAEMM_256_128_TAG_SIZE);
    return 0;
}

int schwaemm_256_128_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    uint32_t s[SPARKLE_384_STATE_SIZE];
    unsigned char *mtemp = m;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < SCHWAEMM_256_128_TAG_SIZE)
        return -1;
    *mlen = clen - SCHWAEMM_256_128_TAG_SIZE;

    /* Initialize the state with the nonce and the key */
    memcpy(SCHWAEMM_256_128_LEFT(s), npub, SCHWAEMM_256_128_NONCE_SIZE);
    memcpy(SCHWAEMM_256_128_RIGHT(s), k, SCHWAEMM_256_128_KEY_SIZE);
    sparkle_384(s, 11);

    /* Process the associated data */
    if (adlen > 0)
        schwaemm_256_128_authenticate(s, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= SCHWAEMM_256_128_TAG_SIZE;
    if (clen > 0) {
        while (clen > SCHWAEMM_256_128_RATE) {
            lw_xor_block_2_src
                (m, (unsigned char *)s, c, SCHWAEMM_256_128_RATE);
            schwaemm_256_128_rho(s);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_256_128_RATE);
            sparkle_384(s, 7);
            c += SCHWAEMM_256_128_RATE;
            m += SCHWAEMM_256_128_RATE;
            clen -= SCHWAEMM_256_128_RATE;
        }
        if (clen == SCHWAEMM_256_128_RATE) {
            lw_xor_block_2_src
                (m, (unsigned char *)s, c, SCHWAEMM_256_128_RATE);
            s[11] ^= DOMAIN(0x07);
            schwaemm_256_128_rho(s);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_256_128_RATE);
        } else {
            unsigned temp = (unsigned)clen;
            lw_xor_block_2_src(m, (unsigned char *)s, c, temp);
            s[11] ^= DOMAIN(0x06);
            schwaemm_256_128_rho(s);
            lw_xor_block((unsigned char *)s, m, temp);
            ((unsigned char *)s)[temp] ^= 0x80;
        }
        sparkle_384(s, 11);
        c += clen;
    }

    /* Check the authentication tag */
    lw_xor_block(SCHWAEMM_256_128_RIGHT(s), k, SCHWAEMM_256_128_TAG_SIZE);
    return aead_check_tag
        (mtemp, *mlen, SCHWAEMM_256_128_RIGHT(s), c, SCHWAEMM_256_128_TAG_SIZE);
}

/**
 * \brief Rate at which bytes are processed by Schwaemm192-192.
 */
#define SCHWAEMM_192_192_RATE 24

/**
 * \brief Pointer to the left of the state for Schwaemm192-192.
 */
#define SCHWAEMM_192_192_LEFT(s) ((unsigned char *)&(s[0]))

/**
 * \brief Pointer to the right of the state for Schwaemm192-192.
 */
#define SCHWAEMM_192_192_RIGHT(s) \
    (SCHWAEMM_192_192_LEFT(s) + SCHWAEMM_192_192_RATE)

/**
 * \brief Perform the rho1 and rate whitening steps for Schwaemm192-192.
 *
 * \param s SPARKLE-384 state.
 */
#define schwaemm_192_192_rho(s) \
    do { \
        uint32_t t = s[0]; \
        s[0] = s[3] ^ s[6]; \
        s[3] ^= t   ^ s[9]; \
        t = s[1]; \
        s[1] = s[4] ^ s[7]; \
        s[4] ^= t   ^ s[10]; \
        t = s[2]; \
        s[2] = s[5] ^ s[8]; \
        s[5] ^= t   ^ s[11]; \
    } while (0)

/**
 * \brief Authenticates the associated data for Schwaemm192-192.
 *
 * \param s SPARKLE-384 state.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data; must be >= 1.
 */
static void schwaemm_192_192_authenticate
    (uint32_t s[SPARKLE_384_STATE_SIZE],
     const unsigned char *ad, size_t adlen)
{
    while (adlen > SCHWAEMM_192_192_RATE) {
        schwaemm_192_192_rho(s);
        lw_xor_block((unsigned char *)s, ad, SCHWAEMM_192_192_RATE);
        sparkle_384(s, 7);
        ad += SCHWAEMM_192_192_RATE;
        adlen -= SCHWAEMM_192_192_RATE;
    }
    if (adlen == SCHWAEMM_192_192_RATE) {
        s[11] ^= DOMAIN(0x09);
        schwaemm_192_192_rho(s);
        lw_xor_block((unsigned char *)s, ad, SCHWAEMM_192_192_RATE);
    } else {
        unsigned temp = (unsigned)adlen;
        s[11] ^= DOMAIN(0x08);
        schwaemm_192_192_rho(s);
        lw_xor_block((unsigned char *)s, ad, temp);
        ((unsigned char *)s)[temp] ^= 0x80;
    }
    sparkle_384(s, 11);
}

int schwaemm_192_192_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    uint32_t s[SPARKLE_384_STATE_SIZE];
    uint8_t block[SCHWAEMM_192_192_RATE];

    /* Set the length of the returned ciphertext */
    *clen = mlen + SCHWAEMM_192_192_TAG_SIZE;

    /* Initialize the state with the nonce and the key */
    memcpy(SCHWAEMM_192_192_LEFT(s), npub, SCHWAEMM_192_192_NONCE_SIZE);
    memcpy(SCHWAEMM_192_192_RIGHT(s), k, SCHWAEMM_192_192_KEY_SIZE);
    sparkle_384(s, 11);

    /* Process the associated data */
    if (adlen > 0)
        schwaemm_192_192_authenticate(s, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    if (mlen > 0) {
        while (mlen > SCHWAEMM_192_192_RATE) {
            lw_xor_block_2_src
                (block, (unsigned char *)s, m, SCHWAEMM_192_192_RATE);
            schwaemm_192_192_rho(s);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_192_192_RATE);
            sparkle_384(s, 7);
            memcpy(c, block, SCHWAEMM_192_192_RATE);
            c += SCHWAEMM_192_192_RATE;
            m += SCHWAEMM_192_192_RATE;
            mlen -= SCHWAEMM_192_192_RATE;
        }
        if (mlen == SCHWAEMM_192_192_RATE) {
            lw_xor_block_2_src
                (block, (unsigned char *)s, m, SCHWAEMM_192_192_RATE);
            s[11] ^= DOMAIN(0x0B);
            schwaemm_192_192_rho(s);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_192_192_RATE);
            memcpy(c, block, SCHWAEMM_192_192_RATE);
        } else {
            unsigned temp = (unsigned)mlen;
            lw_xor_block_2_src(block, (unsigned char *)s, m, temp);
            s[11] ^= DOMAIN(0x0A);
            schwaemm_192_192_rho(s);
            lw_xor_block((unsigned char *)s, m, temp);
            ((unsigned char *)s)[temp] ^= 0x80;
            memcpy(c, block, temp);
        }
        sparkle_384(s, 11);
        c += mlen;
    }

    /* Generate the authentication tag */
    lw_xor_block_2_src
        (c, SCHWAEMM_192_192_RIGHT(s), k, SCHWAEMM_192_192_TAG_SIZE);
    return 0;
}

int schwaemm_192_192_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    uint32_t s[SPARKLE_384_STATE_SIZE];
    unsigned char *mtemp = m;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < SCHWAEMM_192_192_TAG_SIZE)
        return -1;
    *mlen = clen - SCHWAEMM_192_192_TAG_SIZE;

    /* Initialize the state with the nonce and the key */
    memcpy(SCHWAEMM_192_192_LEFT(s), npub, SCHWAEMM_192_192_NONCE_SIZE);
    memcpy(SCHWAEMM_192_192_RIGHT(s), k, SCHWAEMM_192_192_KEY_SIZE);
    sparkle_384(s, 11);

    /* Process the associated data */
    if (adlen > 0)
        schwaemm_192_192_authenticate(s, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= SCHWAEMM_192_192_TAG_SIZE;
    if (clen > 0) {
        while (clen > SCHWAEMM_192_192_RATE) {
            lw_xor_block_2_src
                (m, (unsigned char *)s, c, SCHWAEMM_192_192_RATE);
            schwaemm_192_192_rho(s);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_192_192_RATE);
            sparkle_384(s, 7);
            c += SCHWAEMM_192_192_RATE;
            m += SCHWAEMM_192_192_RATE;
            clen -= SCHWAEMM_192_192_RATE;
        }
        if (clen == SCHWAEMM_192_192_RATE) {
            lw_xor_block_2_src
                (m, (unsigned char *)s, c, SCHWAEMM_192_192_RATE);
            s[11] ^= DOMAIN(0x0B);
            schwaemm_192_192_rho(s);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_192_192_RATE);
        } else {
            unsigned temp = (unsigned)clen;
            lw_xor_block_2_src(m, (unsigned char *)s, c, temp);
            s[11] ^= DOMAIN(0x0A);
            schwaemm_192_192_rho(s);
            lw_xor_block((unsigned char *)s, m, temp);
            ((unsigned char *)s)[temp] ^= 0x80;
        }
        sparkle_384(s, 11);
        c += clen;
    }

    /* Check the authentication tag */
    lw_xor_block(SCHWAEMM_192_192_RIGHT(s), k, SCHWAEMM_192_192_TAG_SIZE);
    return aead_check_tag
        (mtemp, *mlen, SCHWAEMM_192_192_RIGHT(s), c, SCHWAEMM_192_192_TAG_SIZE);
}

/**
 * \brief Rate at which bytes are processed by Schwaemm128-128.
 */
#define SCHWAEMM_128_128_RATE 16

/**
 * \brief Pointer to the left of the state for Schwaemm128-128.
 */
#define SCHWAEMM_128_128_LEFT(s) ((unsigned char *)&(s[0]))

/**
 * \brief Pointer to the right of the state for Schwaemm128-128.
 */
#define SCHWAEMM_128_128_RIGHT(s) \
    (SCHWAEMM_128_128_LEFT(s) + SCHWAEMM_128_128_RATE)

/**
 * \brief Perform the rho1 and rate whitening steps for Schwaemm128-128.
 *
 * \param s SPARKLE-256 state.
 */
#define schwaemm_128_128_rho(s) \
    do { \
        uint32_t t = s[0]; \
        s[0] = s[2] ^ s[4]; \
        s[2] ^= t   ^ s[6]; \
        t = s[1]; \
        s[1] = s[3] ^ s[5]; \
        s[3] ^= t   ^ s[7]; \
    } while (0)

/**
 * \brief Authenticates the associated data for Schwaemm128-128.
 *
 * \param s SPARKLE-256 state.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data; must be >= 1.
 */
static void schwaemm_128_128_authenticate
    (uint32_t s[SPARKLE_256_STATE_SIZE],
     const unsigned char *ad, size_t adlen)
{
    while (adlen > SCHWAEMM_128_128_RATE) {
        schwaemm_128_128_rho(s);
        lw_xor_block((unsigned char *)s, ad, SCHWAEMM_128_128_RATE);
        sparkle_256(s, 7);
        ad += SCHWAEMM_128_128_RATE;
        adlen -= SCHWAEMM_128_128_RATE;
    }
    if (adlen == SCHWAEMM_128_128_RATE) {
        s[7] ^= DOMAIN(0x05);
        schwaemm_128_128_rho(s);
        lw_xor_block((unsigned char *)s, ad, SCHWAEMM_128_128_RATE);
    } else {
        unsigned temp = (unsigned)adlen;
        s[7] ^= DOMAIN(0x04);
        schwaemm_128_128_rho(s);
        lw_xor_block((unsigned char *)s, ad, temp);
        ((unsigned char *)s)[temp] ^= 0x80;
    }
    sparkle_256(s, 10);
}

int schwaemm_128_128_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    uint32_t s[SPARKLE_256_STATE_SIZE];
    uint8_t block[SCHWAEMM_128_128_RATE];

    /* Set the length of the returned ciphertext */
    *clen = mlen + SCHWAEMM_128_128_TAG_SIZE;

    /* Initialize the state with the nonce and the key */
    memcpy(SCHWAEMM_128_128_LEFT(s), npub, SCHWAEMM_128_128_NONCE_SIZE);
    memcpy(SCHWAEMM_128_128_RIGHT(s), k, SCHWAEMM_128_128_KEY_SIZE);
    sparkle_256(s, 10);

    /* Process the associated data */
    if (adlen > 0)
        schwaemm_128_128_authenticate(s, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    if (mlen > 0) {
        while (mlen > SCHWAEMM_128_128_RATE) {
            lw_xor_block_2_src
                (block, (unsigned char *)s, m, SCHWAEMM_128_128_RATE);
            schwaemm_128_128_rho(s);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_128_128_RATE);
            sparkle_256(s, 7);
            memcpy(c, block, SCHWAEMM_128_128_RATE);
            c += SCHWAEMM_128_128_RATE;
            m += SCHWAEMM_128_128_RATE;
            mlen -= SCHWAEMM_128_128_RATE;
        }
        if (mlen == SCHWAEMM_128_128_RATE) {
            lw_xor_block_2_src
                (block, (unsigned char *)s, m, SCHWAEMM_128_128_RATE);
            s[7] ^= DOMAIN(0x07);
            schwaemm_128_128_rho(s);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_128_128_RATE);
            memcpy(c, block, SCHWAEMM_128_128_RATE);
        } else {
            unsigned temp = (unsigned)mlen;
            lw_xor_block_2_src(block, (unsigned char *)s, m, temp);
            s[7] ^= DOMAIN(0x06);
            schwaemm_128_128_rho(s);
            lw_xor_block((unsigned char *)s, m, temp);
            ((unsigned char *)s)[temp] ^= 0x80;
            memcpy(c, block, temp);
        }
        sparkle_256(s, 10);
        c += mlen;
    }

    /* Generate the authentication tag */
    lw_xor_block_2_src
        (c, SCHWAEMM_128_128_RIGHT(s), k, SCHWAEMM_128_128_TAG_SIZE);
    return 0;
}

int schwaemm_128_128_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    uint32_t s[SPARKLE_256_STATE_SIZE];
    unsigned char *mtemp = m;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < SCHWAEMM_128_128_TAG_SIZE)
        return -1;
    *mlen = clen - SCHWAEMM_128_128_TAG_SIZE;

    /* Initialize the state with the nonce and the key */
    memcpy(SCHWAEMM_128_128_LEFT(s), npub, SCHWAEMM_128_128_NONCE_SIZE);
    memcpy(SCHWAEMM_128_128_RIGHT(s), k, SCHWAEMM_128_128_KEY_SIZE);
    sparkle_256(s, 10);

    /* Process the associated data */
    if (adlen > 0)
        schwaemm_128_128_authenticate(s, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= SCHWAEMM_128_128_TAG_SIZE;
    if (clen > 0) {
        while (clen > SCHWAEMM_128_128_RATE) {
            lw_xor_block_2_src
                (m, (unsigned char *)s, c, SCHWAEMM_128_128_RATE);
            schwaemm_128_128_rho(s);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_128_128_RATE);
            sparkle_256(s, 7);
            c += SCHWAEMM_128_128_RATE;
            m += SCHWAEMM_128_128_RATE;
            clen -= SCHWAEMM_128_128_RATE;
        }
        if (clen == SCHWAEMM_128_128_RATE) {
            lw_xor_block_2_src
                (m, (unsigned char *)s, c, SCHWAEMM_128_128_RATE);
            s[7] ^= DOMAIN(0x07);
            schwaemm_128_128_rho(s);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_128_128_RATE);
        } else {
            unsigned temp = (unsigned)clen;
            lw_xor_block_2_src(m, (unsigned char *)s, c, temp);
            s[7] ^= DOMAIN(0x06);
            schwaemm_128_128_rho(s);
            lw_xor_block((unsigned char *)s, m, temp);
            ((unsigned char *)s)[temp] ^= 0x80;
        }
        sparkle_256(s, 10);
        c += clen;
    }

    /* Check the authentication tag */
    lw_xor_block(SCHWAEMM_128_128_RIGHT(s), k, SCHWAEMM_128_128_TAG_SIZE);
    return aead_check_tag
        (mtemp, *mlen, SCHWAEMM_128_128_RIGHT(s), c, SCHWAEMM_128_128_TAG_SIZE);
}

/**
 * \brief Rate at which bytes are processed by Schwaemm256-256.
 */
#define SCHWAEMM_256_256_RATE 32

/**
 * \brief Pointer to the left of the state for Schwaemm256-256.
 */
#define SCHWAEMM_256_256_LEFT(s) ((unsigned char *)&(s[0]))

/**
 * \brief Pointer to the right of the state for Schwaemm256-256.
 */
#define SCHWAEMM_256_256_RIGHT(s) \
    (SCHWAEMM_256_256_LEFT(s) + SCHWAEMM_256_256_RATE)

/**
 * \brief Perform the rho1 and rate whitening steps for Schwaemm256-256.
 *
 * \param s SPARKLE-512 state.
 */
#define schwaemm_256_256_rho(s) \
    do { \
        uint32_t t = s[0]; \
        s[0] = s[4] ^ s[8]; \
        s[4] ^= t   ^ s[12]; \
        t = s[1]; \
        s[1] = s[5] ^ s[9]; \
        s[5] ^= t   ^ s[13]; \
        t = s[2]; \
        s[2] = s[6] ^ s[10]; \
        s[6] ^= t   ^ s[14]; \
        t = s[3]; \
        s[3] = s[7] ^ s[11]; \
        s[7] ^= t   ^ s[15]; \
    } while (0)

/**
 * \brief Authenticates the associated data for Schwaemm256-256.
 *
 * \param s SPARKLE-512 state.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data; must be >= 1.
 */
static void schwaemm_256_256_authenticate
    (uint32_t s[SPARKLE_512_STATE_SIZE],
     const unsigned char *ad, size_t adlen)
{
    while (adlen > SCHWAEMM_256_256_RATE) {
        schwaemm_256_256_rho(s);
        lw_xor_block((unsigned char *)s, ad, SCHWAEMM_256_256_RATE);
        sparkle_512(s, 8);
        ad += SCHWAEMM_256_256_RATE;
        adlen -= SCHWAEMM_256_256_RATE;
    }
    if (adlen == SCHWAEMM_256_256_RATE) {
        s[15] ^= DOMAIN(0x11);
        schwaemm_256_256_rho(s);
        lw_xor_block((unsigned char *)s, ad, SCHWAEMM_256_256_RATE);
    } else {
        unsigned temp = (unsigned)adlen;
        s[15] ^= DOMAIN(0x10);
        schwaemm_256_256_rho(s);
        lw_xor_block((unsigned char *)s, ad, temp);
        ((unsigned char *)s)[temp] ^= 0x80;
    }
    sparkle_512(s, 12);
}

int schwaemm_256_256_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    uint32_t s[SPARKLE_512_STATE_SIZE];
    uint8_t block[SCHWAEMM_256_256_RATE];

    /* Set the length of the returned ciphertext */
    *clen = mlen + SCHWAEMM_256_256_TAG_SIZE;

    /* Initialize the state with the nonce and the key */
    memcpy(SCHWAEMM_256_256_LEFT(s), npub, SCHWAEMM_256_256_NONCE_SIZE);
    memcpy(SCHWAEMM_256_256_RIGHT(s), k, SCHWAEMM_256_256_KEY_SIZE);
    sparkle_512(s, 12);

    /* Process the associated data */
    if (adlen > 0)
        schwaemm_256_256_authenticate(s, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    if (mlen > 0) {
        while (mlen > SCHWAEMM_256_256_RATE) {
            lw_xor_block_2_src
                (block, (unsigned char *)s, m, SCHWAEMM_256_256_RATE);
            schwaemm_256_256_rho(s);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_256_256_RATE);
            sparkle_512(s, 8);
            memcpy(c, block, SCHWAEMM_256_256_RATE);
            c += SCHWAEMM_256_256_RATE;
            m += SCHWAEMM_256_256_RATE;
            mlen -= SCHWAEMM_256_256_RATE;
        }
        if (mlen == SCHWAEMM_256_256_RATE) {
            lw_xor_block_2_src
                (block, (unsigned char *)s, m, SCHWAEMM_256_256_RATE);
            s[15] ^= DOMAIN(0x13);
            schwaemm_256_256_rho(s);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_256_256_RATE);
            memcpy(c, block, SCHWAEMM_256_256_RATE);
        } else {
            unsigned temp = (unsigned)mlen;
            lw_xor_block_2_src(block, (unsigned char *)s, m, temp);
            s[15] ^= DOMAIN(0x12);
            schwaemm_256_256_rho(s);
            lw_xor_block((unsigned char *)s, m, temp);
            ((unsigned char *)s)[temp] ^= 0x80;
            memcpy(c, block, temp);
        }
        sparkle_512(s, 12);
        c += mlen;
    }

    /* Generate the authentication tag */
    lw_xor_block_2_src
        (c, SCHWAEMM_256_256_RIGHT(s), k, SCHWAEMM_256_256_TAG_SIZE);
    return 0;
}

int schwaemm_256_256_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    uint32_t s[SPARKLE_512_STATE_SIZE];
    unsigned char *mtemp = m;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < SCHWAEMM_256_256_TAG_SIZE)
        return -1;
    *mlen = clen - SCHWAEMM_256_256_TAG_SIZE;

    /* Initialize the state with the nonce and the key */
    memcpy(SCHWAEMM_256_256_LEFT(s), npub, SCHWAEMM_256_256_NONCE_SIZE);
    memcpy(SCHWAEMM_256_256_RIGHT(s), k, SCHWAEMM_256_256_KEY_SIZE);
    sparkle_512(s, 12);

    /* Process the associated data */
    if (adlen > 0)
        schwaemm_256_256_authenticate(s, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= SCHWAEMM_256_256_TAG_SIZE;
    if (clen > 0) {
        while (clen > SCHWAEMM_256_256_RATE) {
            lw_xor_block_2_src
                (m, (unsigned char *)s, c, SCHWAEMM_256_256_RATE);
            schwaemm_256_256_rho(s);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_256_256_RATE);
            sparkle_512(s, 8);
            c += SCHWAEMM_256_256_RATE;
            m += SCHWAEMM_256_256_RATE;
            clen -= SCHWAEMM_256_256_RATE;
        }
        if (clen == SCHWAEMM_256_256_RATE) {
            lw_xor_block_2_src
                (m, (unsigned char *)s, c, SCHWAEMM_256_256_RATE);
            s[15] ^= DOMAIN(0x13);
            schwaemm_256_256_rho(s);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_256_256_RATE);
        } else {
            unsigned temp = (unsigned)clen;
            lw_xor_block_2_src(m, (unsigned char *)s, c, temp);
            s[15] ^= DOMAIN(0x12);
            schwaemm_256_256_rho(s);
            lw_xor_block((unsigned char *)s, m, temp);
            ((unsigned char *)s)[temp] ^= 0x80;
        }
        sparkle_512(s, 12);
        c += clen;
    }

    /* Check the authentication tag */
    lw_xor_block(SCHWAEMM_256_256_RIGHT(s), k, SCHWAEMM_256_256_TAG_SIZE);
    return aead_check_tag
        (mtemp, *mlen, SCHWAEMM_256_256_RIGHT(s), c, SCHWAEMM_256_256_TAG_SIZE);
}
