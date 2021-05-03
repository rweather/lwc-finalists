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

#include "photon-beetle-aead.h"
#include "internal-photon256.h"
#include "internal-util.h"
#include <string.h>

/**
 * \brief Rate of operation for PHOTON-Beetle-AEAD-ENC-128.
 */
#define PHOTON_BEETLE_128_RATE 16

/**
 * \brief Rate of operation for PHOTON-Beetle-AEAD-ENC-32.
 */
#define PHOTON_BEETLE_32_RATE 4

/* Shifts a domain constant from the spec to the correct bit position */
#define DOMAIN(c) ((c) << 5)

/**
 * \brief Processes the associated data for PHOTON-Beetle.
 *
 * \param state PHOTON-256 permutation state.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data, must be non-zero.
 * \param rate Rate of absorption for the data.
 * \param mempty Non-zero if the message is empty.
 */
static void photon_beetle_process_ad
    (photon256_state_t *state,
     const unsigned char *ad, size_t adlen,
     unsigned rate, int mempty)
{
    unsigned temp;

    /* Absorb as many full rate blocks as possible */
    while (adlen > rate) {
        photon256_permute(state);
        lw_xor_block(state->B, ad, rate);
        ad += rate;
        adlen -= rate;
    }

    /* Pad and absorb the last block */
    temp = (unsigned)adlen;
    photon256_permute(state);
    lw_xor_block(state->B, ad, temp);
    if (temp < rate)
        state->B[temp] ^= 0x01; /* padding */

    /* Add the domain constant to finalize associated data processing */
    if (mempty && temp == rate)
        state->B[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(3);
    else if (mempty)
        state->B[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(4);
    else if (temp == rate)
        state->B[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(1);
    else
        state->B[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(2);
}

/**
 * \brief Rotates part of the PHOTON-256 state right by one bit.
 *
 * \param out Output state buffer.
 * \param in Input state buffer, must not overlap with \a out.
 * \param len Length of the state buffer.
 */
static void photon_beetle_rotate1
    (unsigned char *out, const unsigned char *in, unsigned len)
{
    unsigned posn;
    for (posn = 0; posn < (len - 1); ++posn)
        out[posn] = (in[posn] >> 1) | (in[posn + 1] << 7);
    out[len - 1] = (in[len - 1] >> 1) | (in[0] << 7);
}

/**
 * \brief Encrypts a plaintext block with PHOTON-Beetle.
 *
 * \param state PHOTON-256 permutation state.
 * \param c Points to the ciphertext output buffer.
 * \param m Points to the plaintext input buffer.
 * \param mlen Length of the message, must be non-zero.
 * \param rate Rate of absorption for the data.
 * \param adempty Non-zero if the associated data is empty.
 */
static void photon_beetle_encrypt
    (photon256_state_t *state, unsigned char *c,
     const unsigned char *m, size_t mlen,
     unsigned rate, int adempty)
{
    unsigned char shuffle[PHOTON_BEETLE_128_RATE]; /* Block of max rate size */
    unsigned temp;

    /* Process all plaintext blocks except the last */
    while (mlen > rate) {
        photon256_permute(state);
        memcpy(shuffle, state->B + rate / 2, rate / 2);
        photon_beetle_rotate1(shuffle + rate / 2, state->B, rate / 2);
        lw_xor_block(state->B, m, rate);
        lw_xor_block_2_src(c, m, shuffle, rate);
        c += rate;
        m += rate;
        mlen -= rate;
    }

    /* Pad and process the last block */
    temp = (unsigned)mlen;
    photon256_permute(state);
    memcpy(shuffle, state->B + rate / 2, rate / 2);
    photon_beetle_rotate1(shuffle + rate / 2, state->B, rate / 2);
    if (temp == rate) {
        lw_xor_block(state->B, m, rate);
        lw_xor_block_2_src(c, m, shuffle, rate);
    } else {
        lw_xor_block(state->B, m, temp);
        state->B[temp] ^= 0x01; /* padding */
        lw_xor_block_2_src(c, m, shuffle, temp);
    }

    /* Add the domain constant to finalize message processing */
    if (adempty && temp == rate)
        state->B[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(5);
    else if (adempty)
        state->B[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(6);
    else if (temp == rate)
        state->B[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(1);
    else
        state->B[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(2);
}

/**
 * \brief Decrypts a ciphertext block with PHOTON-Beetle.
 *
 * \param state PHOTON-256 permutation state.
 * \param m Points to the plaintext output buffer.
 * \param c Points to the ciphertext input buffer.
 * \param mlen Length of the message, must be non-zero.
 * \param rate Rate of absorption for the data.
 * \param adempty Non-zero if the associated data is empty.
 */
static void photon_beetle_decrypt
    (photon256_state_t *state, unsigned char *m,
     const unsigned char *c, size_t mlen,
     unsigned rate, int adempty)
{
    unsigned char shuffle[PHOTON_BEETLE_128_RATE]; /* Block of max rate size */
    unsigned temp;

    /* Process all plaintext blocks except the last */
    while (mlen > rate) {
        photon256_permute(state);
        memcpy(shuffle, state->B + rate / 2, rate / 2);
        photon_beetle_rotate1(shuffle + rate / 2, state->B, rate / 2);
        lw_xor_block_2_src(m, c, shuffle, rate);
        lw_xor_block(state->B, m, rate);
        c += rate;
        m += rate;
        mlen -= rate;
    }

    /* Pad and process the last block */
    temp = (unsigned)mlen;
    photon256_permute(state);
    memcpy(shuffle, state->B + rate / 2, rate / 2);
    photon_beetle_rotate1(shuffle + rate / 2, state->B, rate / 2);
    if (temp == rate) {
        lw_xor_block_2_src(m, c, shuffle, rate);
        lw_xor_block(state->B, m, rate);
    } else {
        lw_xor_block_2_src(m, c, shuffle, temp);
        lw_xor_block(state->B, m, temp);
        state->B[temp] ^= 0x01; /* padding */
    }

    /* Add the domain constant to finalize message processing */
    if (adempty && temp == rate)
        state->B[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(5);
    else if (adempty)
        state->B[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(6);
    else if (temp == rate)
        state->B[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(1);
    else
        state->B[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(2);
}

int photon_beetle_128_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    photon256_state_t state;

    /* Set the length of the returned ciphertext */
    *clen = mlen + PHOTON_BEETLE_TAG_SIZE;

    /* Initialize the state by concatenating the nonce and the key */
    memcpy(state.B, npub, 16);
    memcpy(state.B + 16, k, 16);

    /* Process the associated data */
    if (adlen > 0) {
        photon_beetle_process_ad
            (&state, ad, adlen, PHOTON_BEETLE_128_RATE, mlen == 0);
    } else if (mlen == 0) {
        state.B[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(1);
    }

    /* Encrypt the plaintext to produce the ciphertext */
    if (mlen > 0) {
        photon_beetle_encrypt
            (&state, c, m, mlen, PHOTON_BEETLE_128_RATE, adlen == 0);
    }

    /* Generate the authentication tag */
    photon256_permute(&state);
    memcpy(c + mlen, state.B, PHOTON_BEETLE_TAG_SIZE);
    return 0;
}

int photon_beetle_128_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    photon256_state_t state;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < PHOTON_BEETLE_TAG_SIZE)
        return -1;
    *mlen = clen - PHOTON_BEETLE_TAG_SIZE;

    /* Initialize the state by concatenating the nonce and the key */
    memcpy(state.B, npub, 16);
    memcpy(state.B + 16, k, 16);

    /* Process the associated data */
    clen -= PHOTON_BEETLE_TAG_SIZE;
    if (adlen > 0) {
        photon_beetle_process_ad
            (&state, ad, adlen, PHOTON_BEETLE_128_RATE, clen == 0);
    } else if (clen == 0) {
        state.B[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(1);
    }

    /* Decrypt the ciphertext to produce the plaintext */
    if (clen > 0) {
        photon_beetle_decrypt
            (&state, m, c, clen, PHOTON_BEETLE_128_RATE, adlen == 0);
    }

    /* Check the authentication tag */
    photon256_permute(&state);
    return aead_check_tag(m, clen, state.B, c + clen, PHOTON_BEETLE_TAG_SIZE);
}

int photon_beetle_32_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    photon256_state_t state;

    /* Set the length of the returned ciphertext */
    *clen = mlen + PHOTON_BEETLE_TAG_SIZE;

    /* Initialize the state by concatenating the nonce and the key */
    memcpy(state.B, npub, 16);
    memcpy(state.B + 16, k, 16);

    /* Process the associated data */
    if (adlen > 0) {
        photon_beetle_process_ad
            (&state, ad, adlen, PHOTON_BEETLE_32_RATE, mlen == 0);
    } else if (mlen == 0) {
        state.B[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(1);
    }

    /* Encrypt the plaintext to produce the ciphertext */
    if (mlen > 0) {
        photon_beetle_encrypt
            (&state, c, m, mlen, PHOTON_BEETLE_32_RATE, adlen == 0);
    }

    /* Generate the authentication tag */
    photon256_permute(&state);
    memcpy(c + mlen, state.B, PHOTON_BEETLE_TAG_SIZE);
    return 0;
}

int photon_beetle_32_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    photon256_state_t state;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < PHOTON_BEETLE_TAG_SIZE)
        return -1;
    *mlen = clen - PHOTON_BEETLE_TAG_SIZE;

    /* Initialize the state by concatenating the nonce and the key */
    memcpy(state.B, npub, 16);
    memcpy(state.B + 16, k, 16);

    /* Process the associated data */
    clen -= PHOTON_BEETLE_TAG_SIZE;
    if (adlen > 0) {
        photon_beetle_process_ad
            (&state, ad, adlen, PHOTON_BEETLE_32_RATE, clen == 0);
    } else if (clen == 0) {
        state.B[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(1);
    }

    /* Decrypt the ciphertext to produce the plaintext */
    if (clen > 0) {
        photon_beetle_decrypt
            (&state, m, c, clen, PHOTON_BEETLE_32_RATE, adlen == 0);
    }

    /* Check the authentication tag */
    photon256_permute(&state);
    return aead_check_tag(m, clen, state.B, c + clen, PHOTON_BEETLE_TAG_SIZE);
}
