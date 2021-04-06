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

#include "elephant-dumbo.h"
#include "internal-spongent.h"
#include <string.h>

aead_cipher_t const dumbo_cipher = {
    "Dumbo",
    DUMBO_KEY_SIZE,
    DUMBO_NONCE_SIZE,
    DUMBO_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    dumbo_aead_encrypt,
    dumbo_aead_decrypt
};

/**
 * \brief Applies the Dumbo LFSR to the mask.
 *
 * \param out The output mask.
 * \param in The input mask.
 */
static void dumbo_lfsr
    (unsigned char out[SPONGENT160_STATE_SIZE],
     const unsigned char in[SPONGENT160_STATE_SIZE])
{
    unsigned char temp = 
        leftRotate3_8(in[0]) ^ (in[3] << 7) ^ (in[13] >> 7);
    unsigned index;
    for (index = 0; index < SPONGENT160_STATE_SIZE - 1; ++index)
        out[index] = in[index + 1];
    out[SPONGENT160_STATE_SIZE - 1] = temp;
}

/**
 * \brief Processes the nonce and associated data for Dumbo.
 *
 * \param state Points to the Spongent-pi[160] state.
 * \param mask Points to the initial mask value.
 * \param next Points to the next mask value.
 * \param tag Points to the ongoing tag that is being computed.
 * \param npub Points to the nonce.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data.
 */
static void dumbo_process_ad
    (spongent160_state_t *state,
     unsigned char mask[SPONGENT160_STATE_SIZE],
     unsigned char next[SPONGENT160_STATE_SIZE],
     unsigned char tag[DUMBO_TAG_SIZE],
     const unsigned char *npub,
     const unsigned char *ad, unsigned long long adlen)
{
    unsigned posn, size;

    /* We need the "previous" and "next" masks in each step.
     * Compare the first such values */
    dumbo_lfsr(next, mask);
    dumbo_lfsr(next, next);

    /* Absorb the nonce into the state */
    lw_xor_block_2_src(state->B, mask, next, SPONGENT160_STATE_SIZE);
    lw_xor_block(state->B, npub, DUMBO_NONCE_SIZE);

    /* Absorb the rest of the associated data */
    posn = DUMBO_NONCE_SIZE;
    while (adlen > 0) {
        size = SPONGENT160_STATE_SIZE - posn;
        if (size <= adlen) {
            /* Process a complete block */
            lw_xor_block(state->B + posn, ad, size);
            spongent160_permute(state);
            lw_xor_block(state->B, mask, DUMBO_TAG_SIZE);
            lw_xor_block(state->B, next, DUMBO_TAG_SIZE);
            lw_xor_block(tag, state->B, DUMBO_TAG_SIZE);
            dumbo_lfsr(mask, mask);
            dumbo_lfsr(next, next);
            lw_xor_block_2_src(state->B, mask, next, SPONGENT160_STATE_SIZE);
            posn = 0;
        } else {
            /* Process the partial block at the end of the associated data */
            size = (unsigned)adlen;
            lw_xor_block(state->B + posn, ad, size);
            posn += size;
        }
        ad += size;
        adlen -= size;
    }

    /* Pad and absorb the final block */
    state->B[posn] ^= 0x01;
    spongent160_permute(state);
    lw_xor_block(state->B, mask, DUMBO_TAG_SIZE);
    lw_xor_block(state->B, next, DUMBO_TAG_SIZE);
    lw_xor_block(tag, state->B, DUMBO_TAG_SIZE);
}

int dumbo_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    spongent160_state_t state;
    unsigned char start[SPONGENT160_STATE_SIZE];
    unsigned char mask[SPONGENT160_STATE_SIZE];
    unsigned char next[SPONGENT160_STATE_SIZE];
    unsigned char tag[DUMBO_TAG_SIZE];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + DUMBO_TAG_SIZE;

    /* Hash the key and generate the initial mask */
    memcpy(state.B, k, DUMBO_KEY_SIZE);
    memset(state.B + DUMBO_KEY_SIZE, 0, sizeof(state.B) - DUMBO_KEY_SIZE);
    spongent160_permute(&state);
    memcpy(mask, state.B, DUMBO_KEY_SIZE);
    memset(mask + DUMBO_KEY_SIZE, 0, sizeof(mask) - DUMBO_KEY_SIZE);
    memcpy(start, mask, sizeof(mask));

    /* Tag starts at zero */
    memset(tag, 0, sizeof(tag));

    /* Authenticate the nonce and the associated data */
    dumbo_process_ad(&state, mask, next, tag, npub, ad, adlen);

    /* Reset back to the starting mask for the encryption phase */
    memcpy(mask, start, sizeof(mask));

    /* Encrypt and authenticate the payload */
    while (mlen >= SPONGENT160_STATE_SIZE) {
        /* Encrypt using the current mask */
        memcpy(state.B, mask, SPONGENT160_STATE_SIZE);
        lw_xor_block(state.B, npub, DUMBO_NONCE_SIZE);
        spongent160_permute(&state);
        lw_xor_block(state.B, m, SPONGENT160_STATE_SIZE);
        lw_xor_block(state.B, mask, SPONGENT160_STATE_SIZE);
        memcpy(c, state.B, SPONGENT160_STATE_SIZE);

        /* Authenticate using the next mask */
        dumbo_lfsr(next, mask);
        lw_xor_block(state.B, mask, SPONGENT160_STATE_SIZE);
        lw_xor_block(state.B, next, SPONGENT160_STATE_SIZE);
        spongent160_permute(&state);
        lw_xor_block(state.B, mask, DUMBO_TAG_SIZE);
        lw_xor_block(state.B, next, DUMBO_TAG_SIZE);
        lw_xor_block(tag, state.B, DUMBO_TAG_SIZE);

        /* Advance to the next block */
        memcpy(mask, next, SPONGENT160_STATE_SIZE);
        c += SPONGENT160_STATE_SIZE;
        m += SPONGENT160_STATE_SIZE;
        mlen -= SPONGENT160_STATE_SIZE;
    }
    if (mlen > 0) {
        /* Encrypt the last block using the current mask */
        unsigned temp = (unsigned)mlen;
        memcpy(state.B, mask, SPONGENT160_STATE_SIZE);
        lw_xor_block(state.B, npub, DUMBO_NONCE_SIZE);
        spongent160_permute(&state);
        lw_xor_block(state.B, m, temp);
        lw_xor_block(state.B, mask, SPONGENT160_STATE_SIZE);
        memcpy(c, state.B, temp);

        /* Authenticate the last block using the next mask */
        dumbo_lfsr(next, mask);
        state.B[temp] = 0x01;
        memset(state.B + temp + 1, 0, SPONGENT160_STATE_SIZE - temp - 1);
        lw_xor_block(state.B, mask, SPONGENT160_STATE_SIZE);
        lw_xor_block(state.B, next, SPONGENT160_STATE_SIZE);
        spongent160_permute(&state);
        lw_xor_block(state.B, mask, DUMBO_TAG_SIZE);
        lw_xor_block(state.B, next, DUMBO_TAG_SIZE);
        lw_xor_block(tag, state.B, DUMBO_TAG_SIZE);
        c += temp;
    } else if (*clen != DUMBO_TAG_SIZE) {
        /* Pad and authenticate when the last block is aligned */
        dumbo_lfsr(next, mask);
        lw_xor_block_2_src(state.B, mask, next, SPONGENT160_STATE_SIZE);
        state.B[0] ^= 0x01;
        spongent160_permute(&state);
        lw_xor_block(state.B, mask, DUMBO_TAG_SIZE);
        lw_xor_block(state.B, next, DUMBO_TAG_SIZE);
        lw_xor_block(tag, state.B, DUMBO_TAG_SIZE);
    }

    /* Generate the authentication tag */
    memcpy(c, tag, DUMBO_TAG_SIZE);
    return 0;
}

int dumbo_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    spongent160_state_t state;
    unsigned char *mtemp = m;
    unsigned char start[SPONGENT160_STATE_SIZE];
    unsigned char mask[SPONGENT160_STATE_SIZE];
    unsigned char next[SPONGENT160_STATE_SIZE];
    unsigned char tag[DUMBO_TAG_SIZE];
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < DUMBO_TAG_SIZE)
        return -1;
    *mlen = clen - DUMBO_TAG_SIZE;

    /* Hash the key and generate the initial mask */
    memcpy(state.B, k, DUMBO_KEY_SIZE);
    memset(state.B + DUMBO_KEY_SIZE, 0, sizeof(state.B) - DUMBO_KEY_SIZE);
    spongent160_permute(&state);
    memcpy(mask, state.B, DUMBO_KEY_SIZE);
    memset(mask + DUMBO_KEY_SIZE, 0, sizeof(mask) - DUMBO_KEY_SIZE);
    memcpy(start, mask, sizeof(mask));

    /* Tag starts at zero */
    memset(tag, 0, sizeof(tag));

    /* Authenticate the nonce and the associated data */
    dumbo_process_ad(&state, mask, next, tag, npub, ad, adlen);

    /* Reset back to the starting mask for the encryption phase */
    memcpy(mask, start, sizeof(mask));

    /* Decrypt and authenticate the payload */
    clen -= DUMBO_TAG_SIZE;
    while (clen >= SPONGENT160_STATE_SIZE) {
        /* Authenticate using the next mask */
        dumbo_lfsr(next, mask);
        lw_xor_block_2_src(state.B, mask, next, SPONGENT160_STATE_SIZE);
        lw_xor_block(state.B, c, SPONGENT160_STATE_SIZE);
        spongent160_permute(&state);
        lw_xor_block(state.B, mask, DUMBO_TAG_SIZE);
        lw_xor_block(state.B, next, DUMBO_TAG_SIZE);
        lw_xor_block(tag, state.B, DUMBO_TAG_SIZE);

        /* Decrypt using the current mask */
        memcpy(state.B, mask, SPONGENT160_STATE_SIZE);
        lw_xor_block(state.B, npub, DUMBO_NONCE_SIZE);
        spongent160_permute(&state);
        lw_xor_block(state.B, mask, SPONGENT160_STATE_SIZE);
        lw_xor_block_2_src(m, state.B, c, SPONGENT160_STATE_SIZE);

        /* Advance to the next block */
        memcpy(mask, next, SPONGENT160_STATE_SIZE);
        c += SPONGENT160_STATE_SIZE;
        m += SPONGENT160_STATE_SIZE;
        clen -= SPONGENT160_STATE_SIZE;
    }
    if (clen > 0) {
        /* Authenticate the last block using the next mask */
        unsigned temp = (unsigned)clen;
        dumbo_lfsr(next, mask);
        lw_xor_block_2_src(state.B, mask, next, SPONGENT160_STATE_SIZE);
        lw_xor_block(state.B, c, temp);
        state.B[temp] ^= 0x01;
        spongent160_permute(&state);
        lw_xor_block(state.B, mask, DUMBO_TAG_SIZE);
        lw_xor_block(state.B, next, DUMBO_TAG_SIZE);
        lw_xor_block(tag, state.B, DUMBO_TAG_SIZE);

        /* Decrypt the last block using the current mask */
        memcpy(state.B, mask, SPONGENT160_STATE_SIZE);
        lw_xor_block(state.B, npub, DUMBO_NONCE_SIZE);
        spongent160_permute(&state);
        lw_xor_block(state.B, mask, temp);
        lw_xor_block_2_src(m, state.B, c, temp);
        c += temp;
    } else if (*mlen != 0) {
        /* Pad and authenticate when the last block is aligned */
        dumbo_lfsr(next, mask);
        lw_xor_block_2_src(state.B, mask, next, SPONGENT160_STATE_SIZE);
        state.B[0] ^= 0x01;
        spongent160_permute(&state);
        lw_xor_block(state.B, mask, DUMBO_TAG_SIZE);
        lw_xor_block(state.B, next, DUMBO_TAG_SIZE);
        lw_xor_block(tag, state.B, DUMBO_TAG_SIZE);
    }

    /* Check the authentication tag */
    return aead_check_tag(mtemp, *mlen, tag, c, DUMBO_TAG_SIZE);
}
