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

/*
 * The contents of this header file expand out to the full implementation of
 * Elephant for a specific underlying permutation.  We expect a number of
 * macros to be defined before this file is included to configure the
 * underlying Elephant variant:
 *
 * ELEPHANT_ALG_NAME    Name of the Elephant algorithm; e.g. dumbo
 * ELEPHANT_STATE_SIZE  Size of the permutation state.
 * ELEPHANT_STATE       Permutation state type; e.g. keccakp_200_state_t
 * ELEPHANT_KEY_SIZE    Size of the key
 * ELEPHANT_NONCE_SIZE  Size of the nonce
 * ELEPHANT_TAG_SIZE    Size of the tag
 * ELEPHANT_LFSR        Name of the LFSR function; e.g. dumbo_lfsr
 * ELEPHANT_PERMUTE     Name of the permutation function
 */
#if defined(ELEPHANT_ALG_NAME)

#define ELEPHANT_CONCAT_INNER(name,suffix) name##suffix
#define ELEPHANT_CONCAT(name,suffix) ELEPHANT_CONCAT_INNER(name,suffix)

/**
 * \brief Processes the nonce and associated data for Elephant.
 *
 * \param state Points to the permutation state.
 * \param mask Points to the initial mask value.
 * \param next Points to the next mask value.
 * \param tag Points to the ongoing tag that is being computed.
 * \param npub Points to the nonce.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data.
 */
static void ELEPHANT_CONCAT(ELEPHANT_ALG_NAME,_process_ad)
    (ELEPHANT_STATE *state,
     unsigned char mask[ELEPHANT_STATE_SIZE],
     unsigned char next[ELEPHANT_STATE_SIZE],
     unsigned char tag[ELEPHANT_TAG_SIZE],
     const unsigned char *npub,
     const unsigned char *ad, size_t adlen)
{
    unsigned posn, size;

    /* We need the "previous" and "next" masks in each step.
     * Compare the first such values */
    ELEPHANT_LFSR(next, mask);
    ELEPHANT_LFSR(next, next);

    /* Absorb the nonce into the state */
    lw_xor_block_2_src(state->B, mask, next, ELEPHANT_STATE_SIZE);
    lw_xor_block(state->B, npub, ELEPHANT_NONCE_SIZE);

    /* Absorb the rest of the associated data */
    posn = ELEPHANT_NONCE_SIZE;
    while (adlen > 0) {
        size = ELEPHANT_STATE_SIZE - posn;
        if (size <= adlen) {
            /* Process a complete block */
            lw_xor_block(state->B + posn, ad, size);
            ELEPHANT_PERMUTE(state);
            lw_xor_block(state->B, mask, ELEPHANT_TAG_SIZE);
            lw_xor_block(state->B, next, ELEPHANT_TAG_SIZE);
            lw_xor_block(tag, state->B, ELEPHANT_TAG_SIZE);
            ELEPHANT_LFSR(mask, mask);
            ELEPHANT_LFSR(next, next);
            lw_xor_block_2_src(state->B, mask, next, ELEPHANT_STATE_SIZE);
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
    ELEPHANT_PERMUTE(state);
    lw_xor_block(state->B, mask, ELEPHANT_TAG_SIZE);
    lw_xor_block(state->B, next, ELEPHANT_TAG_SIZE);
    lw_xor_block(tag, state->B, ELEPHANT_TAG_SIZE);
}

int ELEPHANT_CONCAT(ELEPHANT_ALG_NAME,_aead_encrypt)
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ELEPHANT_STATE state;
    unsigned char start[ELEPHANT_STATE_SIZE];
    unsigned char mask[ELEPHANT_STATE_SIZE];
    unsigned char next[ELEPHANT_STATE_SIZE];
    unsigned char tag[ELEPHANT_TAG_SIZE];

    /* Set the length of the returned ciphertext */
    *clen = mlen + ELEPHANT_TAG_SIZE;

    /* Hash the key and generate the initial mask */
    memcpy(state.B, k, ELEPHANT_KEY_SIZE);
    memset(state.B + ELEPHANT_KEY_SIZE, 0, sizeof(state.B) - ELEPHANT_KEY_SIZE);
    ELEPHANT_PERMUTE(&state);
    memcpy(mask, state.B, ELEPHANT_KEY_SIZE);
    memset(mask + ELEPHANT_KEY_SIZE, 0, sizeof(mask) - ELEPHANT_KEY_SIZE);
    memcpy(start, mask, sizeof(mask));

    /* Tag starts at zero */
    memset(tag, 0, sizeof(tag));

    /* Authenticate the nonce and the associated data */
    ELEPHANT_CONCAT(ELEPHANT_ALG_NAME,_process_ad)
        (&state, mask, next, tag, npub, ad, adlen);

    /* Reset back to the starting mask for the encryption phase */
    memcpy(mask, start, sizeof(mask));

    /* Encrypt and authenticate the payload */
    while (mlen >= ELEPHANT_STATE_SIZE) {
        /* Encrypt using the current mask */
        memcpy(state.B, mask, ELEPHANT_STATE_SIZE);
        lw_xor_block(state.B, npub, ELEPHANT_NONCE_SIZE);
        ELEPHANT_PERMUTE(&state);
        lw_xor_block(state.B, m, ELEPHANT_STATE_SIZE);
        lw_xor_block(state.B, mask, ELEPHANT_STATE_SIZE);
        memcpy(c, state.B, ELEPHANT_STATE_SIZE);

        /* Authenticate using the next mask */
        ELEPHANT_LFSR(next, mask);
        lw_xor_block(state.B, mask, ELEPHANT_STATE_SIZE);
        lw_xor_block(state.B, next, ELEPHANT_STATE_SIZE);
        ELEPHANT_PERMUTE(&state);
        lw_xor_block(state.B, mask, ELEPHANT_TAG_SIZE);
        lw_xor_block(state.B, next, ELEPHANT_TAG_SIZE);
        lw_xor_block(tag, state.B, ELEPHANT_TAG_SIZE);

        /* Advance to the next block */
        memcpy(mask, next, ELEPHANT_STATE_SIZE);
        c += ELEPHANT_STATE_SIZE;
        m += ELEPHANT_STATE_SIZE;
        mlen -= ELEPHANT_STATE_SIZE;
    }
    if (mlen > 0) {
        /* Encrypt the last block using the current mask */
        unsigned temp = (unsigned)mlen;
        memcpy(state.B, mask, ELEPHANT_STATE_SIZE);
        lw_xor_block(state.B, npub, ELEPHANT_NONCE_SIZE);
        ELEPHANT_PERMUTE(&state);
        lw_xor_block(state.B, m, temp);
        lw_xor_block(state.B, mask, ELEPHANT_STATE_SIZE);
        memcpy(c, state.B, temp);

        /* Authenticate the last block using the next mask */
        ELEPHANT_LFSR(next, mask);
        state.B[temp] = 0x01;
        memset(state.B + temp + 1, 0, ELEPHANT_STATE_SIZE - temp - 1);
        lw_xor_block(state.B, mask, ELEPHANT_STATE_SIZE);
        lw_xor_block(state.B, next, ELEPHANT_STATE_SIZE);
        ELEPHANT_PERMUTE(&state);
        lw_xor_block(state.B, mask, ELEPHANT_TAG_SIZE);
        lw_xor_block(state.B, next, ELEPHANT_TAG_SIZE);
        lw_xor_block(tag, state.B, ELEPHANT_TAG_SIZE);
        c += temp;
    } else if (*clen != ELEPHANT_TAG_SIZE) {
        /* Pad and authenticate when the last block is aligned */
        ELEPHANT_LFSR(next, mask);
        lw_xor_block_2_src(state.B, mask, next, ELEPHANT_STATE_SIZE);
        state.B[0] ^= 0x01;
        ELEPHANT_PERMUTE(&state);
        lw_xor_block(state.B, mask, ELEPHANT_TAG_SIZE);
        lw_xor_block(state.B, next, ELEPHANT_TAG_SIZE);
        lw_xor_block(tag, state.B, ELEPHANT_TAG_SIZE);
    }

    /* Generate the authentication tag */
    memcpy(c, tag, ELEPHANT_TAG_SIZE);
    return 0;
}

int ELEPHANT_CONCAT(ELEPHANT_ALG_NAME,_aead_decrypt)
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ELEPHANT_STATE state;
    unsigned char *mtemp = m;
    unsigned char start[ELEPHANT_STATE_SIZE];
    unsigned char mask[ELEPHANT_STATE_SIZE];
    unsigned char next[ELEPHANT_STATE_SIZE];
    unsigned char tag[ELEPHANT_TAG_SIZE];

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < ELEPHANT_TAG_SIZE)
        return -1;
    *mlen = clen - ELEPHANT_TAG_SIZE;

    /* Hash the key and generate the initial mask */
    memcpy(state.B, k, ELEPHANT_KEY_SIZE);
    memset(state.B + ELEPHANT_KEY_SIZE, 0, sizeof(state.B) - ELEPHANT_KEY_SIZE);
    ELEPHANT_PERMUTE(&state);
    memcpy(mask, state.B, ELEPHANT_KEY_SIZE);
    memset(mask + ELEPHANT_KEY_SIZE, 0, sizeof(mask) - ELEPHANT_KEY_SIZE);
    memcpy(start, mask, sizeof(mask));

    /* Tag starts at zero */
    memset(tag, 0, sizeof(tag));

    /* Authenticate the nonce and the associated data */
    ELEPHANT_CONCAT(ELEPHANT_ALG_NAME,_process_ad)
        (&state, mask, next, tag, npub, ad, adlen);

    /* Reset back to the starting mask for the encryption phase */
    memcpy(mask, start, sizeof(mask));

    /* Decrypt and authenticate the payload */
    clen -= ELEPHANT_TAG_SIZE;
    while (clen >= ELEPHANT_STATE_SIZE) {
        /* Authenticate using the next mask */
        ELEPHANT_LFSR(next, mask);
        lw_xor_block_2_src(state.B, mask, next, ELEPHANT_STATE_SIZE);
        lw_xor_block(state.B, c, ELEPHANT_STATE_SIZE);
        ELEPHANT_PERMUTE(&state);
        lw_xor_block(state.B, mask, ELEPHANT_TAG_SIZE);
        lw_xor_block(state.B, next, ELEPHANT_TAG_SIZE);
        lw_xor_block(tag, state.B, ELEPHANT_TAG_SIZE);

        /* Decrypt using the current mask */
        memcpy(state.B, mask, ELEPHANT_STATE_SIZE);
        lw_xor_block(state.B, npub, ELEPHANT_NONCE_SIZE);
        ELEPHANT_PERMUTE(&state);
        lw_xor_block(state.B, mask, ELEPHANT_STATE_SIZE);
        lw_xor_block_2_src(m, state.B, c, ELEPHANT_STATE_SIZE);

        /* Advance to the next block */
        memcpy(mask, next, ELEPHANT_STATE_SIZE);
        c += ELEPHANT_STATE_SIZE;
        m += ELEPHANT_STATE_SIZE;
        clen -= ELEPHANT_STATE_SIZE;
    }
    if (clen > 0) {
        /* Authenticate the last block using the next mask */
        unsigned temp = (unsigned)clen;
        ELEPHANT_LFSR(next, mask);
        lw_xor_block_2_src(state.B, mask, next, ELEPHANT_STATE_SIZE);
        lw_xor_block(state.B, c, temp);
        state.B[temp] ^= 0x01;
        ELEPHANT_PERMUTE(&state);
        lw_xor_block(state.B, mask, ELEPHANT_TAG_SIZE);
        lw_xor_block(state.B, next, ELEPHANT_TAG_SIZE);
        lw_xor_block(tag, state.B, ELEPHANT_TAG_SIZE);

        /* Decrypt the last block using the current mask */
        memcpy(state.B, mask, ELEPHANT_STATE_SIZE);
        lw_xor_block(state.B, npub, ELEPHANT_NONCE_SIZE);
        ELEPHANT_PERMUTE(&state);
        lw_xor_block(state.B, mask, temp);
        lw_xor_block_2_src(m, state.B, c, temp);
        c += temp;
    } else if (*mlen != 0) {
        /* Pad and authenticate when the last block is aligned */
        ELEPHANT_LFSR(next, mask);
        lw_xor_block_2_src(state.B, mask, next, ELEPHANT_STATE_SIZE);
        state.B[0] ^= 0x01;
        ELEPHANT_PERMUTE(&state);
        lw_xor_block(state.B, mask, ELEPHANT_TAG_SIZE);
        lw_xor_block(state.B, next, ELEPHANT_TAG_SIZE);
        lw_xor_block(tag, state.B, ELEPHANT_TAG_SIZE);
    }

    /* Check the authentication tag */
    return aead_check_tag(mtemp, *mlen, tag, c, ELEPHANT_TAG_SIZE);
}

#endif /* ELEPHANT_ALG_NAME */

/* Now undefine everything so that we can include this file again for
 * another variant on the Elephant algorithm */
#undef ELEPHANT_ALG_NAME
#undef ELEPHANT_STATE_SIZE
#undef ELEPHANT_STATE
#undef ELEPHANT_KEY_SIZE
#undef ELEPHANT_NONCE_SIZE
#undef ELEPHANT_TAG_SIZE
#undef ELEPHANT_LFSR
#undef ELEPHANT_PERMUTE
#undef ELEPHANT_CONCAT
#undef ELEPHANT_CONCAT_INNER
