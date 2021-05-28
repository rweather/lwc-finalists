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

#include "xoodyak-masked.h"
#include "internal-xoodoo.h"
#include "internal-xoodoo-m.h"
#include <string.h>

/**
 * \brief Rate for absorbing data into the sponge state.
 */
#define XOODYAK_MASKED_ABSORB_RATE 44

/**
 * \brief Rate for squeezing data out of the sponge.
 */
#define XOODYAK_MASKED_SQUEEZE_RATE 24

#if AEAD_MASKING_KEY_ONLY

/**
 * \brief Initializes the Xoodyak state in masked mode.
 *
 * \param state The state after the key and nonce have been absorbed.
 * \param k Points to the key.
 * \param npub Points to the nonce.
 * \param ad Points to the associated data to be absorbed.
 * \param len Length of the associated data to be absorbed.
 */
static void xoodyak_init_masked
    (xoodoo_state_t *state, const unsigned char *k,
     const unsigned char *npub, const unsigned char *ad, size_t len)
{
    mask_uint32_t mstate[12];
    unsigned char padded[48];
    uint32_t domain = 0x03000000U;
    unsigned temp;

    /* Mask the key and nonce to initialize the state */
    aead_random_init();
    mask_input(mstate[0], le_load_word32(k));
    mask_input(mstate[1], le_load_word32(k + 4));
    mask_input(mstate[2], le_load_word32(k + 8));
    mask_input(mstate[3], le_load_word32(k + 12));
    mask_input(mstate[4], le_load_word32(npub));
    mask_input(mstate[5], le_load_word32(npub + 4));
    mask_input(mstate[6], le_load_word32(npub + 8));
    mask_input(mstate[7], le_load_word32(npub + 12));
    mask_input(mstate[8], 0x00000110U); /* Nonce length and padding */
    for (temp = 9; temp < 11; ++temp)
        mask_input(mstate[temp], 0);
    mask_input(mstate[11], 0x02000000U); /* Domain separation */

    /* Absorb the associated data in masked form */
    while (len > XOODYAK_MASKED_ABSORB_RATE) {
        xoodoo_permute_masked(mstate);
        for (temp = 0; temp < 11; ++temp)
            mask_xor_const(mstate[temp], le_load_word32(ad + temp * 4));
        mask_xor_const(mstate[11], domain | 0x01); /* Padding and domain */
        ad += XOODYAK_MASKED_ABSORB_RATE;
        len -= XOODYAK_MASKED_ABSORB_RATE;
        domain = 0;
    }
    xoodoo_permute_masked(mstate);
    memcpy(padded, ad, len);
    padded[len] = 0x01; /* Padding */
    memset(padded + len + 1, 0, sizeof(padded) - (len + 2));
    padded[sizeof(padded) - 1] = (unsigned char)(domain >> 24);
    for (temp = 0; temp < 12; ++temp)
        mask_xor_const(mstate[temp], le_load_word32(padded + temp * 4));

    /* Convert the state into unmasked form */
    xoodoo_unmask(state->W, mstate);
}

int xoodyak_masked_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    xoodoo_state_t state;
    uint8_t domain;
    unsigned temp;

    /* Set the length of the returned ciphertext */
    *clen = mlen + XOODYAK_MASKED_TAG_SIZE;

    /* Initialize the state with the key, nonce, and associated data */
    xoodyak_init_masked(&state, k, npub, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    domain = 0x80;
    while (mlen > XOODYAK_MASKED_SQUEEZE_RATE) {
        state.B[sizeof(state.B) - 1] ^= domain;
        xoodoo_permute(&state);
        lw_xor_block_2_dest(c, state.B, m, XOODYAK_MASKED_SQUEEZE_RATE);
        state.B[XOODYAK_MASKED_SQUEEZE_RATE] ^= 0x01; /* Padding */
        c += XOODYAK_MASKED_SQUEEZE_RATE;
        m += XOODYAK_MASKED_SQUEEZE_RATE;
        mlen -= XOODYAK_MASKED_SQUEEZE_RATE;
        domain = 0;
    }
    state.B[sizeof(state.B) - 1] ^= domain;
    xoodoo_permute(&state);
    temp = (unsigned)mlen;
    lw_xor_block_2_dest(c, state.B, m, temp);
    state.B[temp] ^= 0x01; /* Padding */
    c += temp;

    /* Generate the authentication tag */
    state.B[sizeof(state.B) - 1] ^= 0x40; /* Domain separation */
    xoodoo_permute(&state);
    memcpy(c, state.B, XOODYAK_MASKED_TAG_SIZE);
    aead_random_finish();
    return 0;
}

int xoodyak_masked_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    xoodoo_state_t state;
    uint8_t domain;
    unsigned temp;
    unsigned char *mtemp = m;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < XOODYAK_MASKED_TAG_SIZE)
        return -1;
    *mlen = clen - XOODYAK_MASKED_TAG_SIZE;

    /* Initialize the state with the key, nonce, and associated data */
    xoodyak_init_masked(&state, k, npub, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    domain = 0x80;
    clen -= XOODYAK_MASKED_TAG_SIZE;
    while (clen > XOODYAK_MASKED_SQUEEZE_RATE) {
        state.B[sizeof(state.B) - 1] ^= domain;
        xoodoo_permute(&state);
        lw_xor_block_swap(m, state.B, c, XOODYAK_MASKED_SQUEEZE_RATE);
        state.B[XOODYAK_MASKED_SQUEEZE_RATE] ^= 0x01; /* Padding */
        c += XOODYAK_MASKED_SQUEEZE_RATE;
        m += XOODYAK_MASKED_SQUEEZE_RATE;
        clen -= XOODYAK_MASKED_SQUEEZE_RATE;
        domain = 0;
    }
    state.B[sizeof(state.B) - 1] ^= domain;
    xoodoo_permute(&state);
    temp = (unsigned)clen;
    lw_xor_block_swap(m, state.B, c, temp);
    state.B[temp] ^= 0x01; /* Padding */
    c += temp;

    /* Check the authentication tag */
    state.B[sizeof(state.B) - 1] ^= 0x40; /* Domain separation */
    xoodoo_permute(&state);
    aead_random_finish();
    return aead_check_tag(mtemp, *mlen, state.B, c, XOODYAK_MASKED_TAG_SIZE);
}

#else /* !AEAD_MASKING_KEY_ONLY */

/**
 * \brief Initializes the Xoodyak state in masked mode.
 *
 * \param state The state after the key and nonce have been absorbed.
 * \param k Points to the key.
 * \param npub Points to the nonce.
 */
static void xoodyak_init_masked
    (mask_uint32_t state[12], const unsigned char *k,
     const unsigned char *npub)
{
    int index;

    /* Mask the key and nonce to initialize the state */
    aead_random_init();
    mask_input(state[0], le_load_word32(k));
    mask_input(state[1], le_load_word32(k + 4));
    mask_input(state[2], le_load_word32(k + 8));
    mask_input(state[3], le_load_word32(k + 12));
    mask_input(state[4], le_load_word32(npub));
    mask_input(state[5], le_load_word32(npub + 4));
    mask_input(state[6], le_load_word32(npub + 8));
    mask_input(state[7], le_load_word32(npub + 12));
    mask_input(state[8], 0x00000110U); /* Nonce length and padding */
    for (index = 9; index < 11; ++index)
        mask_input(state[index], 0);
    mask_input(state[11], 0x02000000U); /* Domain separation */
}

/**
 * \brief Absorbs data into the Xoodoo permutation state.
 *
 * \param state Xoodoo permutation state.
 * \param data Points to the data to be absorbed.
 * \param len Length of the data to be absorbed.
 */
static void xoodyak_absorb_masked
    (mask_uint32_t state[12], const unsigned char *data, size_t len)
{
    unsigned char padded[48];
    uint32_t domain = 0x03000000U;
    unsigned temp;
    while (len > XOODYAK_MASKED_ABSORB_RATE) {
        xoodoo_permute_masked(state);
        for (temp = 0; temp < 11; ++temp)
            mask_xor_const(state[temp], le_load_word32(data + temp * 4));
        mask_xor_const(state[11], domain | 0x01); /* Padding and domain */
        data += XOODYAK_MASKED_ABSORB_RATE;
        len -= XOODYAK_MASKED_ABSORB_RATE;
        domain = 0;
    }
    xoodoo_permute_masked(state);
    temp = (unsigned)len;
    memcpy(padded, data, temp);
    padded[temp] = 0x01; /* Padding */
    memset(padded + temp + 1, 0, sizeof(padded) - (temp + 2));
    padded[sizeof(padded) - 1] = (unsigned char)(domain >> 24);
    for (temp = 0; temp < 12; ++temp)
        mask_xor_const(state[temp], le_load_word32(padded + temp * 4));
}

int xoodyak_masked_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    mask_uint32_t state[12];
    uint32_t domain;
    unsigned temp;

    /* Set the length of the returned ciphertext */
    *clen = mlen + XOODYAK_MASKED_TAG_SIZE;

    /* Initialize the state with the key and nonce */
    xoodyak_init_masked(state, k, npub);

    /* Absorb the associated data */
    xoodyak_absorb_masked(state, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    domain = 0x80000000U;
    while (mlen > XOODYAK_MASKED_SQUEEZE_RATE) {
        mask_xor_const(state[11], domain);
        xoodoo_permute_masked(state);
        for (temp = 0; temp < 6; ++temp) {
            mask_xor_const(state[temp], le_load_word32(m + temp * 4));
            le_store_word32(c + temp * 4, mask_output(state[temp]));
        }
        mask_xor_const(state[6], 0x01); /* Padding */
        c += XOODYAK_MASKED_SQUEEZE_RATE;
        m += XOODYAK_MASKED_SQUEEZE_RATE;
        mlen -= XOODYAK_MASKED_SQUEEZE_RATE;
        domain = 0;
    }
    mask_xor_const(state[11], domain);
    xoodoo_permute_masked(state);
    temp = 0;
    while (mlen >= 4) {
        mask_xor_const(state[temp], le_load_word32(m));
        le_store_word32(c, mask_output(state[temp]));
        c += 4;
        m += 4;
        mlen -= 4;
        ++temp;
    }
    if (mlen == 0) {
        mask_xor_const(state[temp], 0x01); /* Padding */
    } else if (mlen == 1) {
        mask_xor_const(state[temp], m[0]);
        c[0] = (unsigned char)(mask_output(state[temp]));
        mask_xor_const(state[temp], 0x0100); /* Padding */
        ++c;
    } else if (mlen == 2) {
        mask_xor_const(state[temp], le_load_word16(m));
        le_store_word16(c, mask_output(state[temp]));
        mask_xor_const(state[temp], 0x010000); /* Padding */
        c += 2;
    } else {
        domain = le_load_word16(m) | (((uint32_t)(m[2])) << 16);
        mask_xor_const(state[temp], domain);
        domain = mask_output(state[temp]);
        c[0] = (unsigned char)domain;
        c[1] = (unsigned char)(domain >> 8);
        c[2] = (unsigned char)(domain >> 16);
        mask_xor_const(state[temp], 0x01000000); /* Padding */
        c += 3;
    }

    /* Generate the authentication tag */
    mask_xor_const(state[11], 0x40000000U); /* Domain separation */
    xoodoo_permute_masked(state);
    le_store_word32(c,      mask_output(state[0]));
    le_store_word32(c + 4,  mask_output(state[1]));
    le_store_word32(c + 8,  mask_output(state[2]));
    le_store_word32(c + 12, mask_output(state[3]));
    aead_random_finish();
    return 0;
}

int xoodyak_masked_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    mask_uint32_t state[12];
    unsigned char tag[XOODYAK_MASKED_TAG_SIZE];
    uint32_t domain, mword;
    unsigned temp;
    unsigned char *mtemp = m;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < XOODYAK_MASKED_TAG_SIZE)
        return -1;
    *mlen = clen - XOODYAK_MASKED_TAG_SIZE;

    /* Initialize the state with the key and nonce */
    xoodyak_init_masked(state, k, npub);

    /* Absorb the associated data */
    xoodyak_absorb_masked(state, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    domain = 0x80000000U;
    clen -= XOODYAK_MASKED_TAG_SIZE;
    while (clen > XOODYAK_MASKED_SQUEEZE_RATE) {
        mask_xor_const(state[11], domain);
        xoodoo_permute_masked(state);
        for (temp = 0; temp < 6; ++temp) {
            mword = mask_output(state[temp]) ^ le_load_word32(c + temp * 4);
            mask_xor_const(state[temp], mword);
            le_store_word32(m + temp * 4, mword);
        }
        mask_xor_const(state[6], 0x01); /* Padding */
        c += XOODYAK_MASKED_SQUEEZE_RATE;
        m += XOODYAK_MASKED_SQUEEZE_RATE;
        clen -= XOODYAK_MASKED_SQUEEZE_RATE;
        domain = 0;
    }
    mask_xor_const(state[11], domain);
    xoodoo_permute_masked(state);
    temp = 0;
    while (clen >= 4) {
        mword = mask_output(state[temp]) ^ le_load_word32(c);
        mask_xor_const(state[temp], mword);
        le_store_word32(m, mword);
        c += 4;
        m += 4;
        clen -= 4;
        ++temp;
    }
    if (clen == 0) {
        mask_xor_const(state[temp], 0x01); /* Padding */
    } else if (clen == 1) {
        mword = (unsigned char)(mask_output(state[temp]) ^ c[0]);
        mask_xor_const(state[temp], mword);
        m[0] = (unsigned char)mword;
        mask_xor_const(state[temp], 0x0100); /* Padding */
        ++c;
    } else if (clen == 2) {
        mword = (uint16_t)(mask_output(state[temp]) ^ le_load_word16(c));
        mask_xor_const(state[temp], mword);
        le_store_word16(m, mword);
        mask_xor_const(state[temp], 0x010000); /* Padding */
        c += 2;
    } else {
        mword = le_load_word16(c) | (((uint32_t)(c[2])) << 16);
        mword = (mword ^ mask_output(state[temp])) & 0x00FFFFFFU;
        mask_xor_const(state[temp], mword);
        m[0] = (unsigned char)mword;
        m[1] = (unsigned char)(mword >> 8);
        m[2] = (unsigned char)(mword >> 16);
        mask_xor_const(state[temp], 0x01000000); /* Padding */
        c += 3;
    }

    /* Check the authentication tag */
    mask_xor_const(state[11], 0x40000000U); /* Domain separation */
    xoodoo_permute_masked(state);
    le_store_word32(tag,      mask_output(state[0]));
    le_store_word32(tag + 4,  mask_output(state[1]));
    le_store_word32(tag + 8,  mask_output(state[2]));
    le_store_word32(tag + 12, mask_output(state[3]));
    aead_random_finish();
    return aead_check_tag(mtemp, *mlen, tag, c, XOODYAK_MASKED_TAG_SIZE);
}

#endif /* !AEAD_MASKING_KEY_ONLY */
