/*
 * Copyright (C) 2020 Southern Storm Software, Pty Ltd.
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

#include "photon-beetle.h"
#include "internal-photon256.h"
#include "internal-util.h"
#include <string.h>

aead_hash_algorithm_t const photon_beetle_hash_algorithm = {
    "PHOTON-Beetle-HASH",
    sizeof(photon_beetle_hash_state_t),
    PHOTON_BEETLE_HASH_SIZE,
    AEAD_FLAG_NONE,
    photon_beetle_hash,
    (aead_hash_init_t)photon_beetle_hash_init,
    (aead_hash_update_t)photon_beetle_hash_update,
    (aead_hash_finalize_t)photon_beetle_hash_finalize,
    (aead_xof_absorb_t)0,
    (aead_xof_squeeze_t)0
};

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

int photon_beetle_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
    unsigned char state[PHOTON256_STATE_SIZE];
    unsigned temp;

    /* Absorb the input data */
    if (inlen == 0) {
        /* No input data at all */
        memset(state, 0, sizeof(state) - 1);
        state[PHOTON256_STATE_SIZE - 1] = DOMAIN(1);
    } else if (inlen <= PHOTON_BEETLE_128_RATE) {
        /* Only one block of input data, which may require padding */
        temp = (unsigned)inlen;
        memcpy(state, in, temp);
        memset(state + temp, 0, sizeof(state) - temp - 1);
        if (temp < PHOTON_BEETLE_128_RATE) {
            state[temp] = 0x01;
            state[PHOTON256_STATE_SIZE - 1] = DOMAIN(1);
        } else {
            state[PHOTON256_STATE_SIZE - 1] = DOMAIN(2);
        }
    } else {
        /* Initialize the state with the first block, then absorb the rest */
        memcpy(state, in, PHOTON_BEETLE_128_RATE);
        memset(state + PHOTON_BEETLE_128_RATE, 0,
               sizeof(state) - PHOTON_BEETLE_128_RATE);
        in += PHOTON_BEETLE_128_RATE;
        inlen -= PHOTON_BEETLE_128_RATE;
        while (inlen > PHOTON_BEETLE_32_RATE) {
            photon256_permute(state);
            lw_xor_block(state, in, PHOTON_BEETLE_32_RATE);
            in += PHOTON_BEETLE_32_RATE;
            inlen -= PHOTON_BEETLE_32_RATE;
        }
        photon256_permute(state);
        temp = (unsigned)inlen;
        if (temp == PHOTON_BEETLE_32_RATE) {
            lw_xor_block(state, in, PHOTON_BEETLE_32_RATE);
            state[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(1);
        } else {
            lw_xor_block(state, in, temp);
            state[temp] ^= 0x01;
            state[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(2);
        }
    }

    /* Generate the output hash */
    photon256_permute(state);
    memcpy(out, state, 16);
    photon256_permute(state);
    memcpy(out + 16, state, 16);
    return 0;
}

void photon_beetle_hash_init(photon_beetle_hash_state_t *state)
{
    memset(state->s.state, 0, sizeof(state->s.state));
    state->s.posn = 0;
    state->s.rate = PHOTON_BEETLE_128_RATE;
    state->s.first = 1;
}

void photon_beetle_hash_update
    (photon_beetle_hash_state_t *state, const unsigned char *in,
     unsigned long long inlen)
{
    unsigned temp;
    while (inlen > 0) {
        if (state->s.posn >= state->s.rate) {
            photon256_permute(state->s.state);
            state->s.posn = 0;
            state->s.rate = PHOTON_BEETLE_32_RATE;
            state->s.first = 0;
        }
        temp = state->s.rate - state->s.posn;
        if (temp > inlen)
            temp = (unsigned)inlen;
        lw_xor_block(state->s.state + state->s.posn, in, temp);
        state->s.posn += temp;
        in += temp;
        inlen -= temp;
    }
}

void photon_beetle_hash_finalize
    (photon_beetle_hash_state_t *state, unsigned char *out)
{
    /* Pad the final block */
    if (state->s.first) {
        if (state->s.posn == 0) {
            state->s.state[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(1);
        } else if (state->s.posn < state->s.rate) {
            state->s.state[state->s.posn] = 0x01;
            state->s.state[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(1);
        } else {
            state->s.state[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(2);
        }
    } else if (state->s.posn >= state->s.rate) {
        state->s.state[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(1);
    } else {
        state->s.state[state->s.posn] ^= 0x01;
        state->s.state[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(2);
    }

    /* Generate the hash output */
    photon256_permute(state->s.state);
    memcpy(out, state->s.state, 16);
    photon256_permute(state->s.state);
    memcpy(out + 16, state->s.state, 16);
}
