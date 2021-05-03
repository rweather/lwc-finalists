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

#include "photon-beetle-hash.h"
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

int photon_beetle_hash
    (unsigned char *out, const unsigned char *in, size_t inlen)
{
    photon256_state_t state;
    unsigned temp;

    /* Absorb the input data */
    if (inlen == 0) {
        /* No input data at all */
        memset(state.B, 0, PHOTON256_STATE_SIZE - 1);
        state.B[PHOTON256_STATE_SIZE - 1] = DOMAIN(1);
    } else if (inlen <= PHOTON_BEETLE_128_RATE) {
        /* Only one block of input data, which may require padding */
        temp = (unsigned)inlen;
        memcpy(state.B, in, temp);
        memset(state.B + temp, 0, PHOTON256_STATE_SIZE - temp - 1);
        if (temp < PHOTON_BEETLE_128_RATE) {
            state.B[temp] = 0x01;
            state.B[PHOTON256_STATE_SIZE - 1] = DOMAIN(1);
        } else {
            state.B[PHOTON256_STATE_SIZE - 1] = DOMAIN(2);
        }
    } else {
        /* Initialize the state with the first block, then absorb the rest */
        memcpy(state.B, in, PHOTON_BEETLE_128_RATE);
        memset(state.B + PHOTON_BEETLE_128_RATE, 0,
               PHOTON256_STATE_SIZE - PHOTON_BEETLE_128_RATE);
        in += PHOTON_BEETLE_128_RATE;
        inlen -= PHOTON_BEETLE_128_RATE;
        while (inlen > PHOTON_BEETLE_32_RATE) {
            photon256_permute(&state);
            lw_xor_block(state.B, in, PHOTON_BEETLE_32_RATE);
            in += PHOTON_BEETLE_32_RATE;
            inlen -= PHOTON_BEETLE_32_RATE;
        }
        photon256_permute(&state);
        temp = (unsigned)inlen;
        if (temp == PHOTON_BEETLE_32_RATE) {
            lw_xor_block(state.B, in, PHOTON_BEETLE_32_RATE);
            state.B[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(1);
        } else {
            lw_xor_block(state.B, in, temp);
            state.B[temp] ^= 0x01;
            state.B[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(2);
        }
    }

    /* Generate the output hash */
    photon256_permute(&state);
    memcpy(out, state.B, 16);
    photon256_permute(&state);
    memcpy(out + 16, state.B, 16);
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
    (photon_beetle_hash_state_t *state, const unsigned char *in, size_t inlen)
{
    photon256_state_t *st = (photon256_state_t *)(state->s.state);
    unsigned temp;
    while (inlen > 0) {
        if (state->s.posn >= state->s.rate) {
            photon256_permute(st);
            state->s.posn = 0;
            state->s.rate = PHOTON_BEETLE_32_RATE;
            state->s.first = 0;
        }
        temp = state->s.rate - state->s.posn;
        if (temp > inlen)
            temp = (unsigned)inlen;
        lw_xor_block(st->B + state->s.posn, in, temp);
        state->s.posn += temp;
        in += temp;
        inlen -= temp;
    }
}

void photon_beetle_hash_finalize
    (photon_beetle_hash_state_t *state, unsigned char *out)
{
    /* Pad the final block */
    photon256_state_t *st = (photon256_state_t *)(state->s.state);
    if (state->s.first) {
        if (state->s.posn == 0) {
            st->B[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(1);
        } else if (state->s.posn < state->s.rate) {
            st->B[state->s.posn] = 0x01;
            st->B[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(1);
        } else {
            st->B[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(2);
        }
    } else if (state->s.posn >= state->s.rate) {
        st->B[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(1);
    } else {
        st->B[state->s.posn] ^= 0x01;
        st->B[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(2);
    }

    /* Generate the hash output */
    photon256_permute(st);
    memcpy(out, st->B, 16);
    photon256_permute(st);
    memcpy(out + 16, st->B, 16);
}
