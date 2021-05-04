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

#include "xoodyak-prng.h"
#include "xoodyak-hash.h"
#include "internal-xoodoo.h"
#include <string.h>

/**
 * \brief Hash of all global identification information that was
 * added by calls to xoodyak_prng_add_ident().
 *
 * The initial value is the result of hashing the empty string with Xoodyak.
 */
static unsigned char xoodyak_id_pool[XOODYAK_HASH_SIZE] = {
    0xEA, 0x15, 0x2F, 0x2B, 0x47, 0xBC, 0xE2, 0x4E,
    0xFB, 0x66, 0xC4, 0x79, 0xD4, 0xAD, 0xF1, 0x7B,
    0xD3, 0x24, 0xD8, 0x06, 0xE8, 0x5F, 0xF7, 0x5E,
    0xE3, 0x69, 0xEE, 0x50, 0xDC, 0x8F, 0x8B, 0xD1
};

/**
 * \brief Converts a pointer to a PRNG state into a pointer to a
 * xoodoo_state_t structure.
 *
 * \param state Pointer to the PRNG state.
 *
 * \return Pointer to the xoodoo_state_t structure inside the PRNG state.
 */
#define XOODOO_STATE(state) ((xoodoo_state_t *)((state)->s.state))

/**
 * \brief Rekeys the Xoodoo-PRNG state to enhance forward security.
 *
 * \param state Points to the PRNG state to be rekeyed.
 *
 * According to section 4.3 of the SpongePRNG paper, forward security can
 * be enhanced by fetching a single rate block from the state and then
 * immediately feeding it back in as seed material.
 *
 * The effect of feeding the rate back into itself is to set the rate
 * block to zero.  When we permute the state afterwards, the rate will
 * be set to something else.  An attacker would need to be able to guess
 * the non-zeroed bits in the previous state to roll the state backwards,
 * which should be infeasible with this construction.
 *
 * The SpongePRNG paper recommends repeating the process ceil(c/r) times,
 * which is ceil((48 - XOODYAK_HASH_RATE) / XOODYAK_HASH_RATE) in our case.
 */
static void xoodyak_prng_rekey(xoodoo_state_t *state)
{
    int temp;
    for (temp = 0; temp < (48 - XOODYAK_HASH_RATE); temp += XOODYAK_HASH_RATE) {
        memset(state->B, 0, XOODYAK_HASH_RATE);
        state->B[47] ^= 0x01; /* Domain separation */
        xoodoo_permute(state);
    }
}

void xoodyak_prng_add_ident(const unsigned char *data, size_t size)
{
    xoodyak_hash_state_t state;
    xoodyak_hash_init(&state);
    xoodyak_hash_absorb(&state, xoodyak_id_pool, sizeof(xoodyak_id_pool));
    xoodyak_hash_absorb(&state, data, size);
    xoodyak_hash_finalize(&state, xoodyak_id_pool);
    aead_clean(&state, sizeof(state));
}

int xoodyak_prng_init(xoodyak_prng_state_t *state)
{
    /* Set up the default input block consisting of the global
     * identification pool and 128 bits of zeroes.  Then permute. */
    memcpy(state->s.state, xoodyak_id_pool, sizeof(xoodyak_id_pool));
    memset(state->s.state + 32, 0, 16);
    xoodoo_permute(XOODOO_STATE(state));

    /* Set the byte counter and default byte limit */
    state->s.count = 0;
    state->s.limit = 16384;

    /* Re-seed the PRNG from the system TRNG */
    return xoodyak_prng_reseed(state);
}

void xoodyak_prng_free(xoodyak_prng_state_t *state)
{
    aead_clean(state, sizeof(xoodyak_prng_state_t));
}

int xoodyak_prng_reseed(xoodyak_prng_state_t *state)
{
    unsigned char seed[AEAD_SYSTEM_SEED_SIZE];
    unsigned index;
    int have_trng;

    /* Get a fresh seed from the system TRNG and absorb it into the state */
    have_trng = aead_random_get_system_seed(seed);
    for (index = 0; index < AEAD_SYSTEM_SEED_SIZE; index += XOODYAK_HASH_RATE) {
        lw_xor_block(state->s.state, seed + index, XOODYAK_HASH_RATE);
        xoodoo_permute(XOODOO_STATE(state));
    }
    aead_clean(seed, sizeof(seed));

    /* Force a rekey on the state */
    xoodyak_prng_rekey(XOODOO_STATE(state));

    /* Reset the reseed counter */
    state->s.count = 0;
    return have_trng;
}

void xoodyak_prng_feed
    (xoodyak_prng_state_t *state, const unsigned char *data, size_t size)
{
    /* Absorb the supplied data into the PRNG state in rate-sized blocks */
    while (size >= XOODYAK_HASH_RATE) {
        lw_xor_block(state->s.state, data, XOODYAK_HASH_RATE);
        xoodoo_permute(XOODOO_STATE(state));
        data += XOODYAK_HASH_RATE;
        size -= XOODYAK_HASH_RATE;
    }
    if (size > 0) {
        lw_xor_block(state->s.state, data, size);
        state->s.state[size] ^= 0x01; /* Padding */
        xoodoo_permute(XOODOO_STATE(state));
    }

    /* Re-key the PRNG state */
    xoodyak_prng_rekey(XOODOO_STATE(state));
}

/**
 * \brief Squeezes data out of a PRNG state.
 *
 * \param state PRNG state to squeeze from.
 * \param data Points to the data buffer to fill.
 * \param size Number of bytes to squeeze out of \a state.
 */
static void xoodyak_prng_squeeze
    (xoodyak_prng_state_t *state, unsigned char *data, size_t size)
{
    /* Squeeze as many rate-sized blocks as possible */
    while (size >= XOODYAK_HASH_RATE) {
        if (state->s.count >= state->s.limit)
            xoodyak_prng_reseed(state);
        memcpy(data, state->s.state, XOODYAK_HASH_RATE);
        xoodoo_permute(XOODOO_STATE(state));
        state->s.count += XOODYAK_HASH_RATE;
        data += XOODYAK_HASH_RATE;
        size -= XOODYAK_HASH_RATE;
    }

    /* Squeeze out the final block */
    if (size > 0) {
        if (state->s.count >= state->s.limit)
            xoodyak_prng_reseed(state);
        memcpy(data, state->s.state, size);
        xoodoo_permute(XOODOO_STATE(state));
        state->s.count += XOODYAK_HASH_RATE;
    }
}

void xoodyak_prng_fetch
    (xoodyak_prng_state_t *state, unsigned char *data, size_t size)
{
    xoodyak_prng_squeeze(state, data, size);
    xoodyak_prng_rekey(XOODOO_STATE(state));
}

void xoodyak_prng_generate(unsigned char *data, size_t size)
{
    xoodyak_prng_state_t state;
    xoodyak_prng_init(&state);
    xoodyak_prng_squeeze(&state, data, size);
    xoodyak_prng_free(&state);
}
