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

#include "photon-beetle-prng.h"
#include "photon-beetle-hash.h"
#include "internal-photon256.h"
#include <string.h>

/**
 * \brief Rate of operation for the PHOTON-256 based PRNG.
 *
 * PHOTON-Beetle-Hash uses 16 for the first data block and 4 for all
 * subsequent blocks.  We use only 4 here.
 */
#define PHOTON_BEETLE_PRNG_RATE 4

/**
 * \brief Hash of all global identification information that was
 * added by calls to photon_beetle_prng_add_ident().
 *
 * The initial value is the result of hashing the empty string with
 * PHOTON-Beetle-Hash.
 */
static unsigned char photon_beetle_id_pool[PHOTON_BEETLE_HASH_SIZE] = {
    0x44, 0xA9, 0x98, 0x82, 0xFE, 0xA0, 0x33, 0x56,
    0x68, 0x56, 0xA2, 0x7E, 0x7F, 0x0C, 0x94, 0xDC,
    0x84, 0xFA, 0xC7, 0xE4, 0x11, 0xB0, 0x8B, 0x89,
    0x0A, 0x4A, 0x57, 0x4E, 0x3D, 0xB7, 0x5D, 0x4A
};

/**
 * \brief Converts a pointer to a PRNG state into a pointer to a
 * photon256_state_t structure.
 *
 * \param st Pointer to the PRNG state.
 *
 * \return Pointer to the photon256_state_t structure inside the PRNG state.
 */
#define PHOTON256_STATE(st) ((photon256_state_t *)((st)->s.state))

/**
 * \brief Absorbs data into a sponge based on PHOTON-256.
 *
 * \param state PHOTON-256 state.
 * \param data Points to the data to be absorbed.
 * \param size Number of bytes to be absorbed.
 * \param pad_final Non-zero to pad the final block even if it is empty,
 * zero to elide the final padding block if \a size is a multiple of the rate.
 */
static void photon_beetle_prng_absorb
    (photon256_state_t *state, const unsigned char *data,
     size_t size, int pad_final)
{
    while (size >= PHOTON_BEETLE_PRNG_RATE) {
        lw_xor_block(state->B, data, PHOTON_BEETLE_PRNG_RATE);
        photon256_permute(state);
        data += PHOTON_BEETLE_PRNG_RATE;
        size -= PHOTON_BEETLE_PRNG_RATE;
    }
    if (size > 0 || pad_final) {
        lw_xor_block(state->B, data, size);
        state->B[size] ^= 0x01; /* Padding */
        photon256_permute(state);
    }
}

/**
 * \brief Rekeys the PHOTON-256 PRNG state to enhance forward security.
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
 * which is ceil((32 - PHOTON_BEETLE_PRNG_RATE) / PHOTON_BEETLE_PRNG_RATE).
 */
static void photon_beetle_prng_rekey(photon256_state_t *state)
{
    int temp;
    for (temp = 0; temp < (PHOTON256_STATE_SIZE - PHOTON_BEETLE_PRNG_RATE);
            temp += PHOTON_BEETLE_PRNG_RATE) {
        memset(state->B, 0, PHOTON_BEETLE_PRNG_RATE);
        state->B[PHOTON256_STATE_SIZE - 1] ^= 0x01; /* Domain separation */
        photon256_permute(state);
    }
}

void photon_beetle_prng_add_ident(const unsigned char *data, size_t size)
{
    photon_beetle_hash_state_t state;
    photon_beetle_hash_init(&state);
    photon_beetle_hash_update
        (&state, photon_beetle_id_pool, sizeof(photon_beetle_id_pool));
    photon_beetle_hash_update(&state, data, size);
    photon_beetle_hash_finalize(&state, photon_beetle_id_pool);
    aead_clean(&state, sizeof(state));
}

int photon_beetle_prng_init(photon_beetle_prng_state_t *state)
{
    /* Set the initial state to the global identification pool */
    memcpy(state->s.state, photon_beetle_id_pool, PHOTON256_STATE_SIZE);

    /* Set the byte counter and default byte limit */
    state->s.count = 0;
    state->s.limit = 16384;

    /* Re-seed the PRNG from the system TRNG */
    return photon_beetle_prng_reseed(state);
}

void photon_beetle_prng_free(photon_beetle_prng_state_t *state)
{
    aead_clean(state, sizeof(photon_beetle_prng_state_t));
}

int photon_beetle_prng_reseed(photon_beetle_prng_state_t *state)
{
    unsigned char seed[AEAD_SYSTEM_SEED_SIZE];
    int have_trng = aead_random_get_system_seed(seed);
    photon_beetle_prng_absorb(PHOTON256_STATE(state), seed, sizeof(seed), 0);
    aead_clean(seed, sizeof(seed));
    photon_beetle_prng_rekey(PHOTON256_STATE(state));
    state->s.count = 0;
    return have_trng;
}

void photon_beetle_prng_feed
    (photon_beetle_prng_state_t *state, const unsigned char *data, size_t size)
{
    photon_beetle_prng_absorb(PHOTON256_STATE(state), data, size, 1);
    photon_beetle_prng_rekey(PHOTON256_STATE(state));
}

/**
 * \brief Squeezes data from a PRNG state.
 *
 * \param state Points to the PRNG state.
 * \param data Points to the buffer to receive the squeezed data.
 * \param size Number of bytes to be squeezed.
 */
static void photon_beetle_prng_squeeze
    (photon_beetle_prng_state_t *state, unsigned char *data, size_t size)
{
    while (size >= PHOTON_BEETLE_PRNG_RATE) {
        if (state->s.count >= state->s.limit)
            photon_beetle_prng_reseed(state);
        memcpy(data, state->s.state, PHOTON_BEETLE_PRNG_RATE);
        photon256_permute(PHOTON256_STATE(state));
        data += PHOTON_BEETLE_PRNG_RATE;
        size -= PHOTON_BEETLE_PRNG_RATE;
        state->s.count += PHOTON_BEETLE_PRNG_RATE;
    }
    if (size > 0) {
        if (state->s.count >= state->s.limit)
            photon_beetle_prng_reseed(state);
        memcpy(data, state->s.state, size);
        photon256_permute(PHOTON256_STATE(state));
        state->s.count += PHOTON_BEETLE_PRNG_RATE;
    }
}

void photon_beetle_prng_fetch
    (photon_beetle_prng_state_t *state, unsigned char *data, size_t size)
{
    photon_beetle_prng_squeeze(state, data, size);
    photon_beetle_prng_rekey(PHOTON256_STATE(state));
}

int photon_beetle_prng_generate(unsigned char *data, size_t size)
{
    photon_beetle_prng_state_t state;
    int have_trng = photon_beetle_prng_init(&state);
    photon_beetle_prng_squeeze(&state, data, size);
    photon_beetle_prng_free(&state);
    return have_trng;
}
