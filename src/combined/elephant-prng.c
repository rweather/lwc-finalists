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

#include "elephant-prng.h"
#include "internal-keccakp-200.h"
#include <string.h>

/**
 * \brief Rate of absorbing and squeezing for the Elephant-based PRNG.
 */
#define ELEPHANT_PRNG_RATE 8

/**
 * \brief Hash of all global identification information that was
 * added by calls to elephant_prng_add_ident().
 *
 * The initial value is the first 25 bytes of the result of hashing the
 * empty string with SHA3-256 (chosen because SHA3 is also Keccak-based).
 */
static unsigned char elephant_id_pool[KECCAKP_200_STATE_SIZE] = {
    0xA7, 0xFF, 0xC6, 0xF8, 0xBF, 0x1E, 0xD7, 0x66,
    0x51, 0xC1, 0x47, 0x56, 0xA0, 0x61, 0xD6, 0x62,
    0xF5, 0x80, 0xFF, 0x4D, 0xE4, 0x3B, 0x49, 0xFA, 0x82
};

/**
 * \brief Converts a pointer to a PRNG state into a pointer to a
 * keccakp_200_state_t structure.
 *
 * \param st Pointer to the PRNG state.
 *
 * \return Pointer to the keccakp_200_state_t structure inside the PRNG state.
 */
#define KECCAK_STATE(st) ((keccakp_200_state_t *)((st)->s.state))

/**
 * \brief Absorbs data into a sponge based on Keccak-p[200].
 *
 * \param state Keccak-p[200] state.
 * \param data Points to the data to be absorbed.
 * \param size Number of bytes to be absorbed.
 * \param pad_final Non-zero to pad the final block even if it is empty,
 * zero to elide the final padding block if \a size is a multiple of the rate.
 */
static void elephant_prng_absorb
    (keccakp_200_state_t *state, const unsigned char *data,
     size_t size, int pad_final)
{
    while (size >= ELEPHANT_PRNG_RATE) {
        lw_xor_block(state->B, data, ELEPHANT_PRNG_RATE);
        keccakp_200_permute(state);
        data += ELEPHANT_PRNG_RATE;
        size -= ELEPHANT_PRNG_RATE;
    }
    if (size > 0 || pad_final) {
        lw_xor_block(state->B, data, size);
        state->B[size] ^= 0x01; /* Padding */
        keccakp_200_permute(state);
    }
}

/**
 * \brief Rekeys the Elephant-PRNG state to enhance forward security.
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
 * which is ceil((25 - ELEPHANT_PRNG_RATE) / ELEPHANT_PRNG_RATE) or 3.
 */
static void elephant_prng_rekey(keccakp_200_state_t *state)
{
    int temp;
    for (temp = 0; temp < 3; ++temp) {
        memset(state->B, 0, ELEPHANT_PRNG_RATE);
        state->B[24] ^= 0x01; /* Domain separation */
        keccakp_200_permute(state);
    }
}

void elephant_prng_add_ident(const unsigned char *data, size_t size)
{
    keccakp_200_state_t state;
    unsigned offset;

    /* Elephant doesn't have a hashing mode, so we have to invent one */

    /* Initialize with the previous state of the identification pool */
    memcpy(state.B, elephant_id_pool, sizeof(elephant_id_pool));

    /* Absorb the data in rate-sized chunks */
    elephant_prng_absorb(&state, data, size, 1);

    /* Squeeze out a new identification pool in rate-sized chunks */
    for (offset = 0; offset < (KECCAKP_200_STATE_SIZE - 1);
            offset += ELEPHANT_PRNG_RATE) {
        memcpy(elephant_id_pool + offset, state.B, ELEPHANT_PRNG_RATE);
        keccakp_200_permute(&state);
    }
    elephant_id_pool[24] = state.B[0];
    aead_clean(&state, sizeof(state));
}

int elephant_prng_init(elephant_prng_state_t *state)
{
    /* Set the initial state to the global identification pool */
    memcpy(state->s.state, elephant_id_pool, sizeof(elephant_id_pool));

    /* Set the byte counter and default byte limit */
    state->s.count = 0;
    state->s.limit = 16384;

    /* Re-seed the PRNG from the system TRNG */
    return elephant_prng_reseed(state);
}

void elephant_prng_free(elephant_prng_state_t *state)
{
    aead_clean(state, sizeof(elephant_prng_state_t));
}

int elephant_prng_reseed(elephant_prng_state_t *state)
{
    unsigned char seed[AEAD_SYSTEM_SEED_SIZE];
    int have_trng = aead_random_get_system_seed(seed);
    elephant_prng_absorb(KECCAK_STATE(state), seed, sizeof(seed), 0);
    aead_clean(seed, sizeof(seed));
    elephant_prng_rekey(KECCAK_STATE(state));
    state->s.count = 0;
    return have_trng;
}

void elephant_prng_feed
    (elephant_prng_state_t *state, const unsigned char *data, size_t size)
{
    elephant_prng_absorb(KECCAK_STATE(state), data, size, 1);
    elephant_prng_rekey(KECCAK_STATE(state));
}

/**
 * \brief Squeezes data from a PRNG state.
 *
 * \param state Points to the PRNG state.
 * \param data Points to the buffer to receive the squeezed data.
 * \param size Number of bytes to be squeezed.
 *
 * \return Zero if the PRNG was re-seeded from the system TRNG during
 * the fetch but there is no system TRNG or it has failed.
 */
static int elephant_prng_squeeze
    (elephant_prng_state_t *state, unsigned char *data, size_t size)
{
    int reseed_ok = 1;
    while (size >= ELEPHANT_PRNG_RATE) {
        if (state->s.count >= state->s.limit)
            reseed_ok &= elephant_prng_reseed(state);
        memcpy(data, state->s.state, ELEPHANT_PRNG_RATE);
        keccakp_200_permute(KECCAK_STATE(state));
        data += ELEPHANT_PRNG_RATE;
        size -= ELEPHANT_PRNG_RATE;
        state->s.count += ELEPHANT_PRNG_RATE;
    }
    if (size > 0) {
        if (state->s.count >= state->s.limit)
            reseed_ok &= elephant_prng_reseed(state);
        memcpy(data, state->s.state, size);
        keccakp_200_permute(KECCAK_STATE(state));
        state->s.count += ELEPHANT_PRNG_RATE;
    }
    return reseed_ok;
}

int elephant_prng_fetch
    (elephant_prng_state_t *state, unsigned char *data, size_t size)
{
    int have_trng = elephant_prng_squeeze(state, data, size);
    elephant_prng_rekey(KECCAK_STATE(state));
    return have_trng;
}

int elephant_prng_generate(unsigned char *data, size_t size)
{
    elephant_prng_state_t state;
    int have_trng = elephant_prng_init(&state);
    have_trng &= elephant_prng_squeeze(&state, data, size);
    elephant_prng_free(&state);
    return have_trng;
}
