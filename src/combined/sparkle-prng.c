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

#include "sparkle-prng.h"
#include "sparkle-hash.h"
#include "internal-sparkle.h"
#include <string.h>

/**
 * \brief Rate at which bytes are processed by the SPARKLE PRNG.
 */
#define SPARKLE_PRNG_RATE 16

/**
 * \brief Hash of all global identification information that was
 * added by calls to sparkle_prng_add_ident().
 *
 * The initial value is the result of hashing the empty string with Esch256.
 */
static unsigned char sparkle_id_pool[ESCH_256_HASH_SIZE] = {
    0xC0, 0xE8, 0x15, 0xD7, 0x8B, 0x87, 0x5D, 0xC7,
    0x68, 0xC6, 0xC8, 0xB3, 0xAF, 0xA5, 0x19, 0x87,
    0xCD, 0x69, 0xE5, 0xC0, 0x87, 0xD3, 0x87, 0x36,
    0x86, 0x28, 0xA5, 0x11, 0xCF, 0xAD, 0x57, 0x30
};

/**
 * \brief Converts a pointer to a PRNG state into a pointer to a
 * SPARKLE-384 state array.
 *
 * \param st Pointer to the PRNG state.
 *
 * \return Pointer to the SPARKLE-384 state array inside the PRNG state.
 */
#define SPARKLE_STATE(st) ((uint32_t *)((st)->s.state))

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
 * \brief Perform the M3 step for Esch256 to mix the input with the state.
 *
 * \param s SPARKLE-384 state words.
 * \param block Block of input data that has been padded to the rate.
 * \param domain Domain separator for this phase.
 */
#define esch_256_m3(s, block, domain) \
    do { \
        uint32_t tx = (block)[0] ^ (block)[2]; \
        uint32_t ty = (block)[1] ^ (block)[3]; \
        tx = leftRotate16(tx ^ (tx << 16)); \
        ty = leftRotate16(ty ^ (ty << 16)); \
        (s)[0] ^= (block)[0] ^ ty; \
        (s)[1] ^= (block)[1] ^ tx; \
        (s)[2] ^= (block)[2] ^ ty; \
        (s)[3] ^= (block)[3] ^ tx; \
        if ((domain) != 0) \
            s[5] ^= DOMAIN(domain); \
        (s)[4] ^= ty; \
        (s)[5] ^= tx; \
    } while (0)

/**
 * \brief Absorbs data into a sponge based on SPARKLE-384.
 *
 * \param state SPARKLE-384 state.
 * \param data Points to the data to be absorbed.
 * \param size Number of bytes to be absorbed.
 *
 * Designed to work in a similar manner to Esch256's hash update process.
 */
static void sparkle_prng_absorb
    (uint32_t *state, const unsigned char *data, size_t size)
{
    uint32_t block[SPARKLE_PRNG_RATE / 4];
    while (size > SPARKLE_PRNG_RATE) {
        memcpy(block, data, SPARKLE_PRNG_RATE);
        esch_256_m3(state, block, 0);
        sparkle_384(state, 7);
        data += SPARKLE_PRNG_RATE;
        size -= SPARKLE_PRNG_RATE;
    }
    if (size == SPARKLE_PRNG_RATE) {
        memcpy(block, data, size);
        esch_256_m3(state, block, 2);
    } else {
        memcpy(block, data, size);
        ((unsigned char *)block)[size] = 0x80; /* Padding */
        memset(((unsigned char *)block) + size + 1, 0,
               SPARKLE_PRNG_RATE - size - 1);
        esch_256_m3(state, block, 1);
    }
    sparkle_384(state, 11);
    aead_clean(block, sizeof(block));
}

/**
 * \brief Rekeys the SPARKLE PRNG state to enhance forward security.
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
 * which is ceil((48 - SPARKLE_PRNG_RATE) / SPARKLE_PRNG_RATE).
 */
static void sparkle_prng_rekey(uint32_t *state)
{
    int temp;
    for (temp = 0; temp < (48 - SPARKLE_PRNG_RATE); temp += SPARKLE_PRNG_RATE) {
        memset(state, 0, SPARKLE_PRNG_RATE);
        state[11] ^= 0x01; /* Domain separation */
        sparkle_384(state, 7);
    }
}

void sparkle_prng_add_ident(const unsigned char *data, size_t size)
{
    esch_256_hash_state_t state;
    esch_256_hash_init(&state);
    esch_256_hash_update(&state, sparkle_id_pool, sizeof(sparkle_id_pool));
    esch_256_hash_update(&state, data, size);
    esch_256_hash_finalize(&state, sparkle_id_pool);
    aead_clean(&state, sizeof(state));
}

int sparkle_prng_init(sparkle_prng_state_t *state)
{
    /* Set up the default input block consisting of the global
     * identification pool and 128 bits of zeroes. */
    memcpy(state->s.state, sparkle_id_pool, sizeof(sparkle_id_pool));
    memset(state->s.state + 32, 0, 16);

    /* Set the byte counter and default byte limit */
    state->s.count = 0;
    state->s.limit = 16384;

    /* Re-seed the PRNG from the system TRNG */
    return sparkle_prng_reseed(state);
}

void sparkle_prng_free(sparkle_prng_state_t *state)
{
    aead_clean(state, sizeof(sparkle_prng_state_t));
}

int sparkle_prng_reseed(sparkle_prng_state_t *state)
{
    unsigned char seed[AEAD_SYSTEM_SEED_SIZE];
    int have_trng;

    /* Get a fresh seed from the system TRNG and absorb it into the state */
    have_trng = aead_random_get_system_seed(seed);
    sparkle_prng_absorb(SPARKLE_STATE(state), seed, sizeof(seed));
    aead_clean(seed, sizeof(seed));

    /* Force a rekey on the state */
    sparkle_prng_rekey(SPARKLE_STATE(state));

    /* Reset the reseed counter */
    state->s.count = 0;
    return have_trng;
}

void sparkle_prng_feed
    (sparkle_prng_state_t *state, const unsigned char *data, size_t size)
{
    sparkle_prng_absorb(SPARKLE_STATE(state), data, size);
    sparkle_prng_rekey(SPARKLE_STATE(state));
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
static int sparkle_prng_squeeze
    (sparkle_prng_state_t *state, unsigned char *data, size_t size)
{
    int reseed_ok = 1;
    while (size >= SPARKLE_PRNG_RATE) {
        if (state->s.count >= state->s.limit)
            reseed_ok &= sparkle_prng_reseed(state);
        memcpy(data, state->s.state, SPARKLE_PRNG_RATE);
        sparkle_384(SPARKLE_STATE(state), 7);
        data += SPARKLE_PRNG_RATE;
        size -= SPARKLE_PRNG_RATE;
        state->s.count += SPARKLE_PRNG_RATE;
    }
    if (size > 0) {
        if (state->s.count >= state->s.limit)
            reseed_ok &= sparkle_prng_reseed(state);
        memcpy(data, state->s.state, size);
        sparkle_384(SPARKLE_STATE(state), 7);
        state->s.count += SPARKLE_PRNG_RATE;
    }
    return reseed_ok;
}

int sparkle_prng_fetch
    (sparkle_prng_state_t *state, unsigned char *data, size_t size)
{
    int have_trng = sparkle_prng_squeeze(state, data, size);
    sparkle_prng_rekey(SPARKLE_STATE(state));
    return have_trng;
}

int sparkle_prng_generate(unsigned char *data, size_t size)
{
    sparkle_prng_state_t state;
    int have_trng = sparkle_prng_init(&state);
    have_trng &= sparkle_prng_squeeze(&state, data, size);
    sparkle_prng_free(&state);
    return have_trng;
}
