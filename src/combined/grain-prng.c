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

#include "grain-prng.h"
#include "internal-grain128.h"
#include <string.h>

/**
 * \brief Compact form of the Grain-128 state.
 *
 * We don't need most of the fields in grain128_state_t for the PRNG
 * so create a compact form that is identical to grain128_state_t in
 * the first two fields (LFSR and NFSR).
 *
 * The compact form can only be used with grain128_core() and
 * grain128_preoutput().  The other helper functions in
 * "internal-grain128.h" must not be used.
 */
typedef struct
{
    uint32_t lfsr[4];       /**< 128-bit LFSR state for Grain-128 */
    uint32_t nfsr[4];       /**< 128-bit NFSR state for Grain-128 */

} grain128_compact_state_t;

/**
 * \brief Converts a compact Grain-128 state into a full state.
 *
 * \param state Points to the compact Grain-128 state.
 *
 * \return A pointer to the full Grain-128 state.
 */
#define GRAIN128_STATE(state) ((grain128_state_t *)(state))

/**
 * \brief Hash of all global identification information that was
 * added by calls to grain_prng_add_ident().
 *
 * The default value is the SHA-256 initialization vector.
 */
static uint32_t grain_id_pool[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/**
 * \brief Absorbs data into a Grain-128 state.
 *
 * \param state Points to the Grain-128 state.
 * \param data Points to the data to be absorbed.
 * \param size Number of bytes to be absorbed.
 */
static void grain_prng_absorb
    (grain128_state_t *state, const unsigned char *data, size_t size)
{
    /* Absorb as many 32-bit blocks as possible */
    while (size >= 4) {
        grain128_core(state, le_load_word32(data), 0);
        data += 4;
        size -= 4;
    }

    /* Pad and absorb the final left-over block */
    if (size == 1) {
        grain128_core(state, data[0] | 0x00000100U, 0);
    } else if (size == 2) {
        grain128_core(state, ((uint32_t)le_load_word16(data)) | 0x00010000U, 0);
    } else if (size == 3) {
        uint32_t value = le_load_word16(data);
        value |= ((uint32_t)(data[2])) << 16;
        value |= 0x01000000U;
        grain128_core(state, value, 0);
    }
}

/**
 * \brief Squeezes data out of a Grain-128 PRNG state.
 *
 * \param state Points to the PRNG state.
 * \param data Points to the data buffer to fill with squeezed data.
 * \param size Number of bytes to be squeezed.
 */
static void grain_prng_squeeze
    (grain_prng_state_t *state, unsigned char *data, size_t size)
{
    uint32_t x;

    /* Squeeze as many 32-bit blocks as possible */
    while (size >= 4) {
        if (state->s.count >= state->s.limit)
            grain_prng_reseed(state);
        x = grain128_preoutput(GRAIN128_STATE(state));
        grain128_core(GRAIN128_STATE(state), 0, 0);
        le_store_word32(data, x);
        data += 4;
        size -= 4;
        state->s.count += 4;
    }

    /* Squeeze out the final partial block */
    if (size > 0) {
        if (state->s.count >= state->s.limit)
            grain_prng_reseed(state);
        x = grain128_preoutput(GRAIN128_STATE(state));
        grain128_core(GRAIN128_STATE(state), 0, 0);
        if (size == 1) {
            data[0] = (unsigned char)x;
        } else if (size == 2) {
            data[0] = (unsigned char)x;
            data[1] = (unsigned char)(x >> 8);
        } else {
            data[0] = (unsigned char)x;
            data[1] = (unsigned char)(x >> 8);
            data[2] = (unsigned char)(x >> 16);
        }
        state->s.count += 4;
    }
}

/**
 * \brief Re-initializes a Grain-128 PRNG with a new key and nonce.
 *
 * \param state Points to the Grain-128 state to re-initialize.
 * \param key Points to the 256-bit key.
 * \param nonce 64-bit nonce value.
 *
 * This uses a variation on the Grain-128AEAD key setup procedure.
 */
static void grain_prng_setup_key
    (grain128_state_t *state, const uint32_t *key, uint64_t nonce)
{
    uint32_t y;
    uint8_t round;

    /* Initialize the LFSR state with the nonce value and padding.
     * Grain-128AEAD has a 96-bit nonce, but we only use 64-bit here. */
    state->lfsr[0] = (uint32_t)nonce;
    state->lfsr[1] = (uint32_t)(nonce >> 32);
    state->lfsr[2] = 0;
    state->lfsr[3] = 0xFFFFFFFEU; /* pad with all-1s and a terminating 0 */

    /* Initialize the NFSR state with the first 128 bits of the key */
    memcpy(state->nfsr, key, 16);

    /* Perform 256 rounds of Grain-128 to mix up the initial state.
     * The rounds can be performed 32 at a time: 32 * 8 = 256 */
    for (round = 0; round < 8; ++round) {
        y = grain128_preoutput(state);
        grain128_core(state, y, y);
    }

    /* Absorb the entire key into the state */
    for (round = 0; round < 8; ++round) {
        grain128_core(GRAIN128_STATE(&state), key[round], 0);
    }

    /* Perform another 256 rounds of Grain-128 to mix up the state some more */
    for (round = 0; round < 8; ++round) {
        y = grain128_preoutput(state);
        grain128_core(state, y, y);
    }
}

/**
 * \brief Re-keys the Grain-128 PRNG state.
 *
 * \param state The state to be re-keyed.
 * \param key Temporary 256-bit buffer from the caller.
 */
static void grain_prng_rekey(grain_prng_state_t *state, uint32_t key[8])
{
    uint8_t round;

    /* Re-key by generating 256 bits of random data to be the new key */
    for (round = 0; round < 7; ++round) {
        key[round] = grain128_preoutput(GRAIN128_STATE(state));
        grain128_core(GRAIN128_STATE(state), 0, 0);
    }
    key[7] = grain128_preoutput(GRAIN128_STATE(state));

    /* Re-initialize the PRNG with the new key and the next nonce */
    ++(state->s.rekeys);
    grain_prng_setup_key(GRAIN128_STATE(state), key, state->s.rekeys);
}

void grain_prng_add_ident(const unsigned char *data, size_t size)
{
    grain128_compact_state_t state;
    uint8_t round;

    /* Set up a Grain-128 state using the identification pool as the key */
    grain_prng_setup_key(GRAIN128_STATE(&state), grain_id_pool, 0);

    /* Absorb the input data into the Grain-128 state */
    grain_prng_absorb(GRAIN128_STATE(&state), data, size);

    /* Generate 32 bytes of output for the new identification pool */
    for (round = 0; round < 7; ++round) {
        grain_id_pool[round] = grain128_preoutput(GRAIN128_STATE(&state));
        grain128_core(GRAIN128_STATE(&state), 0, 0);
    }
    grain_id_pool[7] = grain128_preoutput(GRAIN128_STATE(&state));

    /* Clean up */
    aead_clean(&state, sizeof(state));
}

void grain_prng_init(grain_prng_state_t *state)
{
    uint32_t seed[AEAD_SYSTEM_SEED_SIZE / 4];

    /* By default we can generate 16K of output data before re-seeding */
    state->s.count = 0;
    state->s.limit = 16384;

    /* Generate a seed from the system TRNG and initialize the PRNG */
    aead_random_get_system_seed((unsigned char *)seed);
    grain_prng_setup_key(GRAIN128_STATE(state), seed, 0);
    aead_clean(seed, sizeof(seed));
    state->s.rekeys = 0;

    /* Absorb the identification pool into the state and re-key */
    grain_prng_feed
        (state, (const unsigned char *)grain_id_pool, sizeof(grain_id_pool));
}

void grain_prng_free(grain_prng_state_t *state)
{
    aead_clean(state, sizeof(grain_prng_state_t));
}

void grain_prng_reseed(grain_prng_state_t *state)
{
    uint32_t key[8];

    /* Fetch a seed from the system TRNG and feed it into the PRNG */
    aead_random_get_system_seed((unsigned char *)key);
    grain_prng_absorb(GRAIN128_STATE(state), (const unsigned char *)key, 32);

    /* Re-key the PRNG */
    grain_prng_rekey(state, key);
    aead_clean(key, sizeof(key));

    /* Reset the output byte counter to zero */
    state->s.count = 0;
}

void grain_prng_feed
    (grain_prng_state_t *state, const unsigned char *data, size_t size)
{
    /* Absorb the supplied data into the PRNG state and then re-key */
    uint32_t key[8];
    grain_prng_absorb(GRAIN128_STATE(state), data, size);
    grain_prng_rekey(state, key);
    aead_clean(key, sizeof(key));
}

void grain_prng_fetch
    (grain_prng_state_t *state, unsigned char *data, size_t size)
{
    /* Squeeze data out of the PRNG state */
    grain_prng_squeeze(state, data, size);

    /* Re-key the PRNG after the request */
    grain_prng_feed(state, 0, 0);
}

void grain_prng_generate(unsigned char *data, size_t size)
{
    grain_prng_state_t state;
    grain_prng_init(&state);
    grain_prng_squeeze(&state, data, size);
    aead_clean(&state, sizeof(state));
}
