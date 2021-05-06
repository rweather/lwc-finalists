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

#include "ascon-prng.h"
#include "ascon-hash.h"
#include "internal-ascon.h"
#include <string.h>

/**
 * \brief Hash of all global identification information that was
 * added by calls to ascon_prng_add_ident().
 *
 * The initial value is the result of hashing the empty string with ASCON-HASH.
 */
static unsigned char ascon_id_pool[ASCON_HASH_SIZE] = {
    0x73, 0x46, 0xBC, 0x14, 0xF0, 0x36, 0xE8, 0x7A,
    0xE0, 0x3D, 0x09, 0x97, 0x91, 0x30, 0x88, 0xF5,
    0xF6, 0x84, 0x11, 0x43, 0x4B, 0x3C, 0xF8, 0xB5,
    0x4F, 0xA7, 0x96, 0xA8, 0x0D, 0x25, 0x1F, 0x91
};

/**
 * \brief Initialization vector value for the PRNG.
 *
 * The ASCON specification says that the bottom 4 bytes should be set to
 * zero for arbitrary-length XOF output which is what we are doing.
 *
 * According to the ASCON specification, the top 4 bytes (from the MSB down)
 * should be the key size in bits, the rate in bits, the number of "a" rounds,
 * and the number of "b" rounds.
 *
 * ASCON-XOF normally sets the key size to zero, but we set it to 1
 * so that this IV is unlikely to clash with a future ASCON-XOF variant.
 * It is also unlikely to clash with a future ASCON AEAD mode because a
 * cipher with a 1-bit key isn't very useful.
 */
#define ASCON_PRNG_IV 0x01400C0000000000ULL

/**
 * \brief The PRNG is re-seeded from the system TRNG every 16K bytes.
 */
#define ASCON_PRNG_RESEED_LIMIT 16384

/**
 * \brief Converts a pointer to a PRNG state into a pointer to a
 * ascon_state_t structure.
 *
 * \param st Pointer to the PRNG state.
 *
 * \return Pointer to the ascon_state_t structure inside the PRNG state.
 */
#define ASCON_STATE(st) ((ascon_state_t *)((st)->s.state))

/**
 * \def ascon_prng_permute(state)
 * \brief Permutes the ASCON state.
 *
 * \param state The ascon_state_t to be permuted.
 *
 * In sliced mode we would normally call ascon_absorb_sliced() to inject
 * data into the state and ascon_squeeze_sliced() to extract data from
 * the state.  All this does is rearrange the bits but provides no
 * security advantage when generating random output.  One random bit is
 * just as good as any other random bit, permuted or not.  So we don't
 * bother with ascon_absorb_sliced() and ascon_squeeze_sliced() below.
 *
 * Doing this means that 32-bit systems will generate different random
 * data than 64-bit systems from the same inputs.  But given that we
 * want completely different output on different devices anyway,
 * the lack of binary compatibility is not a big problem for us.
 * The performance savings of not having to convert to and from the
 * slice representation are useful.
 */
#if ASCON_SLICED
#define ascon_prng_permute(state) ascon_permute_sliced((state), 0)
#else
#define ascon_prng_permute(state) ascon_permute((state), 0)
#endif

/**
 * \brief Rekeys the ASCON-PRNG state to enhance forward security.
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
 * which is ceil((40 - ASCON_XOF_RATE) / ASCON_XOF_RATE) in our case.
 */
static void ascon_prng_rekey(ascon_state_t *state)
{
    int temp;
    for (temp = 0; temp < (40 - ASCON_XOF_RATE); temp += ASCON_XOF_RATE) {
        memset(state->B, 0, ASCON_XOF_RATE);
#if ASCON_SLICED
        state->W[8] ^= 0x01; /* Domain separation */
#else
        state->B[39] ^= 0x01; /* Domain separation */
#endif
        ascon_prng_permute(state);
    }
}

void ascon_prng_add_ident(const unsigned char *data, size_t size)
{
    ascon_hash_state_t state;
    ascon_hash_init(&state);
    ascon_hash_update(&state, ascon_id_pool, sizeof(ascon_id_pool));
    ascon_hash_update(&state, data, size);
    ascon_hash_finalize(&state, ascon_id_pool);
    aead_clean(&state, sizeof(state));
}

int ascon_prng_init(ascon_prng_state_t *state)
{
    /* Set up the initial ASCON block with an IV value and the
     * contents of the global identification pool.  ASCON normally
     * puts the IV value first but we put the global identification
     * pool first so that the first block of the seed will XOR
     * with the semi-chaotic hash data rather than the IV. */
    memcpy(state->s.state, ascon_id_pool, ASCON_HASH_SIZE);
    be_store_word64(state->s.state + ASCON_HASH_SIZE, ASCON_PRNG_IV);
#if ASCON_SLICED
    ascon_to_sliced(ASCON_STATE(state));
#endif

    /* Set the default re-seeding limit */
    state->s.limit = ASCON_PRNG_RESEED_LIMIT;

    /* Re-seed the PRNG from the system TRNG */
    return ascon_prng_reseed(state);
}

void ascon_prng_free(ascon_prng_state_t *state)
{
    aead_clean(state, sizeof(ascon_prng_state_t));
}

int ascon_prng_reseed(ascon_prng_state_t *state)
{
    unsigned char seed[AEAD_SYSTEM_SEED_SIZE];
    unsigned index;
    int have_trng;

    /* Get a fresh seed from the system TRNG and absorb it into the state */
    have_trng = aead_random_get_system_seed(seed);
    for (index = 0; index < AEAD_SYSTEM_SEED_SIZE; index += ASCON_XOF_RATE) {
        lw_xor_block(state->s.state, seed + index, ASCON_XOF_RATE);
        ascon_prng_permute(ASCON_STATE(state));
    }
    aead_clean(seed, sizeof(seed));

    /* Force a rekey on the state */
    ascon_prng_rekey(ASCON_STATE(state));

    /* Reset the reseed counter */
    state->s.count = 0;
    return have_trng;
}

void ascon_prng_feed
    (ascon_prng_state_t *state, const unsigned char *data, size_t size)
{
    /* Absorb the supplied data into the PRNG state in rate-sized blocks */
    while (size >= ASCON_XOF_RATE) {
        lw_xor_block(state->s.state, data, ASCON_XOF_RATE);
        ascon_prng_permute(ASCON_STATE(state));
        data += ASCON_XOF_RATE;
        size -= ASCON_XOF_RATE;
    }
    lw_xor_block(state->s.state, data, size);
    state->s.state[size] ^= 0x80; /* Padding */
    ascon_prng_permute(ASCON_STATE(state));

    /* Re-key the PRNG state */
    ascon_prng_rekey(ASCON_STATE(state));
}

/**
 * \brief Squeezes data out of a PRNG state.
 *
 * \param state PRNG state to squeeze from.
 * \param data Points to the data buffer to fill.
 * \param size Number of bytes to squeeze out of \a state.
 */
static void ascon_prng_squeeze
    (ascon_prng_state_t *state, unsigned char *data, size_t size)
{
    /* Squeeze as many rate-sized blocks as possible */
    while (size >= ASCON_XOF_RATE) {
        if (state->s.count >= state->s.limit)
            ascon_prng_reseed(state);
        memcpy(data, state->s.state, ASCON_XOF_RATE);
        ascon_prng_permute(ASCON_STATE(state));
        state->s.count += ASCON_XOF_RATE;
        data += ASCON_XOF_RATE;
        size -= ASCON_XOF_RATE;
    }

    /* Squeeze out the final block */
    if (size > 0) {
        if (state->s.count >= state->s.limit)
            ascon_prng_reseed(state);
        memcpy(data, state->s.state, size);
        ascon_prng_permute(ASCON_STATE(state));
        state->s.count += ASCON_XOF_RATE;
    }
}

void ascon_prng_fetch
    (ascon_prng_state_t *state, unsigned char *data, size_t size)
{
    ascon_prng_squeeze(state, data, size);
    ascon_prng_rekey(ASCON_STATE(state));
}

int ascon_prng_generate(unsigned char *data, size_t size)
{
    ascon_prng_state_t state;
    int have_trng = ascon_prng_init(&state);
    ascon_prng_squeeze(&state, data, size);
    ascon_prng_free(&state);
    return have_trng;
}
