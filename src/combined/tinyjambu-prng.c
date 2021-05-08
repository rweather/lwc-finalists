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

#include "tinyjambu-prng.h"
#include "internal-tinyjambu.h"
#include <string.h>

/**
 * \brief Number of key words for the TinyJAMBU PRNG key schedule.
 */
#define TINYJAMBU_PRNG_KEY_WORDS 8

/**
 * \brief Number of rounds to use when generating data with the PRNG.
 */
#define TINYJAMBU_PRNG_ROUNDS TINYJAMBU_ROUNDS(1280)

/**
 * \brief Number of rounds for absorbing data into the PRNG.
 */
#define TINYJAMBU_ABSORB_ROUNDS TINYJAMBU_ROUNDS(640)

/**
 * \brief Hash of all global identification information that was
 * added by calls to tinyjambu_prng_add_ident().
 *
 * The default value is the SHA-256 initialization vector.
 */
static uint32_t tinyjambu_id_pool[TINYJAMBU_PRNG_KEY_WORDS] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/**
 * \brief Sets up a TinyJAMBU key and state.
 *
 * \param ks Points to the key schedule to populate.
 * \param state Points to the state to initialize.
 * \param key Points to the key.
 * \param nonce Nonce or re-key counter for the setup operation.
 *
 * This uses a variation on the TinyJAMBU AEAD key and nonce setup procedure
 * that also absorbs the contents of the global identification pool.
 */
static void tinyjambu_prng_setup
    (tiny_jambu_key_word_t ks[TINYJAMBU_PRNG_KEY_WORDS],
     tiny_jambu_state_t *state, const unsigned char *key,
     unsigned long long nonce)
{
    int index;

    /* Load the words of the key and convert into the right form */
    for (index = 0; index < TINYJAMBU_PRNG_KEY_WORDS; index += 2) {
        ks[index] = tiny_jambu_key_load_even(key);
        ks[index + 1] = tiny_jambu_key_load_odd(key + 4);
        key += 8;
    }

    /* Initialize the state with the key */
    tiny_jambu_init_state(state);
    tiny_jambu_permutation_256(state, ks, TINYJAMBU_PRNG_ROUNDS);

    /* Absorb the three 32-bit words of the 96-bit AEAD nonce which is
     * the actual "nonce" value XOR'ed with the first three words of
     * the global identification pool. */
    tiny_jambu_add_domain(state, 0x10); /* Domain separator for the nonce */
    tiny_jambu_permutation_256(state, ks, TINYJAMBU_ABSORB_ROUNDS);
    tiny_jambu_absorb(state, ((uint32_t)nonce) ^ tinyjambu_id_pool[0]);
    tiny_jambu_add_domain(state, 0x10);
    tiny_jambu_permutation_256(state, ks, TINYJAMBU_ABSORB_ROUNDS);
    tiny_jambu_absorb(state, ((uint32_t)(nonce >> 32)) ^ tinyjambu_id_pool[1]);
    tiny_jambu_add_domain(state, 0x10);
    tiny_jambu_permutation_256(state, ks, TINYJAMBU_ABSORB_ROUNDS);
    tiny_jambu_absorb(state, tinyjambu_id_pool[2]);

    /* Absorb the rest of the global identification pool as associated data */
    for (index = 3; index < 8; ++index) {
        tiny_jambu_add_domain(state, 0x30); /* Domain sep for associated data */
        tiny_jambu_permutation_256(state, ks, TINYJAMBU_ABSORB_ROUNDS);
        tiny_jambu_absorb(state, tinyjambu_id_pool[index]);
    }
}

/**
 * \brief Absorbs data into the TinyJAMBU state.
 *
 * \param ks Points to the TinyJAMBU key schedule.
 * \param state Points to the TinyJAMBU state.
 * \param data Points to the data to be absorbed.
 * \param size Number of bytes of data to be absorbed.
 */
static void tinyjambu_prng_absorb
    (tiny_jambu_key_word_t ks[TINYJAMBU_PRNG_KEY_WORDS],
     tiny_jambu_state_t *state, const unsigned char *data, size_t size)
{
    /* Process as many full 32-bit words of input as we can */
    while (size >= 4) {
        tiny_jambu_add_domain(state, 0x30); /* Domain sep for associated data */
        tiny_jambu_permutation_256(state, ks, TINYJAMBU_ABSORB_ROUNDS);
        tiny_jambu_absorb(state, le_load_word32(data));
        data += 4;
        size -= 4;
    }

    /* Handle the left-over associated data bytes, if any */
    if (size == 1) {
        tiny_jambu_add_domain(state, 0x30);
        tiny_jambu_permutation_256(state, ks, TINYJAMBU_ABSORB_ROUNDS);
        tiny_jambu_absorb(state, data[0]);
        tiny_jambu_add_domain(state, 0x01);
    } else if (size == 2) {
        tiny_jambu_add_domain(state, 0x30);
        tiny_jambu_permutation_256(state, ks, TINYJAMBU_ABSORB_ROUNDS);
        tiny_jambu_absorb(state, le_load_word16(data));
        tiny_jambu_add_domain(state, 0x02);
    } else if (size == 3) {
        tiny_jambu_add_domain(state, 0x30);
        tiny_jambu_permutation_256(state, ks, TINYJAMBU_ABSORB_ROUNDS);
        tiny_jambu_absorb
            (state, le_load_word16(data) | (((uint32_t)(data[2])) << 16));
        tiny_jambu_add_domain(state, 0x03);
    }
}

/**
 * \brief Squeezes data from the TinyJAMBU state.
 *
 * \param ks Points to the TinyJAMBU key schedule.
 * \param state Points to the TinyJAMBU state.
 * \param data Points to the buffer to be filled with squeezed data.
 * \param size Number of bytes of data to be squeezed out.
 */
static void tinyjambu_prng_squeeze
    (tiny_jambu_key_word_t ks[TINYJAMBU_PRNG_KEY_WORDS],
     tiny_jambu_state_t *state, unsigned char *data, size_t size)
{
    while (size >= 4) {
        tiny_jambu_add_domain(state, 0x50); /* Domain sep for message data */
        tiny_jambu_permutation_256(state, ks, TINYJAMBU_PRNG_ROUNDS);
        le_store_word32(data, tiny_jambu_squeeze(state));
        data += 4;
        size -= 4;
    }
    if (size > 0) {
        uint32_t word;
        tiny_jambu_add_domain(state, 0x50);
        tiny_jambu_permutation_256(state, ks, TINYJAMBU_PRNG_ROUNDS);
        word = tiny_jambu_squeeze(state);
        if (size == 1) {
            data[0] = (unsigned char)word;
        } else if (size == 2) {
            data[0] = (unsigned char)word;
            data[1] = (unsigned char)(word >> 8);
        } else {
            data[0] = (unsigned char)word;
            data[1] = (unsigned char)(word >> 8);
            data[2] = (unsigned char)(word >> 16);
        }
    }
}

void tinyjambu_prng_add_ident(const unsigned char *data, size_t size)
{
    /* Use the AEAD mode as a hash to absorb the data into the pool */
    static unsigned char const ident_key[32] = {0};
    tiny_jambu_key_word_t ks[TINYJAMBU_PRNG_KEY_WORDS];
    tiny_jambu_state_t state;
    tinyjambu_prng_setup(ks, &state, ident_key, 0);
    tinyjambu_prng_absorb(ks, &state, data, size);
    tinyjambu_prng_squeeze
        (ks, &state, (unsigned char *)tinyjambu_id_pool,
         sizeof(tinyjambu_id_pool));
    aead_clean(ks, sizeof(ks));
    aead_clean(&state, sizeof(state));
}

int tinyjambu_prng_init(tinyjambu_prng_state_t *state)
{
    memset(state, 0, sizeof(tinyjambu_prng_state_t));
    state->s.limit = 16384;
    return tinyjambu_prng_reseed(state);
}

void tinyjambu_prng_free(tinyjambu_prng_state_t *state)
{
    aead_clean(state, sizeof(tinyjambu_prng_state_t));
}

int tinyjambu_prng_reseed(tinyjambu_prng_state_t *state)
{
    unsigned char seed[AEAD_SYSTEM_SEED_SIZE];
    int have_trng;

    /* Generate a TRNG seed and XOR it with the current PRNG key to
     * preserve some of the previous entropy in the PRNG state. */
    have_trng = aead_random_get_system_seed(seed);
    lw_xor_block(state->s.state, seed, sizeof(seed));
    aead_clean(seed, sizeof(seed));

    /* Re-key the PRNG by feeding zero bytes into it */
    tinyjambu_prng_feed(state, 0, 0);

    /* Reset the byte limit and return */
    state->s.count = 0;
    return have_trng;
}

void tinyjambu_prng_feed
    (tinyjambu_prng_state_t *state, const unsigned char *data, size_t size)
{
    tiny_jambu_key_word_t ks[TINYJAMBU_PRNG_KEY_WORDS];
    tiny_jambu_state_t tstate;

    /* Set up the TinyJAMBU state and absorb the input data */
    ++(state->s.rekeys);
    tinyjambu_prng_setup(ks, &tstate, state->s.state, state->s.rekeys);
    tinyjambu_prng_absorb(ks, &tstate, data, size);

    /* Squeeze out a new key */
    tinyjambu_prng_squeeze(ks, &tstate, state->s.state, 32);

    /* Clean up */
    aead_clean(ks, sizeof(ks));
    aead_clean(&tstate, sizeof(tstate));
}

/**
 * \brief Squeezes random data out of the PRNG and reseed whenever
 * the byte limit is reached.
 *
 * \param state Points to the PRNG state.
 * \param data Points to the buffer to fill with random data.
 * \param size Number of bytes of random data to generate.
 * \param rekey Non-zero to re-key the PRNG after generating the output.
 *
 * \return Zero if the PRNG was re-seeded from the system TRNG during
 * the squeeze but there is no system TRNG or it has failed.
 */
static int tinyjambu_prng_squeeze_and_reseed
    (tinyjambu_prng_state_t *state, unsigned char *data, size_t size, int rekey)
{
    tiny_jambu_key_word_t ks[TINYJAMBU_PRNG_KEY_WORDS];
    tiny_jambu_state_t tstate;
    int reseed_ok = 1;

    /* Set up to perform the fetch */
    ++(state->s.rekeys);
    tinyjambu_prng_setup(ks, &tstate, state->s.state, state->s.rekeys);

    /* Process as many 32-bit blocks as possible */
    while (size >= 4) {
        if (state->s.count >= state->s.limit) {
            reseed_ok &= tinyjambu_prng_reseed(state);
            ++(state->s.rekeys);
            tinyjambu_prng_setup(ks, &tstate, state->s.state, state->s.rekeys);
        }
        tiny_jambu_add_domain(&tstate, 0x50); /* Domain sep for message data */
        tiny_jambu_permutation_256(&tstate, ks, TINYJAMBU_PRNG_ROUNDS);
        le_store_word32(data, tiny_jambu_squeeze(&tstate));
        data += 4;
        size -= 4;
        state->s.count += 4;
    }

    /* Handle the last left-over block */
    if (size > 0) {
        uint32_t word;
        if (state->s.count >= state->s.limit) {
            reseed_ok &= tinyjambu_prng_reseed(state);
            ++(state->s.rekeys);
            tinyjambu_prng_setup(ks, &tstate, state->s.state, state->s.rekeys);
        }
        tiny_jambu_add_domain(&tstate, 0x50);
        tiny_jambu_permutation_256(&tstate, ks, TINYJAMBU_PRNG_ROUNDS);
        word = tiny_jambu_squeeze(&tstate);
        if (size == 1) {
            data[0] = (unsigned char)word;
        } else if (size == 2) {
            data[0] = (unsigned char)word;
            data[1] = (unsigned char)(word >> 8);
        } else {
            data[0] = (unsigned char)word;
            data[1] = (unsigned char)(word >> 8);
            data[2] = (unsigned char)(word >> 16);
        }
        state->s.count += 4;
    }

    /* Re-key and clean up */
    if (rekey)
        tinyjambu_prng_squeeze(ks, &tstate, state->s.state, 32);
    aead_clean(ks, sizeof(ks));
    aead_clean(&tstate, sizeof(tstate));
    return reseed_ok;
}

int tinyjambu_prng_fetch
    (tinyjambu_prng_state_t *state, unsigned char *data, size_t size)
{
    return tinyjambu_prng_squeeze_and_reseed(state, data, size, 1);
}

int tinyjambu_prng_generate(unsigned char *data, size_t size)
{
    int have_trng;
    tinyjambu_prng_state_t state;
    have_trng = tinyjambu_prng_init(&state);
    have_trng &= tinyjambu_prng_squeeze_and_reseed(&state, data, size, 0);
    tinyjambu_prng_free(&state);
    return have_trng;
}
