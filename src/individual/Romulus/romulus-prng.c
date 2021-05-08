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

#include "romulus-prng.h"
#include "romulus-hash.h"
#include "internal-skinny-plus.h"
#include "internal-util.h"
#include <string.h>

/**
 * \brief Hash of all global identification information that was
 * added by calls to romulus_prng_add_ident().
 *
 * The initial value is the result of hashing the empty string with Romulus-H.
 */
static unsigned char romulus_id_pool[ROMULUS_HASH_SIZE] = {
    0x24, 0x9B, 0x3F, 0x43, 0x70, 0x03, 0x0B, 0x97,
    0x9F, 0x23, 0x0C, 0xE0, 0x50, 0x29, 0x36, 0x10,
    0x85, 0x76, 0x68, 0x58, 0x87, 0x9B, 0x31, 0x04,
    0x47, 0x42, 0xAF, 0xC4, 0xCD, 0xE6, 0xB5, 0xAB
};

/**
 * \brief Increment the 16-bit block counter in a Romulus PRNG state.
 *
 * \param state Points to the Romulus PRNG state.
 */
static void romulus_prng_inc_counter(romulus_prng_state_t *state)
{
    uint16_t counter = state->s.state[63];
    counter |= ((uint16_t)(state->s.state[62])) << 8;
    ++counter;
    state->s.state[63] = (unsigned char)counter;
    state->s.state[62] = (unsigned char)(counter >> 8);
}

/**
 * \brief Re-keys the Romulus PRNG by generating four output blocks
 * to form the new Key and V values for CTR_DRBG.
 *
 * \param state Points to the Romulus PRNG state.
 * \param ks Key schedule that has been initialized with the previous key.
 */
static void romulus_prng_rekey
    (romulus_prng_state_t *state, skinny_plus_key_schedule_t *ks)
{
    romulus_prng_inc_counter(state);
    skinny_plus_encrypt(ks, state->s.state, state->s.state + 48);
    romulus_prng_inc_counter(state);
    skinny_plus_encrypt(ks, state->s.state + 16, state->s.state + 48);
    romulus_prng_inc_counter(state);
    skinny_plus_encrypt(ks, state->s.state + 32, state->s.state + 48);
    romulus_prng_inc_counter(state);
    skinny_plus_encrypt(ks, state->s.state + 48, state->s.state + 48);
}

/**
 * brief Re-keys the Romulus PRNG, using a temporary key schedule.
 *
 * \param state Points to the Romulus PRNG state.
 */
static void romulus_prng_rekey_2(romulus_prng_state_t *state)
{
    skinny_plus_key_schedule_t ks;
    skinny_plus_init(&ks, state->s.state);
    romulus_prng_rekey(state, &ks);
    aead_clean(&ks, sizeof(ks));
}

/**
 * \brief Derives 64 bytes of output from an arbitrary amount of
 * input data using a derivation function based on Romulus-H.
 *
 * \param out 64-byte buffer to XOR the derived output against.
 * \param data1 Points to the first block of input data.
 * \param size1 Number of bytes in the first block of input data.
 * \param data2 Points to the second block of input data (optional).
 * \param size2 Number of bytes in the second block of input data.
 */
static void romulus_prng_derive
    (unsigned char *out, const unsigned char *data1, size_t size1,
     const unsigned char *data2, size_t size2)
{
    /* This is an implementation of "Hash_df" from NIST-800-90A for the
     * special case of 512-bit output, using the Romulus-H hash algorithm. */
    static unsigned char const prefix_1[5] = {0x01, 0x00, 0x00, 0x02, 0x00};
    static unsigned char const prefix_2[5] = {0x02, 0x00, 0x00, 0x02, 0x00};
    romulus_hash_state_t state;
    unsigned char hash[32];
    romulus_hash_init(&state);
    romulus_hash_update(&state, prefix_1, sizeof(prefix_1));
    romulus_hash_update(&state, data1, size1);
    romulus_hash_update(&state, data2, size2);
    romulus_hash_finalize(&state, hash);
    lw_xor_block(out, hash, 32);
    romulus_hash_init(&state);
    romulus_hash_update(&state, prefix_2, sizeof(prefix_2));
    romulus_hash_update(&state, data1, size1);
    romulus_hash_update(&state, data2, size2);
    romulus_hash_finalize(&state, hash);
    lw_xor_block(out + 32, hash, 32);
    aead_clean(&state, sizeof(state));
    aead_clean(hash, sizeof(hash));
}

void romulus_prng_add_ident(const unsigned char *data, size_t size)
{
    romulus_hash_state_t state;
    romulus_hash_init(&state);
    romulus_hash_update(&state, romulus_id_pool, sizeof(romulus_id_pool));
    romulus_hash_update(&state, data, size);
    romulus_hash_finalize(&state, romulus_id_pool);
    aead_clean(&state, sizeof(state));
}

int romulus_prng_init(romulus_prng_state_t *state)
{
    /* The definition of CTR_DRBG_Instantiate in NIST-800-90A is as follows
     * when instantiated with SKINNY-128-384+:
     *
     * 1. Set the Key and V values to zero and generate 4 blocks of output.
     * 2. Process the seed and global identification pool with a hash
     *    based derivation function.
     * 3. XOR the 4 blocks of output with the output of the derivation
     *    function to form the initial Key and V values for the PRNG.
     *
     * We note that step 1 can be pre-computed as it is always the same.
     *
     * The NIST process also requires a nonce as part of initialization
     * if the input may not have "full entropy".  We assume that
     * aead_random_get_system_seed() will return a distinct value each
     * time even if there is no TRNG.  This can act as the nonce.
     */
    static unsigned char const iv[64] = {
        0xf9, 0x59, 0x27, 0xbf, 0x8d, 0x92, 0xbf, 0xf1,
        0xcb, 0x07, 0xdb, 0x89, 0xef, 0x29, 0xb5, 0xf2,
        0x21, 0xde, 0x83, 0xed, 0xfc, 0x05, 0x52, 0xad,
        0x8b, 0x89, 0x6c, 0x1f, 0x9d, 0xc3, 0xcb, 0x3d,
        0xa2, 0x25, 0xe6, 0x73, 0x13, 0xb7, 0x07, 0x9e,
        0xad, 0x5f, 0x7b, 0xab, 0x25, 0x95, 0xd0, 0x6d,
        0xd3, 0x0a, 0xd2, 0x31, 0x00, 0xe9, 0x35, 0xa0,
        0x6d, 0x9c, 0xbd, 0xbd, 0x02, 0x58, 0x76, 0x32
    };
    unsigned char seed[AEAD_SYSTEM_SEED_SIZE];
    int have_trng = aead_random_get_system_seed(seed);
    memcpy(state->s.state, iv, sizeof(iv));
    romulus_prng_derive(state->s.state, seed, AEAD_SYSTEM_SEED_SIZE,
                        romulus_id_pool, sizeof(romulus_id_pool));
    aead_clean(seed, sizeof(seed));
    state->s.count = 0;
    state->s.limit = 16384;
    return have_trng;
}

void romulus_prng_free(romulus_prng_state_t *state)
{
    aead_clean(state, sizeof(romulus_prng_state_t));
}

int romulus_prng_reseed(romulus_prng_state_t *state)
{
    unsigned char seed[AEAD_SYSTEM_SEED_SIZE];
    int have_trng = aead_random_get_system_seed(seed);
    romulus_prng_feed(state, seed, sizeof(seed));
    aead_clean(seed, sizeof(seed));
    state->s.count = 0;
    return have_trng;
}

void romulus_prng_feed
    (romulus_prng_state_t *state, const unsigned char *data, size_t size)
{
    /* Generate 64 bytes of output from the PRNG to rekey the state */
    romulus_prng_rekey_2(state);

    /* Derive a 64 byte value from the input data and XOR it with the state */
    romulus_prng_derive(state->s.state, data, size, 0, 0);
}

/**
 * \brief Simpler version of re-seeding that avoids the derive step.
 *
 * \param state Points to the PRNG state.
 * \param ks Points to the memory for a temporary key schedule.
 *
 * This function is more memory efficient because it only needs one
 * SKINNY-128-384+ key schedule on the stack at a time.  If we were
 * to use romulus_prng_derive(), then we would need one schedule for
 * the PRNG and another internally within Romulus-H.
 */
static int romulus_prng_reseed_simple
    (romulus_prng_state_t *state, skinny_plus_key_schedule_t *ks)
{
    unsigned char seed[AEAD_SYSTEM_SEED_SIZE];
    int have_trng;

    /* Fetch a seed from the system TRNG and XOR it with the
     * TK2 and TK3 parts of the current key */
    have_trng = aead_random_get_system_seed(seed);
    lw_xor_block(state->s.state + 16, seed, AEAD_SYSTEM_SEED_SIZE);
    aead_clean(seed, sizeof(seed));

    /* Reset the byte counter that determines when the next reseed will occur */
    state->s.count = 0;

    /* Re-key the PRNG */
    skinny_plus_init(ks, state->s.state);
    romulus_prng_rekey(state, ks);

    /* Reset the key schedule to use the new key */
    skinny_plus_init(ks, state->s.state);
    return have_trng;
}

/**
 * \brief Squeezes random data out of the PRNG.
 *
 * \param state Points to the PRNG state.
 * \param data Points to the buffer to fill with random data.
 * \param size Number of bytes of random data to generate.
 * \param rekey Non-zero to re-key the PRNG after generating the output.
 *
 * \return Zero if the PRNG was re-seeded from the system TRNG during
 * the squeeze but there is no system TRNG or it has failed.
 */
static int romulus_prng_squeeze
    (romulus_prng_state_t *state, unsigned char *data, size_t size, int rekey)
{
    skinny_plus_key_schedule_t ks;
    int reseed_ok = 1;

#if !defined(__SIZEOF_SIZE_T__) || __SIZEOF_SIZE_T__ >= 4
    /* We have a practical limit of 1Mb due to the 16-bit block counter.
     * Restrict to just less than that before re-seeding.  We need four
     * extra blocks for re-keying after generating the output. */
    if (state->s.limit > 1048512U)
        state->s.limit = 1048512U;
#endif

    /* Set up the key schedule */
    skinny_plus_init(&ks, state->s.state);

    /* Generate the requested number of bytes in CTR mode */
    while (size >= SKINNY_PLUS_BLOCK_SIZE) {
        if (state->s.count >= state->s.limit)
            reseed_ok &= romulus_prng_reseed_simple(state, &ks);
        romulus_prng_inc_counter(state);
        skinny_plus_encrypt(&ks, data, state->s.state + 48);
        data += SKINNY_PLUS_BLOCK_SIZE;
        size -= SKINNY_PLUS_BLOCK_SIZE;
        state->s.count += SKINNY_PLUS_BLOCK_SIZE;
    }
    if (size > 0) {
        unsigned char block[SKINNY_PLUS_BLOCK_SIZE];
        if (state->s.count >= state->s.limit)
            reseed_ok &= romulus_prng_reseed_simple(state, &ks);
        romulus_prng_inc_counter(state);
        skinny_plus_encrypt(&ks, block, state->s.state + 48);
        memcpy(data, block, size);
        aead_clean(block, SKINNY_PLUS_BLOCK_SIZE);
        state->s.count += SKINNY_PLUS_BLOCK_SIZE;
    }

    /* Re-key and clean up */
    if (rekey)
        romulus_prng_rekey(state, &ks);
    aead_clean(&ks, sizeof(ks));
    return reseed_ok;
}

int romulus_prng_fetch
    (romulus_prng_state_t *state, unsigned char *data, size_t size)
{
    return romulus_prng_squeeze(state, data, size, 1);
}

int romulus_prng_generate(unsigned char *data, size_t size)
{
    romulus_prng_state_t state;
    int have_trng = romulus_prng_init(&state);
    have_trng &= romulus_prng_squeeze(&state, data, size, 0);
    aead_clean(&state, sizeof(state));
    return have_trng;
}
