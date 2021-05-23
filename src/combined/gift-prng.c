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

#include "gift-prng.h"
#include "internal-gift128.h"
#include "internal-util.h"
#include <string.h>

/**
 * \brief Hash of all global identification information that was
 * added by calls to gift_prng_add_ident().
 *
 * The initial value is the result of using bitsliced GIFT-128 to
 * encrypt an all-zero block with an all-zero key.
 */
static unsigned char gift_id_pool[GIFT128_BLK_SIZE] = {
    0x5e, 0x8e, 0x3a, 0x2e, 0x16, 0x97, 0xa7, 0x7d,
    0xcc, 0x0b, 0x89, 0xdc, 0xd9, 0x7a, 0x64, 0xee
};

/**
 * \brief Re-keys the GIFT-128 PRNG by generating two output blocks
 * to form the new Key and V values for CTR_DRBG.
 *
 * \param state Points to the GIFT-128 PRNG state.
 * \param ks Key schedule that has been initialized with the previous key.
 */
static void gift_prng_rekey
    (gift_prng_state_t *state, gift128b_key_schedule_t *ks)
{
    /* We just assume that the state is in host endian byte order,
     * ready for gift128b_encrypt_preloaded().  One order is as good
     * as another when generating random data. */
    uint32_t *block = (uint32_t *)(state->s.state);
    ++(block[7]);
    gift128b_encrypt_preloaded(ks, block, block + 4);
    ++(block[7]);
    gift128b_encrypt_preloaded(ks, block + 4, block + 4);
}

/**
 * brief Re-keys the GIFT-128 PRNG, using a temporary key schedule.
 *
 * \param state Points to the Romulus PRNG state.
 */
static void gift_prng_rekey_2(gift_prng_state_t *state)
{
    gift128b_key_schedule_t ks;
    gift128b_init(&ks, state->s.state);
    gift_prng_rekey(state, &ks);
    aead_clean(&ks, sizeof(ks));
}

/**
 * \brief Derives a hash value from data that was fed into the PRNG.
 *
 * \param Points to the key schedule for encrypting blocks with the hash.
 * \param block Output buffer of 16 bytes in size for the hash.
 * \param index Index of the output hash block in the sequence.
 * \param out_len Desired number of output bytes.
 * \param data Points to the data to hash.
 * \param size Number of bytes of data to hash.
 *
 * This implements the "BCC" function from NIST-800-90A including the
 * length-prefixing from the "Block_Cipher_df" function.
 */
static void gift_prng_derive_hash
    (gift128b_key_schedule_t *ks, uint32_t *block,
     unsigned index, unsigned out_len,
     const unsigned char *data, size_t size)
{
    /* Set the chaining block to the index and encrypt it */
    block[0] = (uint32_t)index;
    block[1] = 0;
    block[2] = 0;
    block[3] = 0;
    gift128b_encrypt_preloaded(ks, block, block);

    /* XOR in the length of the data and the desired number of output bytes */
    block[0] ^= (uint32_t)size;
    block[1] ^= (uint32_t)out_len;

    /* Pad and absorb the input data in block-sized chunks, starting just
     * after the length values were absorbed. */
    if (size < 8) {
        lw_xor_block((unsigned char *)(block + 2), data, size);
        ((unsigned char *)(block + 2))[size] ^= 0x80;
    } else {
        lw_xor_block((unsigned char *)(block + 2), data, 8);
        gift128b_encrypt_preloaded(ks, block, block);
        data += 8;
        size -= 8;
        while (size >= GIFT128_BLK_SIZE) {
            lw_xor_block((unsigned char *)block, data, GIFT128_BLK_SIZE);
            gift128b_encrypt_preloaded(ks, block, block);
            data += GIFT128_BLK_SIZE;
            size -= GIFT128_BLK_SIZE;
        }
        lw_xor_block((unsigned char *)block, data, size);
        ((unsigned char *)block)[size] ^= 0x80;
    }
    gift128b_encrypt_preloaded(ks, block, block);
}

void gift_prng_add_ident(const unsigned char *data, size_t size)
{
    /* Hash the incoming identification data with "BCC" from NIST-800-90A */
    gift128b_key_schedule_t ks;
    uint32_t block[4];
    gift128b_init(&ks, gift_id_pool);
    gift_prng_derive_hash(&ks, block, 16, 0, data, size);
    memcpy(gift_id_pool, block, GIFT128_BLK_SIZE);
    aead_clean(&ks, sizeof(ks));
    aead_clean(block, sizeof(block));
}

int gift_prng_init(gift_prng_state_t *state)
{
    /* The definition of CTR_DRBG_Instantiate in NIST-800-90A is as follows
     * when instantiated with GIFT-128:
     *
     * 1. Set the Key and V values to zero and generate 2 blocks of output.
     * 2. XOR the output with the 256-bit TRNG seed to create the initial
     *    Key and V values for the PRNG.
     *
     * We also XOR the global identification pool with the first 16 bytes
     * of the TRNG seed to provide device-specific domain separation.
     *
     * We note that step 1 can be pre-computed as it is always the same.
     *
     * Due to the use of gift128b_encrypt_preloaded(), the second half
     * of the IV value should be byte-swapped on little-endian systems.
     * But the endian-ness isn't critical when generating random data;
     * one bit order is just as good as another.  So we ignore it.
     */
    static unsigned char const iv[32] = {
        0xcc, 0xa2, 0xbc, 0x93, 0x57, 0x3f, 0x0b, 0xf5,
        0xcd, 0x62, 0xa0, 0x5c, 0xd3, 0x1a, 0x43, 0xf7,
        0xa1, 0x29, 0x66, 0xa3, 0x40, 0xf0, 0x50, 0xb8,
        0x92, 0x39, 0xed, 0x36, 0x11, 0xd1, 0xe0, 0x7d
    };

    /* Initialize the state with the TRNG seed, IV, and identification pool */
    int have_trng = aead_random_get_system_seed(state->s.state);
    lw_xor_block(state->s.state, iv, sizeof(iv));
    lw_xor_block(state->s.state, gift_id_pool, sizeof(gift_id_pool));

    /* Set the byte counter and default byte limit */
    state->s.count = 0;
    state->s.limit = 16384;

    /* Re-key the PRNG for good measure.  Technically this isn't
     * required by the NIST CTR_DRBG design.  We do it to provide
     * forward security to the TRNG output and to scatter the entropy
     * to the entire state if the TRNG's entropy is poor. */
    gift_prng_rekey_2(state);
    return have_trng;
}

void gift_prng_free(gift_prng_state_t *state)
{
    aead_clean(state, sizeof(gift_prng_state_t));
}

/**
 * \brief Re-seeds the PRNG using a pre-initialized key schedule.
 *
 * \param state Points to the PRNG state to be re-seeded.
 * \param ks Points to the key schedule.
 *
 * This function generates 32 bytes of output and XOR's it with
 * 32 bytes from the system TRNG to generate the new state.
 */
static int gift_prng_reseed_with_schedule
    (gift_prng_state_t *state, gift128b_key_schedule_t *ks)
{
    unsigned char seed[AEAD_SYSTEM_SEED_SIZE];
    int have_trng;
    gift_prng_rekey(state, ks);
    have_trng = aead_random_get_system_seed(seed);
    lw_xor_block(state->s.state, seed, sizeof(seed));
    aead_clean(seed, sizeof(seed));
    state->s.count = 0;
    return have_trng;
}

int gift_prng_reseed(gift_prng_state_t *state)
{
    int have_trng;
    gift128b_key_schedule_t ks;
    gift128b_init(&ks, state->s.state);
    have_trng = gift_prng_reseed_with_schedule(state, &ks);
    aead_clean(&ks, sizeof(ks));
    return have_trng;
}

void gift_prng_feed
    (gift_prng_state_t *state, const unsigned char *data, size_t size)
{
    static unsigned char const derivation_key[16] = {
        /* Fixed derivation key from NIST-800-90A */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    gift128b_key_schedule_t ks;
    uint32_t temp[8];

    /* Re-key the PRNG state */
    gift128b_init(&ks, state->s.state);
    gift_prng_rekey(state, &ks);

    /* Use the block cipher based derivation function "Block_Cipher_df"
     * from NIST-800-90A to hash the data and absorb it into the state. */
    gift128b_init(&ks, derivation_key);
    gift_prng_derive_hash(&ks, temp, 32, 0, data, size);
    gift_prng_derive_hash(&ks, temp + 4, 32, 1, data, size);
    gift128b_init(&ks, (unsigned char *)temp);
    gift128b_encrypt_preloaded(&ks, temp + 4, temp + 4);
    lw_xor_block(state->s.state, (const unsigned char *)(temp + 4), 16);
    gift128b_encrypt_preloaded(&ks, temp + 4, temp + 4);
    lw_xor_block(state->s.state + 16, (const unsigned char *)(temp + 4), 16);

    /* Clean up */
    aead_clean(&ks, sizeof(ks));
    aead_clean(temp, sizeof(temp));
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
static int gift_prng_squeeze
    (gift_prng_state_t *state, unsigned char *data, size_t size, int rekey)
{
    gift128b_key_schedule_t ks;
    uint32_t *input = ((uint32_t *)(state->s.state)) + 4;
    uint32_t output[4];
    int reseed_ok = 1;

#if !defined(__SIZEOF_SIZE_T__) || __SIZEOF_SIZE_T__ >= 4
    /* Our block counter is 32-bit, but we impose a practical limit of 1Mb.
     * This corresponds to a 16-bit block counter in the NIST sense. */
    if (state->s.limit > 1048576U)
        state->s.limit = 1048576U;
#endif

    /* Set up the key schedule */
    gift128b_init(&ks, state->s.state);

    /* Generate the requested number of bytes in CTR mode */
    while (size >= GIFT128_BLK_SIZE) {
        if (state->s.count >= state->s.limit) {
            reseed_ok &= gift_prng_reseed_with_schedule(state, &ks);
            gift128b_init(&ks, state->s.state);
        }
        ++(input[3]);
        gift128b_encrypt_preloaded(&ks, output, input);
        memcpy(data, output, GIFT128_BLK_SIZE);
        data += GIFT128_BLK_SIZE;
        size -= GIFT128_BLK_SIZE;
        state->s.count += GIFT128_BLK_SIZE;
    }
    if (size > 0) {
        if (state->s.count >= state->s.limit) {
            reseed_ok &= gift_prng_reseed_with_schedule(state, &ks);
            gift128b_init(&ks, state->s.state);
        }
        ++(input[3]);
        gift128b_encrypt_preloaded(&ks, output, input);
        memcpy(data, output, size);
        state->s.count += GIFT128_BLK_SIZE;
    }

    /* Re-key and clean up */
    if (rekey)
        gift_prng_rekey(state, &ks);
    aead_clean(&ks, sizeof(ks));
    aead_clean(output, sizeof(output));
    return reseed_ok;
}

int gift_prng_fetch
    (gift_prng_state_t *state, unsigned char *data, size_t size)
{
    return gift_prng_squeeze(state, data, size, 1);
}

int gift_prng_generate(unsigned char *data, size_t size)
{
    gift_prng_state_t state;
    int have_trng = gift_prng_init(&state);
    have_trng &= gift_prng_squeeze(&state, data, size, 0);
    gift_prng_free(&state);
    return have_trng;
}
