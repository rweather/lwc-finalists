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

#include "internal-ghash.h"
#include <string.h>

#if GHASH_SHOUP_4BIT

/**
 * \brief Performs addition in the GF(2^128) field.
 *
 * \param result Returns the result of x + y.
 * \param x First value.
 * \param y Second value.
 */
#define gf128_add(result, x, y) \
    do { \
        (result).c[0] = (x).c[0] ^ (y).c[0]; \
        (result).c[1] = (x).c[1] ^ (y).c[1]; \
    } while (0)

/**
 * \brief Doubles a value in the GF(2^128) field.
 *
 * \param x The value to be doubled in-place.
 */
#define gf128_double(x) \
    do { \
        mask = ((~((x).c[1] & 0x01)) + 1) & 0xE100000000000000ULL; \
        (x).c[1] = ((x).c[1] >> 1) | ((x).c[0] << 63); \
        (x).c[0] = ((x).c[0] >> 1) ^ mask; \
    } while (0)

/* XOR adjustments for multiplying by 16 */
#define ADJ8 0xE100U
#define ADJ4 (ADJ8 >> 1)
#define ADJ2 (ADJ8 >> 2)
#define ADJ1 (ADJ8 >> 3)
static uint16_t const adjust[16] = {
    0,
    ADJ1,
    ADJ2,
    ADJ2 ^ ADJ1,
    ADJ4,
    ADJ4 ^ ADJ1,
    ADJ4 ^ ADJ2,
    ADJ4 ^ ADJ2 ^ ADJ1,
    ADJ8,
    ADJ8 ^ ADJ1,
    ADJ8 ^ ADJ2,
    ADJ8 ^ ADJ2 ^ ADJ1,
    ADJ8 ^ ADJ4,
    ADJ8 ^ ADJ4 ^ ADJ1,
    ADJ8 ^ ADJ4 ^ ADJ2,
    ADJ8 ^ ADJ4 ^ ADJ2 ^ ADJ1
};

/**
 * \brief Multiplies a value by 16 in the GF(2^128) field.
 *
 * \param x The value to be multiplied by 16.
 */
#define gf128_mul_16(x) \
    do { \
        nibble = (uint8_t)((x).c[1] & 0x0F); \
        (x).c[1] = ((x).c[1] >> 4) | ((x).c[0] << 60); \
        (x).c[0] = ((x).c[0] >> 4) ^ (((uint64_t)(adjust[nibble])) << 48); \
    } while (0)

#endif

/**
 * \fn void ghash_mul(ghash_state_t *state)
 * \brief Perform a multiplication in the GF(2^128) field.
 *
 * \param state Points to the GHASH state.
 */
#if GHASH_SHOUP_4BIT
static void ghash_mul(ghash_state_t *state)
{
    gf128_value_t Z;
    const unsigned char *Y = state->Y;
    uint8_t nibble;
    int posn;

    /* Multiply Z by V for the set bits in Y, starting at the bottom.
     * This version operates 4 bits at a time and is not constant cache. */

    /* Set Z to the hash key that is based on the lowest 4 bits */
    Z = state->H[Y[15] & 0x0F];

    /* Process the high nibble of the low byte */
    gf128_mul_16(Z);
    nibble = (Y[15] >> 4) & 0x0F;
    gf128_add(Z, Z, state->H[nibble]);

    /* Handle the remaining bytes from second lowest to highest */
    for (posn = 14; posn >= 0; --posn) {
        gf128_mul_16(Z);
        nibble = Y[posn] & 0x0F;
        gf128_add(Z, Z, state->H[nibble]);
        gf128_mul_16(Z);
        nibble = (Y[posn] >> 4) & 0x0F;
        gf128_add(Z, Z, state->H[nibble]);
    }

    /* Return the result in big endian byte order */
    be_store_word64(state->Y,     Z.c[0]);
    be_store_word64(state->Y + 8, Z.c[1]);
}
#else
static void ghash_mul(ghash_state_t *state)
{
    uint64_t Z0, Z1;
    uint64_t V0, V1;
    uint8_t posn;

    /* Set Z to 0 and V to H */
    Z0 = Z1 = 0;
    V0 = state->H.c[0];
    V1 = state->H.c[1];

    /* Multiply Z by V for the set bits in Y, starting at the top.
     * This is a very simple bit by bit version that may not be very
     * fast but it should be resistant to cache timing attacks. */
    for (posn = 0; posn < 16; ++posn) {
        uint8_t value = state->Y[posn];
        for (uint8_t bit = 0; bit < 8; ++bit, value <<= 1) {
            /* Extract the high bit of "value" and turn it into a mask */
            uint64_t mask = (~((uint64_t)(value >> 7))) + 1;

            /* XOR V with Z if the bit is 1 */
            Z0 ^= (V0 & mask);
            Z1 ^= (V1 & mask);

            /* Rotate V right by 1 bit */
            mask = ((~(V1 & 0x01)) + 1) & 0xE100000000000000ULL;
            V1 = (V1 >> 1) | (V0 << 63);
            V0 = (V0 >> 1) ^ mask;
        }
    }

    /* Set Y to the multiplication result */
    be_store_word64(state->Y,     Z0);
    be_store_word64(state->Y + 8, Z1);
}
#endif

void ghash_init(ghash_state_t *state, const unsigned char *key)
{
#if GHASH_SHOUP_4BIT
    gf128_value_t H;
    uint64_t mask;

    /* Load the hash key */
    H.c[0] = be_load_word64(key);
    H.c[1] = be_load_word64(key + 8);

    /* Pre-compute H values for input nibbles 0..15 which allows us to
     * do the calculations 4 bits at a time later using Shoup's method */

    /* H[0] is zero */
    state->H[0].c[0] = 0;
    state->H[0].c[1] = 0;

    /* H[8] is the input value */
    state->H[8] = H;

    /* H[4] is the input value times 2 */
    gf128_double(H);
    state->H[4] = H;

    /* H[2] is the input value times 4 */
    gf128_double(H);
    state->H[2] = H;

    /* H[1] is the input value times 8 */
    gf128_double(H);
    state->H[1] = H;

    /* Compute the other values via field addition */
    gf128_add(state->H[3],  state->H[2], state->H[1]);
    gf128_add(state->H[5],  state->H[4], state->H[1]);
    gf128_add(state->H[6],  state->H[4], state->H[2]);
    gf128_add(state->H[7],  state->H[4], state->H[3]);
    gf128_add(state->H[9],  state->H[8], state->H[1]);
    gf128_add(state->H[10], state->H[8], state->H[2]);
    gf128_add(state->H[11], state->H[8], state->H[3]);
    gf128_add(state->H[12], state->H[8], state->H[4]);
    gf128_add(state->H[13], state->H[8], state->H[5]);
    gf128_add(state->H[14], state->H[8], state->H[6]);
    gf128_add(state->H[15], state->H[8], state->H[7]);
#else
    state->H.c[0] = be_load_word64(key);
    state->H.c[1] = be_load_word64(key + 8);
#endif
    memset(state->Y, 0, sizeof(state->Y));
    state->posn = 0;
}

void ghash_update(ghash_state_t *state, const unsigned char *data, size_t size)
{
    /* Deal with a partial left-over block from last time */
    if (state->posn > 0) {
        size_t temp = 16 - state->posn;
        if (temp > size)
            temp = size;
        lw_xor_block(state->Y + state->posn, data, temp);
        state->posn += temp;
        if (state->posn < 16)
            return;
        ghash_mul(state);
        data += temp;
        size -= temp;
    }

    /* Process as many full blocks as possible */
    while (size >= 16) {
        lw_xor_block(state->Y, data, 16);
        ghash_mul(state);
        data += 16;
        size -= 16;
    }

    /* Handle any remaining left-over data */
    lw_xor_block(state->Y, data, size);
    state->posn = size;
}

void ghash_pad(ghash_state_t *state)
{
    if (state->posn != 0) {
        ghash_mul(state);
        state->posn = 0;
    }
}

void ghash_finalize(ghash_state_t *state, unsigned char *hash)
{
    ghash_pad(state);
    memcpy(hash, state->Y, sizeof(state->Y));
}
