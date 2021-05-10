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

/**
 * \brief Perform a multiplication in the GF(2^128) field.
 *
 * \param state Points to the GHASH state.
 */
static void ghash_mul(ghash_state_t *state)
{
    uint32_t Z0, Z1, Z2, Z3;
    uint32_t V0, V1, V2, V3;
    uint8_t posn;

    /* Set Z to 0 and V to H */
    Z0 = Z1 = Z2 = Z3 = 0;
    V0 = state->H[0];
    V1 = state->H[1];
    V2 = state->H[2];
    V3 = state->H[3];

    /* Multiply Z by V for the set bits in Y, starting at the top.
     * This is a very simple bit by bit version that may not be very
     * fast but it should be resistant to cache timing attacks. */
    for (posn = 0; posn < 16; ++posn) {
        uint8_t value = state->Y[posn];
        for (uint8_t bit = 0; bit < 8; ++bit, value <<= 1) {
            /* Extract the high bit of "value" and turn it into a mask */
            uint32_t mask = (~((uint32_t)(value >> 7))) + 1;

            /* XOR V with Z if the bit is 1 */
            Z0 ^= (V0 & mask);
            Z1 ^= (V1 & mask);
            Z2 ^= (V2 & mask);
            Z3 ^= (V3 & mask);

            /* Rotate V right by 1 bit */
            mask = ((~(V3 & 0x01)) + 1) & 0xE1000000;
            V3 = (V3 >> 1) | (V2 << 31);
            V2 = (V2 >> 1) | (V1 << 31);
            V1 = (V1 >> 1) | (V0 << 31);
            V0 = (V0 >> 1) ^ mask;
        }
    }

    /* Set Y to the multiplication result */
    be_store_word32(state->Y,      Z0);
    be_store_word32(state->Y + 4,  Z1);
    be_store_word32(state->Y + 8,  Z2);
    be_store_word32(state->Y + 12, Z3);
}

void ghash_init(ghash_state_t *state, const unsigned char *key)
{
    memset(state->Y, 0, sizeof(state->Y));
    state->H[0] = be_load_word32(key);
    state->H[1] = be_load_word32(key + 4);
    state->H[2] = be_load_word32(key + 8);
    state->H[3] = be_load_word32(key + 12);
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
