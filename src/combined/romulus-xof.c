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

#include "romulus-xof.h"
#include "internal-util.h"
#include <string.h>

int romulus_xof
    (unsigned char *out, const unsigned char *in, size_t inlen)
{
    romulus_xof_state_t state;
    romulus_xof_init(&state);
    romulus_xof_absorb(&state, in, inlen);
    romulus_xof_squeeze(&state, out, ROMULUS_HASH_SIZE);
    return 0;
}

void romulus_xof_init(romulus_xof_state_t *state)
{
    memset(state, 0, sizeof(romulus_xof_state_t));
}

void romulus_xof_absorb
    (romulus_xof_state_t *state, const unsigned char *in, size_t inlen)
{
    romulus_hash_update(&(state->hash), in, inlen);
}

/* Defined in romulus_hash.c */
extern void romulus_hash_process_chunk(romulus_hash_state_t *state);

/**
 * \brief Squeeze out a single block of output using Romulus-H and MGF1.
 *
 * \param state Points to the XOF state.
 * \param out Points to a buffer of ROMULUS_HASH_SIZE bytes in size
 * to receive the squeezed output.
 */
static void romulus_xof_squeeze_block
    (romulus_xof_state_t *state, unsigned char *out)
{
    romulus_hash_state_t temp = state->hash;
    be_store_word32(temp.s.tk + 16, (uint32_t)(state->mgf1_count));
    memset(temp.s.tk + 20, 0, ROMULUS_HASH_RATE - 5);
    temp.s.tk[47] = 0x04;
    temp.s.h[0] ^= 0x02;
    romulus_hash_process_chunk(&temp);
    memcpy(out, temp.s.h, 16);
    memcpy(out + 16, temp.s.tk, 16);
    ++(state->mgf1_count);
}

void romulus_xof_squeeze
    (romulus_xof_state_t *state, unsigned char *out, size_t outlen)
{
    size_t len;

    /* If we were still absorbing, then pad and process the last input chunk */
    if (!state->hash.s.mode) {
        memset(state->hash.s.tk + 16 + state->hash.s.count, 0,
               ROMULUS_HASH_RATE - 1 - state->hash.s.count);
        state->hash.s.tk[47] = state->hash.s.count;
        romulus_hash_process_chunk(&(state->hash));
        state->hash.s.mode = 1;
        state->hash.s.count = ROMULUS_HASH_SIZE;
        state->mgf1_count = 0;
    }

    /* Deal with left-over data from last time */
    len = ROMULUS_HASH_SIZE - state->hash.s.count;
    if (len > outlen)
        len = outlen;
    memcpy(out, state->out + state->hash.s.count, len);
    out += len;
    outlen -= len;
    state->hash.s.count += len;

    /* Handle full output blocks */
    while (outlen >= ROMULUS_HASH_SIZE) {
        romulus_xof_squeeze_block(state, out);
        out += ROMULUS_HASH_SIZE;
        outlen -= ROMULUS_HASH_SIZE;
    }

    /* Deal with the final left-over block */
    if (outlen > 0) {
        romulus_xof_squeeze_block(state, state->out);
        memcpy(out, state->out, outlen);
        state->hash.s.count = outlen;
    }
}
