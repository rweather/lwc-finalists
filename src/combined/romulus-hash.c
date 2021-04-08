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

#include "romulus-hash.h"
#include "internal-skinny-plus.h"
#include <string.h>

/**
 * \var ROMULUS_HASH_KEY_SCHEDULE
 * \brief Define to 1 to use a full key schedule for the hash block operation.
 *
 * This option will use a significant amount of stack space but may be
 * faster because it avoids expanding the key schedule twice in the
 * skinny_plus_encrypt_tk_full() calls within romulus_hash_process_chunk().
 */
#if defined(__AVR__)
#define ROMULUS_HASH_KEY_SCHEDULE 0
#elif SKINNY_PLUS_VARIANT == SKINNY_PLUS_VARIANT_FULL
#define ROMULUS_HASH_KEY_SCHEDULE 1
#else
#define ROMULUS_HASH_KEY_SCHEDULE 0
#endif

/**
 * \brief Number of bytes in a rate block for Romulus-H+.
 */
#define ROMULUS_HASH_RATE 32

aead_hash_algorithm_t const romulus_hash_algorithm = {
    "Romulus-H+",
    sizeof(romulus_hash_state_t),
    ROMULUS_HASH_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    romulus_hash,
    (aead_hash_init_t)romulus_hash_init,
    (aead_hash_update_t)romulus_hash_update,
    (aead_hash_finalize_t)romulus_hash_finalize,
    (aead_xof_absorb_t)0,
    (aead_xof_squeeze_t)0
};

int romulus_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
    romulus_hash_state_t state;
    romulus_hash_init(&state);
    romulus_hash_update(&state, in, inlen);
    romulus_hash_finalize(&state, out);
    return 0;
}

void romulus_hash_init(romulus_hash_state_t *state)
{
    memset(state, 0, sizeof(romulus_hash_state_t));
}

/**
 * \brief Processes a full chunk of input data.
 *
 * \param Points to the Romulus-H+ hash state.
 */
static void romulus_hash_process_chunk(romulus_hash_state_t *state)
{
    /*
     * TK = M + S1 is 32 bytes of the message followed by the 16 byte S1 value.
     * S2 is a separate 16 byte rolling state value.  Compute:
     *
     *      S1' = encrypt(M + S1, S2)
     *      S2' = encrypt(M + S1, S2 ^ 0x80)
     */
#if ROMULUS_HASH_KEY_SCHEDULE
    unsigned char s1[16];
    skinny_plus_key_schedule_t ks;
    skinny_plus_init(&ks, state->s.tk);
    skinny_plus_encrypt(&ks, s1, state->s.s2);
    state->s.s2[0] ^= 0x80;
    skinny_plus_encrypt(&ks, state->s.s2, state->s.s2);
    memcpy(state->s.tk + 32, s1, 16);
#else
    unsigned char s1[16];
    skinny_plus_encrypt_tk_full(state->s.tk, s1, state->s.s2);
    state->s.s2[0] ^= 0x80;
    skinny_plus_encrypt_tk_full(state->s.tk, state->s.s2, state->s.s2);
    memcpy(state->s.tk + 32, s1, 16);
#endif
}

void romulus_hash_update
    (romulus_hash_state_t *state, const unsigned char *in,
     unsigned long long inlen)
{
    unsigned temp;

    if (state->s.mode) {
        /* We were squeezing output - go back to the absorb phase */
        state->s.mode = 0;
        state->s.count = 0;
        romulus_hash_process_chunk(state);
    }

    /* Handle the partial left-over block from last time */
    if (state->s.count) {
        temp = ROMULUS_HASH_RATE - state->s.count;
        if (temp > inlen) {
            temp = (unsigned)inlen;
            memcpy(state->s.tk + state->s.count, in, temp);
            state->s.count += temp;
            return;
        }
        memcpy(state->s.tk + state->s.count, in, temp);
        state->s.count = 0;
        in += temp;
        inlen -= temp;
        romulus_hash_process_chunk(state);
    }

    /* Process full blocks that are aligned at state->s.count == 0 */
    while (inlen >= ROMULUS_HASH_RATE) {
        memcpy(state->s.tk, in, ROMULUS_HASH_RATE);
        in += ROMULUS_HASH_RATE;
        inlen -= ROMULUS_HASH_RATE;
        romulus_hash_process_chunk(state);
    }

    /* Process the left-over block at the end of the input */
    temp = (unsigned)inlen;
    memcpy(state->s.tk, in, temp);
    state->s.count = temp;
}

void romulus_hash_finalize(romulus_hash_state_t *state, unsigned char *out)
{
    if (!state->s.mode) {
        /* We were still absorbing, so pad and process the last chunk */
        state->s.tk[state->s.count] = 0x80;
        memset(state->s.tk + state->s.count + 1, 0,
               ROMULUS_HASH_RATE - 1 - state->s.count);
        romulus_hash_process_chunk(state);
        state->s.mode = 1;
        state->s.count = 0;
    }

    /* The hash value is S1 concatenated with S2 */
    memcpy(out, state->s.tk + 32, 16);
    memcpy(out + 16, state->s.s2, 16);
}
