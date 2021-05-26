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

#include "sparkle-kmac.h"
#include "internal-util.h"
#include <string.h>

/* The actual implementation is in the common "internal-kmac.h" file */

/* XOEsch256-KMAC */
static void esch_256_hash_pad(esch_256_hash_state_t *state)
{
    static unsigned char padding[ESCH_256_RATE] = {0};
    if (state->s.count != 0)
        esch_256_hash_update(state, padding, ESCH_256_RATE - state->s.count);
}
#define KMAC_ALG_NAME esch_256_kmac
#define KMAC_SIZE ESCH_256_KMAC_SIZE
#define KMAC_STATE esch_256_kmac_state_t
#define KMAC_RATE ESCH_256_RATE
#define KMAC_XOF_INIT esch_256_hash_init
#define KMAC_XOF_ABSORB esch_256_hash_update
#define KMAC_XOF_SQUEEZE esch_256_hash_squeeze
#define KMAC_XOF_PAD esch_256_hash_pad
#define KMAC_XOF_IS_ABSORBING(state) ((state)->s.mode == 0)
#include "internal-kmac.h"

/* XOEsch384-KMAC */
static void esch_384_hash_pad(esch_384_hash_state_t *state)
{
    static unsigned char padding[ESCH_384_RATE] = {0};
    if (state->s.count != 0)
        esch_384_hash_update(state, padding, ESCH_384_RATE - state->s.count);
}
#define KMAC_ALG_NAME esch_384_kmac
#define KMAC_SIZE ESCH_384_KMAC_SIZE
#define KMAC_STATE esch_384_kmac_state_t
#define KMAC_RATE ESCH_384_RATE
#define KMAC_XOF_INIT esch_384_hash_init
#define KMAC_XOF_ABSORB esch_384_hash_update
#define KMAC_XOF_SQUEEZE esch_384_hash_squeeze
#define KMAC_XOF_PAD esch_384_hash_pad
#define KMAC_XOF_IS_ABSORBING(state) ((state)->s.mode == 0)
#include "internal-kmac.h"
