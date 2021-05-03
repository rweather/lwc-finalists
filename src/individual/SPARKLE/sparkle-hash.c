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

#include "sparkle-hash.h"
#include "internal-sparkle.h"
#include <string.h>

/**
 * \def DOMAIN(value)
 * \brief Build a domain separation value as a 32-bit word.
 *
 * \param value The base value.
 * \return The domain separation value as a 32-bit word.
 */
#if defined(LW_UTIL_LITTLE_ENDIAN)
#define DOMAIN(value) (((uint32_t)(value)) << 24)
#else
#define DOMAIN(value) (value)
#endif

/**
 * \brief Rate at which bytes are processed by Esch256.
 */
#define ESCH_256_RATE 16

/**
 * \brief Perform the M3 step for Esch256 to mix the input with the state.
 *
 * \param s SPARKLE-384 state.
 * \param block Block of input data that has been padded to the rate.
 * \param domain Domain separator for this phase.
 */
#define esch_256_m3(s, block, domain) \
    do { \
        uint32_t tx = (block)[0] ^ (block)[2]; \
        uint32_t ty = (block)[1] ^ (block)[3]; \
        tx = leftRotate16(tx ^ (tx << 16)); \
        ty = leftRotate16(ty ^ (ty << 16)); \
        s[0] ^= (block)[0] ^ ty; \
        s[1] ^= (block)[1] ^ tx; \
        s[2] ^= (block)[2] ^ ty; \
        s[3] ^= (block)[3] ^ tx; \
        if ((domain) != 0) \
            s[5] ^= DOMAIN(domain); \
        s[4] ^= ty; \
        s[5] ^= tx; \
    } while (0)

/** @cond esch_256 */

/**
 * \brief Word-based state for the Esch256 incremental hash mode.
 */
typedef union
{
    struct {
        uint32_t state[SPARKLE_384_STATE_SIZE];
        uint32_t block[4];
        unsigned char count;
    } s;
    size_t align;

} esch_256_hash_state_wt;

/** @endcond */

int esch_256_hash
    (unsigned char *out, const unsigned char *in, size_t inlen)
{
    uint32_t s[SPARKLE_384_STATE_SIZE];
    uint32_t block[ESCH_256_RATE / 4];
    memset(s, 0, sizeof(s));
    while (inlen > ESCH_256_RATE) {
        memcpy(block, in, ESCH_256_RATE);
        esch_256_m3(s, block, 0x00);
        sparkle_384(s, 7);
        in += ESCH_256_RATE;
        inlen -= ESCH_256_RATE;
    }
    if (inlen == ESCH_256_RATE) {
        memcpy(block, in, ESCH_256_RATE);
        esch_256_m3(s, block, 0x02);
    } else {
        unsigned temp = (unsigned)inlen;
        memcpy(block, in, temp);
        ((unsigned char *)block)[temp] = 0x80;
        memset(((unsigned char *)block) + temp + 1, 0,
               ESCH_256_RATE - temp - 1);
        esch_256_m3(s, block, 0x01);
    }
    sparkle_384(s, 11);
    memcpy(out, s, ESCH_256_RATE);
    sparkle_384(s, 7);
    memcpy(out + ESCH_256_RATE, s, ESCH_256_RATE);
    return 0;
}

void esch_256_hash_init(esch_256_hash_state_t *state)
{
    memset(state, 0, sizeof(esch_256_hash_state_t));
}

void esch_256_hash_update
    (esch_256_hash_state_t *state, const unsigned char *in, size_t inlen)
{
    esch_256_hash_state_wt *st = (esch_256_hash_state_wt *)state;
    unsigned temp;
    while (inlen > 0) {
        if (st->s.count == ESCH_256_RATE) {
            esch_256_m3(st->s.state, st->s.block, 0x00);
            sparkle_384(st->s.state, 7);
            st->s.count = 0;
        }
        temp = ESCH_256_RATE - st->s.count;
        if (temp > inlen)
            temp = (unsigned)inlen;
        memcpy(((unsigned char *)(st->s.block)) + st->s.count, in, temp);
        st->s.count += temp;
        in += temp;
        inlen -= temp;
    }
}

void esch_256_hash_finalize
    (esch_256_hash_state_t *state, unsigned char *out)
{
    esch_256_hash_state_wt *st = (esch_256_hash_state_wt *)state;

    /* Pad and process the last block */
    if (st->s.count == ESCH_256_RATE) {
        esch_256_m3(st->s.state, st->s.block, 0x02);
    } else {
        unsigned temp = st->s.count;
        ((unsigned char *)(st->s.block))[temp] = 0x80;
        memset(((unsigned char *)(st->s.block)) + temp + 1, 0,
               ESCH_256_RATE - temp - 1);
        esch_256_m3(st->s.state, st->s.block, 0x01);
    }
    sparkle_384(st->s.state, 11);

    /* Generate the final hash value */
    memcpy(out, st->s.state, ESCH_256_RATE);
    sparkle_384(st->s.state, 7);
    memcpy(out + ESCH_256_RATE, st->s.state, ESCH_256_RATE);
}

/**
 * \brief Rate at which bytes are processed by Esch384.
 */
#define ESCH_384_RATE 16

/**
 * \brief Perform the M4 step for Esch384 to mix the input with the state.
 *
 * \param s SPARKLE-512 state.
 * \param block Block of input data that has been padded to the rate.
 * \param domain Domain separator for this phase.
 */
#define esch_384_m4(s, block, domain) \
    do { \
        uint32_t tx = block[0] ^ block[2]; \
        uint32_t ty = block[1] ^ block[3]; \
        tx = leftRotate16(tx ^ (tx << 16)); \
        ty = leftRotate16(ty ^ (ty << 16)); \
        s[0] ^= block[0] ^ ty; \
        s[1] ^= block[1] ^ tx; \
        s[2] ^= block[2] ^ ty; \
        s[3] ^= block[3] ^ tx; \
        if ((domain) != 0) \
            s[7] ^= DOMAIN(domain); \
        s[4] ^= ty; \
        s[5] ^= tx; \
        s[6] ^= ty; \
        s[7] ^= tx; \
    } while (0)

/** @cond esch_384 */

/**
 * \brief Word-based state for the Esch384 incremental hash mode.
 */
typedef union
{
    struct {
        uint32_t state[SPARKLE_512_STATE_SIZE];
        uint32_t block[4];
        unsigned char count;
    } s;
    size_t align;

} esch_384_hash_state_wt;

/** @endcond */

int esch_384_hash
    (unsigned char *out, const unsigned char *in, size_t inlen)
{
    uint32_t s[SPARKLE_512_STATE_SIZE];
    uint32_t block[ESCH_256_RATE / 4];
    memset(s, 0, sizeof(s));
    while (inlen > ESCH_384_RATE) {
        memcpy(block, in, ESCH_384_RATE);
        esch_384_m4(s, block, 0x00);
        sparkle_512(s, 8);
        in += ESCH_384_RATE;
        inlen -= ESCH_384_RATE;
    }
    if (inlen == ESCH_384_RATE) {
        memcpy(block, in, ESCH_384_RATE);
        esch_384_m4(s, block, 0x02);
    } else {
        unsigned temp = (unsigned)inlen;
        memcpy(block, in, temp);
        ((unsigned char *)block)[temp] = 0x80;
        memset(((unsigned char *)block) + temp + 1, 0,
               ESCH_384_RATE - temp - 1);
        esch_384_m4(s, block, 0x01);
    }
    sparkle_512(s, 12);
    memcpy(out, s, ESCH_384_RATE);
    sparkle_512(s, 8);
    memcpy(out + ESCH_384_RATE, s, ESCH_384_RATE);
    sparkle_512(s, 8);
    memcpy(out + ESCH_384_RATE * 2, s, ESCH_384_RATE);
    return 0;
}

void esch_384_hash_init(esch_384_hash_state_t *state)
{
    memset(state, 0, sizeof(esch_384_hash_state_t));
}

void esch_384_hash_update
    (esch_384_hash_state_t *state, const unsigned char *in, size_t inlen)
{
    esch_384_hash_state_wt *st = (esch_384_hash_state_wt *)state;
    unsigned temp;
    while (inlen > 0) {
        if (st->s.count == ESCH_384_RATE) {
            esch_384_m4(st->s.state, st->s.block, 0x00);
            sparkle_512(st->s.state, 8);
            st->s.count = 0;
        }
        temp = ESCH_384_RATE - st->s.count;
        if (temp > inlen)
            temp = (unsigned)inlen;
        memcpy(((unsigned char *)(st->s.block)) + st->s.count, in, temp);
        st->s.count += temp;
        in += temp;
        inlen -= temp;
    }
}

void esch_384_hash_finalize
    (esch_384_hash_state_t *state, unsigned char *out)
{
    esch_384_hash_state_wt *st = (esch_384_hash_state_wt *)state;

    /* Pad and process the last block */
    if (st->s.count == ESCH_384_RATE) {
        esch_384_m4(st->s.state, st->s.block, 0x02);
    } else {
        unsigned temp = st->s.count;
        ((unsigned char *)(st->s.block))[temp] = 0x80;
        memset(((unsigned char *)(st->s.block)) + temp + 1, 0,
               ESCH_384_RATE - temp - 1);
        esch_384_m4(st->s.state, st->s.block, 0x01);
    }
    sparkle_512(st->s.state, 12);

    /* Generate the final hash value */
    memcpy(out, st->s.state, ESCH_384_RATE);
    sparkle_512(st->s.state, 8);
    memcpy(out + ESCH_384_RATE, st->s.state, ESCH_384_RATE);
    sparkle_512(st->s.state, 8);
    memcpy(out + ESCH_384_RATE * 2, st->s.state, ESCH_384_RATE);
}
