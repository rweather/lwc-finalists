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

/*
 * This file contains a default PRNG implementation based on ChaCha20 and
 * seed data from the system TRNG.  The plan is to eventually replace this
 * with better PRNG's based on the finalists to the NIST Lightweight
 * Cryptography Competition.
 *
 * WARNING: The functions in this file are not thread-safe!
 */

#include "aead-random.h"
#include "internal-util.h"
#include <string.h>

/* Perform a ChaCha quarter round operation */
#define quarterRound(a, b, c, d)    \
    do { \
        uint32_t _b = (b); \
        uint32_t _a = (a) + _b; \
        uint32_t _d = leftRotate16((d) ^ _a); \
        uint32_t _c = (c) + _d; \
        _b = leftRotate12(_b ^ _c); \
        _a += _b; \
        (d) = _d = leftRotate8(_d ^ _a); \
        _c += _d; \
        (a) = _a; \
        (b) = leftRotate7(_b ^ _c); \
        (c) = _c; \
    } while (0)

/**
 * \brief Executes the ChaCha20 hash core on a block.
 *
 * \param output Output block, must not overlap with \a input.
 * \param input Input block.
 *
 * Both blocks are assumed to be in host byte order.
 */
static void aead_chacha_core(uint32_t output[16], const uint32_t input[16])
{
    uint8_t round;
    uint8_t posn;

    /* Copy the input buffer to the output prior to the first round */
    for (posn = 0; posn < 16; ++posn)
        output[posn] = input[posn];

    /* Perform the ChaCha rounds in sets of two */
    for (round = 20; round >= 2; round -= 2) {
        /* Column round */
        quarterRound(output[0], output[4], output[8],  output[12]);
        quarterRound(output[1], output[5], output[9],  output[13]);
        quarterRound(output[2], output[6], output[10], output[14]);
        quarterRound(output[3], output[7], output[11], output[15]);

        /* Diagonal round */
        quarterRound(output[0], output[5], output[10], output[15]);
        quarterRound(output[1], output[6], output[11], output[12]);
        quarterRound(output[2], output[7], output[8],  output[13]);
        quarterRound(output[3], output[4], output[9],  output[14]);
    }

    /* Add the original input to the final output */
    for (posn = 0; posn < 16; ++posn)
        output[posn] += input[posn];
}

/**
 * \brief Global PRNG state.
 *
 * The starting value is the string "expand 32-byte k" followed by zeroes.
 * It will not stay in this state for long as aead_random_init() will
 * reseed and re-key the PRNG when it is called.
 *
 * The last word is used as a block counter when multiple output blocks
 * are required.  The PRNG is reseeded every AEAD_PRNG_RESEED_BLOCKS.
 */
static uint32_t aead_chacha_state[16] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/**
 * \brief Temporary output for the generation of data between re-keying.
 */
static uint32_t aead_chacha_output[16];

/**
 * \brief Position of the next word to return from the PRNG.
 */
static uint8_t aead_chacha_posn = 16;

/**
 * \brief Number of blocks that have been generated since the last re-key.
 */
static uint16_t aead_chacha_blocks = 0;

/**
 * \brief Automatically re-key every 16K of output data.  This can be adjusted.
 */
#define AEAD_PRNG_REKEY_BLOCKS 256

/**
 * \brief Automatically re-seed every 64K of output data.  This can be adjusted.
 */
#define AEAD_PRNG_RESEED_BLOCKS 1024

/**
 * \brief Re-keys the PRNG state to enforce forward secrecy.
 *
 * This function generates a new output block and then copies the first
 * 384 bits of the output to the last 384 bits of aead_chacha_state,
 * which will destroy any chance of going backwards.
 */
static void aead_chacha_rekey(void)
{
    ++(aead_chacha_state[15]);
    aead_chacha_core(aead_chacha_output, aead_chacha_state);
    memcpy(aead_chacha_state + 4, aead_chacha_output, 48);
    aead_chacha_posn = 16;
}

void aead_random_init(void)
{
    /* Load an initial seed from the system TRNG and then re-key */
    aead_random_reseed();
}

void aead_random_finish(void)
{
    /* Re-key the random number generator to enforce forward secrecy */
    aead_chacha_rekey();
}

uint32_t aead_random_generate_32(void)
{
    if (aead_chacha_posn < 16) {
        /* We still have data in the previous block */
        return aead_chacha_output[aead_chacha_posn++];
    } else {
        /* Re-seed or re-key if we have generated too many blocks */
        ++aead_chacha_blocks;
        if (aead_chacha_blocks >= AEAD_PRNG_RESEED_BLOCKS)
            aead_random_reseed();
        else if ((aead_chacha_blocks % AEAD_PRNG_REKEY_BLOCKS) == 0)
            aead_chacha_rekey();

        /* Increment the block counter and generate a new output block */
        ++(aead_chacha_state[15]);
        aead_chacha_core(aead_chacha_output, aead_chacha_state);
        aead_chacha_posn = 1;
        return aead_chacha_output[0];
    }
}

uint64_t aead_random_generate_64(void)
{
    uint32_t x, y;
    x = aead_random_generate_32();
    y = aead_random_generate_32();
    return x | (((uint64_t)y) << 32);
}

void aead_random_generate(void *buffer, unsigned size)
{
    unsigned char *buf = (unsigned char *)buffer;
    uint32_t x;
    while (size >= sizeof(uint32_t)) {
        x = aead_random_generate_32();
        memcpy(buf, &x, sizeof(x));
        buf += sizeof(uint32_t);
        size -= sizeof(uint32_t);
    }
    if (size > 0) {
        x = aead_random_generate_32();
        memcpy(buf, &x, size);
    }
}

void aead_random_reseed(void)
{
    /* Reseed the PRNG state from the system TRNG */
    aead_random_get_system_seed((unsigned char *)(aead_chacha_state + 4));

    /* Re-key the PRNG to enforce forward secrecy */
    aead_chacha_rekey();

    /* Restart the periodic re-key/re-seed block counter */
    aead_chacha_blocks = 0;
}
