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

#include "internal-photon256.h"
#include "internal-photon256-mix.h"
#include "internal-util.h"

#if !defined(__AVR__)

/**
 * \brief Number of rounds in the PHOTON-256 permutation in bit-sliced form.
 */
#define PHOTON256_ROUNDS 12

/* Round constants for PHOTON-256, split out into separate bit-slices */
static uint32_t const photon256_rc[PHOTON256_ROUNDS * 8] = {
    0x00000001, 0x01010000, 0x01000000, 0x00000000, /* Round  1 */
    0x01010100, 0x00000101, 0x00010101, 0x01010101,
    0x00000001, 0x00000101, 0x01000000, 0x00000000, /* Round  2 */
    0x01010100, 0x01010000, 0x00010101, 0x01010101,
    0x00000001, 0x00000101, 0x00010101, 0x00000000, /* Round  3 */
    0x01010100, 0x01010000, 0x01000000, 0x01010101,
    0x01010100, 0x00000101, 0x00010101, 0x01010101, /* Round  4 */
    0x00000001, 0x01010000, 0x01000000, 0x00000000,
    0x00000001, 0x01010000, 0x00010101, 0x01010101, /* Round  5 */
    0x01010100, 0x00000101, 0x01000000, 0x00000000,
    0x00000001, 0x00000101, 0x01000000, 0x01010101, /* Round  6 */
    0x01010100, 0x01010000, 0x00010101, 0x00000000,
    0x01010100, 0x00000101, 0x00010101, 0x00000000, /* Round  7 */
    0x00000001, 0x01010000, 0x01000000, 0x01010101,
    0x01010100, 0x01010000, 0x00010101, 0x01010101, /* Round  8 */
    0x00000001, 0x00000101, 0x01000000, 0x00000000,
    0x00000001, 0x01010000, 0x01000000, 0x01010101, /* Round  9 */
    0x01010100, 0x00000101, 0x00010101, 0x00000000,
    0x01010100, 0x00000101, 0x01000000, 0x00000000, /* Round 10 */
    0x00000001, 0x01010000, 0x00010101, 0x01010101,
    0x00000001, 0x01010000, 0x00010101, 0x00000000, /* Round 11 */
    0x01010100, 0x00000101, 0x01000000, 0x01010101,
    0x01010100, 0x00000101, 0x01000000, 0x01010101, /* Round 12 */
    0x00000001, 0x01010000, 0x00010101, 0x00000000
};

/**
 * \brief Evaluates the PHOTON-256 S-box in bit-sliced form.
 *
 * \param x0 Slice with bit 0 of all nibbles.
 * \param x1 Slice with bit 1 of all nibbles.
 * \param x2 Slice with bit 2 of all nibbles.
 * \param x3 Slice with bit 3 of all nibbles.
 *
 * This bit-sliced S-box implementation is based on the AVR version
 * "add_avr8_bitslice_asm" from the PHOTON-Beetle reference code.
 */
#define photon256_sbox(x0, x1, x2, x3) \
    do { \
        x1 ^= x2; \
        x3 ^= (x2 & x1); \
        t1 = x3; \
        x3 = (x3 & x1) ^ x2; \
        t2 = x3; \
        x3 ^= x0; \
        x3 = ~(x3); \
        x2 = x3; \
        t2 |= x0; \
        x0 ^= t1; \
        x1 ^= x0; \
        x2 |= x1; \
        x2 ^= t1; \
        x1 ^= t2; \
        x3 ^= x1; \
    } while (0)

/* http://programming.sirrida.de/perm_fn.html#bit_permute_step */
#define bit_permute_step(_y, mask, shift) \
    do { \
        uint32_t y = (_y); \
        uint32_t t = ((y >> (shift)) ^ y) & (mask); \
        (_y) = (y ^ t) ^ (t << (shift)); \
    } while (0)

/* To convert to bit-sliced form, we first scatter bits 0..3 of the nibbles
 * to bytes 0..3 of the words.  Then we rearrange the bytes to group all
 * bits N into word N.
 *
 * Permutation generated with "http://programming.sirrida.de/calcperm.php".
 *
 * P = [0 8 16 24 1 9 17 25 2 10 18 26 3 11 19 27
 *      4 12 20 28 5 13 21 29 6 14 22 30 7 15 23 31]
 */
#define TO_BITSLICED_PERM(x) \
    do { \
        bit_permute_step(x, 0x0a0a0a0a, 3); \
        bit_permute_step(x, 0x00cc00cc, 6); \
        bit_permute_step(x, 0x0000f0f0, 12); \
        bit_permute_step(x, 0x0000ff00, 8); \
    } while (0)
#define FROM_BITSLICED_PERM(x) \
    do { \
        bit_permute_step(x, 0x00aa00aa, 7); \
        bit_permute_step(x, 0x0000cccc, 14); \
        bit_permute_step(x, 0x00f000f0, 4); \
        bit_permute_step(x, 0x0000ff00, 8); \
    } while (0)

/**
 * \brief Converts half of the PHOTON-256 state into bit-sliced form.
 *
 * \param s0 First word of the state half on output.
 * \param s1 Second word of the state half on output.
 * \param s2 Third word of the state half on output.
 * \param s3 Fourth word of the state half on output.
 * \param in Points to the input bytes to convert.
 *
 * Assumes temporary variables t0, t1, t2, and t3 are in the calling scope.
 */
#define photon256_to_sliced_half(s0, s1, s2, s3, in) \
    do { \
        t0 = le_load_word32((in)); \
        t1 = le_load_word32((in) + 4); \
        t2 = le_load_word32((in) + 8); \
        t3 = le_load_word32((in) + 12); \
        TO_BITSLICED_PERM(t0); \
        TO_BITSLICED_PERM(t1); \
        TO_BITSLICED_PERM(t2); \
        TO_BITSLICED_PERM(t3); \
        (s0) = (t0 & 0x000000FFU) | ((t1 << 8) & 0x0000FF00U) | \
               ((t2 << 16) & 0x00FF0000U) | ((t3 << 24) & 0xFF000000U); \
        (s1) = ((t0 >> 8) & 0x000000FFU) | (t1 & 0x0000FF00U) | \
               ((t2 << 8) & 0x00FF0000U) | ((t3 << 16) & 0xFF000000U); \
        (s2) = ((t0 >> 16) & 0x000000FFU) | ((t1 >> 8) & 0x0000FF00U) | \
               (t2 & 0x00FF0000U) | ((t3 << 8) & 0xFF000000U); \
        (s3) = ((t0 >> 24) & 0x000000FFU) | ((t1 >> 16) & 0x0000FF00U) | \
               ((t2 >> 8) & 0x00FF0000U) | (t3 & 0xFF000000U); \
    } while (0)

/**
 * \brief Converts half of the PHOTON-256 state into bit-sliced form.
 *
 * \param out Points to the output buffer.
 * \param s0 First word of the state half on input.
 * \param s1 Second word of the state half on input.
 * \param s2 Third word of the state half on input.
 * \param s3 Fourth word of the state half on input.
 *
 * Assumes temporary variables t0, t1, t2, and t3 are in the calling scope.
 */
#define photon256_from_sliced_half(out, s0, s1, s2, s3) \
    do { \
        t0 = ((s0) & 0x000000FFU) | (((s1) & 0x000000FFU) << 8) | \
             (((s2) & 0x000000FFU) << 16) | (((s3) & 0x000000FFU) << 24); \
        t1 = (((s0) & 0x0000FF00U) >> 8) | ((s1) & 0x0000FF00U) | \
             (((s2) & 0x0000FF00U) << 8) | (((s3) & 0x0000FF00U) << 16); \
        t2 = (((s0) & 0x00FF0000U) >> 16) | (((s1) & 0x00FF0000U) >> 8) | \
             ((s2) & 0x00FF0000U) | (((s3) & 0x00FF0000U) << 8); \
        t3 = (((s0) & 0xFF000000U) >> 24) | (((s1) & 0xFF000000U) >> 16) | \
             (((s2) & 0xFF000000U) >> 8) | ((s3) & 0xFF000000U); \
        FROM_BITSLICED_PERM(t0); \
        FROM_BITSLICED_PERM(t1); \
        FROM_BITSLICED_PERM(t2); \
        FROM_BITSLICED_PERM(t3); \
        le_store_word32((out),      t0); \
        le_store_word32((out) + 4,  t1); \
        le_store_word32((out) + 8,  t2); \
        le_store_word32((out) + 12, t3); \
    } while (0)

#if defined(LW_UTIL_LITTLE_ENDIAN)
/* Index the bit-sliced state bytes in little-endian byte order */
#define READ_ROW0() \
     (((uint32_t)(S.B[0])) | \
     (((uint32_t)(S.B[4]))  << 8)  | \
     (((uint32_t)(S.B[8]))  << 16) | \
     (((uint32_t)(S.B[12])) << 24))
#define READ_ROW1() \
     (((uint32_t)(S.B[1])) | \
     (((uint32_t)(S.B[5]))  << 8)  | \
     (((uint32_t)(S.B[9]))  << 16) | \
     (((uint32_t)(S.B[13])) << 24))
#define READ_ROW2() \
     (((uint32_t)(S.B[2])) | \
     (((uint32_t)(S.B[6]))  << 8)  | \
     (((uint32_t)(S.B[10])) << 16) | \
     (((uint32_t)(S.B[14])) << 24))
#define READ_ROW3() \
     (((uint32_t)(S.B[3])) | \
     (((uint32_t)(S.B[7]))  << 8)  | \
     (((uint32_t)(S.B[11])) << 16) | \
     (((uint32_t)(S.B[15])) << 24))
#define READ_ROW4() \
     (((uint32_t)(S.B[16])) | \
     (((uint32_t)(S.B[20])) << 8)  | \
     (((uint32_t)(S.B[24])) << 16) | \
     (((uint32_t)(S.B[28])) << 24))
#define READ_ROW5() \
     (((uint32_t)(S.B[17])) | \
     (((uint32_t)(S.B[21])) << 8)  | \
     (((uint32_t)(S.B[25])) << 16) | \
     (((uint32_t)(S.B[29])) << 24))
#define READ_ROW6() \
     (((uint32_t)(S.B[18])) | \
     (((uint32_t)(S.B[22])) << 8)  | \
     (((uint32_t)(S.B[26])) << 16) | \
     (((uint32_t)(S.B[30])) << 24))
#define READ_ROW7() \
     (((uint32_t)(S.B[19])) | \
     (((uint32_t)(S.B[23])) << 8)  | \
     (((uint32_t)(S.B[27])) << 16) | \
     (((uint32_t)(S.B[31])) << 24))
#define WRITE_ROW(row, value) \
    do { \
        if ((row) < 4) { \
            state->B[(row)]      = (uint8_t)(value); \
            state->B[(row) + 4]  = (uint8_t)((value) >> 8); \
            state->B[(row) + 8]  = (uint8_t)((value) >> 16); \
            state->B[(row) + 12] = (uint8_t)((value) >> 24); \
        } else { \
            state->B[(row) + 12] = (uint8_t)(value); \
            state->B[(row) + 16] = (uint8_t)((value) >> 8); \
            state->B[(row) + 20] = (uint8_t)((value) >> 16); \
            state->B[(row) + 24] = (uint8_t)((value) >> 24); \
        } \
    } while (0)
#else
/* Index the bit-sliced state B in big-endian byte order */
#define READ_ROW0() \
     (((uint32_t)(S.B[3])) | \
     (((uint32_t)(S.B[7]))  << 8)  | \
     (((uint32_t)(S.B[11])) << 16) | \
     (((uint32_t)(S.B[15])) << 24))
#define READ_ROW1() \
     (((uint32_t)(S.B[2])) | \
     (((uint32_t)(S.B[6]))  << 8)  | \
     (((uint32_t)(S.B[10])) << 16) | \
     (((uint32_t)(S.B[14])) << 24))
#define READ_ROW2() \
     (((uint32_t)(S.B[1])) | \
     (((uint32_t)(S.B[5]))  << 8)  | \
     (((uint32_t)(S.B[9]))  << 16) | \
     (((uint32_t)(S.B[13])) << 24))
#define READ_ROW3() \
     (((uint32_t)(S.B[0])) | \
     (((uint32_t)(S.B[4]))  << 8)  | \
     (((uint32_t)(S.B[8]))  << 16) | \
     (((uint32_t)(S.B[12])) << 24))
#define READ_ROW4() \
     (((uint32_t)(S.B[19])) | \
     (((uint32_t)(S.B[23])) << 8)  | \
     (((uint32_t)(S.B[27])) << 16) | \
     (((uint32_t)(S.B[31])) << 24))
#define READ_ROW5() \
     (((uint32_t)(S.B[18])) | \
     (((uint32_t)(S.B[22])) << 8)  | \
     (((uint32_t)(S.B[26])) << 16) | \
     (((uint32_t)(S.B[30])) << 24))
#define READ_ROW6() \
     (((uint32_t)(S.B[17])) | \
     (((uint32_t)(S.B[21])) << 8)  | \
     (((uint32_t)(S.B[25])) << 16) | \
     (((uint32_t)(S.B[29])) << 24))
#define READ_ROW7() \
     (((uint32_t)(S.B[16])) | \
     (((uint32_t)(S.B[20])) << 8)  | \
     (((uint32_t)(S.B[24])) << 16) | \
     (((uint32_t)(S.B[28])) << 24))
#define WRITE_ROW(row, value) \
    do { \
        if ((row) < 4) { \
            state->B[3  - (row)] = (uint8_t)(value); \
            state->B[7  - (row)] = (uint8_t)((value) >> 8); \
            state->B[11 - (row)] = (uint8_t)((value) >> 16); \
            state->B[15 - (row)] = (uint8_t)((value) >> 24); \
        } else { \
            state->B[20 - (row)] = (uint8_t)(value); \
            state->B[24 - (row)] = (uint8_t)((value) >> 8); \
            state->B[28 - (row)] = (uint8_t)((value) >> 16); \
            state->B[32 - (row)] = (uint8_t)((value) >> 24); \
        } \
    } while (0)
#endif

/* Rotate all rows left by the row number.
 *
 * We do this by applying permutations to the top and bottom words
 * to rearrange the bits into the rotated form.  Permutations
 * generated with "http://programming.sirrida.de/calcperm.php".
 *
 * P_top = [0 1 2 3 4 5 6 7 15 8 9 10 11 12 13 14 22 23
 *          16 17 18 19 20 21 29 30 31 24 25 26 27 28]
 * P_bot = [4 5 6 7 0 1 2 3 11 12 13 14 15 8 9 10 18 19
 *          20 21 22 23 16 17 25 26 27 28 29 30 31 24
 */
#define TOP_ROTATE_PERM(x) \
    do { \
        t1 = (x); \
        bit_permute_step(t1, 0x07030100, 4); \
        bit_permute_step(t1, 0x22331100, 2); \
        bit_permute_step(t1, 0x55005500, 1); \
        (x) = t1; \
    } while (0)
#define BOTTOM_ROTATE_PERM(x) \
    do { \
        t1 = (x); \
        bit_permute_step(t1, 0x080c0e0f, 4); \
        bit_permute_step(t1, 0x22331100, 2); \
        bit_permute_step(t1, 0x55005500, 1); \
        (x) = t1; \
    } while (0)

void photon256_permute(photon256_state_t *state)
{
    uint32_t s0, s1, s2, s3;
    uint32_t t0, t1, t2, t3;
    uint32_t t4, t5, t6, t7;
    const uint32_t *rc = photon256_rc;
    uint8_t round;

    /* Temporary state to convert from column order to row order */
    photon256_state_t S;

    /* Convert the state into bit-sliced form.  The bottom half of the
     * state is left in memory with the top half in local variables */
    photon256_to_sliced_half(s0, s1, s2, s3, state->B + 16);
    state->W[4] = s0;
    state->W[5] = s1;
    state->W[6] = s2;
    state->W[7] = s3;
    photon256_to_sliced_half(s0, s1, s2, s3, state->B);

    /* Perform all 12 permutation rounds.  To reduce the register pressure
     * on the CPU, we operate on half of the state at a time: top, bottom,
     * left, or right depending upon the step */
    for (round = 0; round < PHOTON256_ROUNDS; ++round) {
        /* Apply the round constants to the top half of the state */
        s0 ^= rc[0];
        s1 ^= rc[1];
        s2 ^= rc[2];
        s3 ^= rc[3];

        /* Apply the sbox to the top half of the state */
        photon256_sbox(s0, s1, s2, s3);

        /* Rotate the rows of the top half by 0..3 bit positions and store */
        TOP_ROTATE_PERM(s0);
        TOP_ROTATE_PERM(s1);
        TOP_ROTATE_PERM(s2);
        TOP_ROTATE_PERM(s3);
        S.W[0] = s0;
        S.W[1] = s1;
        S.W[2] = s2;
        S.W[3] = s3;

        /* Load the bottom half of the state */
        s0 = state->W[4];
        s1 = state->W[5];
        s2 = state->W[6];
        s3 = state->W[7];

        /* Apply the round constants to the bottom half of the state */
        s0 ^= rc[4];
        s1 ^= rc[5];
        s2 ^= rc[6];
        s3 ^= rc[7];
        rc += 8;

        /* Apply the sbox to the bottom half of the state */
        photon256_sbox(s0, s1, s2, s3);

        /* Rotate the rows of the bottom half by 4..7 bit positions and store */
        BOTTOM_ROTATE_PERM(s0);
        BOTTOM_ROTATE_PERM(s1);
        BOTTOM_ROTATE_PERM(s2);
        BOTTOM_ROTATE_PERM(s3);
        S.W[4] = s0;
        S.W[5] = s1;
        S.W[6] = s2;
        S.W[7] = s3;

        /* Mixing the columns; process the left half of the state */
        #define MUL(a, x) (photon256_field_multiply((a), (x)))
        s0 = READ_ROW0();
        s1 = READ_ROW1();
        s2 = READ_ROW2();
        s3 = READ_ROW3();
        MIXL0(t0, s0, s1, s2, s3);
        MIXL1(t1, s0, s1, s2, s3);
        MIXL2(t2, s0, s1, s2, s3);
        MIXL3(t3, s0, s1, s2, s3);
        MIXL4(t4, s0, s1, s2, s3);
        MIXL5(t5, s0, s1, s2, s3);
        MIXL6(t6, s0, s1, s2, s3);
        MIXL7(t7, s0, s1, s2, s3);

        /* Mixing the columns; process the right half of the state */
        s0 = READ_ROW4();
        s1 = READ_ROW5();
        s2 = READ_ROW6();
        s3 = READ_ROW7();
        MIXR4(t4, s0, s1, s2, s3);
        MIXR5(t5, s0, s1, s2, s3);
        MIXR6(t6, s0, s1, s2, s3);
        MIXR7(t7, s0, s1, s2, s3);
        WRITE_ROW(4, t4);
        WRITE_ROW(5, t5);
        WRITE_ROW(6, t6);
        WRITE_ROW(7, t7);
        MIXR0(t0, s0, s1, s2, s3);
        MIXR1(t1, s0, s1, s2, s3);
        MIXR2(t2, s0, s1, s2, s3);
        MIXR3(t3, s0, s1, s2, s3);
        WRITE_ROW(0, t0);
        WRITE_ROW(1, t1);
        WRITE_ROW(2, t2);
        WRITE_ROW(3, t3);

        /* Reload the top half of the state for the next round */
        s0 = state->W[0];
        s1 = state->W[1];
        s2 = state->W[2];
        s3 = state->W[3];
    }

    /* Convert back from bit-sliced form to regular form */
    photon256_from_sliced_half(state->B, s0, s1, s2, s3);
    s0 = state->W[4];
    s1 = state->W[5];
    s2 = state->W[6];
    s3 = state->W[7];
    photon256_from_sliced_half(state->B + 16, s0, s1, s2, s3);
}

#endif /* !__AVR__ */
