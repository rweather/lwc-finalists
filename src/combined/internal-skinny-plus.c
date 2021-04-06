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

#include "internal-skinny-plus.h"
#include "internal-util.h"
#include <string.h>

#if !SKINNY_PLUS_VARIANT_ASM

/** @cond skinnyutil */

/* Utilities for implementing SKINNY-128 and its variants */

#define skinny128_LFSR2(x) \
    do { \
        uint32_t _x = (x); \
        (x) = ((_x << 1) & 0xFEFEFEFEU) ^ \
             (((_x >> 7) ^ (_x >> 5)) & 0x01010101U); \
    } while (0)


#define skinny128_LFSR3(x) \
    do { \
        uint32_t _x = (x); \
        (x) = ((_x >> 1) & 0x7F7F7F7FU) ^ \
              (((_x << 7) ^ (_x << 1)) & 0x80808080U); \
    } while (0)

#define skinny128_permute_tk_half(tk2, tk3) \
    do { \
        /* Permute the bottom half of the tweakey state in place, no swap */ \
        uint32_t row2 = tk2; \
        uint32_t row3 = tk3; \
        row3 = (row3 << 16) | (row3 >> 16); \
        tk2 = ((row2 >>  8) & 0x000000FFU) | \
              ((row2 << 16) & 0x00FF0000U) | \
              ( row3        & 0xFF00FF00U); \
        tk3 = ((row2 >> 16) & 0x000000FFU) | \
               (row2        & 0xFF000000U) | \
              ((row3 <<  8) & 0x0000FF00U) | \
              ( row3        & 0x00FF0000U); \
    } while (0)

/*
 * Apply the SKINNY sbox.  The original version from the specification is
 * equivalent to:
 *
 * #define SBOX_MIX(x)
 *     (((~((((x) >> 1) | (x)) >> 2)) & 0x11111111U) ^ (x))
 * #define SBOX_SWAP(x)
 *     (((x) & 0xF9F9F9F9U) |
 *     (((x) >> 1) & 0x02020202U) |
 *     (((x) << 1) & 0x04040404U))
 * #define SBOX_PERMUTE(x)
 *     ((((x) & 0x01010101U) << 2) |
 *      (((x) & 0x06060606U) << 5) |
 *      (((x) & 0x20202020U) >> 5) |
 *      (((x) & 0xC8C8C8C8U) >> 2) |
 *      (((x) & 0x10101010U) >> 1))
 *
 * x = SBOX_MIX(x);
 * x = SBOX_PERMUTE(x);
 * x = SBOX_MIX(x);
 * x = SBOX_PERMUTE(x);
 * x = SBOX_MIX(x);
 * x = SBOX_PERMUTE(x);
 * x = SBOX_MIX(x);
 * return SBOX_SWAP(x);
 *
 * However, we can mix the bits in their original positions and then
 * delay the SBOX_PERMUTE and SBOX_SWAP steps to be performed with one
 * final permuatation.  This reduces the number of shift operations.
 */
#define skinny128_sbox(x) \
do { \
    uint32_t y; \
    \
    /* Mix the bits */ \
    x = ~x; \
    x ^= (((x >> 2) & (x >> 3)) & 0x11111111U); \
    y  = (((x << 5) & (x << 1)) & 0x20202020U); \
    x ^= (((x << 5) & (x << 4)) & 0x40404040U) ^ y; \
    y  = (((x << 2) & (x << 1)) & 0x80808080U); \
    x ^= (((x >> 2) & (x << 1)) & 0x02020202U) ^ y; \
    y  = (((x >> 5) & (x << 1)) & 0x04040404U); \
    x ^= (((x >> 1) & (x >> 2)) & 0x08080808U) ^ y; \
    x = ~x; \
    \
    /* Permutation generated by http://programming.sirrida.de/calcperm.php */ \
    /* The final permutation for each byte is [2 7 6 1 3 0 4 5] */ \
    x = ((x & 0x08080808U) << 1) | \
        ((x & 0x32323232U) << 2) | \
        ((x & 0x01010101U) << 5) | \
        ((x & 0x80808080U) >> 6) | \
        ((x & 0x40404040U) >> 4) | \
        ((x & 0x04040404U) >> 2); \
} while (0)

/** @endcond */

void skinny_plus_init
    (skinny_plus_key_schedule_t *ks, const unsigned char key[48])
{
#if SKINNY_PLUS_VARIANT != SKINNY_PLUS_VARIANT_TINY
    uint32_t TK2[4];
    uint32_t TK3[4];
    uint32_t *schedule;
    unsigned round;
    uint8_t rc;
#endif

#if SKINNY_PLUS_VARIANT == SKINNY_PLUS_VARIANT_TINY
    /* Copy the input key as-is when using the tiny key schedule version */
    memcpy(ks->TK1, key, sizeof(ks->TK1));
    memcpy(ks->TK2, key + 16, sizeof(ks->TK2));
    memcpy(ks->TK3, key + 32, sizeof(ks->TK3));
#else
    /* Set the initial states of TK1, TK2, and TK3 */
    memcpy(ks->TK1, key, 16);
    TK2[0] = le_load_word32(key + 16);
    TK2[1] = le_load_word32(key + 20);
    TK2[2] = le_load_word32(key + 24);
    TK2[3] = le_load_word32(key + 28);
    TK3[0] = le_load_word32(key + 32);
    TK3[1] = le_load_word32(key + 36);
    TK3[2] = le_load_word32(key + 40);
    TK3[3] = le_load_word32(key + 44);

    /* Set up the key schedule using TK2 and TK3.  TK1 is not added
     * to the key schedule because we will derive that part of the
     * schedule during encryption operations */
    schedule = ks->k;
    rc = 0;
    for (round = 0; round < SKINNY_PLUS_ROUNDS; round += 2, schedule += 4) {
        /* XOR the round constants with the current schedule words.
         * The round constants for the 3rd and 4th rows are
         * fixed and will be applied during encryption. */
        rc = (rc << 1) ^ ((rc >> 5) & 0x01) ^ ((rc >> 4) & 0x01) ^ 0x01;
        rc &= 0x3F;
        schedule[0] = TK2[0] ^ TK3[0] ^ (rc & 0x0F);
        schedule[1] = TK2[1] ^ TK3[1] ^ (rc >> 4);

        /* Permute the bottom half of TK2 and TK3 for the next round */
        skinny128_permute_tk_half(TK2[2], TK2[3]);
        skinny128_permute_tk_half(TK3[2], TK3[3]);
        skinny128_LFSR2(TK2[2]);
        skinny128_LFSR2(TK2[3]);
        skinny128_LFSR3(TK3[2]);
        skinny128_LFSR3(TK3[3]);

        /* XOR the round constants with the current schedule words.
         * The round constants for the 3rd and 4th rows are
         * fixed and will be applied during encryption. */
        rc = (rc << 1) ^ ((rc >> 5) & 0x01) ^ ((rc >> 4) & 0x01) ^ 0x01;
        rc &= 0x3F;
        schedule[2] = TK2[2] ^ TK3[2] ^ (rc & 0x0F);
        schedule[3] = TK2[3] ^ TK3[3] ^ (rc >> 4);

        /* Permute the top half of TK2 and TK3 for the next round */
        skinny128_permute_tk_half(TK2[0], TK2[1]);
        skinny128_permute_tk_half(TK3[0], TK3[1]);
        skinny128_LFSR2(TK2[0]);
        skinny128_LFSR2(TK2[1]);
        skinny128_LFSR3(TK3[0]);
        skinny128_LFSR3(TK3[1]);
    }
#endif
}

/**
 * \brief Performs an unrolled round for Skinny-128-384 when only TK1 is
 * computed on the fly.
 *
 * \param s0 First word of the state.
 * \param s1 Second word of the state.
 * \param s2 Third word of the state.
 * \param s3 Fourth word of the state.
 * \param half 0 for the bottom half and 1 for the top half of the TK values.
 * \param offset Offset between 0 and 3 of the current unrolled round.
 */
#define skinny_plus_round(s0, s1, s2, s3, half, offset) \
    do { \
        /* Apply the S-box to all bytes in the state */ \
        skinny128_sbox(s0); \
        skinny128_sbox(s1); \
        skinny128_sbox(s2); \
        skinny128_sbox(s3); \
        \
        /* XOR the round constant and the subkey for this round */ \
        s0 ^= schedule[offset * 2]     ^ TK1[half * 2]; \
        s1 ^= schedule[offset * 2 + 1] ^ TK1[half * 2 + 1]; \
        s2 ^= 0x02; \
        \
        /* Shift the cells in the rows right, which moves the cell \
         * values up closer to the MSB.  That is, we do a left rotate \
         * on the word to rotate the cells in the word right */ \
        s1 = leftRotate8(s1); \
        s2 = leftRotate16(s2); \
        s3 = leftRotate24(s3); \
        \
        /* Mix the columns, but don't rotate the words yet */ \
        s1 ^= s2; \
        s2 ^= s0; \
        s3 ^= s2; \
        \
        /* Permute TK1 in-place for the next round */ \
        skinny128_permute_tk_half \
            (TK1[(1 - half) * 2], TK1[(1 - half) * 2 + 1]); \
    } while (0)

/**
 * \brief Performs an unrolled round for Skinny-128-384 when the entire
 * tweakey schedule is computed on the fly.
 *
 * \param s0 First word of the state.
 * \param s1 Second word of the state.
 * \param s2 Third word of the state.
 * \param s3 Fourth word of the state.
 * \param half 0 for the bottom half and 1 for the top half of the TK values.
 */
#define skinny_plus_round_tk_full(s0, s1, s2, s3, half) \
    do { \
        /* Apply the S-box to all bytes in the state */ \
        skinny128_sbox(s0); \
        skinny128_sbox(s1); \
        skinny128_sbox(s2); \
        skinny128_sbox(s3); \
        \
        /* XOR the round constant and the subkey for this round */ \
        rc = (rc << 1) ^ ((rc >> 5) & 0x01) ^ ((rc >> 4) & 0x01) ^ 0x01; \
        rc &= 0x3F; \
        s0 ^= TK1[half * 2] ^ TK2[half * 2] ^ TK3[half * 2] ^ (rc & 0x0F); \
        s1 ^= TK1[half * 2 + 1] ^ TK2[half * 2 + 1] ^ TK3[half * 2 + 1] ^ \
              (rc >> 4); \
        s2 ^= 0x02; \
        \
        /* Shift the cells in the rows right, which moves the cell \
         * values up closer to the MSB.  That is, we do a left rotate \
         * on the word to rotate the cells in the word right */ \
        s1 = leftRotate8(s1); \
        s2 = leftRotate16(s2); \
        s3 = leftRotate24(s3); \
        \
        /* Mix the columns, but don't rotate the words yet */ \
        s1 ^= s2; \
        s2 ^= s0; \
        s3 ^= s2; \
        \
        /* Permute TK1, TK2, and TK3 in-place for the next round */ \
        skinny128_permute_tk_half \
            (TK1[(1 - half) * 2], TK1[(1 - half) * 2 + 1]); \
        skinny128_permute_tk_half \
            (TK2[(1 - half) * 2], TK2[(1 - half) * 2 + 1]); \
        skinny128_permute_tk_half \
            (TK3[(1 - half) * 2], TK3[(1 - half) * 2 + 1]); \
        skinny128_LFSR2(TK2[(1 - half) * 2]); \
        skinny128_LFSR2(TK2[(1 - half) * 2 + 1]); \
        skinny128_LFSR3(TK3[(1 - half) * 2]); \
        skinny128_LFSR3(TK3[(1 - half) * 2 + 1]); \
    } while (0)

void skinny_plus_encrypt
    (const skinny_plus_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;
    uint32_t TK1[4];
#if SKINNY_PLUS_VARIANT == SKINNY_PLUS_VARIANT_TINY
    uint32_t TK2[4];
    uint32_t TK3[4];
    uint8_t rc = 0;
#else
    const uint32_t *schedule = ks->k;
#endif
    unsigned round;

    /* Unpack the input block into the state array */
    s0 = le_load_word32(input);
    s1 = le_load_word32(input + 4);
    s2 = le_load_word32(input + 8);
    s3 = le_load_word32(input + 12);

    /* Make a local copy of the tweakable part of the state */
    TK1[0] = le_load_word32(ks->TK1);
    TK1[1] = le_load_word32(ks->TK1 + 4);
    TK1[2] = le_load_word32(ks->TK1 + 8);
    TK1[3] = le_load_word32(ks->TK1 + 12);
#if SKINNY_PLUS_VARIANT == SKINNY_PLUS_VARIANT_TINY
    TK2[0] = le_load_word32(ks->TK2);
    TK2[1] = le_load_word32(ks->TK2 + 4);
    TK2[2] = le_load_word32(ks->TK2 + 8);
    TK2[3] = le_load_word32(ks->TK2 + 12);
    TK3[0] = le_load_word32(ks->TK3);
    TK3[1] = le_load_word32(ks->TK3 + 4);
    TK3[2] = le_load_word32(ks->TK3 + 8);
    TK3[3] = le_load_word32(ks->TK3 + 12);
#endif

    /* Perform all encryption rounds four at a time */
    for (round = 0; round < SKINNY_PLUS_ROUNDS; round += 4) {
#if SKINNY_PLUS_VARIANT == SKINNY_PLUS_VARIANT_TINY
        skinny_plus_round_tk_full(s0, s1, s2, s3, 0);
        skinny_plus_round_tk_full(s3, s0, s1, s2, 1);
        skinny_plus_round_tk_full(s2, s3, s0, s1, 0);
        skinny_plus_round_tk_full(s1, s2, s3, s0, 1);
#else
        skinny_plus_round(s0, s1, s2, s3, 0, 0);
        skinny_plus_round(s3, s0, s1, s2, 1, 1);
        skinny_plus_round(s2, s3, s0, s1, 0, 2);
        skinny_plus_round(s1, s2, s3, s0, 1, 3);
        schedule += 8;
#endif
    }

    /* Pack the result into the output buffer */
    le_store_word32(output,      s0);
    le_store_word32(output + 4,  s1);
    le_store_word32(output + 8,  s2);
    le_store_word32(output + 12, s3);
}

/**
 * \def skinny_plus_round_tk2(s0, s1, s2, s3, half)
 * \brief Performs an unrolled round for skinny_plus_encrypt_tk2().
 *
 * \param s0 First word of the state.
 * \param s1 Second word of the state.
 * \param s2 Third word of the state.
 * \param s3 Fourth word of the state.
 * \param half 0 for the bottom half and 1 for the top half of the TK values.
 * \param offset Offset between 0 and 3 of the current unrolled round.
 */
#if SKINNY_PLUS_VARIANT == SKINNY_PLUS_VARIANT_TINY
#define skinny_plus_round_tk2(s0, s1, s2, s3, half, offset) \
    skinny_plus_round_tk_full(s0, s1, s2, s3, half)
#else /* !SKINNY_PLUS_VARIANT_TINY */
#define skinny_plus_round_tk2(s0, s1, s2, s3, half, offset) \
    do { \
        /* Apply the S-box to all bytes in the state */ \
        skinny128_sbox(s0); \
        skinny128_sbox(s1); \
        skinny128_sbox(s2); \
        skinny128_sbox(s3); \
        \
        /* XOR the round constant and the subkey for this round */ \
        s0 ^= schedule[offset * 2] ^ TK1[half * 2] ^ TK2[half * 2]; \
        s1 ^= schedule[offset * 2 + 1] ^ TK1[half * 2 + 1] ^ \
              TK2[half * 2 + 1]; \
        s2 ^= 0x02; \
        \
        /* Shift the cells in the rows right, which moves the cell \
         * values up closer to the MSB.  That is, we do a left rotate \
         * on the word to rotate the cells in the word right */ \
        s1 = leftRotate8(s1); \
        s2 = leftRotate16(s2); \
        s3 = leftRotate24(s3); \
        \
        /* Mix the columns, but don't rotate the words yet */ \
        s1 ^= s2; \
        s2 ^= s0; \
        s3 ^= s2; \
        \
        /* Permute TK1 and TK2 in-place for the next round */ \
        skinny128_permute_tk_half \
            (TK1[(1 - half) * 2], TK1[(1 - half) * 2 + 1]); \
        skinny128_permute_tk_half \
            (TK2[(1 - half) * 2], TK2[(1 - half) * 2 + 1]); \
        skinny128_LFSR2(TK2[(1 - half) * 2]); \
        skinny128_LFSR2(TK2[(1 - half) * 2 + 1]); \
    } while (0)
#endif /* !SKINNY_PLUS_VARIANT_TINY */

void skinny_plus_encrypt_tk2
    (skinny_plus_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, const unsigned char *tk2)
{
    uint32_t s0, s1, s2, s3;
    uint32_t TK1[4];
    uint32_t TK2[4];
#if SKINNY_PLUS_VARIANT == SKINNY_PLUS_VARIANT_TINY
    uint32_t TK3[4];
    uint8_t rc = 0;
#else
    const uint32_t *schedule = ks->k;
#endif
    unsigned round;

    /* Unpack the input block into the state array */
    s0 = le_load_word32(input);
    s1 = le_load_word32(input + 4);
    s2 = le_load_word32(input + 8);
    s3 = le_load_word32(input + 12);

    /* Make a local copy of the tweakable part of the state */
    TK1[0] = le_load_word32(ks->TK1);
    TK1[1] = le_load_word32(ks->TK1 + 4);
    TK1[2] = le_load_word32(ks->TK1 + 8);
    TK1[3] = le_load_word32(ks->TK1 + 12);
    TK2[0] = le_load_word32(tk2);
    TK2[1] = le_load_word32(tk2 + 4);
    TK2[2] = le_load_word32(tk2 + 8);
    TK2[3] = le_load_word32(tk2 + 12);
#if SKINNY_PLUS_VARIANT == SKINNY_PLUS_VARIANT_TINY
    TK3[0] = le_load_word32(ks->TK3);
    TK3[1] = le_load_word32(ks->TK3 + 4);
    TK3[2] = le_load_word32(ks->TK3 + 8);
    TK3[3] = le_load_word32(ks->TK3 + 12);
#endif

    /* Perform all encryption rounds four at a time */
    for (round = 0; round < SKINNY_PLUS_ROUNDS; round += 4) {
        skinny_plus_round_tk2(s0, s1, s2, s3, 0, 0);
        skinny_plus_round_tk2(s3, s0, s1, s2, 1, 1);
        skinny_plus_round_tk2(s2, s3, s0, s1, 0, 2);
        skinny_plus_round_tk2(s1, s2, s3, s0, 1, 3);
#if SKINNY_PLUS_VARIANT != SKINNY_PLUS_VARIANT_TINY
        schedule += 8;
#endif
    }

    /* Pack the result into the output buffer */
    le_store_word32(output,      s0);
    le_store_word32(output + 4,  s1);
    le_store_word32(output + 8,  s2);
    le_store_word32(output + 12, s3);
}

void skinny_plus_encrypt_tk_full
    (const unsigned char key[48], unsigned char *output,
     const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;
    uint32_t TK1[4];
    uint32_t TK2[4];
    uint32_t TK3[4];
    unsigned round;
    uint8_t rc = 0;

    /* Unpack the input block into the state array */
    s0 = le_load_word32(input);
    s1 = le_load_word32(input + 4);
    s2 = le_load_word32(input + 8);
    s3 = le_load_word32(input + 12);

    /* Make a local copy of the tweakey */
    TK1[0] = le_load_word32(key);
    TK1[1] = le_load_word32(key + 4);
    TK1[2] = le_load_word32(key + 8);
    TK1[3] = le_load_word32(key + 12);
    TK2[0] = le_load_word32(key + 16);
    TK2[1] = le_load_word32(key + 20);
    TK2[2] = le_load_word32(key + 24);
    TK2[3] = le_load_word32(key + 28);
    TK3[0] = le_load_word32(key + 32);
    TK3[1] = le_load_word32(key + 36);
    TK3[2] = le_load_word32(key + 40);
    TK3[3] = le_load_word32(key + 44);

    /* Perform all encryption rounds four at a time */
    for (round = 0; round < SKINNY_PLUS_ROUNDS; round += 4) {
        skinny_plus_round_tk_full(s0, s1, s2, s3, 0);
        skinny_plus_round_tk_full(s3, s0, s1, s2, 1);
        skinny_plus_round_tk_full(s2, s3, s0, s1, 0);
        skinny_plus_round_tk_full(s1, s2, s3, s0, 1);
    }

    /* Pack the result into the output buffer */
    le_store_word32(output,      s0);
    le_store_word32(output + 4,  s1);
    le_store_word32(output + 8,  s2);
    le_store_word32(output + 12, s3);
}

#endif /* !SKINNY_PLUS_VARIANT_ASM */

#if SKINNY_PLUS_VARIANT_ASM && SKINNY_PLUS_VARIANT == SKINNY_PLUS_VARIANT_TINY

void skinny_plus_encrypt_tk2
    (skinny_plus_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, const unsigned char *tk2)
{
    memcpy(ks->TK2, tk2, 16);
    skinny_plus_encrypt(ks, output, input);
}

#endif /* SKINNY_PLUS_VARIANT == SKINNY_PLUS_VARIANT_TINY */