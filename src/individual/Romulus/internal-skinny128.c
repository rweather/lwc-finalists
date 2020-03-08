/*
 * Copyright (C) 2020 Southern Storm Software, Pty Ltd.
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

#include "internal-skinny128.h"
#include "internal-skinnyutil.h"
#include "internal-util.h"
#include <string.h>

STATIC_INLINE void skinny128_fast_forward_tk(uint32_t *tk)
{
    /* This function is used to fast-forward the TK1 tweak value
     * to the value at the end of the key schedule for decryption.
     *
     * The tweak permutation repeats every 16 rounds, so SKINNY-128-256
     * with 48 rounds does not need any fast forwarding applied.
     * SKINNY-128-128 with 40 rounds and SKINNY-128-384 with 56 rounds
     * are equivalent to applying the permutation 8 times:
     *
     * PT*8 = [5, 6, 3, 2, 7, 0, 1, 4, 13, 14, 11, 10, 15, 8, 9, 12]
     */
    uint32_t row0 = tk[0];
    uint32_t row1 = tk[1];
    uint32_t row2 = tk[2];
    uint32_t row3 = tk[3];
    tk[0] = ((row1 >>  8) & 0x0000FFFFU) |
            ((row0 >>  8) & 0x00FF0000U) |
            ((row0 <<  8) & 0xFF000000U);
    tk[1] = ((row1 >> 24) & 0x000000FFU) |
            ((row0 <<  8) & 0x00FFFF00U) |
            ((row1 << 24) & 0xFF000000U);
    tk[2] = ((row3 >>  8) & 0x0000FFFFU) |
            ((row2 >>  8) & 0x00FF0000U) |
            ((row2 <<  8) & 0xFF000000U);
    tk[3] = ((row3 >> 24) & 0x000000FFU) |
            ((row2 <<  8) & 0x00FFFF00U) |
            ((row3 << 24) & 0xFF000000U);
}

int skinny_128_384_init
    (skinny_128_384_key_schedule_t *ks, const unsigned char *key,
     size_t key_len)
{
    uint32_t TK2[4];
    uint32_t TK3[4];
    uint32_t *schedule;
    unsigned round;
    uint8_t rc;

    /* Validate the parameters */
    if (!ks || !key || (key_len != 32 && key_len != 48))
        return 0;

    /* Set the initial states of TK1, TK2, and TK3 */
    if (key_len == 32) {
        memset(ks->TK1, 0, sizeof(ks->TK1));
        TK2[0] = le_load_word32(key);
        TK2[1] = le_load_word32(key + 4);
        TK2[2] = le_load_word32(key + 8);
        TK2[3] = le_load_word32(key + 12);
        TK3[0] = le_load_word32(key + 16);
        TK3[1] = le_load_word32(key + 20);
        TK3[2] = le_load_word32(key + 24);
        TK3[3] = le_load_word32(key + 28);
    } else {
        memcpy(ks->TK1, key, 16);
        TK2[0] = le_load_word32(key + 16);
        TK2[1] = le_load_word32(key + 20);
        TK2[2] = le_load_word32(key + 24);
        TK2[3] = le_load_word32(key + 28);
        TK3[0] = le_load_word32(key + 32);
        TK3[1] = le_load_word32(key + 36);
        TK3[2] = le_load_word32(key + 40);
        TK3[3] = le_load_word32(key + 44);
    }

    /* Set up the key schedule using TK2 and TK3.  TK1 is not added
     * to the key schedule because we will derive that part of the
     * schedule during encryption operations */
    schedule = ks->k;
    rc = 0;
    for (round = 0; round < SKINNY_128_384_ROUNDS; ++round, schedule += 2) {
        /* XOR the round constants with the current schedule words.
         * The round constants for the 3rd and 4th rows are
         * fixed and will be applied during encryption. */
        rc = (rc << 1) ^ ((rc >> 5) & 0x01) ^ ((rc >> 4) & 0x01) ^ 0x01;
        rc &= 0x3F;
        schedule[0] = TK2[0] ^ TK3[0] ^ (rc & 0x0F);
        schedule[1] = TK2[1] ^ TK3[1] ^ (rc >> 4);

        /* Permute TK2 and TK3 for the next round */
        skinny128_permute_tk(TK2);
        skinny128_permute_tk(TK3);

        /* Apply the LFSR's to TK2 and TK3 */
        skinny128_LFSR2(TK2[0]);
        skinny128_LFSR2(TK2[1]);
        skinny128_LFSR3(TK3[0]);
        skinny128_LFSR3(TK3[1]);
    }
    return 1;
}

int skinny_128_384_set_tweak
    (skinny_128_384_key_schedule_t *ks, const unsigned char *tweak,
     size_t tweak_len)
{
    /* Validate the parameters */
    if (!ks || !tweak || tweak_len != 16)
        return 0;

    /* Set TK1 directly from the tweak value */
    memcpy(ks->TK1, tweak, 16);
    return 1;
}

void skinny_128_384_encrypt
    (const skinny_128_384_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;
    uint32_t TK1[4];
    const uint32_t *schedule = ks->k;
    uint32_t temp;
    unsigned round;

    /* Unpack the input block into the state array */
    s0 = le_load_word32(input);
    s1 = le_load_word32(input + 4);
    s2 = le_load_word32(input + 8);
    s3 = le_load_word32(input + 12);

    /* Make a local copy of the tweakable part of the state, TK1 */
    TK1[0] = le_load_word32(ks->TK1);
    TK1[1] = le_load_word32(ks->TK1 + 4);
    TK1[2] = le_load_word32(ks->TK1 + 8);
    TK1[3] = le_load_word32(ks->TK1 + 12);

    /* Perform all encryption rounds */
    for (round = 0; round < SKINNY_128_384_ROUNDS; ++round, schedule += 2) {
        /* Apply the S-box to all bytes in the state */
        skinny128_sbox(s0);
        skinny128_sbox(s1);
        skinny128_sbox(s2);
        skinny128_sbox(s3);

        /* Apply the subkey for this round */
        s0 ^= schedule[0] ^ TK1[0];
        s1 ^= schedule[1] ^ TK1[1];
        s2 ^= 0x02;

        /* Shift the cells in the rows right, which moves the cell
         * values up closer to the MSB.  That is, we do a left rotate
         * on the word to rotate the cells in the word right */
        s1 = leftRotate8(s1);
        s2 = leftRotate16(s2);
        s3 = leftRotate24(s3);

        /* Mix the columns */
        s1 ^= s2;
        s2 ^= s0;
        temp = s3 ^ s2;
        s3 = s2;
        s2 = s1;
        s1 = s0;
        s0 = temp;

        /* Permute TK1 for the next round */
        skinny128_permute_tk(TK1);
    }

    /* Pack the result into the output buffer */
    le_store_word32(output,      s0);
    le_store_word32(output + 4,  s1);
    le_store_word32(output + 8,  s2);
    le_store_word32(output + 12, s3);
}

void skinny_128_384_decrypt
    (const skinny_128_384_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;
    uint32_t TK1[4];
    const uint32_t *schedule;
    uint32_t temp;
    unsigned round;

    /* Unpack the input block into the state array */
    s0 = le_load_word32(input);
    s1 = le_load_word32(input + 4);
    s2 = le_load_word32(input + 8);
    s3 = le_load_word32(input + 12);

    /* Make a local copy of the tweakable part of the state, TK1 */
    TK1[0] = le_load_word32(ks->TK1);
    TK1[1] = le_load_word32(ks->TK1 + 4);
    TK1[2] = le_load_word32(ks->TK1 + 8);
    TK1[3] = le_load_word32(ks->TK1 + 12);

    /* Permute TK1 to fast-forward it to the end of the key schedule */
    skinny128_fast_forward_tk(TK1);

    /* Perform all decryption rounds */
    schedule = &(ks->k[SKINNY_128_384_ROUNDS * 2 - 2]);
    for (round = 0; round < SKINNY_128_384_ROUNDS; ++round, schedule -= 2) {
        /* Inverse permutation on TK1 for this round */
        skinny128_inv_permute_tk(TK1);

        /* Inverse mix of the columns */
        temp = s3;
        s3 = s0;
        s0 = s1;
        s1 = s2;
        s3 ^= temp;
        s2 = temp ^ s0;
        s1 ^= s2;

        /* Inverse shift of the rows */
        s1 = leftRotate24(s1);
        s2 = leftRotate16(s2);
        s3 = leftRotate8(s3);

        /* Apply the subkey for this round */
        s0 ^= schedule[0] ^ TK1[0];
        s1 ^= schedule[1] ^ TK1[1];
        s2 ^= 0x02;

        /* Apply the inverse of the S-box to all bytes in the state */
        skinny128_inv_sbox(s0);
        skinny128_inv_sbox(s1);
        skinny128_inv_sbox(s2);
        skinny128_inv_sbox(s3);
    }

    /* Pack the result into the output buffer */
    le_store_word32(output,      s0);
    le_store_word32(output + 4,  s1);
    le_store_word32(output + 8,  s2);
    le_store_word32(output + 12, s3);
}

void skinny_128_384_encrypt_tk2
    (const skinny_128_384_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, const unsigned char *tk2)
{
    uint32_t s0, s1, s2, s3;
    uint32_t TK1[4];
    uint32_t TK2[4];
    const uint32_t *schedule = ks->k;
    uint32_t temp;
    unsigned round;

    /* Unpack the input block into the state array */
    s0 = le_load_word32(input);
    s1 = le_load_word32(input + 4);
    s2 = le_load_word32(input + 8);
    s3 = le_load_word32(input + 12);

    /* Make a local copy of the tweakable part of the state, TK1/TK2 */
    TK1[0] = le_load_word32(ks->TK1);
    TK1[1] = le_load_word32(ks->TK1 + 4);
    TK1[2] = le_load_word32(ks->TK1 + 8);
    TK1[3] = le_load_word32(ks->TK1 + 12);
    TK2[0] = le_load_word32(tk2);
    TK2[1] = le_load_word32(tk2 + 4);
    TK2[2] = le_load_word32(tk2 + 8);
    TK2[3] = le_load_word32(tk2 + 12);

    /* Perform all encryption rounds */
    for (round = 0; round < SKINNY_128_384_ROUNDS; ++round, schedule += 2) {
        /* Apply the S-box to all bytes in the state */
        skinny128_sbox(s0);
        skinny128_sbox(s1);
        skinny128_sbox(s2);
        skinny128_sbox(s3);

        /* Apply the subkey for this round */
        s0 ^= schedule[0] ^ TK1[0] ^ TK2[0];
        s1 ^= schedule[1] ^ TK1[1] ^ TK2[1];
        s2 ^= 0x02;

        /* Shift the cells in the rows right, which moves the cell
         * values up closer to the MSB.  That is, we do a left rotate
         * on the word to rotate the cells in the word right */
        s1 = leftRotate8(s1);
        s2 = leftRotate16(s2);
        s3 = leftRotate24(s3);

        /* Mix the columns */
        s1 ^= s2;
        s2 ^= s0;
        temp = s3 ^ s2;
        s3 = s2;
        s2 = s1;
        s1 = s0;
        s0 = temp;

        /* Permute TK1 and TK2 for the next round */
        skinny128_permute_tk(TK1);
        skinny128_permute_tk(TK2);
        skinny128_LFSR2(TK2[0]);
        skinny128_LFSR2(TK2[1]);
    }

    /* Pack the result into the output buffer */
    le_store_word32(output,      s0);
    le_store_word32(output + 4,  s1);
    le_store_word32(output + 8,  s2);
    le_store_word32(output + 12, s3);
}

void skinny_128_384_encrypt_tk_full
    (const unsigned char key[48], unsigned char *output,
     const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;
    uint32_t TK1[4];
    uint32_t TK2[4];
    uint32_t TK3[4];
    uint32_t temp;
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

    /* Perform all encryption rounds */
    for (round = 0; round < SKINNY_128_384_ROUNDS; ++round) {
        /* Apply the S-box to all bytes in the state */
        skinny128_sbox(s0);
        skinny128_sbox(s1);
        skinny128_sbox(s2);
        skinny128_sbox(s3);

        /* XOR the round constant and the subkey for this round */
        rc = (rc << 1) ^ ((rc >> 5) & 0x01) ^ ((rc >> 4) & 0x01) ^ 0x01;
        rc &= 0x3F;
        s0 ^= TK1[0] ^ TK2[0] ^ TK3[0] ^ (rc & 0x0F);
        s1 ^= TK1[1] ^ TK2[1] ^ TK3[1] ^ (rc >> 4);
        s2 ^= 0x02;

        /* Shift the cells in the rows right, which moves the cell
         * values up closer to the MSB.  That is, we do a left rotate
         * on the word to rotate the cells in the word right */
        s1 = leftRotate8(s1);
        s2 = leftRotate16(s2);
        s3 = leftRotate24(s3);

        /* Mix the columns */
        s1 ^= s2;
        s2 ^= s0;
        temp = s3 ^ s2;
        s3 = s2;
        s2 = s1;
        s1 = s0;
        s0 = temp;

        /* Permute TK1, TK2, and TK3 for the next round */
        skinny128_permute_tk(TK1);
        skinny128_permute_tk(TK2);
        skinny128_permute_tk(TK3);
        skinny128_LFSR2(TK2[0]);
        skinny128_LFSR2(TK2[1]);
        skinny128_LFSR3(TK3[0]);
        skinny128_LFSR3(TK3[1]);
    }

    /* Pack the result into the output buffer */
    le_store_word32(output,      s0);
    le_store_word32(output + 4,  s1);
    le_store_word32(output + 8,  s2);
    le_store_word32(output + 12, s3);
}

int skinny_128_256_init
    (skinny_128_256_key_schedule_t *ks, const unsigned char *key,
     size_t key_len)
{
    uint32_t TK2[4];
    uint32_t *schedule;
    unsigned round;
    uint8_t rc;

    /* Validate the parameters */
    if (!ks || !key || (key_len != 16 && key_len != 32))
        return 0;

    /* Set the initial states of TK1 and TK2 */
    if (key_len == 16) {
        memset(ks->TK1, 0, sizeof(ks->TK1));
        TK2[0] = le_load_word32(key);
        TK2[1] = le_load_word32(key + 4);
        TK2[2] = le_load_word32(key + 8);
        TK2[3] = le_load_word32(key + 12);
    } else {
        memcpy(ks->TK1, key, 16);
        TK2[0] = le_load_word32(key + 16);
        TK2[1] = le_load_word32(key + 20);
        TK2[2] = le_load_word32(key + 24);
        TK2[3] = le_load_word32(key + 28);
    }

    /* Set up the key schedule using TK2.  TK1 is not added
     * to the key schedule because we will derive that part of the
     * schedule during encryption operations */
    schedule = ks->k;
    rc = 0;
    for (round = 0; round < SKINNY_128_256_ROUNDS; ++round, schedule += 2) {
        /* XOR the round constants with the current schedule words.
         * The round constants for the 3rd and 4th rows are
         * fixed and will be applied during encryption. */
        rc = (rc << 1) ^ ((rc >> 5) & 0x01) ^ ((rc >> 4) & 0x01) ^ 0x01;
        rc &= 0x3F;
        schedule[0] = TK2[0] ^ (rc & 0x0F);
        schedule[1] = TK2[1] ^ (rc >> 4);

        /* Permute TK2 for the next round */
        skinny128_permute_tk(TK2);

        /* Apply the LFSR to TK2 */
        skinny128_LFSR2(TK2[0]);
        skinny128_LFSR2(TK2[1]);
    }
    return 1;
}

int skinny_128_256_set_tweak
    (skinny_128_256_key_schedule_t *ks, const unsigned char *tweak,
     size_t tweak_len)
{
    /* Validate the parameters */
    if (!ks || !tweak || tweak_len != 16)
        return 0;

    /* Set TK1 directly from the tweak value */
    memcpy(ks->TK1, tweak, 16);
    return 1;
}

void skinny_128_256_encrypt
    (const skinny_128_256_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;
    uint32_t TK1[4];
    const uint32_t *schedule = ks->k;
    uint32_t temp;
    unsigned round;

    /* Unpack the input block into the state array */
    s0 = le_load_word32(input);
    s1 = le_load_word32(input + 4);
    s2 = le_load_word32(input + 8);
    s3 = le_load_word32(input + 12);

    /* Make a local copy of the tweakable part of the state, TK1 */
    TK1[0] = le_load_word32(ks->TK1);
    TK1[1] = le_load_word32(ks->TK1 + 4);
    TK1[2] = le_load_word32(ks->TK1 + 8);
    TK1[3] = le_load_word32(ks->TK1 + 12);

    /* Perform all encryption rounds */
    for (round = 0; round < SKINNY_128_256_ROUNDS; ++round, schedule += 2) {
        /* Apply the S-box to all bytes in the state */
        skinny128_sbox(s0);
        skinny128_sbox(s1);
        skinny128_sbox(s2);
        skinny128_sbox(s3);

        /* Apply the subkey for this round */
        s0 ^= schedule[0] ^ TK1[0];
        s1 ^= schedule[1] ^ TK1[1];
        s2 ^= 0x02;

        /* Shift the cells in the rows right, which moves the cell
         * values up closer to the MSB.  That is, we do a left rotate
         * on the word to rotate the cells in the word right */
        s1 = leftRotate8(s1);
        s2 = leftRotate16(s2);
        s3 = leftRotate24(s3);

        /* Mix the columns */
        s1 ^= s2;
        s2 ^= s0;
        temp = s3 ^ s2;
        s3 = s2;
        s2 = s1;
        s1 = s0;
        s0 = temp;

        /* Permute TK1 for the next round */
        skinny128_permute_tk(TK1);
    }

    /* Pack the result into the output buffer */
    le_store_word32(output,      s0);
    le_store_word32(output + 4,  s1);
    le_store_word32(output + 8,  s2);
    le_store_word32(output + 12, s3);
}

void skinny_128_256_decrypt
    (const skinny_128_256_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;
    uint32_t TK1[4];
    const uint32_t *schedule;
    uint32_t temp;
    unsigned round;

    /* Unpack the input block into the state array */
    s0 = le_load_word32(input);
    s1 = le_load_word32(input + 4);
    s2 = le_load_word32(input + 8);
    s3 = le_load_word32(input + 12);

    /* Make a local copy of the tweakable part of the state, TK1.
     * There is no need to fast-forward TK1 because the value at
     * the end of the key schedule is the same as at the start */
    TK1[0] = le_load_word32(ks->TK1);
    TK1[1] = le_load_word32(ks->TK1 + 4);
    TK1[2] = le_load_word32(ks->TK1 + 8);
    TK1[3] = le_load_word32(ks->TK1 + 12);

    /* Perform all decryption rounds */
    schedule = &(ks->k[SKINNY_128_256_ROUNDS * 2 - 2]);
    for (round = 0; round < SKINNY_128_256_ROUNDS; ++round, schedule -= 2) {
        /* Inverse permutation on TK1 for this round */
        skinny128_inv_permute_tk(TK1);

        /* Inverse mix of the columns */
        temp = s3;
        s3 = s0;
        s0 = s1;
        s1 = s2;
        s3 ^= temp;
        s2 = temp ^ s0;
        s1 ^= s2;

        /* Inverse shift of the rows */
        s1 = leftRotate24(s1);
        s2 = leftRotate16(s2);
        s3 = leftRotate8(s3);

        /* Apply the subkey for this round */
        s0 ^= schedule[0] ^ TK1[0];
        s1 ^= schedule[1] ^ TK1[1];
        s2 ^= 0x02;

        /* Apply the inverse of the S-box to all bytes in the state */
        skinny128_inv_sbox(s0);
        skinny128_inv_sbox(s1);
        skinny128_inv_sbox(s2);
        skinny128_inv_sbox(s3);
    }

    /* Pack the result into the output buffer */
    le_store_word32(output,      s0);
    le_store_word32(output + 4,  s1);
    le_store_word32(output + 8,  s2);
    le_store_word32(output + 12, s3);
}

void skinny_128_256_encrypt_tk_full
    (const unsigned char key[32], unsigned char *output,
     const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;
    uint32_t TK1[4];
    uint32_t TK2[4];
    uint32_t temp;
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

    /* Perform all encryption rounds */
    for (round = 0; round < SKINNY_128_256_ROUNDS; ++round) {
        /* Apply the S-box to all bytes in the state */
        skinny128_sbox(s0);
        skinny128_sbox(s1);
        skinny128_sbox(s2);
        skinny128_sbox(s3);

        /* XOR the round constant and the subkey for this round */
        rc = (rc << 1) ^ ((rc >> 5) & 0x01) ^ ((rc >> 4) & 0x01) ^ 0x01;
        rc &= 0x3F;
        s0 ^= TK1[0] ^ TK2[0] ^ (rc & 0x0F);
        s1 ^= TK1[1] ^ TK2[1] ^ (rc >> 4);
        s2 ^= 0x02;

        /* Shift the cells in the rows right, which moves the cell
         * values up closer to the MSB.  That is, we do a left rotate
         * on the word to rotate the cells in the word right */
        s1 = leftRotate8(s1);
        s2 = leftRotate16(s2);
        s3 = leftRotate24(s3);

        /* Mix the columns */
        s1 ^= s2;
        s2 ^= s0;
        temp = s3 ^ s2;
        s3 = s2;
        s2 = s1;
        s1 = s0;
        s0 = temp;

        /* Permute TK1 and TK2 for the next round */
        skinny128_permute_tk(TK1);
        skinny128_permute_tk(TK2);
        skinny128_LFSR2(TK2[0]);
        skinny128_LFSR2(TK2[1]);
    }

    /* Pack the result into the output buffer */
    le_store_word32(output,      s0);
    le_store_word32(output + 4,  s1);
    le_store_word32(output + 8,  s2);
    le_store_word32(output + 12, s3);
}

int skinny_128_128_init
    (skinny_128_128_key_schedule_t *ks, const unsigned char *key,
     size_t key_len)
{
    uint32_t TK1[4];
    uint32_t *schedule;
    unsigned round;
    uint8_t rc;

    /* Validate the parameters */
    if (!ks || !key || key_len != 16)
        return 0;

    /* Set the initial state of TK1 */
    TK1[0] = le_load_word32(key);
    TK1[1] = le_load_word32(key + 4);
    TK1[2] = le_load_word32(key + 8);
    TK1[3] = le_load_word32(key + 12);

    /* Set up the key schedule using TK1 */
    schedule = ks->k;
    rc = 0;
    for (round = 0; round < SKINNY_128_128_ROUNDS; ++round, schedule += 2) {
        /* XOR the round constants with the current schedule words.
         * The round constants for the 3rd and 4th rows are
         * fixed and will be applied during encryption. */
        rc = (rc << 1) ^ ((rc >> 5) & 0x01) ^ ((rc >> 4) & 0x01) ^ 0x01;
        rc &= 0x3F;
        schedule[0] = TK1[0] ^ (rc & 0x0F);
        schedule[1] = TK1[1] ^ (rc >> 4);

        /* Permute TK1 for the next round */
        skinny128_permute_tk(TK1);
    }
    return 1;
}

void skinny_128_128_encrypt
    (const skinny_128_128_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;
    const uint32_t *schedule = ks->k;
    uint32_t temp;
    unsigned round;

    /* Unpack the input block into the state array */
    s0 = le_load_word32(input);
    s1 = le_load_word32(input + 4);
    s2 = le_load_word32(input + 8);
    s3 = le_load_word32(input + 12);

    /* Perform all encryption rounds */
    for (round = 0; round < SKINNY_128_128_ROUNDS; ++round, schedule += 2) {
        /* Apply the S-box to all bytes in the state */
        skinny128_sbox(s0);
        skinny128_sbox(s1);
        skinny128_sbox(s2);
        skinny128_sbox(s3);

        /* Apply the subkey for this round */
        s0 ^= schedule[0];
        s1 ^= schedule[1];
        s2 ^= 0x02;

        /* Shift the cells in the rows right, which moves the cell
         * values up closer to the MSB.  That is, we do a left rotate
         * on the word to rotate the cells in the word right */
        s1 = leftRotate8(s1);
        s2 = leftRotate16(s2);
        s3 = leftRotate24(s3);

        /* Mix the columns */
        s1 ^= s2;
        s2 ^= s0;
        temp = s3 ^ s2;
        s3 = s2;
        s2 = s1;
        s1 = s0;
        s0 = temp;
    }

    /* Pack the result into the output buffer */
    le_store_word32(output,      s0);
    le_store_word32(output + 4,  s1);
    le_store_word32(output + 8,  s2);
    le_store_word32(output + 12, s3);
}

void skinny_128_128_decrypt
    (const skinny_128_128_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;
    const uint32_t *schedule;
    uint32_t temp;
    unsigned round;

    /* Unpack the input block into the state array */
    s0 = le_load_word32(input);
    s1 = le_load_word32(input + 4);
    s2 = le_load_word32(input + 8);
    s3 = le_load_word32(input + 12);

    /* Perform all decryption rounds */
    schedule = &(ks->k[SKINNY_128_128_ROUNDS * 2 - 2]);
    for (round = 0; round < SKINNY_128_128_ROUNDS; ++round, schedule -= 2) {
        /* Inverse mix of the columns */
        temp = s3;
        s3 = s0;
        s0 = s1;
        s1 = s2;
        s3 ^= temp;
        s2 = temp ^ s0;
        s1 ^= s2;

        /* Inverse shift of the rows */
        s1 = leftRotate24(s1);
        s2 = leftRotate16(s2);
        s3 = leftRotate8(s3);

        /* Apply the subkey for this round */
        s0 ^= schedule[0];
        s1 ^= schedule[1];
        s2 ^= 0x02;

        /* Apply the inverse of the S-box to all bytes in the state */
        skinny128_inv_sbox(s0);
        skinny128_inv_sbox(s1);
        skinny128_inv_sbox(s2);
        skinny128_inv_sbox(s3);
    }

    /* Pack the result into the output buffer */
    le_store_word32(output,      s0);
    le_store_word32(output + 4,  s1);
    le_store_word32(output + 8,  s2);
    le_store_word32(output + 12, s3);
}