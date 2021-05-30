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

#include "internal-keccakp-400.h"

/* Determine if Keccak-p[400] should be accelerated with assembly code */
#if defined(__AVR__)
#define KECCAKP_400_ASM 1
#elif defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7
#define KECCAKP_400_ASM 1
#else
#define KECCAKP_400_ASM 0
#endif

#if !KECCAKP_400_ASM

/* Define to 1 to select the optimised 64-bit version of Keccak-p[400] */
#if defined(LW_UTIL_CPU_IS_64BIT)
#define KECCAKP_400_OPT64 1
#else
#define KECCAKP_400_OPT64 0
#endif

#if KECCAKP_400_OPT64

/*
 * Optimized version for 64-bit platforms, inspired by the ARMv7 code at:
 *
 * https://github.com/XKCP/XKCP/blob/master/lib/low/KeccakP-200/ARM/KeccakP-200-armv7m-le-gcc.s
 *
 * Note: Inspired by the Keccak-p[200] version as it packs up multiple
 * 8-bit lanes into 32-bit registers and processes them in parallel.
 * We do the same here with 64-bit registers and 16-bit lanes.  By contrast,
 * the XKCP armv7m version of Keccak-p[400] is a more straight-forward
 * 16-bit implementation.
 */

void keccakp_400_permute(keccakp_400_state_t *state, unsigned rounds)
{
    static uint16_t const RC[20] = {
        0x0001, 0x8082, 0x808A, 0x8000, 0x808B, 0x0001, 0x8081, 0x8009,
        0x008A, 0x0088, 0x8009, 0x000A, 0x808B, 0x008B, 0x8089, 0x8003,
        0x8002, 0x0080, 0x800A, 0x000A
    };
    uint64_t r0_l, r0_r;        /* Left and right halves of row 0 */
    uint64_t r1_l, r1_r;        /* Left and right halves of row 1 */
    uint64_t r2_l, r2_r;        /* Left and right halves of row 2 */
    uint64_t r3_l, r3_r;        /* Left and right halves of row 3 */
    uint64_t r4_l, r4_r;        /* Left and right halves of row 4 */
    uint64_t C_l, C_r;
    unsigned round;

    /* Load the state into the row vectors */
    r0_l = le_load_word64((const unsigned char *)&(state->A[0][0]));
    r1_l = le_load_word64((const unsigned char *)&(state->A[1][0]));
    r2_l = le_load_word64((const unsigned char *)&(state->A[2][0]));
    r3_l = le_load_word64((const unsigned char *)&(state->A[3][0]));
    r4_l = le_load_word64((const unsigned char *)&(state->A[4][0]));
#if defined(LW_UTIL_LITTLE_ENDIAN)
    r0_r = state->A[0][4];
    r1_r = state->A[1][4];
    r2_r = state->A[2][4];
    r3_r = state->A[3][4];
    r4_r = state->A[4][4];
#else
    r0_r = le_load_word16((const unsigned char *)&(state->A[0][4]));
    r1_r = le_load_word16((const unsigned char *)&(state->A[1][4]));
    r2_r = le_load_word16((const unsigned char *)&(state->A[2][4]));
    r3_r = le_load_word16((const unsigned char *)&(state->A[3][4]));
    r4_r = le_load_word16((const unsigned char *)&(state->A[4][4]));
#endif

    /* Perform all rounds */
    for (round = 20 - rounds; round < 20; ++round) {
        /* Step mapping theta */
        /*
         * C[index] = state->A[0][index] ^ state->A[1][index] ^
         *            state->A[2][index] ^ state->A[3][index] ^
         *            state->A[4][index];
         */
        C_l = r0_l ^ r1_l ^ r2_l ^ r3_l ^ r4_l;
        C_r = r0_r ^ r1_r ^ r2_r ^ r3_r ^ r4_r;
        /*
         * D = C[(index + 4) % 5] ^ leftRotate1_16(C[(index + 1) % 5])
         */
        C_r = (((C_l & 0x7FFF7FFF7FFF7FFFULL) >> 15) |
               ((C_l & 0x8000800080008000ULL) >> 31) |
               ((C_r & 0x7FFFU) << 49) | ((C_r & 0x8000U) << 33)) ^
              ((C_l << 16) | C_r);
        C_l = (((C_l & 0x7FFFU) << 1) | ((C_l & 0x8000UL) >> 15)) ^ (C_l >> 48);
        /*
         * Apply D to all rows.  The left word of D is in the right word of C.
         */
        r0_l ^= C_r;
        r1_l ^= C_r;
        r2_l ^= C_r;
        r3_l ^= C_r;
        r4_l ^= C_r;
        r0_r ^= C_l;
        r1_r ^= C_l;
        r2_r ^= C_l;
        r3_r ^= C_l;
        r4_r ^= C_l;

        /* Step mapping rho and pi combined into a single step.
         * Rotate all lanes by a specific offset and rearrange */
        #define MASK_OFF(col) (~(0xFFFFULL << (((col) & 3) * 16)))
        #define RHO_PI(dest, destcol, src, srccol, rot) \
            do { \
                C_l = ((src) >> (((srccol) & 3) * 16)) & 0xFFFFULL; \
                C_l = ((C_l << (rot)) | (C_l >> (16 - (rot)))) & 0xFFFFULL; \
                (dest) = ((dest) & MASK_OFF((destcol))) | \
                         (C_l << (((destcol) & 3) * 16)); \
            } while (0)
        /* D = state->A[0][1]; */
        C_r = (r0_l >> 16) & 0xFFFFU;
        /* state->A[0][1] = leftRotate12_16(state->A[1][1]); */
        RHO_PI(r0_l, 1, r1_l, 1, 12);
        /* state->A[1][1] = leftRotate4_16 (state->A[1][4]); */
        RHO_PI(r1_l, 1, r1_r, 4, 4);
        /* state->A[1][4] = leftRotate13_16(state->A[4][2]); */
        RHO_PI(r1_r, 4, r4_l, 2, 13);
        /* state->A[4][2] = leftRotate7_16 (state->A[2][4]); */
        RHO_PI(r4_l, 2, r2_r, 4, 7);
        /* state->A[2][4] = leftRotate2_16 (state->A[4][0]); */
        RHO_PI(r2_r, 4, r4_l, 0, 2);
        /* state->A[4][0] = leftRotate14_16(state->A[0][2]); */
        RHO_PI(r4_l, 0, r0_l, 2, 14);
        /* state->A[0][2] = leftRotate11_16(state->A[2][2]); */
        RHO_PI(r0_l, 2, r2_l, 2, 11);
        /* state->A[2][2] = leftRotate9_16 (state->A[2][3]); */
        RHO_PI(r2_l, 2, r2_l, 3, 9);
        /* state->A[2][3] = leftRotate8_16 (state->A[3][4]); */
        RHO_PI(r2_l, 3, r3_r, 4, 8);
        /* state->A[3][4] = leftRotate8_16 (state->A[4][3]); */
        RHO_PI(r3_r, 4, r4_l, 3, 8);
        /* state->A[4][3] = leftRotate9_16 (state->A[3][0]); */
        RHO_PI(r4_l, 3, r3_l, 0, 9);
        /* state->A[3][0] = leftRotate11_16(state->A[0][4]); */
        RHO_PI(r3_l, 0, r0_r, 4, 11);
        /* state->A[0][4] = leftRotate14_16(state->A[4][4]); */
        RHO_PI(r0_r, 4, r4_r, 4, 14);
        /* state->A[4][4] = leftRotate2_16 (state->A[4][1]); */
        RHO_PI(r4_r, 4, r4_l, 1, 2);
        /* state->A[4][1] = leftRotate7_16 (state->A[1][3]); */
        RHO_PI(r4_l, 1, r1_l, 3, 7);
        /* state->A[1][3] = leftRotate13_16(state->A[3][1]); */
        RHO_PI(r1_l, 3, r3_l, 1, 13);
        /* state->A[3][1] = leftRotate4_16 (state->A[1][0]); */
        RHO_PI(r3_l, 1, r1_l, 0, 4);
        /* state->A[1][0] = leftRotate12_16(state->A[0][3]); */
        RHO_PI(r1_l, 0, r0_l, 3, 12);
        /* state->A[0][3] = leftRotate5_16 (state->A[3][3]); */
        RHO_PI(r0_l, 3, r3_l, 3, 5);
        /* state->A[3][3] = leftRotate15_16(state->A[3][2]); */
        RHO_PI(r3_l, 3, r3_l, 2, 15);
        /* state->A[3][2] = leftRotate10_16(state->A[2][1]); */
        RHO_PI(r3_l, 2, r2_l, 1, 10);
        /* state->A[2][1] = leftRotate6_16 (state->A[1][2]); */
        RHO_PI(r2_l, 1, r1_l, 2, 6);
        /* state->A[1][2] = leftRotate3_16 (state->A[2][0]); */
        RHO_PI(r1_l, 2, r2_l, 0, 3);
        /* state->A[2][0] = leftRotate1_16(D); */
        r2_l = (r2_l & ~0xFFFFULL) | (((C_r << 1) | (C_r >> 15)) & 0xFFFFU);

        /* Step mapping chi.  Combine each lane with two others in its row */
        /*
         * for (index = 0; index < 5; ++index) {
         *     C[0] = state->A[index][0];
         *     C[1] = state->A[index][1];
         *     C[2] = state->A[index][2];
         *     C[3] = state->A[index][3];
         *     C[4] = state->A[index][4];
         *     for (index2 = 0; index2 < 5; ++index2) {
         *         state->A[index][index2] =
         *             C[index2] ^
         *             ((~C[addMod5(index2, 1)]) & C[addMod5(index2, 2)]);
         *     }
         * }
         */
        #define CHI(rl, rr) \
            do { \
                C_l = (~(((rl) >> 16) | ((rr) << 48))) & \
                      (((rl) >> 32) | ((rl) << 48) | ((rr) << 32)); \
                C_r = ((~(rl)) & ((rl) >> 16)) & 0xFFFFU; \
                (rl) ^= C_l; \
                (rr) ^= C_r; \
            } while (0)
        CHI(r0_l, r0_r);
        CHI(r1_l, r1_r);
        CHI(r2_l, r2_r);
        CHI(r3_l, r3_r);
        CHI(r4_l, r4_r);

        /* Step mapping iota.  XOR A[0][0] with the round constant */
        r0_l ^= RC[round];
    }

    /* Write the row vectors back to the state */
    le_store_word64((unsigned char *)&(state->A[0][0]), r0_l);
    le_store_word64((unsigned char *)&(state->A[1][0]), r1_l);
    le_store_word64((unsigned char *)&(state->A[2][0]), r2_l);
    le_store_word64((unsigned char *)&(state->A[3][0]), r3_l);
    le_store_word64((unsigned char *)&(state->A[4][0]), r4_l);
#if defined(LW_UTIL_LITTLE_ENDIAN)
    state->A[0][4] = (uint16_t)r0_r;
    state->A[1][4] = (uint16_t)r1_r;
    state->A[2][4] = (uint16_t)r2_r;
    state->A[3][4] = (uint16_t)r3_r;
    state->A[4][4] = (uint16_t)r4_r;
#else
    le_store_word16((unsigned char *)&(state->A[0][4]), r0_r);
    le_store_word16((unsigned char *)&(state->A[1][4]), r1_r);
    le_store_word16((unsigned char *)&(state->A[2][4]), r2_r);
    le_store_word16((unsigned char *)&(state->A[3][4]), r3_r);
    le_store_word16((unsigned char *)&(state->A[4][4]), r4_r);
#endif
}

#else /* !KECCAKP_400_OPT64 */

/* Faster method to compute ((x + y) % 5) that avoids the division */
static unsigned char const addMod5Table[9] = {
    0, 1, 2, 3, 4, 0, 1, 2, 3
};
#define addMod5(x, y) (addMod5Table[(x) + (y)])

#if defined(LW_UTIL_LITTLE_ENDIAN)
#define keccakp_400_permute_host keccakp_400_permute
#endif

/* Keccak-p[400] that assumes that the input is already in host byte order */
void keccakp_400_permute_host(keccakp_400_state_t *state, unsigned rounds)
{
    static uint16_t const RC[20] = {
        0x0001, 0x8082, 0x808A, 0x8000, 0x808B, 0x0001, 0x8081, 0x8009,
        0x008A, 0x0088, 0x8009, 0x000A, 0x808B, 0x008B, 0x8089, 0x8003,
        0x8002, 0x0080, 0x800A, 0x000A
    };
    uint16_t C[5];
    uint16_t D;
    unsigned round;
    unsigned index, index2;
    for (round = 20 - rounds; round < 20; ++round) {
        /* Step mapping theta.  The specification mentions two temporary
         * arrays of size 5 called C and D.  Compute D on the fly */
        for (index = 0; index < 5; ++index) {
            C[index] = state->A[0][index] ^ state->A[1][index] ^
                       state->A[2][index] ^ state->A[3][index] ^
                       state->A[4][index];
        }
        for (index = 0; index < 5; ++index) {
            D = C[addMod5(index, 4)] ^
                leftRotate1_16(C[addMod5(index, 1)]);
            for (index2 = 0; index2 < 5; ++index2)
                state->A[index2][index] ^= D;
        }

        /* Step mapping rho and pi combined into a single step.
         * Rotate all lanes by a specific offset and rearrange */
        D = state->A[0][1];
        state->A[0][1] = leftRotate12_16(state->A[1][1]);
        state->A[1][1] = leftRotate4_16 (state->A[1][4]);
        state->A[1][4] = leftRotate13_16(state->A[4][2]);
        state->A[4][2] = leftRotate7_16 (state->A[2][4]);
        state->A[2][4] = leftRotate2_16 (state->A[4][0]);
        state->A[4][0] = leftRotate14_16(state->A[0][2]);
        state->A[0][2] = leftRotate11_16(state->A[2][2]);
        state->A[2][2] = leftRotate9_16 (state->A[2][3]);
        state->A[2][3] = leftRotate8_16 (state->A[3][4]);
        state->A[3][4] = leftRotate8_16 (state->A[4][3]);
        state->A[4][3] = leftRotate9_16 (state->A[3][0]);
        state->A[3][0] = leftRotate11_16(state->A[0][4]);
        state->A[0][4] = leftRotate14_16(state->A[4][4]);
        state->A[4][4] = leftRotate2_16 (state->A[4][1]);
        state->A[4][1] = leftRotate7_16 (state->A[1][3]);
        state->A[1][3] = leftRotate13_16(state->A[3][1]);
        state->A[3][1] = leftRotate4_16 (state->A[1][0]);
        state->A[1][0] = leftRotate12_16(state->A[0][3]);
        state->A[0][3] = leftRotate5_16 (state->A[3][3]);
        state->A[3][3] = leftRotate15_16(state->A[3][2]);
        state->A[3][2] = leftRotate10_16(state->A[2][1]);
        state->A[2][1] = leftRotate6_16 (state->A[1][2]);
        state->A[1][2] = leftRotate3_16 (state->A[2][0]);
        state->A[2][0] = leftRotate1_16(D);

        /* Step mapping chi.  Combine each lane with two others in its row */
        for (index = 0; index < 5; ++index) {
            C[0] = state->A[index][0];
            C[1] = state->A[index][1];
            C[2] = state->A[index][2];
            C[3] = state->A[index][3];
            C[4] = state->A[index][4];
            for (index2 = 0; index2 < 5; ++index2) {
                state->A[index][index2] =
                    C[index2] ^
                    ((~C[addMod5(index2, 1)]) & C[addMod5(index2, 2)]);
            }
        }

        /* Step mapping iota.  XOR A[0][0] with the round constant */
        state->A[0][0] ^= RC[round];
    }
}

#if !defined(LW_UTIL_LITTLE_ENDIAN)

/**
 * \brief Reverses the bytes in a Keccak-p[400] state.
 *
 * \param state The Keccak-p[400] state to apply byte-reversal to.
 */
static void keccakp_400_reverse_bytes(keccakp_400_state_t *state)
{
    unsigned index;
    unsigned char temp1;
    unsigned char temp2;
    for (index = 0; index < 50; index += 2) {
        temp1 = state->B[index];
        temp2 = state->B[index + 1];
        state->B[index] = temp2;
        state->B[index + 1] = temp1;
    }
}

/* Keccak-p[400] that requires byte reversal on input and output */
void keccakp_400_permute(keccakp_400_state_t *state, unsigned rounds)
{
    keccakp_400_reverse_bytes(state);
    keccakp_400_permute_host(state, rounds);
    keccakp_400_reverse_bytes(state);
}

#endif

#endif /* !KECCAKP_400_OPT64 */

#endif /* !KECCAKP_400_ASM */
