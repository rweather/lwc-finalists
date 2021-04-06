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
 * This program is used to generate the assembly code version of the
 * Spongnt-pi permutation for ARM v7m microprocessors.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Round constants for Spongent-pi[160] */
static uint8_t const RC_160[] = {
    0x75, 0xae, 0x6a, 0x56, 0x54, 0x2a, 0x29, 0x94,
    0x53, 0xca, 0x27, 0xe4, 0x4f, 0xf2, 0x1f, 0xf8,
    0x3e, 0x7c, 0x7d, 0xbe, 0x7a, 0x5e, 0x74, 0x2e,
    0x68, 0x16, 0x50, 0x0a, 0x21, 0x84, 0x43, 0xc2,
    0x07, 0xe0, 0x0e, 0x70, 0x1c, 0x38, 0x38, 0x1c,
    0x71, 0x8e, 0x62, 0x46, 0x44, 0x22, 0x09, 0x90,
    0x12, 0x48, 0x24, 0x24, 0x49, 0x92, 0x13, 0xc8,
    0x26, 0x64, 0x4d, 0xb2, 0x1b, 0xd8, 0x36, 0x6c,
    0x6d, 0xb6, 0x5a, 0x5a, 0x35, 0xac, 0x6b, 0xd6,
    0x56, 0x6a, 0x2d, 0xb4, 0x5b, 0xda, 0x37, 0xec,
    0x6f, 0xf6, 0x5e, 0x7a, 0x3d, 0xbc, 0x7b, 0xde,
    0x76, 0x6e, 0x6c, 0x36, 0x58, 0x1a, 0x31, 0x8c,
    0x63, 0xc6, 0x46, 0x62, 0x0d, 0xb0, 0x1a, 0x58,
    0x34, 0x2c, 0x69, 0x96, 0x52, 0x4a, 0x25, 0xa4,
    0x4b, 0xd2, 0x17, 0xe8, 0x2e, 0x74, 0x5d, 0xba,
    0x3b, 0xdc, 0x77, 0xee, 0x6e, 0x76, 0x5c, 0x3a,
    0x39, 0x9c, 0x73, 0xce, 0x66, 0x66, 0x4c, 0x32,
    0x19, 0x98, 0x32, 0x4c, 0x65, 0xa6, 0x4a, 0x52,
    0x15, 0xa8, 0x2a, 0x54, 0x55, 0xaa, 0x2b, 0xd4,
    0x57, 0xea, 0x2f, 0xf4, 0x5f, 0xfa, 0x3f, 0xfc
};

/* Round constants for Spongent-pi[176] */
static uint8_t const RC_176[] = {
    0x45, 0xa2, 0x0b, 0xd0, 0x16, 0x68, 0x2c, 0x34,
    0x59, 0x9a, 0x33, 0xcc, 0x67, 0xe6, 0x4e, 0x72,
    0x1d, 0xb8, 0x3a, 0x5c, 0x75, 0xae, 0x6a, 0x56,
    0x54, 0x2a, 0x29, 0x94, 0x53, 0xca, 0x27, 0xe4,
    0x4f, 0xf2, 0x1f, 0xf8, 0x3e, 0x7c, 0x7d, 0xbe,
    0x7a, 0x5e, 0x74, 0x2e, 0x68, 0x16, 0x50, 0x0a,
    0x21, 0x84, 0x43, 0xc2, 0x07, 0xe0, 0x0e, 0x70,
    0x1c, 0x38, 0x38, 0x1c, 0x71, 0x8e, 0x62, 0x46,
    0x44, 0x22, 0x09, 0x90, 0x12, 0x48, 0x24, 0x24,
    0x49, 0x92, 0x13, 0xc8, 0x26, 0x64, 0x4d, 0xb2,
    0x1b, 0xd8, 0x36, 0x6c, 0x6d, 0xb6, 0x5a, 0x5a,
    0x35, 0xac, 0x6b, 0xd6, 0x56, 0x6a, 0x2d, 0xb4,
    0x5b, 0xda, 0x37, 0xec, 0x6f, 0xf6, 0x5e, 0x7a,
    0x3d, 0xbc, 0x7b, 0xde, 0x76, 0x6e, 0x6c, 0x36,
    0x58, 0x1a, 0x31, 0x8c, 0x63, 0xc6, 0x46, 0x62,
    0x0d, 0xb0, 0x1a, 0x58, 0x34, 0x2c, 0x69, 0x96,
    0x52, 0x4a, 0x25, 0xa4, 0x4b, 0xd2, 0x17, 0xe8,
    0x2e, 0x74, 0x5d, 0xba, 0x3b, 0xdc, 0x77, 0xee,
    0x6e, 0x76, 0x5c, 0x3a, 0x39, 0x9c, 0x73, 0xce,
    0x66, 0x66, 0x4c, 0x32, 0x19, 0x98, 0x32, 0x4c,
    0x65, 0xa6, 0x4a, 0x52, 0x15, 0xa8, 0x2a, 0x54,
    0x55, 0xaa, 0x2b, 0xd4, 0x57, 0xea, 0x2f, 0xf4,
    0x5f, 0xfa, 0x3f, 0xfc
};

static void function_header(const char *name)
{
    printf("\n\t.align\t2\n");
    printf("\t.global\t%s\n", name);
    printf("\t.thumb\n");
    printf("\t.thumb_func\n");
    printf("\t.type\t%s, %%function\n", name);
    printf("%s:\n", name);
}

static void function_footer(const char *name)
{
    printf("\t.size\t%s, .-%s\n", name, name);
}

/* List of all registers that we can work with */
typedef struct
{
    const char *x[6];
    const char *t0;
    const char *t1;
    const char *t2;
    const char *t3;
    const char *t4;
    const char *rc;
    const char *round;

} reg_names;

static int is_low_reg(const char *reg)
{
    return reg[0] == 'r' && atoi(reg + 1) < 8;
}

/* Generates a binary operator, preferring thumb instructions if possible */
static void binop(const char *name, const char *reg1, const char *reg2)
{
    if (is_low_reg(reg1) && is_low_reg(reg2))
        printf("\t%ss\t%s, %s\n", name, reg1, reg2);
    else
        printf("\t%s\t%s, %s\n", name, reg1, reg2);
}

/* Determine if a constant can be used as "Operand2" in an instruction */
static int is_op2_constant(uint32_t value)
{
    int shift;
    uint32_t mask;

    /* If the value is less than 256, then it can be used directly */
    if (value < 256U)
        return 1;

    /* If the value has the form 00XY00XY, XY00XY00, or XYXYXYXY, then
     * it can be used as a "modified immediate" in Thumb code */
    if ((value & 0x00FF00FFU) == value && (value >> 16) == (value & 0xFFU))
        return 1;
    if ((value & 0xFF00FF00U) == value && (value >> 16) == (value & 0xFF00U))
        return 1;
    if (((value >> 24) & 0xFF) == (value & 0xFF) &&
             ((value >> 16) & 0xFF) == (value & 0xFF) &&
             ((value >>  8) & 0xFF) == (value & 0xFF))
        return 1;

    /* Check if the value can be expressed as an 8-bit quantity that has
     * been rotated right by a multiple of 4 bits and the top-most bit
     * of the 8 is set to 1 */
    for (shift = 0; shift <= 24; shift += 4) {
        mask = 0xFF000000U >> shift;
        if ((value & mask) != value)
            continue;
        mask = 0x80000000U >> shift;
        if ((value & mask) == mask)
            return 1;
    }

    /* Not usable as a constant in "Operand2" */
    return 0;
}

/* Load an immediate value into a register using the most efficient sequence */
static void loadimm(const char *reg, uint32_t value)
{
    if (is_low_reg(reg) && value < 256U) {
        printf("\tmovs\t%s, #%lu\n", reg, (unsigned long)value);
    } else if (is_op2_constant(value)) {
        printf("\tmov\t%s, #%lu\n", reg, (unsigned long)value);
    } else if (value < 0x10000U) {
        printf("\tmovw\t%s, #%lu\n", reg, (unsigned long)value);
    } else if (is_op2_constant(~value)) {
        printf("\tmvn\t%s, #%lu\n", reg,
               (unsigned long)((~value) & 0xFFFFFFFFUL));
    } else {
        printf("\tmovw\t%s, #%lu\n", reg, (unsigned long)(value & 0xFFFFU));
        printf("\tmovt\t%s, #%lu\n", reg, (unsigned long)(value >> 16));
    }
}

/* Generates the code for the bit-sliced Spongent-pi S-box */
static void gen_spongent_sbox(const reg_names *regs, const char *x)
{
    const char *q0 = 0;
    const char *q1 = 0;
    const char *q2 = 0;
    const char *q3 = 0;
    const char *u0 = 0;
    const char *u1 = 0;
    const char *u2 = 0;
    const char *u3 = 0;

    /* The input value is split into separate bits b0...b3.
     * The separation is done virtually in the code below. */
    /* b3 = x; */
    /* b2 = (x >> 1); */
    /* b1 = (x >> 2); */
    /* b0 = (x >> 3); */

    /* q0 = b0 ^ b2; */
    q0 = regs->t0;
    printf("\tlsr\t%s, %s, #3\n", q0, x); /* b0 */
    printf("\teor\t%s, %s, %s, lsr #1\n", q0, q0, x); /* b2 */
    /* t0 in use */

    /* q1 = b1 ^ b2; */
    q1 = regs->t1;
    printf("\tlsr\t%s, %s, #2\n", q1, x); /* b1 */
    printf("\teor\t%s, %s, %s, lsr #1\n", q1, q1, x); /* b2 */
    /* t0, t1 in use */

    /* u0 = q0 & q1; */
    u0 = q0;
    binop("and", u0, q1);
    q0 = 0;
    q1 = 0;
    /* t0 in use */

    /* q2 = ~(b0 ^ b1 ^ b3 ^ u0); */
    q2 = regs->t1;
    printf("\tlsr\t%s, %s, #3\n", q2, x); /* b0 */
    printf("\teor\t%s, %s, %s, lsr #2\n", q2, q2, x); /* b1 */
    binop("eor", q2, x); /* b3 */
    binop("eor", q2, u0);
    binop("mvn", q2, q2);
    /* t0, t1 in use */

    /* u1 = q2 & ~b0; */
    u1 = q2;
    printf("\tlsr\t%s, %s, #3\n", regs->t2, x); /* b0 */
    binop("mvn", regs->t2, regs->t2);
    binop("and", u1, regs->t2);
    q2 = 0;
    /* t0, t1 in use */

    /* q3 = b1 ^ u1; */
    q3 = regs->t2;
    printf("\tlsr\t%s, %s, #2\n", q3, x); /* b1 */
    binop("eor", q3, u1);
    /* t0, t1, t2 in use */

    /* u2 = q3 & (q3 ^ b2 ^ b3 ^ u0); */
    u2 = q3;
    printf("\tlsr\t%s, %s, #1\n", regs->t3, x); /* b2 */
    binop("eor", regs->t3, x); /* b3 */
    binop("eor", regs->t3, q3);
    binop("eor", regs->t3, u0);
    binop("and", u2, regs->t3);
    q3 = 0;
    /* t0, t1, t2 in use */

    /* u3 = (b2 ^ u0) & ~(b1 ^ u0); */
    u3 = regs->t3;
    printf("\tlsr\t%s, %s, #1\n", u3, x); /* b2 */
    binop("eor", u3, u0);
    printf("\tlsr\t%s, %s, #2\n", regs->t4, x); /* b1 */
    binop("eor", regs->t4, u0);
    binop("mvn", regs->t4, regs->t4);
    binop("and", u3, regs->t4);
    /* t0, t1, t2, t3 in use */

    /* q0 = b1 ^ b2 ^ b3 ^ u2;      x =  (q0 << 3) & 0x88888888U; */
    q0 = u2;
    printf("\teor\t%s, %s, %s, lsr #2\n", q0, u2, x); /* b1 */
    printf("\teor\t%s, %s, %s, lsr #1\n", q0, q0, x); /* b2 */
    binop("eor", q0, x); /* b3 */
    printf("\tand\t%s, %s, #0x11111111\n", q0, q0);
    u2 = 0;
    /* t0, t1, t2, t3 in use */

    /* q1 = b0 ^ b2 ^ b3 ^ u0 ^ u1; x |= (q1 << 2) & 0x44444444U; */
    q1 = regs->t4;
    printf("\teor\t%s, %s, %s, lsr #3\n", q1, x, x); /* b0 ^ b3 */
    printf("\teor\t%s, %s, %s, lsr #1\n", q1, q1, x); /* b2 */
    binop("eor", q1, u0);
    binop("eor", q1, u1);
    printf("\tand\t%s, %s, #0x11111111\n", q1, q1);
    /* t0, t1, t2, t3, t4 in use */

    /* q2 = b0 ^ b1 ^ b2 ^ u1;      x |= (q2 << 1) & 0x22222222U; */
    q2 = u1;
    printf("\teor\t%s, %s, %s, lsr #3\n", q2, u1, x); /* b0 ^ u1 */
    printf("\teor\t%s, %s, %s, lsr #2\n", q2, q2, x); /* b1 */
    printf("\teor\t%s, %s, %s, lsr #1\n", q2, q2, x); /* b2 */
    printf("\tand\t%s, %s, #0x11111111\n", q2, q2);
    u1 = 0;
    /* t0, t1, t2, t3, t4 in use */

    /* q3 = b0 ^ b3 ^ u0 ^ u3;      x |= q3 & 0x11111111U;        */
    printf("\teor\t%s, %s, %s, lsr #3\n", x, x, x); /* b0 ^ b3 */
    binop("eor", x, u0);
    binop("eor", x, u3);
    printf("\tand\t%s, %s, #0x11111111\n", x, x);
    printf("\torr\t%s, %s, %s, lsl #1\n", x, x, q2);
    printf("\torr\t%s, %s, %s, lsl #2\n", x, x, q1);
    printf("\torr\t%s, %s, %s, lsl #3\n", x, x, q0);
}

/* Generates the code for the Spongent-pi permutation */
static void gen_spongent_permutation
    (const reg_names *regs, const unsigned char *perm, int size)
{
    int index, prev, next;
    unsigned char P[176];
    unsigned char done[176];

    /* Invert the permutation to convert "source bit goes to destination bit"
     * into "destination bit comes from source bit". */
    memset(P, 0xFF, size);
    for (index = 0; index < size; ++index) {
        int dest = perm[index];
        if (dest >= size || P[dest] != 0xFF) {
            /* Invalid destination bit number, or multiple source bits
             * are mapped to the same destination bit. */
            exit(1);
        }
        P[dest] = index;
    }

    /* Scan through the inverted permutation multiple times to find all
     * bit cycles, where A <- B <- ... <- Z <- A.  We stop once all
     * elements in the permutation have been moved to their destination. */
    memset(done, 0, size);
    for (index = 0; index < size; ++index) {
        int src = P[index];
        if (index == src) {
            /* Bit is moving to itself, so nothing to do */
            done[index] = 1;
            continue;
        } else if (done[index]) {
            /* We already handled this bit as part of a previous bit cycle */
            continue;
        }

        /* Move the first bit in the cycle out into a temporary register */
        if ((index % 32) == 0) {
            binop("mov", regs->t0, regs->x[index / 32]);
        } else {
            printf("\tlsr\t%s, %s, #%d\n", regs->t0,
                   regs->x[index / 32], index % 32);
        }
        done[index] = 1;

        /* Copy the rest of the bits in the cycle.  We stop once we
         * see something that is already done because that is the
         * starting bit in the cycle.  Or at least it should be. */
        prev = index;
        next = P[index];
        while (!done[next]) {
            if ((next % 32) == 0) {
                printf("\tbfi\t%s, %s, #%d, #1\n", regs->x[prev / 32],
                       regs->x[next / 32], prev % 32);
            } else {
                printf("\tlsr\t%s, %s, #%d\n", regs->t1,
                       regs->x[next / 32], next % 32);
                printf("\tbfi\t%s, %s, #%d, #1\n", regs->x[prev / 32],
                       regs->t1, prev % 32);
            }
            done[next] = 1;
            prev = next;
            next = P[prev];
        }

        /* Copy the saved bit in the temporary register to the last position */
        printf("\tbfi\t%s, %s, #%d, #1\n", regs->x[prev / 32],
               regs->t0, prev % 32);
    }
}

/* Generate the body of the Spongent-pi[160] permutation function */
static void gen_spongnent160_permute(void)
{
    /*
     * r0 holds the pointer to the Spongent state on entry and exit.
     *
     * r0, r1, r2, r3, and ip can be used as scratch registers without saving,
     * but the value of ip may not survive across a branch instruction.
     *
     * r4, r5, r6, r7, r8, r9, r10, fp, and lr must be callee-saved.
     */
    unsigned char perm[160];
    int posn;
    reg_names regs = { .t0 = 0 };
    regs.x[0] = "r2";
    regs.x[1] = "r3";
    regs.x[2] = "r4";
    regs.x[3] = "r5";
    regs.x[4] = "r6";
    regs.t0 = "r7";
    regs.t1 = "r8";
    regs.t2 = "r9";
    regs.t3 = "lr";
    regs.t4 = "ip";
    regs.rc = "r10";
    regs.round = "r1";

    /* Save callee-preserved registers on the stack */
    printf("\tpush\t{r4, r5, r6, r7, r8, r9, r10, lr}\n");

    /* Load the state into registers */
    printf("\tldr\t%s, [r0, #0]\n", regs.x[0]);
    printf("\tldr\t%s, [r0, #4]\n", regs.x[1]);
    printf("\tldr\t%s, [r0, #8]\n", regs.x[2]);
    printf("\tldr\t%s, [r0, #12]\n", regs.x[3]);
    printf("\tldr\t%s, [r0, #16]\n", regs.x[4]);

    /* Top of the round loop */
    printf("\tadr\t%s, rconst160\n", regs.rc);
    loadimm(regs.round, 80);
    printf(".L1:\n");

    /* Add the round constant to front and back of the state */
    /* x0 ^= rc[0]; */
    /* x4 ^= ((uint32_t)(rc[1])) << 24; */
    printf("\tldrb\t%s, [%s], #1\n", regs.t0, regs.rc);
    printf("\tldrb\t%s, [%s], #1\n", regs.t1, regs.rc);
    binop("eor", regs.x[0], regs.t0);
    printf("\teor\t%s, %s, %s, lsl #24\n", regs.x[4], regs.x[4], regs.t1);

    /* Apply the S-box to all 4-bit groups in the state */
    gen_spongent_sbox(&regs, regs.x[0]);
    gen_spongent_sbox(&regs, regs.x[1]);
    gen_spongent_sbox(&regs, regs.x[2]);
    gen_spongent_sbox(&regs, regs.x[3]);
    gen_spongent_sbox(&regs, regs.x[4]);

    /* Permute the bits of the state in-place */
    for (posn = 0; posn < 159; ++posn)
        perm[posn] = (40 * posn) % 159;
    perm[159] = 159;
    gen_spongent_permutation(&regs, perm, 160);

    /* Bottom of the round loop */
    printf("\tsubs\t%s, %s, #1\n", regs.round, regs.round);
    printf("\tbne\t.L1\n");

    /* Store the registers back to the state */
    printf("\tstr\t%s, [r0, #0]\n", regs.x[0]);
    printf("\tstr\t%s, [r0, #4]\n", regs.x[1]);
    printf("\tstr\t%s, [r0, #8]\n", regs.x[2]);
    printf("\tstr\t%s, [r0, #12]\n", regs.x[3]);
    printf("\tstr\t%s, [r0, #16]\n", regs.x[4]);

    /* Pop the stack frame and return */
    printf("\tpop\t{r4, r5, r6, r7, r8, r9, r10, pc}\n");
}

/* Generate the body of the Spongent-pi[176] permutation function */
static void gen_spongnent176_permute(void)
{
    /*
     * r0 holds the pointer to the Spongent state on entry and exit.
     *
     * r0, r1, r2, r3, and ip can be used as scratch registers without saving,
     * but the value of ip may not survive across a branch instruction.
     *
     * r4, r5, r6, r7, r8, r9, r10, fp, and lr must be callee-saved.
     */
    unsigned char perm[176];
    int posn;
    reg_names regs = { .t0 = 0 };
    regs.x[0] = "r2";
    regs.x[1] = "r3";
    regs.x[2] = "r4";
    regs.x[3] = "r5";
    regs.x[4] = "r6";
    regs.x[5] = "r7";
    regs.t0 = "r8";
    regs.t1 = "r9";
    regs.t2 = "lr";
    regs.t3 = "fp";
    regs.t4 = "ip";
    regs.rc = "r10";
    regs.round = "r1";

    /* Save callee-preserved registers on the stack */
    printf("\tpush\t{r4, r5, r6, r7, r8, r9, r10, fp, lr}\n");

    /* Load the state into registers */
    printf("\tldr\t%s, [r0, #0]\n", regs.x[0]);
    printf("\tldr\t%s, [r0, #4]\n", regs.x[1]);
    printf("\tldr\t%s, [r0, #8]\n", regs.x[2]);
    printf("\tldr\t%s, [r0, #12]\n", regs.x[3]);
    printf("\tldr\t%s, [r0, #16]\n", regs.x[4]);
    printf("\tldrh\t%s, [r0, #20]\n", regs.x[5]);

    /* Top of the round loop */
    printf("\tadr\t%s, rconst176\n", regs.rc);
    loadimm(regs.round, 90);
    printf(".L2:\n");

    /* Add the round constant to front and back of the state */
    /* x0 ^= rc[0]; */
    /* x5 ^= ((uint32_t)(rc[1])) << 8; */
    printf("\tldrb\t%s, [%s], #1\n", regs.t0, regs.rc);
    printf("\tldrb\t%s, [%s], #1\n", regs.t1, regs.rc);
    binop("eor", regs.x[0], regs.t0);
    printf("\teor\t%s, %s, %s, lsl #8\n", regs.x[5], regs.x[5], regs.t1);

    /* Apply the S-box to all 4-bit groups in the state */
    gen_spongent_sbox(&regs, regs.x[0]);
    gen_spongent_sbox(&regs, regs.x[1]);
    gen_spongent_sbox(&regs, regs.x[2]);
    gen_spongent_sbox(&regs, regs.x[3]);
    gen_spongent_sbox(&regs, regs.x[4]);
    gen_spongent_sbox(&regs, regs.x[5]);

    /* Permute the bits of the state in-place */
    for (posn = 0; posn < 175; ++posn)
        perm[posn] = (44 * posn) % 175;
    perm[175] = 175;
    gen_spongent_permutation(&regs, perm, 176);

    /* Bottom of the round loop */
    printf("\tsubs\t%s, %s, #1\n", regs.round, regs.round);
    printf("\tbne\t.L2\n");

    /* Store the registers back to the state */
    printf("\tstr\t%s, [r0, #0]\n", regs.x[0]);
    printf("\tstr\t%s, [r0, #4]\n", regs.x[1]);
    printf("\tstr\t%s, [r0, #8]\n", regs.x[2]);
    printf("\tstr\t%s, [r0, #12]\n", regs.x[3]);
    printf("\tstr\t%s, [r0, #16]\n", regs.x[4]);
    printf("\tstrh\t%s, [r0, #20]\n", regs.x[5]);

    /* Pop the stack frame and return */
    printf("\tpop\t{r4, r5, r6, r7, r8, r9, r10, fp, pc}\n");
}

/* Generates the round constant table for Spongent */
static void gen_spongent_rc(const char *name, const uint8_t *rc, unsigned size)
{
    printf("\n\t.align\t4\n");
    printf("\t.type\t%s, %%object\n", name);
    printf("%s:\n", name);
    while (size > 0) {
        printf("\t.byte\t%d\n", rc[0]);
        ++rc;
        --size;
    }
    printf("\t.size\t%s, .-%s\n", name, name);
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    /* Output the file header */
    printf("#if defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7\n");
    printf("\t.syntax unified\n");
    printf("\t.thumb\n");
    printf("\t.text\n");

    /* Output the round constant tables */
    gen_spongent_rc("rconst160", RC_160, sizeof(RC_160));
    gen_spongent_rc("rconst176", RC_176, sizeof(RC_176));

    /* Output the Spongent-pi[160] permutation function */
    function_header("spongent160_permute");
    gen_spongnent160_permute();
    function_footer("spongent160_permute");

    /* Output the Spongent-pi[176] permutation function */
    function_header("spongent176_permute");
    gen_spongnent176_permute();
    function_footer("spongent176_permute");

    /* Output the file footer */
    printf("\n");
    printf("#endif\n");
    return 0;
}
