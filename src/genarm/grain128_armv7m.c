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
 * Grain128 stream cipher for ARM v7m microprocessors.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

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
    const char *s0;
    const char *s1;
    const char *s2;
    const char *s3;
    const char *b0;
    const char *b1;
    const char *b2;
    const char *b3;
    const char *x;
    const char *x0;
    const char *x2;
    const char *x4;
    const char *y;
    const char *t0;
    const char *t1;

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

/* Extract a 32-bit word from the Grain128 state and XOR it with "x" */
static void xor_gword
    (const reg_names *regs, const char *x, const char *a,
     const char *b, int start_bit)
{
    start_bit %= 32;
    printf("\teor\t%s, %s, %s, lsl #%d\n", x, x, a, start_bit);
    printf("\teor\t%s, %s, %s, lsr #%d\n", x, x, b, 32 - start_bit);
}

/* Extract two 32-bit words from the Grain128 state, AND them and then
 * XOR the result with "x" */
static void xor_gword_2
    (const reg_names *regs, const char *x, const char *a1,
     const char *b1, int start_bit1, const char *a2,
     const char *b2, int start_bit2)
{
    start_bit1 %= 32;
    start_bit2 %= 32;
    printf("\tlsl\t%s, %s, #%d\n", regs->t0, a1, start_bit1);
    printf("\tlsl\t%s, %s, #%d\n", regs->t1, a2, start_bit2);
    printf("\teor\t%s, %s, %s, lsr #%d\n", regs->t0, regs->t0, b1, 32 - start_bit1);
    printf("\teor\t%s, %s, %s, lsr #%d\n", regs->t1, regs->t1, b2, 32 - start_bit2);
    binop("and", regs->t0, regs->t1);
    binop("eor", x, regs->t0);
}

/* Extract three 32-bit words from the Grain128 state, AND them and then
 * XOR the result with "x" */
static void xor_gword_3
    (const reg_names *regs, const char *x, const char *a1,
     const char *b1, int start_bit1, const char *a2,
     const char *b2, int start_bit2, const char *a3,
     const char *b3, int start_bit3)
{
    start_bit1 %= 32;
    start_bit2 %= 32;
    start_bit3 %= 32;
    printf("\tlsl\t%s, %s, #%d\n", regs->t0, a1, start_bit1);
    printf("\tlsl\t%s, %s, #%d\n", regs->t1, a2, start_bit2);
    printf("\teor\t%s, %s, %s, lsr #%d\n", regs->t0, regs->t0, b1, 32 - start_bit1);
    printf("\teor\t%s, %s, %s, lsr #%d\n", regs->t1, regs->t1, b2, 32 - start_bit2);
    binop("and", regs->t0, regs->t1);
    printf("\tlsl\t%s, %s, #%d\n", regs->t1, a3, start_bit3);
    printf("\teor\t%s, %s, %s, lsr #%d\n", regs->t1, regs->t1, b3, 32 - start_bit3);
    binop("and", regs->t0, regs->t1);
    binop("eor", x, regs->t0);
}

/* Extract four 32-bit words from the Grain128 state, AND them and then
 * XOR the result with "x" */
static void xor_gword_4
    (const reg_names *regs, const char *x, const char *a1,
     const char *b1, int start_bit1, const char *a2,
     const char *b2, int start_bit2, const char *a3,
     const char *b3, int start_bit3, const char *a4,
     const char *b4, int start_bit4)
{
    start_bit1 %= 32;
    start_bit2 %= 32;
    start_bit3 %= 32;
    start_bit4 %= 32;
    printf("\tlsl\t%s, %s, #%d\n", regs->t0, a1, start_bit1);
    printf("\tlsl\t%s, %s, #%d\n", regs->t1, a2, start_bit2);
    printf("\teor\t%s, %s, %s, lsr #%d\n", regs->t0, regs->t0, b1, 32 - start_bit1);
    printf("\teor\t%s, %s, %s, lsr #%d\n", regs->t1, regs->t1, b2, 32 - start_bit2);
    binop("and", regs->t0, regs->t1);
    printf("\tlsl\t%s, %s, #%d\n", regs->t1, a3, start_bit3);
    printf("\teor\t%s, %s, %s, lsr #%d\n", regs->t1, regs->t1, b3, 32 - start_bit3);
    binop("and", regs->t0, regs->t1);
    printf("\tlsl\t%s, %s, #%d\n", regs->t1, a4, start_bit4);
    printf("\teor\t%s, %s, %s, lsr #%d\n", regs->t1, regs->t1, b4, 32 - start_bit4);
    binop("and", regs->t0, regs->t1);
    binop("eor", x, regs->t0);
}

/* Get a 32-bit word from the Grain128 state and assign it to "x" */
static void get_gword
    (const reg_names *regs, const char *x, const char *a,
     const char *b, int start_bit)
{
    start_bit %= 32;
    printf("\tlsl\t%s, %s, #%d\n", x, a, start_bit);
    printf("\teor\t%s, %s, %s, lsr #%d\n", x, x, b, 32 - start_bit);
}

/* Generate an unrolled version of the Grain128 core function */
static void gen_grain128_core_unrolled(const reg_names *regs, int zero_inputs)
{
    /* From the Grain-128AEAD specification, the LFSR feedback algorithm is:
     *
     *      s'[i] = s[i + 1]
     *      s'[127] = s[0] ^ s[7] ^ s[38] ^ s[70] ^ s[81] ^ s[96] ^ x
     *
     * The bits are numbered from the most significant bit in the first
     * word of the LFSR state.  Calculate the feedback bits 32 at a time.
     */
    /* x ^= s0;                        // s[0] */
    if (zero_inputs)
        binop("mov", regs->x, regs->s0);
    else
        binop("eor", regs->x, regs->s0);
    /* x ^= GWORD(s0, s1, 7);          // s[7] */
    xor_gword(regs, regs->x, regs->s0, regs->s1, 7);
    /* x ^= GWORD(s1, s2, 38);         // s[38] */
    xor_gword(regs, regs->x, regs->s1, regs->s2, 38);
    /* x ^= GWORD(s2, s3, 70);         // s[70] */
    xor_gword(regs, regs->x, regs->s2, regs->s3, 70);
    /* x ^= GWORD(s2, s3, 81);         // s[81] */
    xor_gword(regs, regs->x, regs->s2, regs->s3, 81);
    /* x ^= s3;                        // s[96] */
    binop("eor", regs->x, regs->s3);

    /* Rotate the LFSR state left by 32 bits and feed s0 into the NFSR */
    if (!strcmp(regs->s0, regs->b0)) {
        /* We are sharing registers, so we need to save the LFSR now */
        /* state->lfsr[0] = s1; */
        /* state->lfsr[1] = s2; */
        /* state->lfsr[2] = s3; */
        /* state->lfsr[3] = x; */
        printf("\tstr\t%s, [r0, #0]\n", regs->s1);
        printf("\tstr\t%s, [r0, #4]\n", regs->s2);
        printf("\tstr\t%s, [r0, #8]\n", regs->s3);
        printf("\tstr\t%s, [r0, #12]\n", regs->x);
        /* x2 ^= s0; */
        if (zero_inputs)
            binop("mov", regs->x2, regs->s0);
        else
            binop("eor", regs->x2, regs->s0);
    } else {
        /* Rotate x into the LFSR registers and s0 into the NFSR */
        if (zero_inputs)
            binop("mov", regs->x2, regs->s0);
        else
            binop("eor", regs->x2, regs->s0);
        binop("mov", regs->s0, regs->x);
    }

    /* Perform the NFSR feedback algorithm from the specification:
     *
     *      b'[i] = b[i + 1]
     *      b'[127] = s[0] ^ b[0] ^ b[26] ^ b[56] ^ b[91] ^ b[96]
     *              ^ (b[3] & b[67]) ^ (b[11] & b[13]) ^ (b[17] & b[18])
     *              ^ (b[27] & b[59]) ^ (b[40] & b[48]) ^ (b[61] & b[65])
     *              ^ (b[68] & b[84]) ^ (b[22] & b[24] & b[25])
     *              ^ (b[70] & b[78] & b[82])
     *              ^ (b[88] & b[92] & b[93] & b[95]) ^ x2
     *
     * Once again, we calculate 32 feedback bits in parallel.
     */
    if (!strcmp(regs->s0, regs->b0)) {
        /* Load the NFSR state because it isn't in registers yet */
        /* b0 = state->nfsr[0]; */
        /* b1 = state->nfsr[1]; */
        /* b2 = state->nfsr[2]; */
        /* b3 = state->nfsr[3]; */
        printf("\tldr\t%s, [r0, #16]\n", regs->b0);
        printf("\tldr\t%s, [r0, #20]\n", regs->b1);
        printf("\tldr\t%s, [r0, #24]\n", regs->b2);
        printf("\tldr\t%s, [r0, #28]\n", regs->b3);
    }
    /* x2 ^= b0;                                       // b[0] */
    binop("eor", regs->x2, regs->b0);
    /* x2 ^= GWORD(b0, b1, 26);                        // b[26] */
    xor_gword(regs, regs->x2, regs->b0, regs->b1, 26);
    /* x2 ^= GWORD(b1, b2, 56);                        // b[56] */
    xor_gword(regs, regs->x2, regs->b1, regs->b2, 56);
    /* x2 ^= GWORD(b2, b3, 91);                        // b[91] */
    xor_gword(regs, regs->x2, regs->b2, regs->b3, 91);
    /* x2 ^= b3;                                       // b[96] */
    binop("eor", regs->x2, regs->b3);
    /* x2 ^= GWORD(b0, b1,  3) & GWORD(b2, b3, 67);    // b[3] & b[67] */
    xor_gword_2(regs, regs->x2, regs->b0, regs->b1, 3, regs->b2, regs->b3, 67);
    /* x2 ^= GWORD(b0, b1, 11) & GWORD(b0, b1, 13);    // b[11] & b[13] */
    xor_gword_2(regs, regs->x2, regs->b0, regs->b1, 11, regs->b0, regs->b1, 13);
    /* x2 ^= GWORD(b0, b1, 17) & GWORD(b0, b1, 18);    // b[17] & b[18] */
    xor_gword_2(regs, regs->x2, regs->b0, regs->b1, 17, regs->b0, regs->b1, 18);
    /* x2 ^= GWORD(b0, b1, 27) & GWORD(b1, b2, 59);    // b[27] & b[59] */
    xor_gword_2(regs, regs->x2, regs->b0, regs->b1, 27, regs->b1, regs->b2, 59);
    /* x2 ^= GWORD(b1, b2, 40) & GWORD(b1, b2, 48);    // b[40] & b[48] */
    xor_gword_2(regs, regs->x2, regs->b1, regs->b2, 40, regs->b1, regs->b2, 48);
    /* x2 ^= GWORD(b1, b2, 61) & GWORD(b2, b3, 65);    // b[61] & b[65] */
    xor_gword_2(regs, regs->x2, regs->b1, regs->b2, 61, regs->b2, regs->b3, 65);
    /* x2 ^= GWORD(b2, b3, 68) & GWORD(b2, b3, 84);    // b[68] & b[84] */
    xor_gword_2(regs, regs->x2, regs->b2, regs->b3, 68, regs->b2, regs->b3, 84);
    /* x2 ^= GWORD(b0, b1, 22) & GWORD(b0, b1, 24) &   // b[22] & b[24] & b[25] */
    /*       GWORD(b0, b1, 25); */
    xor_gword_3(regs, regs->x2, regs->b0, regs->b1, 22, regs->b0, regs->b1, 24,
                regs->b0, regs->b1, 25);
    /* x2 ^= GWORD(b2, b3, 70) & GWORD(b2, b3, 78) &   // b[70] & b[78] & b[82] */
    /*       GWORD(b2, b3, 82); */
    xor_gword_3(regs, regs->x2, regs->b2, regs->b3, 70, regs->b2, regs->b3, 78,
                regs->b2, regs->b3, 82);
    /* x2 ^= GWORD(b2, b3, 88) & GWORD(b2, b3, 92) &   // b[88] & b[92] ... */
    /*       GWORD(b2, b3, 93) & GWORD(b2, b3, 95);    // ... & b[93] & b[95] */
    xor_gword_4(regs, regs->x2, regs->b2, regs->b3, 88, regs->b2, regs->b3, 92,
                regs->b2, regs->b3, 93, regs->b2, regs->b3, 95);
}

/* Generate an unrolled version of the Grain128 preoutput function */
static void gen_grain128_preoutput_unrolled(const reg_names *regs)
{
    /* From the Grain-128AEAD specification, each pre-output bit y is given by:
     *
     *      x[0..8] = b[12], s[8], s[13], s[20], b[95],
     *                s[42], s[60], s[79], s[94]
     *      h(x) = (x[0] & x[1]) ^ (x[2] & x[3]) ^ (x[4] & x[5])
     *           ^ (x[6] & x[7]) ^ (x[0] & x[4] & x[8])
     *      y = h(x) ^ s[93] ^ b[2] ^ b[15] ^ b[36] ^ b[45]
     *               ^ b[64] ^ b[73] ^ b[89]
     *
     * Calculate 32 pre-output bits in parallel.
     */
    /* x0 = GWORD(b0, b1, 12); */
    get_gword(regs, regs->x0, regs->b0, regs->b1, 12);
    /* x4 = GWORD(b2, b3, 95); */
    get_gword(regs, regs->x4, regs->b2, regs->b3, 95);
    /* y  = (x0 & GWORD(s0, s1, 8));                   // x[0] & x[1] */
    get_gword(regs, regs->y, regs->s0, regs->s1, 8);
    binop("and", regs->y, regs->x0);
    /* y ^= (GWORD(s0, s1, 13) & GWORD(s0, s1, 20));   // x[2] & x[3] */
    xor_gword_2(regs, regs->y, regs->s0, regs->s1, 13, regs->s0, regs->s1, 20);
    /* y ^= (x4 & GWORD(s1, s2, 42));                  // x[4] & x[5] */
    get_gword(regs, regs->t0, regs->s1, regs->s2, 42);
    binop("and", regs->t0, regs->x4);
    binop("eor", regs->y, regs->t0);
    /* y ^= (GWORD(s1, s2, 60) & GWORD(s2, s3, 79));   // x[6] & x[7] */
    xor_gword_2(regs, regs->y, regs->s1, regs->s2, 60, regs->s2, regs->s3, 79);
    /* y ^= (x0 & x4 & GWORD(s2, s3, 94));             // x[0] & x[4] & x[8] */
    binop("and", regs->x0, regs->x4);
    get_gword(regs, regs->t0, regs->s2, regs->s3, 94);
    binop("and", regs->x0, regs->t0);
    binop("eor", regs->y, regs->x0);
    /* y ^= GWORD(s2, s3, 93);                         // s[93] */
    xor_gword(regs, regs->y, regs->s2, regs->s3, 93);
    /* y ^= GWORD(b0, b1, 2);                          // b[2] */
    xor_gword(regs, regs->y, regs->b0, regs->b1, 2);
    /* y ^= GWORD(b0, b1, 15);                         // b[15] */
    xor_gword(regs, regs->y, regs->b0, regs->b1, 15);
    /* y ^= GWORD(b1, b2, 36);                         // b[36] */
    xor_gword(regs, regs->y, regs->b1, regs->b2, 36);
    /* y ^= GWORD(b1, b2, 45);                         // b[45] */
    xor_gword(regs, regs->y, regs->b1, regs->b2, 45);
    /* y ^= b2;                                        // b[64] */
    binop("eor", regs->y, regs->b2);
    /* y ^= GWORD(b2, b3, 73);                         // b[73] */
    xor_gword(regs, regs->y, regs->b2, regs->b3, 73);
    /* y ^= GWORD(b2, b3, 89);                         // b[89] */
    xor_gword(regs, regs->y, regs->b2, regs->b3, 89);
}

/* Generate code for the Grain128 core function */
static void gen_grain128_core(void)
{
    /*
     * r0 holds the pointer to the Grain128 state.
     * r1 is the "x" parameter
     * r2 is the "x2" parameter
     *
     * r0, r1, r2, r3, and ip can be used as scratch registers without saving,
     * but the value of ip may not survive across a branch instruction.
     *
     * r4, r5, r6, r7, r8, r9, r10, and fp must be callee-saved.
     *
     * lr can be used as a temporary as long as it is saved on the stack.
     */
    reg_names regs = { .s0 = 0 };
    regs.s0 = "r3";
    regs.s1 = "r4";
    regs.s2 = "r5";
    regs.s3 = "r6";
    regs.b0 = regs.s0;
    regs.b1 = regs.s1;
    regs.b2 = regs.s2;
    regs.b3 = regs.s3;
    regs.x  = "r1";
    regs.x2 = "r2";
    regs.t0 = "r7";
    regs.t1 = regs.x;

    /* Save callee-preserved registers on the stack */
    printf("\tpush\t{r4, r5, r6, r7, lr}\n");

    /* Load the LFSR state */
    /* s0 = state->lfsr[0]; */
    /* s1 = state->lfsr[1]; */
    /* s2 = state->lfsr[2]; */
    /* s3 = state->lfsr[3]; */
    printf("\tldr\t%s, [r0, #0]\n", regs.s0);
    printf("\tldr\t%s, [r0, #4]\n", regs.s1);
    printf("\tldr\t%s, [r0, #8]\n", regs.s2);
    printf("\tldr\t%s, [r0, #12]\n", regs.s3);

    /* Perform the core operation, which will save the LFSR and
     * then load the NFSR */
    gen_grain128_core_unrolled(&regs, 0);

    /* Rotate the NFSR state left by 32 bits and store back */
    /* state->nfsr[0] = b1; */
    /* state->nfsr[1] = b2; */
    /* state->nfsr[2] = b3; */
    /* state->nfsr[3] = x2; */
    printf("\tstr\t%s, [r0, #16]\n", regs.b1);
    printf("\tstr\t%s, [r0, #20]\n", regs.b2);
    printf("\tstr\t%s, [r0, #24]\n", regs.b3);
    printf("\tstr\t%s, [r0, #28]\n", regs.x2);

    /* Pop the stack frame and return */
    printf("\tpop\t{r4, r5, r6, r7, pc}\n");
}

/* Generate code for the Grain128 preoutput function */
static void gen_grain128_preoutput(void)
{
    /*
     * r0 holds the pointer to the Grain128 state on entry.
     * r0 is the 32-bit preoutput value on exit.
     *
     * r0, r1, r2, r3, and ip can be used as scratch registers without saving,
     * but the value of ip may not survive across a branch instruction.
     *
     * r4, r5, r6, r7, r8, r9, r10, and fp must be callee-saved.
     *
     * lr can be used as a temporary as long as it is saved on the stack.
     */
    reg_names regs = { .s0 = 0 };
    regs.s0 = "r1";
    regs.s1 = "r2";
    regs.s2 = "r3";
    regs.s3 = "r4";
    regs.b0 = "r5";
    regs.b1 = "r6";
    regs.b2 = "r7";
    regs.b3 = "r8";
    regs.x0 = "r9";
    regs.x4 = "r10";
    regs.y  = "r0";
    regs.t0 = "ip";
    regs.t1 = "fp";

    /* Save callee-preserved registers on the stack */
    printf("\tpush\t{r4, r5, r6, r7, r8, r9, r10, fp, lr}\n");

    /* Load the LFSR and NFSR state into registers */
    /* s0 = state->lfsr[0]; */
    /* s1 = state->lfsr[1]; */
    /* s2 = state->lfsr[2]; */
    /* s3 = state->lfsr[3]; */
    printf("\tldr\t%s, [r0, #0]\n", regs.s0);
    printf("\tldr\t%s, [r0, #4]\n", regs.s1);
    printf("\tldr\t%s, [r0, #8]\n", regs.s2);
    printf("\tldr\t%s, [r0, #12]\n", regs.s3);
    /* b0 = state->nfsr[0]; */
    /* b1 = state->nfsr[1]; */
    /* b2 = state->nfsr[2]; */
    /* b3 = state->nfsr[3]; */
    printf("\tldr\t%s, [r0, #16]\n", regs.b0);
    printf("\tldr\t%s, [r0, #20]\n", regs.b1);
    printf("\tldr\t%s, [r0, #24]\n", regs.b2);
    printf("\tldr\t%s, [r0, #28]\n", regs.b3);

    /* Compute the preoutput value, with the result in y = r0 */
    gen_grain128_preoutput_unrolled(&regs);

    /* Pop the stack frame and return, result is already in "r0" */
    printf("\tpop\t{r4, r5, r6, r7, r8, r9, r10, fp, pc}\n");
}

/* Perform a bit permutation step */
void bit_permute_step
    (const reg_names *regs, const char *y, uint32_t mask, int shift)
{
    /* t = ((y >> shift) ^ y) & mask */
    printf("\teor\t%s, %s, %s, lsr #%d\n", regs->t0, y, y, shift);
    if (is_op2_constant(mask)) {
        printf("\tand\t%s, %s, #%lu\n", regs->t0, regs->t0,
               (unsigned long)mask);
    } else {
        loadimm(regs->t1, mask);
        printf("\tand\t%s, %s, %s\n", regs->t0, regs->t0, regs->t1);
    }

    /* y = (y ^ t) ^ (t << shift) */
    printf("\teor\t%s, %s, %s\n", y, y, regs->t0);
    printf("\teor\t%s, %s, %s, lsl #%d\n", y, y, regs->t0, shift);
}

/* Swap the bits in the preoutput data and store them to the keystream */
static void gen_grain128_bitswap_and_store
    (const reg_names *regs, int offset, const char *x)
{
    /* Permute the bits to separate into even and odd bytes */
    bit_permute_step(regs, x, 0x11111111, 3);
    bit_permute_step(regs, x, 0x03030303, 6);
    bit_permute_step(regs, x, 0x000f000f, 12);
    /* bit_permute_step_simple(regs, x, 0x00ff00ff, 8); */
    printf("\trev16\t%s, %s\n", x, x);

    /* be_store_word32(state->ks + posn, x); */
    printf("\trev\t%s, %s\n", x, x);
    printf("\tstr\t%s, [r0, #%d]\n", x, offset);
}

/* Rotates the words of the LFSR and NFSR state virtually */
static void gen_grain128_rotate_state(reg_names *regs)
{
    const char *temp = regs->s0;
    regs->s0 = regs->s1;
    regs->s1 = regs->s2;
    regs->s2 = regs->s3;
    regs->s3 = temp;

    temp = regs->b0;
    regs->b0 = regs->b1;
    regs->b1 = regs->b2;
    regs->b2 = regs->b3;
    regs->b3 = regs->x2;
    regs->x2 = temp;
    regs->x4 = temp;
}

/* Generate code for the unrollled Grain128 keystream function */
static void gen_grain128_next_keystream(void)
{
    /*
     * r0 holds the pointer to the Grain128 state on entry.
     *
     * r0, r1, r2, r3, and ip can be used as scratch registers without saving,
     * but the value of ip may not survive across a branch instruction.
     *
     * r4, r5, r6, r7, r8, r9, r10, and fp must be callee-saved.
     *
     * lr can be used as a temporary as long as it is saved on the stack.
     */
    reg_names regs = { .s0 = 0 };
    regs.s0 = "r1";
    regs.s1 = "r2";
    regs.s2 = "r3";
    regs.s3 = "r4";
    regs.b0 = "r5";
    regs.b1 = "r6";
    regs.b2 = "r7";
    regs.b3 = "r8";
    regs.x0 = "r9";
    regs.x  = "r10";
    regs.x2 = "lr";
    regs.x4 = regs.x2;
    regs.y  = regs.x;
    regs.t0 = "ip";
    regs.t1 = "fp";

    /* Save callee-preserved registers on the stack */
    printf("\tpush\t{r4, r5, r6, r7, r8, r9, r10, fp, lr}\n");

    /* Load the LFSR and NFSR state into registers */
    /* s0 = state->lfsr[0]; */
    /* s1 = state->lfsr[1]; */
    /* s2 = state->lfsr[2]; */
    /* s3 = state->lfsr[3]; */
    printf("\tldr\t%s, [r0, #0]\n", regs.s0);
    printf("\tldr\t%s, [r0, #4]\n", regs.s1);
    printf("\tldr\t%s, [r0, #8]\n", regs.s2);
    printf("\tldr\t%s, [r0, #12]\n", regs.s3);
    /* b0 = state->nfsr[0]; */
    /* b1 = state->nfsr[1]; */
    /* b2 = state->nfsr[2]; */
    /* b3 = state->nfsr[3]; */
    printf("\tldr\t%s, [r0, #16]\n", regs.b0);
    printf("\tldr\t%s, [r0, #20]\n", regs.b1);
    printf("\tldr\t%s, [r0, #24]\n", regs.b2);
    printf("\tldr\t%s, [r0, #28]\n", regs.b3);

    /* Unroll the loop 4 times to generate all 16 bytes of keystream output */
    gen_grain128_preoutput_unrolled(&regs);
    gen_grain128_bitswap_and_store(&regs, 48, regs.y);
    gen_grain128_core_unrolled(&regs, 1);
    gen_grain128_rotate_state(&regs);
    gen_grain128_preoutput_unrolled(&regs);
    gen_grain128_bitswap_and_store(&regs, 52, regs.y);
    gen_grain128_core_unrolled(&regs, 1);
    gen_grain128_rotate_state(&regs);
    gen_grain128_preoutput_unrolled(&regs);
    gen_grain128_bitswap_and_store(&regs, 56, regs.y);
    gen_grain128_core_unrolled(&regs, 1);
    gen_grain128_rotate_state(&regs);
    gen_grain128_preoutput_unrolled(&regs);
    gen_grain128_bitswap_and_store(&regs, 60, regs.y);
    gen_grain128_core_unrolled(&regs, 1);
    gen_grain128_rotate_state(&regs);

    /* Store the LFSR and NFSR values back to the state */
    /* state->lfsr[0] = s0; */
    /* state->lfsr[1] = s1; */
    /* state->lfsr[2] = s2; */
    /* state->lfsr[3] = s3; */
    printf("\tstr\t%s, [r0, #0]\n", regs.s0);
    printf("\tstr\t%s, [r0, #4]\n", regs.s1);
    printf("\tstr\t%s, [r0, #8]\n", regs.s2);
    printf("\tstr\t%s, [r0, #12]\n", regs.s3);
    /* state->nfsr[0] = b0; */
    /* state->nfsr[1] = b1; */
    /* state->nfsr[2] = b2; */
    /* state->nfsr[3] = b3; */
    printf("\tstr\t%s, [r0, #16]\n", regs.b0);
    printf("\tstr\t%s, [r0, #20]\n", regs.b1);
    printf("\tstr\t%s, [r0, #24]\n", regs.b2);
    printf("\tstr\t%s, [r0, #28]\n", regs.b3);

    /* Pop the stack frame and return */
    printf("\tpop\t{r4, r5, r6, r7, r8, r9, r10, fp, pc}\n");
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

    /* Output the Grain128 core function */
    function_header("grain128_core");
    gen_grain128_core();
    function_footer("grain128_core");

    /* Output the Grain128 preoutput function */
    function_header("grain128_preoutput");
    gen_grain128_preoutput();
    function_footer("grain128_preoutput");

    /* Output the Grain128 keystream function */
    function_header("grain128_next_keystream");
    gen_grain128_next_keystream();
    function_footer("grain128_next_keystream");

    /* Output the file footer */
    printf("\n");
    printf("#endif\n");
    return 0;
}
