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
 * SKINNY-128-384 and SKINNY-128-384+ ciphers for ARM v7m microprocessors.
 * At present only the encryption operations are generated.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "copyright.h"

#define SKINNY128_VARIANT_FULL 0
#define SKINNY128_VARIANT_SMALL 1
#define SKINNY128_VARIANT_TINY 2

static int variant = SKINNY128_VARIANT_FULL;
static int round_count = 56;
static int label = 1;

static void function_header(const char *prefix, const char *name)
{
    printf("\n\t.align\t2\n");
    printf("\t.global\t%s_%s\n", prefix, name);
    printf("\t.thumb\n");
    printf("\t.thumb_func\n");
    printf("\t.type\t%s_%s, %%function\n", prefix, name);
    printf("%s_%s:\n", prefix, name);
}

static void function_footer(const char *prefix, const char *name)
{
    printf("\t.size\t%s_%s, .-%s_%s\n", prefix, name, prefix, name);
}

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

/* List of all registers that we can work with */
typedef struct
{
    const char *s0;
    const char *s1;
    const char *s2;
    const char *s3;
    const char *tk1[4];
    const char *tk2[4];
    const char *tk3[4];
    const char *t1;
    const char *t2;
    const char *t3;
    const char *t4;
    const char *round;

} reg_names;

/* Generate the code for the SKINNY-128 S-box */
static void skinny128_sbox(const reg_names *regs, const char *x)
{
    const char *y = regs->t1;
    const char *t = regs->t2;

    /* Mix the bits */
    /* x = ~x; */
    binop("mvn", x, x);
    /* x ^= (((x >> 2) & (x >> 3)) & 0x11111111U); */
    printf("\tlsr\t%s, %s, #2\n", t, x);
    printf("\tand\t%s, %s, %s, lsr #3\n", t, t, x);
    printf("\tand\t%s, %s, #0x11111111\n", t, t);
    binop("eor", x, t);
    /* y  = (((x << 5) & (x << 1)) & 0x20202020U); */
    printf("\tlsl\t%s, %s, #5\n", y, x);
    printf("\tand\t%s, %s, %s, lsl #1\n", y, y, x);
    printf("\tand\t%s, %s, #0x20202020\n", y, y);
    /* x ^= (((x << 5) & (x << 4)) & 0x40404040U) ^ y; */
    printf("\tlsl\t%s, %s, #5\n", t, x);
    printf("\tand\t%s, %s, %s, lsl #4\n", t, t, x);
    printf("\tand\t%s, %s, #0x40404040\n", t, t);
    binop("eor", x, t);
    binop("eor", x, y);
    /* y  = (((x << 2) & (x << 1)) & 0x80808080U); */
    printf("\tlsl\t%s, %s, #2\n", y, x);
    printf("\tand\t%s, %s, %s, lsl #1\n", y, y, x);
    printf("\tand\t%s, %s, #0x80808080\n", y, y);
    /* x ^= (((x >> 2) & (x << 1)) & 0x02020202U) ^ y; */
    printf("\tlsr\t%s, %s, #2\n", t, x);
    printf("\tand\t%s, %s, %s, lsl #1\n", t, t, x);
    printf("\tand\t%s, %s, #0x02020202\n", t, t);
    binop("eor", x, t);
    binop("eor", x, y);
    /* y  = (((x >> 5) & (x << 1)) & 0x04040404U); */
    printf("\tlsr\t%s, %s, #5\n", y, x);
    printf("\tand\t%s, %s, %s, lsl #1\n", y, y, x);
    printf("\tand\t%s, %s, #0x04040404\n", y, y);
    /* x ^= (((x >> 1) & (x >> 2)) & 0x08080808U) ^ y; */
    printf("\tlsr\t%s, %s, #1\n", t, x);
    printf("\tand\t%s, %s, %s, lsr #2\n", t, t, x);
    printf("\tand\t%s, %s, #0x08080808\n", t, t);
    binop("eor", x, t);
    binop("eor", x, y);
    /* y = ~x; */
    binop("mvn", y, x);

    /* Permutation generated by http://programming.sirrida.de/calcperm.php */
    /* The final permutation for each byte is [2 7 6 1 3 0 4 5] */
    /* x = ((y & 0x08080808U) << 1) |
     *     ((y & 0x32323232U) << 2) |
     *     ((y & 0x01010101U) << 5) |
     *     ((y & 0x80808080U) >> 6) |
     *     ((y & 0x40404040U) >> 4) |
     *     ((y & 0x04040404U) >> 2); */
    printf("\tand\t%s, %s, #0x08080808\n", x, y);
    printf("\tand\t%s, %s, #0x32323232\n", t, y);
    printf("\tlsl\t%s, %s, #1\n", x, x);
    printf("\torr\t%s, %s, %s, lsl #2\n", x, x, t);
    printf("\tand\t%s, %s, #0x01010101\n", t, y);
    printf("\torr\t%s, %s, %s, lsl #5\n", x, x, t);
    printf("\tand\t%s, %s, #0x80808080\n", t, y);
    printf("\torr\t%s, %s, %s, lsr #6\n", x, x, t);
    printf("\tand\t%s, %s, #0x40404040\n", t, y);
    printf("\torr\t%s, %s, %s, lsr #4\n", x, x, t);
    printf("\tand\t%s, %s, #0x04040404\n", t, y);
    printf("\torr\t%s, %s, %s, lsr #2\n", x, x, t);
}

/* Performs half of a TK value that lives in registers */
static void skinny128_permute_tk_half
    (const reg_names *regs, const char *tk2, const char *tk3)
{
    const char *row2 = regs->t1;
    const char *row3 = regs->t2;
    /* row2 = tk2; */
    binop("mov", row2, tk2);
    /* row3 = tk3; */
    /* row3 = (row3 << 16) | (row3 >> 16); */
    printf("\tror\t%s, %s, #16\n", row3, tk3);
    /* tk2 = ((row2 >>  8) & 0x000000FFU) |
     *       ((row2 << 16) & 0x00FF0000U) |
     *       ( row3        & 0xFF00FF00U); */
    printf("\tuxtb\t%s, %s, ror #8\n", tk2, row2);
    printf("\tbfi\t%s, %s, #16, #8\n", tk2, row2);
    printf("\tand\t%s, %s, #0xFF00FF00\n", tk3, row3);
    binop("orr", tk2, tk3);
    /* tk3 = ((row2 >> 16) & 0x000000FFU) |
     *        (row2        & 0xFF000000U) |
     *       ((row3 <<  8) & 0x0000FF00U) |
     *       ( row3        & 0x00FF0000U); */
    printf("\tuxtb\t%s, %s, ror #16\n", tk3, row2);
    printf("\tand\t%s, %s, #0xFF000000\n", row2, row2);
    binop("orr", tk3, row2);
    printf("\tbfi\t%s, %s, #8, #8\n", tk3, row3);
    printf("\tand\t%s, %s, #0x00FF0000\n", row3, row3);
    binop("orr", tk3, row3);
}

/* Apply LFSR2 to a pair of words */
static void skinny128_LFSR2
    (const reg_names *regs, const char *x1, const char *x2)
{
    /* x = ((x << 1) & 0xFEFEFEFEU) ^ (((x >> 7) ^ (x >> 5)) & 0x01010101U); */
    printf("\tlsl\t%s, %s, #1\n", regs->t1, x1);
    printf("\tlsl\t%s, %s, #1\n", regs->t2, x2);
    printf("\tand\t%s, %s, #0xFEFEFEFE\n", regs->t1, regs->t1);
    printf("\tand\t%s, %s, #0xFEFEFEFE\n", regs->t2, regs->t2);
    printf("\tlsr\t%s, %s, #5\n", x1, x1);
    printf("\tlsr\t%s, %s, #5\n", x2, x2);
    printf("\teor\t%s, %s, %s, lsr #2\n", x1, x1, x1);
    printf("\teor\t%s, %s, %s, lsr #2\n", x2, x2, x2);
    printf("\tand\t%s, %s, #0x01010101\n", x1, x1);
    printf("\tand\t%s, %s, #0x01010101\n", x2, x2);
    printf("\teor\t%s, %s, %s\n", x1, x1, regs->t1);
    printf("\teor\t%s, %s, %s\n", x2, x2, regs->t2);
}

/* Apply LFSR3 to a pair of words */
static void skinny128_LFSR3
    (const reg_names *regs, const char *x1, const char *x2)
{
    /* x = ((x >> 1) & 0x7F7F7F7FU) ^ (((x << 7) ^ (x << 1)) & 0x80808080U) */
    printf("\tlsr\t%s, %s, #1\n", regs->t1, x1);
    printf("\tlsr\t%s, %s, #1\n", regs->t2, x2);
    printf("\tand\t%s, %s, #0x7F7F7F7F\n", regs->t1, regs->t1);
    printf("\tand\t%s, %s, #0x7F7F7F7F\n", regs->t2, regs->t2);
    printf("\tlsl\t%s, %s, #1\n", x1, x1);
    printf("\tlsl\t%s, %s, #1\n", x2, x2);
    printf("\teor\t%s, %s, %s, lsl #6\n", x1, x1, x1);
    printf("\teor\t%s, %s, %s, lsl #6\n", x2, x2, x2);
    printf("\tand\t%s, %s, #0x80808080\n", x1, x1);
    printf("\tand\t%s, %s, #0x80808080\n", x2, x2);
    printf("\teor\t%s, %s, %s\n", x1, x1, regs->t1);
    printf("\teor\t%s, %s, %s\n", x2, x2, regs->t2);
}

/* Generates the next rc value in the key schedule */
static void gen_next_rc(const reg_names *regs, const char *rc)
{
    /* rc = (rc << 1) ^ ((rc >> 5) & 0x01) ^ ((rc >> 4) & 0x01) ^ 0x01; */
    printf("\tlsr\t%s, %s, #5\n", regs->t1, rc);
    printf("\teor\t%s, %s, %s, lsr #4\n", regs->t1, regs->t1, rc);
    printf("\teor\t%s, %s, #1\n", regs->t1, regs->t1);
    printf("\tand\t%s, %s, #1\n", regs->t1, regs->t1);
    printf("\teor\t%s, %s, %s, lsl #1\n", rc, regs->t1, rc);
    /* rc &= 0x3F; */
    printf("\tand\t%s, %s, #0x3F\n", rc, rc);
}

/* Generate the key setup function for the tiny version */
static void gen_skinny_128_384_init_tiny(int without_tk1)
{
    /*
     * r0 holds the pointer to the output key schedule.
     * r1 points to the input key.
     *
     * For the "without_tk1" version, "r1" points to TK2 and "r2" to TK3.
     *
     * r0, r1, r2, r3, and ip can be used as scratch registers without saving,
     * but the value of ip may not survive across a branch instruction.
     *
     * r4, r5, r6, r7, r8, r9, r10, and fp must be callee-saved.
     *
     * lr can be used as a temporary as long as it is saved on the stack.
     */
    int index;
    reg_names regs = { .s0 = 0 };
    regs.t1 = "r2";
    regs.t2 = "r3";

    if (without_tk1) {
        /* Copy the 32 bytes of TK2 and TK3 directly to the key schedule */
        for (index = 0; index < 16; index += 4) {
            printf("\tldr\t%s, [r1, #%d]\n", regs.t1, index);
            printf("\tldr\t%s, [r2, #%d]\n", regs.t2, index + 16);
            printf("\tstr\t%s, [r0, #%d]\n", regs.t1, index + 16);
            printf("\tstr\t%s, [r0, #%d]\n", regs.t2, index + 32);
        }
    } else {
        /* Copy the 48 bytes of the tweakey directly to the key schedule */
        for (index = 0; index < 48; index += 8) {
            printf("\tldr\t%s, [r1, #%d]\n", regs.t1, index);
            printf("\tldr\t%s, [r1, #%d]\n", regs.t2, index + 4);
            printf("\tstr\t%s, [r0, #%d]\n", regs.t1, index);
            printf("\tstr\t%s, [r0, #%d]\n", regs.t2, index + 4);
        }
    }

    printf("\tbx\tlr\n");
}

/* Generate the key setup function for the standard version */
static void gen_skinny_128_384_init_standard(int without_tk1)
{
    /*
     * r0 holds the pointer to the output key schedule.
     * r1 points to the input key.
     *
     * For the "without_tk1" version, "r1" points to TK2 and "r2" to TK3.
     *
     * r0, r1, r2, r3, and ip can be used as scratch registers without saving,
     * but the value of ip may not survive across a branch instruction.
     *
     * r4, r5, r6, r7, r8, r9, r10, and fp must be callee-saved.
     *
     * lr can be used as a temporary as long as it is saved on the stack.
     */
    int top_label;
    reg_names regs = { .s0 = 0 };
    regs.tk2[0] = "r3";
    regs.tk2[1] = "r4";
    regs.tk2[2] = "r5";
    regs.tk2[3] = "r6";
    regs.tk3[0] = "r7";
    regs.tk3[1] = "r8";
    regs.tk3[2] = "r9";
    regs.tk3[3] = "r2";
    regs.t1 = "r10";
    regs.t2 = "ip";
    regs.t3 = "lr";

    /* Save callee-preserved registers on the stack */
    printf("\tpush\t{r4, r5, r6, r7, r8, r9, r10, lr}\n");

    /* Copy the value of TK1 directly to the key schedule */
    if (!without_tk1) {
        printf("\tldr\t%s, [r1, #0]\n", regs.t1);
        printf("\tldr\t%s, [r1, #4]\n", regs.t2);
        printf("\tstr\t%s, [r0, #0]\n", regs.t1);
        printf("\tstr\t%s, [r0, #4]\n", regs.t2);
        printf("\tldr\t%s, [r1, #8]\n", regs.t1);
        printf("\tldr\t%s, [r1, #12]\n", regs.t2);
        printf("\tstr\t%s, [r0, #8]\n", regs.t1);
        printf("\tstr\t%s, [r0, #12]\n", regs.t2);
    }

    /* Load the initial values of TK2 and TK3 into registers */
    if (!without_tk1) {
        printf("\tldr\t%s, [r1, #16]\n", regs.tk2[0]);
        printf("\tldr\t%s, [r1, #20]\n", regs.tk2[1]);
        printf("\tldr\t%s, [r1, #24]\n", regs.tk2[2]);
        printf("\tldr\t%s, [r1, #28]\n", regs.tk2[3]);
        printf("\tldr\t%s, [r1, #32]\n", regs.tk3[0]);
        printf("\tldr\t%s, [r1, #36]\n", regs.tk3[1]);
        printf("\tldr\t%s, [r1, #40]\n", regs.tk3[2]);
        printf("\tldr\t%s, [r1, #44]\n", regs.tk3[3]);
    } else {
        printf("\tldr\t%s, [r1, #0]\n",  regs.tk2[0]);
        printf("\tldr\t%s, [r1, #4]\n",  regs.tk2[1]);
        printf("\tldr\t%s, [r1, #8]\n",  regs.tk2[2]);
        printf("\tldr\t%s, [r1, #12]\n", regs.tk2[3]);
        printf("\tldr\t%s, [r2, #0]\n",  regs.tk3[0]);
        printf("\tldr\t%s, [r2, #4]\n",  regs.tk3[1]);
        printf("\tldr\t%s, [r2, #8]\n",  regs.tk3[2]);
        printf("\tldr\t%s, [r2, #12]\n", regs.tk3[3]);
    }

    /* r1 can now be used as an extra temporary register */
    regs.t4 = "r1";

    /* Top of the round loop; the rounds are performed two at a time */
    loadimm(regs.t3, 0); /* rc working value */
    loadimm(regs.t4, round_count / 2);
    top_label = label++;
    printf(".L%d:\n", top_label);
    printf("\tadd\tr0, #16\n"); /* update the key schedule pointer */

    /* First round of the pair */

    /* Generate the next rc value and create the next two key schedule words */
    gen_next_rc(&regs, regs.t3);
    /* schedule[0] = TK2[0] ^ TK3[0] ^ (rc & 0x0F); */
    /* schedule[1] = TK2[1] ^ TK3[1] ^ (rc >> 4); */
    printf("\tand\t%s, %s, #0x0F\n", regs.t1, regs.t3);
    printf("\tlsr\t%s, %s, #4\n", regs.t2, regs.t3);
    binop("eor", regs.t1, regs.tk2[0]);
    binop("eor", regs.t2, regs.tk2[1]);
    binop("eor", regs.t1, regs.tk3[0]);
    binop("eor", regs.t2, regs.tk3[1]);
    printf("\tstr\t%s, [r0, #0]\n", regs.t1);
    printf("\tstr\t%s, [r0, #4]\n", regs.t2);

    /* Permute the bottom half of TK2 and TK3 for the next round */
    skinny128_permute_tk_half(&regs, regs.tk2[2], regs.tk2[3]);
    skinny128_permute_tk_half(&regs, regs.tk3[2], regs.tk3[3]);
    skinny128_LFSR2(&regs, regs.tk2[2], regs.tk2[3]);
    skinny128_LFSR3(&regs, regs.tk3[2], regs.tk3[3]);

    /* Second round of the pair */

    /* Generate the next rc value and create the next two key schedule words */
    gen_next_rc(&regs, regs.t3);
    /* schedule[2] = TK2[2] ^ TK3[2] ^ (rc & 0x0F); */
    /* schedule[3] = TK2[3] ^ TK3[3] ^ (rc >> 4); */
    printf("\tand\t%s, %s, #0x0F\n", regs.t1, regs.t3);
    printf("\tlsr\t%s, %s, #4\n", regs.t2, regs.t3);
    binop("eor", regs.t1, regs.tk2[2]);
    binop("eor", regs.t2, regs.tk2[3]);
    binop("eor", regs.t1, regs.tk3[2]);
    binop("eor", regs.t2, regs.tk3[3]);
    printf("\tstr\t%s, [r0, #8]\n", regs.t1);
    printf("\tstr\t%s, [r0, #12]\n", regs.t2);

    /* Permute the top half of TK2 and TK3 for the next round */
    skinny128_permute_tk_half(&regs, regs.tk2[0], regs.tk2[1]);
    skinny128_permute_tk_half(&regs, regs.tk3[0], regs.tk3[1]);
    skinny128_LFSR2(&regs, regs.tk2[0], regs.tk2[1]);
    skinny128_LFSR3(&regs, regs.tk3[0], regs.tk3[1]);

    /* Bottom of the round loop */
    printf("\tsubs\t%s, %s, #1\n", regs.t4, regs.t4);
    printf("\tbne\t.L%d\n", top_label);

    /* Pop the stack frame and return */
    printf("\tpop\t{r4, r5, r6, r7, r8, r9, r10, pc}\n");
}

/* Perform a swap and move operation on 1 to 4 groups in parallel */
static void skinny_swap_move_parallel
    (const reg_names *regs, const char *a1, const char *b1,
     const char *a2, const char *b2, const char *a3, const char *b3,
     const char *a4, const char *b4, uint32_t mask, int shift)
{
    /* tmp1 = (b ^ (a >> shift)) & mask; */
    if (!is_op2_constant(mask))
        exit(1); /* Must have a mask we can express as an immediate constant */
    printf("\teor\t%s, %s, %s, lsr #%d\n", regs->t1, b1, a1, shift);
    if (a2)
        printf("\teor\t%s, %s, %s, lsr #%d\n", regs->t2, b2, a2, shift);
    if (a3)
        printf("\teor\t%s, %s, %s, lsr #%d\n", regs->t3, b3, a3, shift);
    if (a4)
        printf("\teor\t%s, %s, %s, lsr #%d\n", regs->t4, b4, a4, shift);
    printf("\tand\t%s, %s, #%d\n", regs->t1, regs->t1, (int)mask);
    if (a2)
        printf("\tand\t%s, %s, #%d\n", regs->t2, regs->t2, (int)mask);
    if (a3)
        printf("\tand\t%s, %s, #%d\n", regs->t3, regs->t3, (int)mask);
    if (a4)
        printf("\tand\t%s, %s, #%d\n", regs->t4, regs->t4, (int)mask);

    /* b ^= tmp; */
    binop("eor", b1, regs->t1);
    if (b2)
        binop("eor", b2, regs->t2);
    if (b3)
        binop("eor", b3, regs->t3);
    if (b4)
        binop("eor", b4, regs->t4);

    /* a ^= tmp << shift; */
    printf("\teor\t%s, %s, %s, lsl #%d\n", a1, a1, regs->t1, shift);
    if (a2)
        printf("\teor\t%s, %s, %s, lsl #%d\n", a2, a2, regs->t2, shift);
    if (a3)
        printf("\teor\t%s, %s, %s, lsl #%d\n", a3, a3, regs->t3, shift);
    if (a4)
        printf("\teor\t%s, %s, %s, lsl #%d\n", a4, a4, regs->t4, shift);
}

/* Swap and move on a single group */
static void skinny_swap_move
    (const reg_names *regs, const char *a, const char *b,
     uint32_t mask, int shift)
{
    skinny_swap_move_parallel(regs, a, b, 0, 0, 0, 0, 0, 0, mask, shift);
}

/* Converts four 32-bit state words into fixsliced form */
static void skinny_to_fixsliced
    (const reg_names *regs, const char *a, const char *b,
     const char *c, const char *d)
{
    skinny_swap_move_parallel(regs, a, a, b, b, c, c, d, d, 0x0A0A0A0AU, 3);
    skinny_swap_move(regs, c, a, 0x30303030U, 2);
    skinny_swap_move(regs, b, a, 0x0C0C0C0CU, 4);
    skinny_swap_move(regs, d, a, 0x03030303U, 6);
    skinny_swap_move(regs, b, c, 0x0C0C0C0CU, 2);
    skinny_swap_move(regs, d, c, 0x03030303U, 4);
    skinny_swap_move(regs, d, b, 0x03030303U, 2);
}

/* Converts four 32-bit state words from fixsliced form */
static void skinny_from_fixsliced
    (const reg_names *regs, const char *a, const char *b,
     const char *c, const char *d)
{
    skinny_swap_move(regs, d, b, 0x03030303U, 2);
    skinny_swap_move(regs, d, c, 0x03030303U, 4);
    skinny_swap_move(regs, b, c, 0x0C0C0C0CU, 2);
    skinny_swap_move(regs, d, a, 0x03030303U, 6);
    skinny_swap_move(regs, b, a, 0x0C0C0C0CU, 4);
    skinny_swap_move(regs, c, a, 0x30303030U, 2);
    skinny_swap_move_parallel(regs, a, a, b, b, c, c, d, d, 0x0A0A0A0AU, 3);
}

/* Generates the fixsliced version of LFSR2 */
static void gen_fixsliced_lfsr2
    (const reg_names *regs, const char *tk0, const char *tk1)
{
    /* tk0 ^= (tk1 & 0xAAAAAAAAU); */
    printf("\tand\t%s, %s, #0xAAAAAAAA\n", regs->t1, tk1);
    binop("eor", tk0, regs->t1);
    /* tk0 = ((tk0 & 0xAAAAAAAAU) >> 1) | ((tk0 << 1) & 0xAAAAAAAAU); */
    printf("\tand\t%s, %s, #0xAAAAAAAA\n", regs->t1, tk0);
    printf("\tlsl\t%s, %s, #1\n", tk0, tk0);
    printf("\tand\t%s, %s, #0xAAAAAAAA\n", tk0, tk0);
    printf("\torr\t%s, %s, %s, lsr #1\n", tk0, tk0, regs->t1);
}

/* Generates the fixsliced version of LFSR3 */
static void gen_fixsliced_lfsr3
    (const reg_names *regs, const char *tk0, const char *tk1)
{
    /* tk0 ^= ((tk1 & 0xAAAAAAAAU) >> 1); */
    printf("\tand\t%s, %s, #0xAAAAAAAA\n", regs->t1, tk1);
    printf("\teor\t%s, %s, %s, lsr #1\n", tk0, tk0, regs->t1);
    /* tk0 = ((tk0 & 0xAAAAAAAAU) >> 1) | ((tk0 << 1) & 0xAAAAAAAAU); */
    printf("\tand\t%s, %s, #0xAAAAAAAA\n", regs->t1, tk0);
    printf("\tlsl\t%s, %s, #1\n", tk0, tk0);
    printf("\tand\t%s, %s, #0xAAAAAAAA\n", tk0, tk0);
    printf("\torr\t%s, %s, %s, lsr #1\n", tk0, tk0, regs->t1);
}

/* Run LFSR2 and LFSR3 to generate unpermuted values for all rounds */
static void gen_skinny_128_384_expand_lfsr
    (const reg_names *regs, const char *ptr, int offset)
{
    int skip_label;
    int top_label;

    /* Round 1 LFSR values are TK2 ^ TK3 on the first pass and
     * zero on subsequent passes.  We set the values for the
     * first pass outside the loop and then skip ahead. */
    top_label = label++;
    skip_label = label++;
    loadimm(regs->round, round_count / 8);
    loadimm(regs->t4, 0); /* We will need some zero values below, so preload */
    printf("\teor\t%s, %s, %s\n", regs->t1, regs->tk2[0], regs->tk3[0]);
    printf("\teor\t%s, %s, %s\n", regs->t2, regs->tk2[1], regs->tk3[1]);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t1, ptr, offset);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t2, ptr, offset + 4);
    printf("\teor\t%s, %s, %s\n", regs->t1, regs->tk2[2], regs->tk3[2]);
    printf("\teor\t%s, %s, %s\n", regs->t2, regs->tk2[3], regs->tk3[3]);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t1, ptr, offset + 8);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t2, ptr, offset + 12);
    printf("\tb\t.L%d\n", skip_label);
    printf(".L%d:\n", top_label);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t4, ptr, offset);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t4, ptr, offset + 4);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t4, ptr, offset + 8);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t4, ptr, offset + 12);
    printf(".L%d:\n", skip_label);
    offset += 16;

    /* Round 2 */
    gen_fixsliced_lfsr2(regs, regs->tk2[0], regs->tk2[2]);
    gen_fixsliced_lfsr3(regs, regs->tk3[3], regs->tk3[1]);
    printf("\teor\t%s, %s, %s\n", regs->t1, regs->tk2[1], regs->tk3[3]);
    printf("\teor\t%s, %s, %s\n", regs->t2, regs->tk2[2], regs->tk3[0]);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t1, ptr, offset);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t2, ptr, offset + 4);
    printf("\teor\t%s, %s, %s\n", regs->t1, regs->tk2[3], regs->tk3[1]);
    printf("\teor\t%s, %s, %s\n", regs->t2, regs->tk2[0], regs->tk3[2]);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t1, ptr, offset + 8);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t2, ptr, offset + 12);
    offset += 16;

    /* Round 3 */
    printf("\tstr\t%s, [%s, #%d]\n", regs->t4, ptr, offset);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t4, ptr, offset + 4);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t4, ptr, offset + 8);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t4, ptr, offset + 12);
    offset += 16;

    /* Round 4 */
    gen_fixsliced_lfsr2(regs, regs->tk2[1], regs->tk2[3]);
    gen_fixsliced_lfsr3(regs, regs->tk3[2], regs->tk3[0]);
    printf("\teor\t%s, %s, %s\n", regs->t1, regs->tk2[2], regs->tk3[2]);
    printf("\teor\t%s, %s, %s\n", regs->t2, regs->tk2[3], regs->tk3[3]);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t1, ptr, offset);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t2, ptr, offset + 4);
    printf("\teor\t%s, %s, %s\n", regs->t1, regs->tk2[0], regs->tk3[0]);
    printf("\teor\t%s, %s, %s\n", regs->t2, regs->tk2[1], regs->tk3[1]);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t1, ptr, offset + 8);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t2, ptr, offset + 12);
    offset += 16;

    /* Round 5 */
    printf("\tstr\t%s, [%s, #%d]\n", regs->t4, ptr, offset);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t4, ptr, offset + 4);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t4, ptr, offset + 8);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t4, ptr, offset + 12);
    offset += 16;

    /* Round 6 */
    gen_fixsliced_lfsr2(regs, regs->tk2[2], regs->tk2[0]);
    gen_fixsliced_lfsr3(regs, regs->tk3[1], regs->tk3[3]);
    printf("\teor\t%s, %s, %s\n", regs->t1, regs->tk2[3], regs->tk3[1]);
    printf("\teor\t%s, %s, %s\n", regs->t2, regs->tk2[0], regs->tk3[2]);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t1, ptr, offset);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t2, ptr, offset + 4);
    printf("\teor\t%s, %s, %s\n", regs->t1, regs->tk2[1], regs->tk3[3]);
    printf("\teor\t%s, %s, %s\n", regs->t2, regs->tk2[2], regs->tk3[0]);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t1, ptr, offset + 8);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t2, ptr, offset + 12);
    offset += 16;

    /* Round 7 */
    printf("\tstr\t%s, [%s, #%d]\n", regs->t4, ptr, offset);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t4, ptr, offset + 4);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t4, ptr, offset + 8);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t4, ptr, offset + 12);
    offset += 16;

    /* Round 8 */
    gen_fixsliced_lfsr2(regs, regs->tk2[3], regs->tk2[1]);
    gen_fixsliced_lfsr3(regs, regs->tk3[0], regs->tk3[2]);
    printf("\teor\t%s, %s, %s\n", regs->t1, regs->tk2[0], regs->tk3[0]);
    printf("\teor\t%s, %s, %s\n", regs->t2, regs->tk2[1], regs->tk3[1]);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t1, ptr, offset);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t2, ptr, offset + 4);
    printf("\teor\t%s, %s, %s\n", regs->t1, regs->tk2[2], regs->tk3[2]);
    printf("\teor\t%s, %s, %s\n", regs->t2, regs->tk2[3], regs->tk3[3]);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t1, ptr, offset + 8);
    printf("\tstr\t%s, [%s, #%d]\n", regs->t2, ptr, offset + 12);

    /* Bottom of the round loop */
    printf("\tadd\t%s, %s, #%d\n", ptr, ptr, 32 * 4);
    printf("\tsubs\t%s, %s, #1\n", regs->round, regs->round);
    printf("\tbne\t.L%d\n", top_label);
}

/* Load a 16-byte value from the key schedule and optionally XOR with TK1 */
static void load_key
    (const reg_names *regs, const char **t,
     const char *ptr, int offset, int with_tk1)
{
    if (with_tk1) {
        /* TK1 is stored in local variables just down from the fp pointer.
         * The key schedule is assumed to be zero in this case. */
        printf("\tldr\t%s, [fp, #-16]\n", t[0]);
        printf("\tldr\t%s, [fp, #-12]\n", t[1]);
        printf("\tldr\t%s, [fp, #-8]\n", t[2]);
        printf("\tldr\t%s, [fp, #-4]\n", t[3]);
    } else {
        /* TK1 assumed to be zero, so load from the key schedule */
        printf("\tldr\t%s, [%s, #%d]\n", t[0], ptr, offset);
        printf("\tldr\t%s, [%s, #%d]\n", t[1], ptr, offset + 4);
        printf("\tldr\t%s, [%s, #%d]\n", t[2], ptr, offset + 8);
        printf("\tldr\t%s, [%s, #%d]\n", t[3], ptr, offset + 12);
    }
}

/* Permute LFSR values by 2 rounds */
static void skinny_permute_tk_2
    (const reg_names *regs, const char *t, int first)
{
    /* t = (rightRotate14(t) & 0xCC00CC00U) |
     *     ((t & 0x000000FFU) << 16) |
     *     ((t & 0xCC000000U) >> 2)  |
     *     ((t & 0x0033CC00U) >> 8)  |
     *     ((t & 0x00CC0000U) >> 18); */
    if (first)
        loadimm(regs->tk3[0], 0x0033CC00U);
    printf("\tror\t%s, %s, #14\n", regs->t1, t);
    printf("\tand\t%s, %s, #0xCC000000\n", regs->t2, t);
    printf("\tand\t%s, %s, #0xCC00CC00\n", regs->t1, regs->t1);
    printf("\tand\t%s, %s, %s\n", regs->t3, t, regs->tk3[0]);
    printf("\tbfi\t%s, %s, #16, #8\n", regs->t1, t);
    printf("\tand\t%s, %s, #0x00CC0000\n", t, t);
    printf("\torr\t%s, %s, %s, lsr #18\n", t, regs->t1, t);
    printf("\torr\t%s, %s, %s, lsr #2\n", t, t, regs->t2);
    printf("\torr\t%s, %s, %s, lsr #8\n", t, t, regs->t3);
}

/* Permute LFSR values by 4 rounds */
static void skinny_permute_tk_4
    (const reg_names *regs, const char *t, int first)
{
    /* t = (rightRotate22(t) & 0xCC0000CCU) |
     *     (rightRotate16(t) & 0x3300CC00U) |
     *     (rightRotate24(t) & 0x00CC3300U) |
     *     ((t & 0x00CC00CCU) >> 2); */
    if (first) {
        loadimm(regs->tk3[0], 0xCC0000CCU);
        loadimm(regs->tk3[1], 0x3300CC00U);
        loadimm(regs->tk3[2], 0x00CC3300U);
    }
    printf("\tror\t%s, %s, #22\n", regs->t1, t);
    printf("\tror\t%s, %s, #16\n", regs->t2, t);
    printf("\tror\t%s, %s, #24\n", regs->t3, t);
    printf("\tand\t%s, %s, %s\n", regs->t1, regs->t1, regs->tk3[0]);
    printf("\tand\t%s, %s, %s\n", regs->t2, regs->t2, regs->tk3[1]);
    printf("\tand\t%s, %s, #0x00CC00CC\n", t, t);
    printf("\tand\t%s, %s, %s\n", regs->t3, regs->t3, regs->tk3[2]);
    printf("\torr\t%s, %s, %s, lsr #2\n", t, regs->t1, t);
    printf("\torr\t%s, %s, %s\n", t, t, regs->t2);
    printf("\torr\t%s, %s, %s\n", t, t, regs->t3);
}

/* Permute LFSR values by 6 rounds */
static void skinny_permute_tk_6
    (const reg_names *regs, const char *t, int first)
{
    /* t = (rightRotate6((t))  & 0xCCCC0000U) |
     *     (rightRotate24((t)) & 0x330000CCU) |
     *     (rightRotate10((t)) & 0x00003333U) |
     *     (((t) & 0x000000CCU) << 14) |
     *     (((t) & 0x00003300U) << 2); */
    if (first) {
        loadimm(regs->tk3[0], 0xCCCC0000U);
        loadimm(regs->tk3[1], 0x330000CCU);
        loadimm(regs->tk3[2], 0x00003333U);
    }
    printf("\tror\t%s, %s, #6\n", regs->t1, t);
    printf("\tror\t%s, %s, #24\n", regs->t2, t);
    printf("\tror\t%s, %s, #10\n", regs->t3, t);
    printf("\tand\t%s, %s, #0x000000CC\n", regs->t4, t);
    printf("\tand\t%s, %s, %s\n", regs->t1, regs->t1, regs->tk3[0]);
    printf("\tand\t%s, %s, %s\n", regs->t2, regs->t2, regs->tk3[1]);
    printf("\tand\t%s, %s, #0x00003300\n", t, t);
    printf("\tand\t%s, %s, %s\n", regs->t3, regs->t3, regs->tk3[2]);
    printf("\torr\t%s, %s, %s, lsl #2\n", t, regs->t1, t);
    printf("\torr\t%s, %s, %s\n", t, t, regs->t2);
    printf("\torr\t%s, %s, %s\n", t, t, regs->t3);
    printf("\torr\t%s, %s, %s, lsl #14\n", t, t, regs->t4);
}

/* Permute LFSR values by 8 rounds */
static void skinny_permute_tk_8
    (const reg_names *regs, const char *t, int first)
{
    /* t = (rightRotate24(t) & 0xCC000033U) |
     *     (rightRotate8(t)  & 0x33CC0000U) |
     *     (rightRotate26(t) & 0x00333300U) |
     *     ((t & 0x00333300U) >> 6); */
    if (first) {
        loadimm(regs->tk3[0], 0xCC000033U);
        loadimm(regs->tk3[1], 0x33CC0000U);
        loadimm(regs->tk3[2], 0x00333300U);
    }
    printf("\tror\t%s, %s, #24\n", regs->t1, t);
    printf("\tror\t%s, %s, #8\n", regs->t2, t);
    printf("\tror\t%s, %s, #26\n", regs->t3, t);
    printf("\tand\t%s, %s, %s\n", regs->t1, regs->t1, regs->tk3[0]);
    printf("\tand\t%s, %s, %s\n", regs->t2, regs->t2, regs->tk3[1]);
    printf("\tand\t%s, %s, %s\n", regs->t3, regs->t3, regs->tk3[2]);
    printf("\tand\t%s, %s, %s\n", t, t, regs->tk3[2]);
    printf("\torr\t%s, %s, %s, lsr #6\n", t, regs->t1, t);
    printf("\torr\t%s, %s, %s\n", t, t, regs->t2);
    printf("\torr\t%s, %s, %s\n", t, t, regs->t3);
}

/* Permute LFSR values by 10 rounds */
static void skinny_permute_tk_10
    (const reg_names *regs, const char *t, int first)
{
    /* t = (rightRotate8(t)  & 0xCC330000U) |
     *     (rightRotate26(t) & 0x33000033U) |
     *     (rightRotate22(t) & 0x00CCCC00U) |
     *     ((t & 0x00330000U) >> 14) |
     *     ((t & 0x0000CC00U) >> 2); */
    if (first) {
        loadimm(regs->tk3[0], 0xCC330000U);
        loadimm(regs->tk3[1], 0x33000033U);
        loadimm(regs->tk3[2], 0x00CCCC00U);
    }
    printf("\tror\t%s, %s, #8\n", regs->t1, t);
    printf("\tror\t%s, %s, #26\n", regs->t2, t);
    printf("\tror\t%s, %s, #22\n", regs->t3, t);
    printf("\tand\t%s, %s, #0x00330000\n", regs->t4, t);
    printf("\tand\t%s, %s, %s\n", regs->t1, regs->t1, regs->tk3[0]);
    printf("\tand\t%s, %s, %s\n", regs->t2, regs->t2, regs->tk3[1]);
    printf("\tand\t%s, %s, %s\n", regs->t3, regs->t3, regs->tk3[2]);
    printf("\tand\t%s, %s, #0x0000CC00\n", t, t);
    printf("\torr\t%s, %s, %s\n", regs->t1, regs->t1, regs->t2);
    printf("\torr\t%s, %s, %s\n", regs->t1, regs->t1, regs->t3);
    printf("\torr\t%s, %s, %s, lsr #14\n", regs->t1, regs->t1, regs->t4);
    printf("\torr\t%s, %s, %s, lsr #2\n", t, regs->t1, t);
}

/* Permute LFSR values by 12 rounds */
static void skinny_permute_tk_12
    (const reg_names *regs, const char *t, int first)
{
    /* t = (rightRotate8(t)  & 0x0000CC33U) |
     *     (rightRotate30(t) & 0x00CC00CCU) |
     *     (rightRotate10(t) & 0x33330000U) |
     *     (rightRotate16(t) & 0xCC003300U); */
    if (first) {
        loadimm(regs->tk3[0], 0x0000CC33U);
        loadimm(regs->tk3[1], 0x33330000U);
        loadimm(regs->tk3[2], 0x3300CC00U); /* rightRotate16(0xCC003300U) */
    }
    printf("\tror\t%s, %s, #8\n", regs->t1, t);
    printf("\tror\t%s, %s, #30\n", regs->t2, t);
    printf("\tror\t%s, %s, #10\n", regs->t3, t);
    printf("\tand\t%s, %s, %s\n", t, t, regs->tk3[2]);
    printf("\tand\t%s, %s, %s\n", regs->t1, regs->t1, regs->tk3[0]);
    printf("\tand\t%s, %s, #0x00CC00CC\n", regs->t2, regs->t2);
    printf("\tand\t%s, %s, %s\n", regs->t3, regs->t3, regs->tk3[1]);
    printf("\torr\t%s, %s, %s, ror #16\n", t, regs->t1, t);
    printf("\torr\t%s, %s, %s\n", t, t, regs->t2);
    printf("\torr\t%s, %s, %s\n", t, t, regs->t3);
}

/* Permute LFSR values by 14 rounds */
static void skinny_permute_tk_14
    (const reg_names *regs, const char *t, int first)
{
    /* t = (rightRotate24((t)) & 0x0033CC00U) |
     *     (rightRotate14((t)) & 0x00CC0000U) |
     *     (rightRotate30((t)) & 0xCC000000U) |
     *     (rightRotate16((t)) & 0x000000FFU) |
     *     (rightRotate18((t)) & 0x33003300U); */
    if (first)
        loadimm(regs->tk3[0], 0x0033CC00U);
    printf("\tror\t%s, %s, #24\n", regs->t1, t);
    printf("\tror\t%s, %s, #14\n", regs->t2, t);
    printf("\tror\t%s, %s, #30\n", regs->t3, t);
    printf("\tror\t%s, %s, #16\n", regs->t4, t);
    printf("\tror\t%s, %s, #18\n", t, t);
    printf("\tand\t%s, %s, %s\n", regs->t1, regs->t1, regs->tk3[0]);
    printf("\tand\t%s, %s, #0x00CC0000\n", regs->t2, regs->t2);
    printf("\tand\t%s, %s, #0xCC000000\n", regs->t3, regs->t3);
    printf("\tand\t%s, %s, #0x33003300\n", t, t);
    printf("\tbfi\t%s, %s, #0, #8\n", t, regs->t4);
    printf("\torr\t%s, %s, %s\n", t, t, regs->t1);
    printf("\torr\t%s, %s, %s\n", t, t, regs->t2);
    printf("\torr\t%s, %s, %s\n", t, t, regs->t3);
}

/* Permutes and expands a TK value */
static void gen_skinny_permute_and_expand_tk
    (const reg_names *regs, const char *ptr, int offset,
     int round_count, int with_tk1)
{
    int top_label = -1;
    int end_label = -1;
    int phase, index;

    /* Note: We assume that the TK2 and TK3 registers are now free
     * for use as temporaries. */
    const char *t[4];
    t[0] = regs->tk2[0];
    t[1] = regs->tk2[1];
    t[2] = regs->tk2[2];
    t[3] = regs->tk2[3];

    /* Load the first key and optionally XOR with TK1 in s0...s3 */
    load_key(regs, t, ptr, offset, with_tk1);

    /* Top of the round loop, unrolling 16 rounds at a time */
    if (round_count > 16) {
        top_label = label++;
        end_label = label++;
        loadimm(regs->round, round_count / 8);
        printf(".L%d:\n", top_label);
    }

    /* Unroll the rounds in two 8-round phases */
    for (phase = 1; phase >= 0; --phase) {
        /* Rounds 1 and 9 */
        /* k[0] = t2 & 0xF0F0F0F0U; */
        /* k[1] = t3 & 0xF0F0F0F0U; */
        /* k[2] = t0 & 0xF0F0F0F0U; */
        /* k[3] = t1 & 0xF0F0F0F0U; */
        printf("\tand\t%s, %s, #0xF0F0F0F0\n", regs->t1, t[2]);
        printf("\tand\t%s, %s, #0xF0F0F0F0\n", regs->t2, t[3]);
        printf("\tand\t%s, %s, #0xF0F0F0F0\n", regs->t3, t[0]);
        printf("\tand\t%s, %s, #0xF0F0F0F0\n", regs->t4, t[1]);
        printf("\tstr\t%s, [%s, #%d]\n", regs->t1, ptr, offset);
        printf("\tstr\t%s, [%s, #%d]\n", regs->t2, ptr, offset + 4);
        printf("\tstr\t%s, [%s, #%d]\n", regs->t3, ptr, offset + 8);
        printf("\tstr\t%s, [%s, #%d]\n", regs->t4, ptr, offset + 12);
        /* t0 = k[4] ^ s0; */
        /* t1 = k[5] ^ s1; */
        /* t2 = k[6] ^ s2; */
        /* t3 = k[7] ^ s3; */
        offset += 16;
        load_key(regs, t, ptr, offset, with_tk1);

        /* Rounds 2 and 10 */
        if (phase) {
            skinny_permute_tk_2(regs, t[0], 1);
            skinny_permute_tk_2(regs, t[1], 0);
            skinny_permute_tk_2(regs, t[2], 0);
            skinny_permute_tk_2(regs, t[3], 0);
        } else {
            skinny_permute_tk_10(regs, t[0], 1);
            skinny_permute_tk_10(regs, t[1], 0);
            skinny_permute_tk_10(regs, t[2], 0);
            skinny_permute_tk_10(regs, t[3], 0);
        }
        /* k[4] = rightRotate26(t0) & 0xC3C3C3C3U; */
        /* k[5] = rightRotate26(t1) & 0xC3C3C3C3U; */
        /* k[6] = rightRotate26(t2) & 0xC3C3C3C3U; */
        /* k[7] = rightRotate26(t3) & 0xC3C3C3C3U; */
        printf("\tror\t%s, %s, #26\n", regs->t1, t[0]);
        printf("\tror\t%s, %s, #26\n", regs->t2, t[1]);
        printf("\tror\t%s, %s, #26\n", regs->t3, t[2]);
        printf("\tror\t%s, %s, #26\n", regs->t4, t[3]);
        printf("\tand\t%s, %s, #0xC3C3C3C3\n", regs->t1, regs->t1);
        printf("\tand\t%s, %s, #0xC3C3C3C3\n", regs->t2, regs->t2);
        printf("\tand\t%s, %s, #0xC3C3C3C3\n", regs->t3, regs->t3);
        printf("\tand\t%s, %s, #0xC3C3C3C3\n", regs->t4, regs->t4);
        printf("\tstr\t%s, [%s, #%d]\n", regs->t1, ptr, offset);
        printf("\tstr\t%s, [%s, #%d]\n", regs->t2, ptr, offset + 4);
        printf("\tstr\t%s, [%s, #%d]\n", regs->t3, ptr, offset + 8);
        printf("\tstr\t%s, [%s, #%d]\n", regs->t4, ptr, offset + 12);
        offset += 16;

        /* Rounds 3 and 11 */
        /* k[8]  = (rightRotate28(t2) & 0x03030303U) | */
        /*         (rightRotate12(t2) & 0x0C0C0C0CU);  */
        /* k[9]  = (rightRotate28(t3) & 0x03030303U) | */
        /*         (rightRotate12(t3) & 0x0C0C0C0CU);  */
        /* k[10] = (rightRotate28(t0) & 0x03030303U) | */
        /*         (rightRotate12(t0) & 0x0C0C0C0CU);  */
        /* k[11] = (rightRotate28(t1) & 0x03030303U) | */
        /*         (rightRotate12(t1) & 0x0C0C0C0CU);  */
        for (index = 0; index < 4; ++index) {
            printf("\tror\t%s, %s, #28\n", regs->t1, t[(index + 2) % 4]);
            printf("\tror\t%s, %s, #12\n", regs->t2, t[(index + 2) % 4]);
            printf("\tand\t%s, %s, #0x03030303\n", regs->t1, regs->t1);
            printf("\tand\t%s, %s, #0x0C0C0C0C\n", regs->t2, regs->t2);
            binop("orr", regs->t1, regs->t2);
            printf("\tstr\t%s, [%s, #%d]\n", regs->t1, ptr, offset + index * 4);
        }
        /* t0 = k[12] ^ s0; */
        /* t1 = k[13] ^ s1; */
        /* t2 = k[14] ^ s2; */
        /* t3 = k[15] ^ s3; */
        offset += 16;
        load_key(regs, t, ptr, offset, with_tk1);

        /* Rounds 4 and 12 */
        if (phase) {
            skinny_permute_tk_4(regs, t[0], 1);
            skinny_permute_tk_4(regs, t[1], 0);
            skinny_permute_tk_4(regs, t[2], 0);
            skinny_permute_tk_4(regs, t[3], 0);
        } else {
            skinny_permute_tk_12(regs, t[0], 1);
            skinny_permute_tk_12(regs, t[1], 0);
            skinny_permute_tk_12(regs, t[2], 0);
            skinny_permute_tk_12(regs, t[3], 0);
        }
        /* k[12] = (rightRotate14(t0) & 0x30303030U) |
         *         (rightRotate6(t0)  & 0x0C0C0C0CU);
         * k[13] = (rightRotate14(t1) & 0x30303030U) |
         *         (rightRotate6(t1)  & 0x0C0C0C0CU);
         * k[14] = (rightRotate14(t2) & 0x30303030U) |
         *         (rightRotate6(t2)  & 0x0C0C0C0CU);
         * k[15] = (rightRotate14(t3) & 0x30303030U) |
         *         (rightRotate6(t3)  & 0x0C0C0C0CU); */
        for (index = 0; index < 4; ++index) {
            printf("\tror\t%s, %s, #14\n", regs->t1, t[index]);
            printf("\tror\t%s, %s, #6\n", regs->t2, t[index]);
            printf("\tand\t%s, %s, #0x30303030\n", regs->t1, regs->t1);
            printf("\tand\t%s, %s, #0x0C0C0C0C\n", regs->t2, regs->t2);
            binop("orr", regs->t1, regs->t2);
            printf("\tstr\t%s, [%s, #%d]\n", regs->t1, ptr, offset + index * 4);
        }
        offset += 16;

        /* Rounds 5 and 13 */
        /* k[16] = rightRotate16(t2) & 0xF0F0F0F0U; */
        /* k[17] = rightRotate16(t3) & 0xF0F0F0F0U; */
        /* k[18] = rightRotate16(t0) & 0xF0F0F0F0U; */
        /* k[19] = rightRotate16(t1) & 0xF0F0F0F0U; */
        printf("\tror\t%s, %s, #16\n", t[2], t[2]);
        printf("\tror\t%s, %s, #16\n", t[3], t[3]);
        printf("\tror\t%s, %s, #16\n", t[0], t[0]);
        printf("\tror\t%s, %s, #16\n", t[1], t[1]);
        printf("\tand\t%s, %s, #0xF0F0F0F0\n", t[2], t[2]);
        printf("\tand\t%s, %s, #0xF0F0F0F0\n", t[3], t[3]);
        printf("\tand\t%s, %s, #0xF0F0F0F0\n", t[0], t[0]);
        printf("\tand\t%s, %s, #0xF0F0F0F0\n", t[1], t[1]);
        printf("\tstr\t%s, [%s, #%d]\n", t[2], ptr, offset);
        printf("\tstr\t%s, [%s, #%d]\n", t[3], ptr, offset + 4);
        printf("\tstr\t%s, [%s, #%d]\n", t[0], ptr, offset + 8);
        printf("\tstr\t%s, [%s, #%d]\n", t[1], ptr, offset + 12);
        offset += 16;
        load_key(regs, t, ptr, offset, with_tk1);

        /* Rounds 6 and 14 */
        if (phase) {
            skinny_permute_tk_6(regs, t[0], 1);
            skinny_permute_tk_6(regs, t[1], 0);
            skinny_permute_tk_6(regs, t[2], 0);
            skinny_permute_tk_6(regs, t[3], 0);
        } else {
            skinny_permute_tk_14(regs, t[0], 1);
            skinny_permute_tk_14(regs, t[1], 0);
            skinny_permute_tk_14(regs, t[2], 0);
            skinny_permute_tk_14(regs, t[3], 0);
        }
        /* k[20] = rightRotate10(t0) & 0xC3C3C3C3U; */
        /* k[21] = rightRotate10(t1) & 0xC3C3C3C3U; */
        /* k[22] = rightRotate10(t2) & 0xC3C3C3C3U; */
        /* k[23] = rightRotate10(t3) & 0xC3C3C3C3U; */
        printf("\tror\t%s, %s, #10\n", regs->t1, t[0]);
        printf("\tror\t%s, %s, #10\n", regs->t2, t[1]);
        printf("\tror\t%s, %s, #10\n", regs->t3, t[2]);
        printf("\tror\t%s, %s, #10\n", regs->t4, t[3]);
        printf("\tand\t%s, %s, #0xC3C3C3C3\n", regs->t1, regs->t1);
        printf("\tand\t%s, %s, #0xC3C3C3C3\n", regs->t2, regs->t2);
        printf("\tand\t%s, %s, #0xC3C3C3C3\n", regs->t3, regs->t3);
        printf("\tand\t%s, %s, #0xC3C3C3C3\n", regs->t4, regs->t4);
        printf("\tstr\t%s, [%s, #%d]\n", regs->t1, ptr, offset);
        printf("\tstr\t%s, [%s, #%d]\n", regs->t2, ptr, offset + 4);
        printf("\tstr\t%s, [%s, #%d]\n", regs->t3, ptr, offset + 8);
        printf("\tstr\t%s, [%s, #%d]\n", regs->t4, ptr, offset + 12);
        offset += 16;

        /* Rounds 7 and 15 */
        /* k[24] = (rightRotate12(t2) & 0x03030303U) |
         *         (rightRotate28(t2) & 0x0C0C0C0CU);
         * k[25] = (rightRotate12(t3) & 0x03030303U) |
         *         (rightRotate28(t3) & 0x0C0C0C0CU);
         * k[26] = (rightRotate12(t0) & 0x03030303U) |
         *         (rightRotate28(t0) & 0x0C0C0C0CU);
         * k[27] = (rightRotate12(t1) & 0x03030303U) |
         *         (rightRotate28(t1) & 0x0C0C0C0CU); */
        for (index = 0; index < 4; ++index) {
            printf("\tror\t%s, %s, #12\n", regs->t1, t[(index + 2) % 4]);
            printf("\tror\t%s, %s, #28\n", regs->t2, t[(index + 2) % 4]);
            printf("\tand\t%s, %s, #0x03030303\n", regs->t1, regs->t1);
            printf("\tand\t%s, %s, #0x0C0C0C0C\n", regs->t2, regs->t2);
            binop("orr", regs->t1, regs->t2);
            printf("\tstr\t%s, [%s, #%d]\n", regs->t1, ptr, offset + index * 4);
        }
        /* t0 = k[28] ^ s0; */
        /* t1 = k[29] ^ s1; */
        /* t2 = k[30] ^ s2; */
        /* t3 = k[31] ^ s3; */
        offset += 16;
        load_key(regs, t, ptr, offset, with_tk1);

        /* Rounds 8 and 16 */
        if (phase) {
            skinny_permute_tk_8(regs, t[0], 1);
            skinny_permute_tk_8(regs, t[1], 0);
            skinny_permute_tk_8(regs, t[2], 0);
            skinny_permute_tk_8(regs, t[3], 0);
        }
        /* k[28] = (rightRotate30(t0) & 0x30303030U) |
         *         (rightRotate22(t0) & 0x0C0C0C0CU);
         * k[29] = (rightRotate30(t1) & 0x30303030U) |
         *         (rightRotate22(t1) & 0x0C0C0C0CU);
         * k[30] = (rightRotate30(t2) & 0x30303030U) |
         *         (rightRotate22(t2) & 0x0C0C0C0CU);
         * k[31] = (rightRotate30(t3) & 0x30303030U) |
         *         (rightRotate22(t3) & 0x0C0C0C0CU); */
        for (index = 0; index < 4; ++index) {
            printf("\tror\t%s, %s, #30\n", regs->t1, t[index]);
            printf("\tror\t%s, %s, #22\n", regs->t2, t[index]);
            printf("\tand\t%s, %s, #0x30303030\n", regs->t1, regs->t1);
            printf("\tand\t%s, %s, #0x0C0C0C0C\n", regs->t2, regs->t2);
            binop("orr", regs->t1, regs->t2);
            printf("\tstr\t%s, [%s, #%d]\n", regs->t1, ptr, offset + index * 4);
        }
        offset += 16;

        /* We unroll 16 rounds at a time, but round_count is a multiple of
         * 8 not 16, so we may need to bail out early in the first phase. */
        if (phase && round_count > 16) {
            printf("\tsubs\t%s, %s, #1\n", regs->round, regs->round);
            printf("\tbeq\t.L%d\n", end_label);
        }
    }

    /* Bottom of the round loop */
    if (round_count > 16) {
        printf("\tadd\t%s, %s, #%d\n", ptr, ptr, 256);
        printf("\tsubs\t%s, %s, #1\n", regs->round, regs->round);
        printf("\tbne\t.L%d\n", top_label);
        printf(".L%d:\n", end_label);
    }
}

/* Initialize the key schedule in fixsliced form */
static void gen_skinny_128_384_init_schedule
    (const reg_names *regs, const char *ptr, int offset)
{
    int rc_label;

    /* Convert TK2 and TK3 into fixsliced form */
    skinny_to_fixsliced
        (regs, regs->tk2[0], regs->tk2[1], regs->tk2[2], regs->tk2[3]);
    skinny_to_fixsliced
        (regs, regs->tk3[0], regs->tk3[1], regs->tk3[2], regs->tk3[3]);

    /* Run LFSR2 and LFSR3 to generate unpermuted values for all rounds */
    gen_skinny_128_384_expand_lfsr(regs, ptr, offset);

    /* Permute the TK2 and TK3 values for all rounds */
    loadimm(regs->t4, round_count * 16);
    binop("sub", ptr, regs->t4);
    gen_skinny_permute_and_expand_tk(regs, ptr, offset, round_count, 0);
    /* Due to the early bailout, ptr increment is short */
    printf("\tadd\t%s, %s, #%d\n", ptr, ptr, 8 * 16 + offset);

    /* Add the round constants to the key schedule */
    loadimm(regs->round, round_count * 4);
    printf("\tadr\t%s, rconst\n", regs->t3);
    loadimm(regs->t4, round_count * 16);
    binop("add", regs->t3, regs->t4);
    rc_label = label++;
    printf(".L%d:\n", rc_label);
    printf("\tldr\t%s, [%s, #-4]!\n", regs->t1, regs->t3);
    printf("\tldr\t%s, [%s, #-4]!\n", regs->t2, ptr);
    binop("eor", regs->t1, regs->t2);
    printf("\tstr\t%s, [%s, #0]\n", regs->t1, ptr);
    printf("\tsubs\t%s, %s, #1\n", regs->round, regs->round);
    printf("\tbne\t.L%d\n", rc_label);
}

/* Generate the key setup function for the full fixsliced version */
static void gen_skinny_128_384_init_full(int without_tk1)
{
    /*
     * r0 holds the pointer to the output key schedule.
     * r1 points to the input key.
     *
     * For the "without_tk1" version, "r1" points to TK2 and "r2" to TK3.
     *
     * r0, r1, r2, r3, and ip can be used as scratch registers without saving,
     * but the value of ip may not survive across a branch instruction.
     *
     * r4, r5, r6, r7, r8, r9, r10, and fp must be callee-saved.
     *
     * lr can be used as a temporary as long as it is saved on the stack.
     */
    reg_names regs = { .s0 = 0 };
    regs.tk2[0] = "r3";
    regs.tk2[1] = "r4";
    regs.tk2[2] = "r5";
    regs.tk2[3] = "r6";
    regs.tk3[0] = "r7";
    regs.tk3[1] = "r8";
    regs.tk3[2] = "r9";
    regs.tk3[3] = "r2";
    regs.t1 = "r10";
    regs.t2 = "ip";
    regs.t3 = "lr";
    regs.t4 = "fp";
    regs.round = "r1";

    /* Save callee-preserved registers on the stack */
    printf("\tpush\t{r4, r5, r6, r7, r8, r9, r10, fp, lr}\n");

    /* Copy TK1 to the key schedule and then load TK2 and TK3 */
    if (without_tk1) {
        /* Load just TK2 and TK3 */
        printf("\tldr\t%s, [r1, #%d]\n", regs.tk2[0], 0);
        printf("\tldr\t%s, [r1, #%d]\n", regs.tk2[1], 8);
        printf("\tldr\t%s, [r1, #%d]\n", regs.tk2[2], 4);
        printf("\tldr\t%s, [r1, #%d]\n", regs.tk2[3], 12);
        printf("\tldr\t%s, [r2, #%d]\n", regs.tk3[0], 0);
        printf("\tldr\t%s, [r2, #%d]\n", regs.tk3[1], 8);
        printf("\tldr\t%s, [r2, #%d]\n", regs.tk3[2], 4);
        printf("\tldr\t%s, [r2, #%d]\n", regs.tk3[3], 12);
    } else {
        /* Copy TK1 to the key schedule */
        printf("\tldr\t%s, [r1, #%d]\n", regs.t1, 0);
        printf("\tldr\t%s, [r1, #%d]\n", regs.t2, 4);
        printf("\tldr\t%s, [r1, #%d]\n", regs.t3, 8);
        printf("\tldr\t%s, [r1, #%d]\n", regs.t4, 12);
        printf("\tstr\t%s, [r0, #%d]\n", regs.t1, 0);
        printf("\tstr\t%s, [r0, #%d]\n", regs.t2, 4);
        printf("\tstr\t%s, [r0, #%d]\n", regs.t3, 8);
        printf("\tstr\t%s, [r0, #%d]\n", regs.t4, 12);

        /* Load TK2 and TK3 */
        printf("\tldr\t%s, [r1, #%d]\n", regs.tk2[0], 16);
        printf("\tldr\t%s, [r1, #%d]\n", regs.tk2[1], 24);
        printf("\tldr\t%s, [r1, #%d]\n", regs.tk2[2], 20);
        printf("\tldr\t%s, [r1, #%d]\n", regs.tk2[3], 28);
        printf("\tldr\t%s, [r1, #%d]\n", regs.tk3[0], 32);
        printf("\tldr\t%s, [r1, #%d]\n", regs.tk3[1], 40);
        printf("\tldr\t%s, [r1, #%d]\n", regs.tk3[2], 36);
        printf("\tldr\t%s, [r1, #%d]\n", regs.tk3[3], 44);
    }

    /* Generate the key schedule based on TK2 and TK3 */
    gen_skinny_128_384_init_schedule(&regs, "r0", 16);

    /* Pop the stack frame and return */
    printf("\tpop\t{r4, r5, r6, r7, r8, r9, r10, fp, pc}\n");
}

/* Generate code for a standard SKINNY-128 round with TK1 expansion only */
static void skinny128_standard_round
    (const reg_names *regs, const char *s0, const char *s1,
     const char *s2, const char *s3, int half, int offset)
{
    /* Apply the SKINNY-128 S-box to all state words */
    skinny128_sbox(regs, s0);
    skinny128_sbox(regs, s1);
    skinny128_sbox(regs, s2);
    skinny128_sbox(regs, s3);

    /* XOR the round constant and the subkey for this round */
    printf("\tldr\t%s, [r0, #%d]\n", regs->t1, 16 + (offset * 2) * 4);
    printf("\tldr\t%s, [r0, #%d]\n", regs->t2, 16 + (offset * 2 + 1) * 4);
    printf("\teor\t%s, %s, #2\n", s2, s2);
    binop("eor", s0, regs->tk1[half * 2]);
    binop("eor", s1, regs->tk1[half * 2 + 1]);
    binop("eor", s0, regs->t1);
    binop("eor", s1, regs->t2);

    /* Shift the cells in the rows right */
    printf("\tror\t%s, %s, #24\n", s1, s1);
    printf("\tror\t%s, %s, #16\n", s2, s2);
    printf("\tror\t%s, %s, #8\n", s3, s3);

    /* Mix the columns */
    binop("eor", s1, s2);
    binop("eor", s2, s0);
    binop("eor", s3, s2);

    /* Permute TK1 in-place for the next round */
    skinny128_permute_tk_half
        (regs, regs->tk1[(1 - half) * 2], regs->tk1[(1 - half) * 2 + 1]);
}

/* Generate code for a standard SKINNY-128 round with full TK expansion */
static void skinny128_full_round
    (const reg_names *regs, const char *s0, const char *s1,
     const char *s2, const char *s3, int half, int offset, int stack_base)
{
    /* Apply the SKINNY-128 S-box to all state words */
    skinny128_sbox(regs, s0);
    skinny128_sbox(regs, s1);
    skinny128_sbox(regs, s2);
    skinny128_sbox(regs, s3);

    /* Generate the next round constant */
    gen_next_rc(regs, regs->t3);

    /* XOR the round constant and the subkey for this round */
    binop("eor", s0, regs->tk1[0]);
    binop("eor", s1, regs->tk1[1]);
    printf("\teor\t%s, %s, #2\n", s2, s2);
    printf("\tldr\t%s, [fp, #%d]\n", regs->t1, stack_base + (half * 2) * 4);
    printf("\tldr\t%s, [fp, #%d]\n", regs->t2, stack_base + (half * 2 + 1) * 4);
    binop("eor", s0, regs->tk1[2]); /* Cached TK3 from previous round */
    binop("eor", s1, regs->tk1[3]);
    binop("eor", s0, regs->t1);
    binop("eor", s1, regs->t2);
    printf("\tand\t%s, %s, #0x0F\n", regs->t1, regs->t3);
    printf("\teor\t%s, %s, %s, lsr #4\n", s1, s1, regs->t3);
    binop("eor", s0, regs->t1);

    /* Shift the cells in the rows right */
    printf("\tror\t%s, %s, #24\n", s1, s1);
    printf("\tror\t%s, %s, #16\n", s2, s2);
    printf("\tror\t%s, %s, #8\n", s3, s3);

    /* Mix the columns */
    binop("eor", s1, s2);
    binop("eor", s2, s0);
    binop("eor", s3, s2);

    /* Swap the TK1 halves and perform TK1 in-place for the next round */
    printf("\tstr\t%s, [fp, #%d]\n", regs->tk1[0],
           stack_base + 32 + (half * 2) * 4);
    printf("\tstr\t%s, [fp, #%d]\n", regs->tk1[1],
           stack_base + 32 + (half * 2 + 1) * 4);
    printf("\tldr\t%s, [fp, #%d]\n", regs->tk1[0],
           stack_base + 32 + ((1 - half) * 2) * 4);
    printf("\tldr\t%s, [fp, #%d]\n", regs->tk1[1],
           stack_base + 32 + ((1 - half) * 2 + 1) * 4);
    skinny128_permute_tk_half(regs, regs->tk1[0], regs->tk1[1]);

    /* Permute TK2 in-place for the next round */
    printf("\tldr\t%s, [fp, #%d]\n", regs->tk1[2],
           stack_base + ((1 - half) * 2) * 4);
    printf("\tldr\t%s, [fp, #%d]\n", regs->tk1[3],
           stack_base + ((1 - half) * 2 + 1) * 4);
    skinny128_permute_tk_half(regs, regs->tk1[2], regs->tk1[3]);
    skinny128_LFSR2(regs, regs->tk1[2], regs->tk1[3]);
    printf("\tstr\t%s, [fp, #%d]\n", regs->tk1[2],
           stack_base + ((1 - half) * 2) * 4);
    printf("\tstr\t%s, [fp, #%d]\n", regs->tk1[3],
           stack_base + ((1 - half) * 2 + 1) * 4);

    /* Permute TK3 in-place for the next round */
    printf("\tldr\t%s, [fp, #%d]\n", regs->tk1[2],
           stack_base + 16 + ((1 - half) * 2) * 4);
    printf("\tldr\t%s, [fp, #%d]\n", regs->tk1[3],
           stack_base + 16 + ((1 - half) * 2 + 1) * 4);
    skinny128_permute_tk_half(regs, regs->tk1[2], regs->tk1[3]);
    skinny128_LFSR3(regs, regs->tk1[2], regs->tk1[3]);
    printf("\tstr\t%s, [fp, #%d]\n", regs->tk1[2],
           stack_base + 16 + ((1 - half) * 2) * 4);
    printf("\tstr\t%s, [fp, #%d]\n", regs->tk1[3],
           stack_base + 16 + ((1 - half) * 2 + 1) * 4);

    /* We leave the TK3 values in registers so that we can use
     * them without a reload during the next key schedule step */
}

/* Generate code for a standard SKINNY-128 round with TK2 expansion */
static void skinny128_tk2_round
    (const reg_names *regs, const char *s0, const char *s1,
     const char *s2, const char *s3, int half, int offset, int stack_base)
{
    /* Apply the SKINNY-128 S-box to all state words */
    skinny128_sbox(regs, s0);
    skinny128_sbox(regs, s1);
    skinny128_sbox(regs, s2);
    skinny128_sbox(regs, s3);

    /* XOR the subkey for this round */
    printf("\tldr\t%s, [r0, #%d]\n", regs->t1, 16 + (offset * 2) * 4);
    printf("\tldr\t%s, [r0, #%d]\n", regs->t2, 16 + (offset * 2 + 1) * 4);
    printf("\teor\t%s, %s, #2\n", s2, s2);
    binop("eor", s0, regs->tk1[0]);
    binop("eor", s1, regs->tk1[1]);
    binop("eor", s0, regs->t1);
    binop("eor", s1, regs->t2);
    binop("eor", s0, regs->tk1[2]); /* Cached TK2 from previous round */
    binop("eor", s1, regs->tk1[3]);

    /* Shift the cells in the rows right */
    printf("\tror\t%s, %s, #24\n", s1, s1);
    printf("\tror\t%s, %s, #16\n", s2, s2);
    printf("\tror\t%s, %s, #8\n", s3, s3);

    /* Mix the columns */
    binop("eor", s1, s2);
    binop("eor", s2, s0);
    binop("eor", s3, s2);

    /* Swap the TK1 halves and perform TK1 in-place for the next round */
    printf("\tstr\t%s, [fp, #%d]\n", regs->tk1[0],
           stack_base + 16 + (half * 2) * 4);
    printf("\tstr\t%s, [fp, #%d]\n", regs->tk1[1],
           stack_base + 16 + (half * 2 + 1) * 4);
    printf("\tldr\t%s, [fp, #%d]\n", regs->tk1[0],
           stack_base + 16 + ((1 - half) * 2) * 4);
    printf("\tldr\t%s, [fp, #%d]\n", regs->tk1[1],
           stack_base + 16 + ((1 - half) * 2 + 1) * 4);
    skinny128_permute_tk_half(regs, regs->tk1[0], regs->tk1[1]);

    /* Permute TK2 in-place for the next round */
    printf("\tldr\t%s, [fp, #%d]\n", regs->tk1[2],
           stack_base + ((1 - half) * 2) * 4);
    printf("\tldr\t%s, [fp, #%d]\n", regs->tk1[3],
           stack_base + ((1 - half) * 2 + 1) * 4);
    skinny128_permute_tk_half(regs, regs->tk1[2], regs->tk1[3]);
    skinny128_LFSR2(regs, regs->tk1[2], regs->tk1[3]);
    printf("\tstr\t%s, [fp, #%d]\n", regs->tk1[2],
           stack_base + ((1 - half) * 2) * 4);
    printf("\tstr\t%s, [fp, #%d]\n", regs->tk1[3],
           stack_base + ((1 - half) * 2 + 1) * 4);

    /* We leave the TK2 values in registers so that we can use
     * them without a reload during the next key schedule step */
}

/* Generate the SKINNY-128 encryption code with the full key schedule
 * expanded on the fly instead of ahead of time */
static void gen_skinny_128_384_encrypt_full(void)
{
    /*
     * r0 holds the pointer to the key schedule.
     * r1 points to the output buffer.
     * r2 points to the input buffer.
     *
     * r0, r1, r2, r3, and ip can be used as scratch registers without saving,
     * but the value of ip may not survive across a branch instruction.
     *
     * r4, r5, r6, r7, r8, r9, r10, and fp must be callee-saved.
     *
     * lr can be used as a temporary as long as it is saved on the stack.
     */
    int index;
    int top_label;
    int stack_base;
    reg_names regs = { .s0 = 0 };
    regs.s0 = "r3";
    regs.s1 = "r4";
    regs.s2 = "r5";
    regs.s3 = "r6";
    regs.tk1[0] = "r7";
    regs.tk1[1] = "r8";
    regs.tk1[2] = "r9";
    regs.tk1[3] = "r10";
    regs.t1 = "lr";
    regs.t2 = "ip";
    regs.t3 = "r2";

    /* Save callee-preserved registers on the stack */
    printf("\tpush\t{r4, r5, r6, r7, r8, r9, r10, fp, lr}\n");

    /* Need 48 bytes of stack space to store TK1, TK2, and TK3
     * while they are being expanded on the fly */
    printf("\tmov\tfp, sp\n");
    printf("\tsub\tsp, sp, #48\n");
    stack_base = -48;

    /* Load the input state into registers */
    printf("\tldr\t%s, [r2, #0]\n", regs.s0);
    printf("\tldr\t%s, [r2, #4]\n", regs.s1);
    printf("\tldr\t%s, [r2, #8]\n", regs.s2);
    printf("\tldr\t%s, [r2, #12]\n", regs.s3);

    /* Load half TK1 into registers and the other half onto the stack */
    printf("\tldr\t%s, [r0, #0]\n", regs.tk1[0]);
    printf("\tldr\t%s, [r0, #4]\n", regs.tk1[1]);
    printf("\tldr\t%s, [r0, #8]\n", regs.tk1[2]);
    printf("\tldr\t%s, [r0, #12]\n", regs.tk1[3]);
    printf("\tstr\t%s, [fp, #%d]\n", regs.tk1[2], stack_base + 32 + 8);
    printf("\tstr\t%s, [fp, #%d]\n", regs.tk1[3], stack_base + 32 + 12);

    /* Copy the TK2 and TK3 values to the stack.  We also leave
     * TK3[0] and TK3[1] in registers for use by skinny128_full_round() */
    for (index = 0; index < 32; index += 8) {
        if (index == 16) {
            printf("\tldr\t%s, [r0, #%d]\n", regs.tk1[2], 16 + index);
            printf("\tldr\t%s, [r0, #%d]\n", regs.tk1[3], 20 + index);
            printf("\tstr\t%s, [fp, #%d]\n", regs.tk1[2], stack_base + index);
            printf("\tstr\t%s, [fp, #%d]\n", regs.tk1[3], stack_base + index + 4);
        } else {
            printf("\tldr\t%s, [r0, #%d]\n", regs.t1, 16 + index);
            printf("\tldr\t%s, [r0, #%d]\n", regs.t2, 20 + index);
            printf("\tstr\t%s, [fp, #%d]\n", regs.t1, stack_base + index);
            printf("\tstr\t%s, [fp, #%d]\n", regs.t2, stack_base + index + 4);
        }
    }

    /* r0 can now be used as an extra temporary register */
    regs.t4 = "r0";

    /* Top of the round loop; all rounds are performed four at a time */
    loadimm(regs.t3, 0); /* rc working value */
    loadimm(regs.t4, round_count / 4);
    top_label = label++;
    printf(".L%d:\n", top_label);

    /* Generate the code for the four inner rounds */
    skinny128_full_round
        (&regs, regs.s0, regs.s1, regs.s2, regs.s3, 0, 0, stack_base);
    skinny128_full_round
        (&regs, regs.s3, regs.s0, regs.s1, regs.s2, 1, 1, stack_base);
    skinny128_full_round
        (&regs, regs.s2, regs.s3, regs.s0, regs.s1, 0, 2, stack_base);
    skinny128_full_round
        (&regs, regs.s1, regs.s2, regs.s3, regs.s0, 1, 3, stack_base);

    /* Bottom of the round loop */
    printf("\tsubs\t%s, %s, #1\n", regs.t4, regs.t4);
    printf("\tbne\t.L%d\n", top_label);

    /* Save the state to the output buffer */
    printf("\tstr\t%s, [r1, #0]\n", regs.s0);
    printf("\tstr\t%s, [r1, #4]\n", regs.s1);
    printf("\tstr\t%s, [r1, #8]\n", regs.s2);
    printf("\tstr\t%s, [r1, #12]\n", regs.s3);

    /* Pop the stack frame and return */
    printf("\tmov\tsp, fp\n");
    printf("\tpop\t{r4, r5, r6, r7, r8, r9, r10, fp, pc}\n");
}

/* Generate the SKINNY-128 encryption code for the standard key schedule */
static void gen_skinny_128_384_encrypt_standard(void)
{
    /*
     * r0 holds the pointer to the key schedule.
     * r1 points to the output buffer.
     * r2 points to the input buffer.
     *
     * r0, r1, r2, r3, and ip can be used as scratch registers without saving,
     * but the value of ip may not survive across a branch instruction.
     *
     * r4, r5, r6, r7, r8, r9, r10, and fp must be callee-saved.
     *
     * lr can be used as a temporary as long as it is saved on the stack.
     */
    int top_label;
    reg_names regs = { .s0 = 0 };
    regs.s0 = "r3";
    regs.s1 = "r4";
    regs.s2 = "r5";
    regs.s3 = "r6";
    regs.tk1[0] = "r7";
    regs.tk1[1] = "r8";
    regs.tk1[2] = "r9";
    regs.tk1[3] = "r10";
    regs.t1 = "lr";
    regs.t2 = "ip";
    regs.t3 = "r2";

    /* Save callee-preserved registers on the stack */
    printf("\tpush\t{r4, r5, r6, r7, r8, r9, r10, lr}\n");

    /* Load the input state into registers */
    printf("\tldr\t%s, [r2, #0]\n", regs.s0);
    printf("\tldr\t%s, [r2, #4]\n", regs.s1);
    printf("\tldr\t%s, [r2, #8]\n", regs.s2);
    printf("\tldr\t%s, [r2, #12]\n", regs.s3);

    /* Load the initial TK1 value into registers */
    printf("\tldr\t%s, [r0, #0]\n", regs.tk1[0]);
    printf("\tldr\t%s, [r0, #4]\n", regs.tk1[1]);
    printf("\tldr\t%s, [r0, #8]\n", regs.tk1[2]);
    printf("\tldr\t%s, [r0, #12]\n", regs.tk1[3]);

    /* Top of the round loop; all rounds are performed four at a time */
    loadimm(regs.t3, round_count / 4);
    top_label = label++;
    printf(".L%d:\n", top_label);

    /* Generate the code for the four inner rounds */
    skinny128_standard_round(&regs, regs.s0, regs.s1, regs.s2, regs.s3, 0, 0);
    skinny128_standard_round(&regs, regs.s3, regs.s0, regs.s1, regs.s2, 1, 1);
    skinny128_standard_round(&regs, regs.s2, regs.s3, regs.s0, regs.s1, 0, 2);
    skinny128_standard_round(&regs, regs.s1, regs.s2, regs.s3, regs.s0, 1, 3);

    /* Bottom of the round loop */
    printf("\tadd\tr0, #32\n");
    printf("\tsubs\t%s, %s, #1\n", regs.t3, regs.t3);
    printf("\tbne\t.L%d\n", top_label);

    /* Save the state to the output buffer */
    printf("\tstr\t%s, [r1, #0]\n", regs.s0);
    printf("\tstr\t%s, [r1, #4]\n", regs.s1);
    printf("\tstr\t%s, [r1, #8]\n", regs.s2);
    printf("\tstr\t%s, [r1, #12]\n", regs.s3);

    /* Pop the stack frame and return */
    printf("\tpop\t{r4, r5, r6, r7, r8, r9, r10, pc}\n");
}

/* Applies the first S-box to the fixsliced state */
static void skinny_fixsliced_sbox_1(const reg_names *regs)
{
    /* s3 ^= ~(s0 | s1); */
    printf("\torr\t%s, %s, %s\n", regs->t1, regs->s0, regs->s1);
    binop("mvn", regs->t1, regs->t1);
    binop("eor", regs->s3, regs->t1);

    skinny_swap_move(regs, regs->s2, regs->s1, 0x55555555U, 1);
    skinny_swap_move(regs, regs->s3, regs->s2, 0x55555555U, 1);

    /* s1 ^= ~(s2 | s3); */
    printf("\torr\t%s, %s, %s\n", regs->t1, regs->s2, regs->s3);
    binop("mvn", regs->t1, regs->t1);
    binop("eor", regs->s1, regs->t1);

    skinny_swap_move(regs, regs->s1, regs->s0, 0x55555555U, 1);
    skinny_swap_move(regs, regs->s0, regs->s3, 0x55555555U, 1);

    /* s3 ^= ~(s0 | s1); */
    printf("\torr\t%s, %s, %s\n", regs->t1, regs->s0, regs->s1);
    binop("mvn", regs->t1, regs->t1);
    binop("eor", regs->s3, regs->t1);

    skinny_swap_move(regs, regs->s2, regs->s1, 0x55555555U, 1);
    skinny_swap_move(regs, regs->s3, regs->s2, 0x55555555U, 1);

    /* s1 ^= (s2 | s3); */
    printf("\torr\t%s, %s, %s\n", regs->t1, regs->s2, regs->s3);
    binop("eor", regs->s1, regs->t1);

    skinny_swap_move(regs, regs->s3, regs->s0, 0x55555555U, 0);
}

/* Applies the second S-box to the fixsliced state */
static void skinny_fixsliced_sbox_2(const reg_names *regs)
{
    /* s1 ^= ~(s2 | s3); */
    printf("\torr\t%s, %s, %s\n", regs->t1, regs->s2, regs->s3);
    binop("mvn", regs->t1, regs->t1);
    binop("eor", regs->s1, regs->t1);

    skinny_swap_move(regs, regs->s1, regs->s0, 0x55555555U, 1);
    skinny_swap_move(regs, regs->s0, regs->s3, 0x55555555U, 1);

    /* s3 ^= ~(s0 | s1); */
    printf("\torr\t%s, %s, %s\n", regs->t1, regs->s0, regs->s1);
    binop("mvn", regs->t1, regs->t1);
    binop("eor", regs->s3, regs->t1);

    skinny_swap_move(regs, regs->s2, regs->s1, 0x55555555U, 1);
    skinny_swap_move(regs, regs->s3, regs->s2, 0x55555555U, 1);

    /* s1 ^= ~(s2 | s3); */
    printf("\torr\t%s, %s, %s\n", regs->t1, regs->s2, regs->s3);
    binop("mvn", regs->t1, regs->t1);
    binop("eor", regs->s1, regs->t1);

    skinny_swap_move(regs, regs->s1, regs->s0, 0x55555555U, 1);
    skinny_swap_move(regs, regs->s0, regs->s3, 0x55555555U, 1);

    /* s3 ^= (s0 | s1); */
    printf("\torr\t%s, %s, %s\n", regs->t1, regs->s0, regs->s1);
    binop("eor", regs->s3, regs->t1);

    skinny_swap_move(regs, regs->s1, regs->s2, 0x55555555U, 0);
}

/* Applies the round keys to the state */
static void skinny_fixsliced_add_key
    (const reg_names *regs, const char *k1, const char *k2)
{
    printf("\tldr\t%s, [%s], #4\n", regs->t1, k1);
    printf("\tldr\t%s, [%s], #4\n", regs->t2, k2);
    binop("eor", regs->s0, regs->t1);
    binop("eor", regs->s0, regs->t2);

    printf("\tldr\t%s, [%s], #4\n", regs->t1, k1);
    printf("\tldr\t%s, [%s], #4\n", regs->t2, k2);
    binop("eor", regs->s1, regs->t1);
    binop("eor", regs->s1, regs->t2);

    printf("\tldr\t%s, [%s], #4\n", regs->t1, k1);
    printf("\tldr\t%s, [%s], #4\n", regs->t2, k2);
    binop("eor", regs->s2, regs->t1);
    binop("eor", regs->s2, regs->t2);

    printf("\tldr\t%s, [%s], #4\n", regs->t1, k1);
    printf("\tldr\t%s, [%s], #4\n", regs->t2, k2);
    binop("eor", regs->s3, regs->t1);
    binop("eor", regs->s3, regs->t2);
}

/* Mixes the columns for the first round of 4 in the fixsliced state */
static void skinny_mix_columns_1_of_4(const reg_names *regs, const char *s)
{
    /* t = rightRotate24(s) & 0x0C0C0C0CU; */
    printf("\tror\t%s, %s, #24\n", regs->t1, s);
    printf("\tand\t%s, %s, #0x0C0C0C0C\n", regs->t1, regs->t1);

    /* s ^= rightRotate30(t); */
    printf("\teor\t%s, %s, %s, ror #30\n", s, s, regs->t1);

    /* t = rightRotate16(s) & 0xC0C0C0C0U; */
    printf("\tror\t%s, %s, #16\n", regs->t1, s);
    printf("\tand\t%s, %s, #0xC0C0C0C0\n", regs->t1, regs->t1);

    /* s ^= rightRotate4(t); */
    printf("\teor\t%s, %s, %s, ror #4\n", s, s, regs->t1);

    /* t = rightRotate8(s) & 0x0C0C0C0CU; */
    printf("\tror\t%s, %s, #8\n", regs->t1, s);
    printf("\tand\t%s, %s, #0x0C0C0C0C\n", regs->t1, regs->t1);

    /* s ^= rightRotate2(t); */
    printf("\teor\t%s, %s, %s, ror #2\n", s, s, regs->t1);
}

/* Mixes the columns for the second round of 4 in the fixsliced state */
static void skinny_mix_columns_2_of_4(const reg_names *regs, const char *s)
{
    /* t = rightRotate16(s) & 0x30303030U; */
    printf("\tror\t%s, %s, #16\n", regs->t1, s);
    printf("\tand\t%s, %s, #0x30303030\n", regs->t1, regs->t1);

    /* s ^= rightRotate30(t); */
    printf("\teor\t%s, %s, %s, ror #30\n", s, s, regs->t1);

    /* t = s & 0x03030303U; */
    printf("\tand\t%s, %s, #0x03030303\n", regs->t1, s);

    /* s ^= rightRotate28(t); */
    printf("\teor\t%s, %s, %s, ror #28\n", s, s, regs->t1);

    /* t = rightRotate16(s) & 0x30303030U; */
    printf("\tror\t%s, %s, #16\n", regs->t1, s);
    printf("\tand\t%s, %s, #0x30303030\n", regs->t1, regs->t1);

    /* s ^= rightRotate2(t); */
    printf("\teor\t%s, %s, %s, ror #2\n", s, s, regs->t1);
}

/* Mixes the columns for the third round of 4 in the fixsliced state */
static void skinny_mix_columns_3_of_4(const reg_names *regs, const char *s)
{
    /* t = rightRotate8(s) & 0xC0C0C0C0U; */
    printf("\tror\t%s, %s, #8\n", regs->t1, s);
    printf("\tand\t%s, %s, #0xC0C0C0C0\n", regs->t1, regs->t1);

    /* s ^= rightRotate6(t); */
    printf("\teor\t%s, %s, %s, ror #6\n", s, s, regs->t1);

    /* t = rightRotate16(s) & 0x0C0C0C0CU; */
    printf("\tror\t%s, %s, #16\n", regs->t1, s);
    printf("\tand\t%s, %s, #0x0C0C0C0C\n", regs->t1, regs->t1);

    /* s ^= rightRotate28(t); */
    printf("\teor\t%s, %s, %s, ror #28\n", s, s, regs->t1);

    /* t = rightRotate24(s) & 0xC0C0C0C0U; */
    printf("\tror\t%s, %s, #24\n", regs->t1, s);
    printf("\tand\t%s, %s, #0xC0C0C0C0\n", regs->t1, regs->t1);

    /* s ^= rightRotate2(t); */
    printf("\teor\t%s, %s, %s, ror #2\n", s, s, regs->t1);
}

/* Mixes the columns for the fourth round of 4 in the fixsliced state */
static void skinny_mix_columns_4_of_4(const reg_names *regs, const char *s)
{
    /* t = s & 0x03030303U; */
    printf("\tand\t%s, %s, #0x03030303\n", regs->t1, s);

    /* s ^= rightRotate30(t); */
    printf("\teor\t%s, %s, %s, ror #30\n", s, s, regs->t1);

    /* t = s & 0x30303030U; */
    printf("\tand\t%s, %s, #0x30303030\n", regs->t1, s);

    /* s ^= rightRotate4(t); */
    printf("\teor\t%s, %s, %s, ror #4\n", s, s, regs->t1);

    /* t = s & 0x03030303U; */
    printf("\tand\t%s, %s, #0x03030303\n", regs->t1, s);

    /* s ^= rightRotate26(t); */
    printf("\teor\t%s, %s, %s, ror #26\n", s, s, regs->t1);
}

/* Generate the SKINNY-128 encryption code for the fixsliced key schedule */
static void gen_skinny_128_384_encrypt_fixsliced(void)
{
    /*
     * r0 holds the pointer to the key schedule.
     * r1 points to the output buffer.
     * r2 points to the input buffer.
     *
     * r0, r1, r2, r3, and ip can be used as scratch registers without saving,
     * but the value of ip may not survive across a branch instruction.
     *
     * r4, r5, r6, r7, r8, r9, r10, and fp must be callee-saved.
     *
     * lr can be used as a temporary as long as it is saved on the stack.
     */
    int stack_offset;
    int top_label;
    const char *tk1_base;
    const char *tk1_ptr;
    reg_names regs = { .s0 = 0 };
    regs.s0 = "r3";
    regs.s1 = "r4";
    regs.s2 = "r5";
    regs.s3 = "r6";
    regs.tk1[0] = regs.s0; /* Aliased registers */
    regs.tk1[1] = regs.s1;
    regs.tk1[2] = regs.s2;
    regs.tk1[3] = regs.s3;
    regs.tk2[0] = regs.s0; /* Aliased registers - extra temporaries */
    regs.tk2[1] = regs.s1;
    regs.tk2[2] = regs.s2;
    regs.tk2[3] = regs.s3;
    regs.tk3[0] = "r7";    /* Extra temporaries for TK1 expansion */
    regs.tk3[1] = "r8";
    regs.tk3[2] = "r9";
    regs.tk3[3] = 0;
    regs.t1 = "lr";
    regs.t2 = "ip";
    regs.t3 = "r2";
    regs.t4 = "r10";
    regs.round = "r1";

    /* Save callee-preserved registers on the stack */
    printf("\tpush\t{r4, r5, r6, r7, r8, r9, r10, fp, lr}\n");

    /* Need space for 16 rounds of expanded TK1 schedule on the stack */
    stack_offset = 16 *16 + 16;
    printf("\tmov\tfp, sp\n");
    printf("\tsub\tsp, sp, #%d\n", stack_offset);

    /* Save "r1" and "r2" on the stack; we will need them later */
    printf("\tpush\t{r1}\n");
    printf("\tpush\t{r2}\n");

    /* Load and expand the TK1 schedule */
    printf("\tldr\t%s, [r0, #0]\n", regs.tk1[0]);
    printf("\tldr\t%s, [r0, #4]\n", regs.tk1[2]);
    printf("\tldr\t%s, [r0, #8]\n", regs.tk1[1]);
    printf("\tldr\t%s, [r0, #12]\n", regs.tk1[3]);
    skinny_to_fixsliced
        (&regs, regs.tk1[0], regs.tk1[1], regs.tk1[2], regs.tk1[3]);
    printf("\tstr\t%s, [fp, #-16]\n", regs.tk1[0]);
    printf("\tstr\t%s, [fp, #-12]\n", regs.tk1[1]);
    printf("\tstr\t%s, [fp, #-8]\n", regs.tk1[2]);
    printf("\tstr\t%s, [fp, #-4]\n", regs.tk1[3]);
    printf("\tsub\t%s, %s, #%d\n", "r1", "fp", stack_offset);
    gen_skinny_permute_and_expand_tk(&regs, "r1", 0, 16, 1);

    /* Load the contents of the input buffer and convert to fixsliced form */
    printf("\tpop\t{r2}\n");
    printf("\tldr\t%s, [r2, #0]\n", regs.s0);
    printf("\tldr\t%s, [r2, #4]\n", regs.s2);
    printf("\tldr\t%s, [r2, #8]\n", regs.s1);
    printf("\tldr\t%s, [r2, #12]\n", regs.s3);
    skinny_to_fixsliced(&regs, regs.s0, regs.s1, regs.s2, regs.s3);

    /* Top of the round loop; perform the encryption rounds four at a time */
    loadimm(regs.round, 0);
    top_label = label++;
    tk1_base = regs.tk3[0];
    tk1_ptr = regs.tk3[1];
    printf("\tsub\t%s, %s, #%d\n", tk1_base, "fp", stack_offset);
    printf("\tadd\tr0, r0, #16\n");
    printf(".L%d:\n", top_label);
    printf("\tand\t%s, %s, #0xFF\n", tk1_ptr, regs.round);
    printf("\tadd\t%s, %s, %s\n", tk1_ptr, tk1_base, tk1_ptr);

    /* Round 1 of 4 */
    skinny_fixsliced_sbox_1(&regs);
    skinny_fixsliced_add_key(&regs, "r0", tk1_ptr);
    skinny_mix_columns_1_of_4(&regs, regs.s0);
    skinny_mix_columns_1_of_4(&regs, regs.s1);
    skinny_mix_columns_1_of_4(&regs, regs.s2);
    skinny_mix_columns_1_of_4(&regs, regs.s3);

    /* Round 2 of 4 */
    skinny_fixsliced_sbox_2(&regs);
    skinny_fixsliced_add_key(&regs, "r0", tk1_ptr);
    skinny_mix_columns_2_of_4(&regs, regs.s0);
    skinny_mix_columns_2_of_4(&regs, regs.s1);
    skinny_mix_columns_2_of_4(&regs, regs.s2);
    skinny_mix_columns_2_of_4(&regs, regs.s3);

    /* Round 3 of 4 */
    skinny_fixsliced_sbox_1(&regs);
    skinny_fixsliced_add_key(&regs, "r0", tk1_ptr);
    skinny_mix_columns_3_of_4(&regs, regs.s0);
    skinny_mix_columns_3_of_4(&regs, regs.s1);
    skinny_mix_columns_3_of_4(&regs, regs.s2);
    skinny_mix_columns_3_of_4(&regs, regs.s3);

    /* Round 4 of 4 */
    skinny_fixsliced_sbox_2(&regs);
    skinny_fixsliced_add_key(&regs, "r0", tk1_ptr);
    skinny_mix_columns_4_of_4(&regs, regs.s0);
    skinny_mix_columns_4_of_4(&regs, regs.s1);
    skinny_mix_columns_4_of_4(&regs, regs.s2);
    skinny_mix_columns_4_of_4(&regs, regs.s3);

    /* Bottom of the round loop */
    printf("\tadd\t%s, %s, #64\n", regs.round, regs.round);
    printf("\tcmp\t%s, #%d\n", regs.round, round_count * 16);
    printf("\tbne\t.L%d\n", top_label);

    /* Convert from fixsliced form and store the state to the output buffer */
    printf("\tpop\t{r1}\n");
    skinny_from_fixsliced(&regs, regs.s0, regs.s1, regs.s2, regs.s3);
    printf("\tstr\t%s, [r1, #0]\n", regs.s0);
    printf("\tstr\t%s, [r1, #4]\n", regs.s2);
    printf("\tstr\t%s, [r1, #8]\n", regs.s1);
    printf("\tstr\t%s, [r1, #12]\n", regs.s3);

    /* Pop the stack frame and return */
    printf("\tmov\tsp, fp\n");
    printf("\tpop\t{r4, r5, r6, r7, r8, r9, r10, fp, pc}\n");
}

/* Generate the SKINNY-128 encryption code with both TK1 and TK2
 * expanded on the fly instead of ahead of time.  TK3 is in the
 * pre-computed key schedule. */
static void gen_skinny_128_384_encrypt_tk2(void)
{
    /*
     * r0 holds the pointer to the key schedule.
     * r1 points to the output buffer.
     * r2 points to the input buffer.
     * r3 points to the TK2 value on entry.
     *
     * r0, r1, r2, r3, and ip can be used as scratch registers without saving,
     * but the value of ip may not survive across a branch instruction.
     *
     * r4, r5, r6, r7, r8, r9, r10, and fp must be callee-saved.
     *
     * lr can be used as a temporary as long as it is saved on the stack.
     */
    int top_label;
    int stack_base;
    reg_names regs = { .s0 = 0 };
    regs.s0 = "r4";
    regs.s1 = "r5";
    regs.s2 = "r6";
    regs.s3 = "r7";
    regs.tk1[0] = "r8";
    regs.tk1[1] = "r9";
    regs.tk1[2] = "r10";
    regs.tk1[3] = "r3";
    regs.t1 = "lr";
    regs.t2 = "ip";
    regs.t3 = "r2";

    /* Save callee-preserved registers on the stack */
    printf("\tpush\t{r4, r5, r6, r7, r8, r9, r10, fp, lr}\n");

    /* Need 32 bytes of stack space to store TK1 and TK2
     * while they are being expanded on the fly */
    printf("\tmov\tfp, sp\n");
    printf("\tsub\tsp, sp, #32\n");
    stack_base = -32;

    /* Load the input state into registers */
    printf("\tldr\t%s, [r2, #0]\n", regs.s0);
    printf("\tldr\t%s, [r2, #4]\n", regs.s1);
    printf("\tldr\t%s, [r2, #8]\n", regs.s2);
    printf("\tldr\t%s, [r2, #12]\n", regs.s3);

    /* Load half of TK1 into registers and the other half onto the stack */
    printf("\tldr\t%s, [r0, #0]\n", regs.tk1[0]);
    printf("\tldr\t%s, [r0, #4]\n", regs.tk1[1]);
    printf("\tldr\t%s, [r0, #8]\n", regs.t1);
    printf("\tldr\t%s, [r0, #12]\n", regs.t2);
    printf("\tstr\t%s, [fp, #%d]\n", regs.t1, stack_base + 16 + 8);
    printf("\tstr\t%s, [fp, #%d]\n", regs.t2, stack_base + 16 + 12);

    /* Copy the TK2 value to the stack, and leave the first half in registers */
    printf("\tldr\t%s, [r3, #8]\n", regs.t1);
    printf("\tldr\t%s, [r3, #12]\n", regs.t2);
    printf("\tldr\t%s, [r3, #0]\n", regs.tk1[2]);
    printf("\tldr\t%s, [r3, #4]\n", regs.tk1[3]);
    printf("\tstr\t%s, [fp, #%d]\n", regs.t1, stack_base + 8);
    printf("\tstr\t%s, [fp, #%d]\n", regs.t2, stack_base + 12);
    printf("\tstr\t%s, [fp, #%d]\n", regs.tk1[2], stack_base + 0);
    printf("\tstr\t%s, [fp, #%d]\n", regs.tk1[3], stack_base + 4);

    /* Top of the round loop; all rounds are performed four at a time */
    loadimm(regs.t3, round_count / 4);
    top_label = label++;
    printf(".L%d:\n", top_label);

    /* Generate the code for the four inner rounds */
    skinny128_tk2_round
        (&regs, regs.s0, regs.s1, regs.s2, regs.s3, 0, 0, stack_base);
    skinny128_tk2_round
        (&regs, regs.s3, regs.s0, regs.s1, regs.s2, 1, 1, stack_base);
    skinny128_tk2_round
        (&regs, regs.s2, regs.s3, regs.s0, regs.s1, 0, 2, stack_base);
    skinny128_tk2_round
        (&regs, regs.s1, regs.s2, regs.s3, regs.s0, 1, 3, stack_base);

    /* Bottom of the round loop */
    printf("\tadd\tr0, #32\n");
    printf("\tsubs\t%s, %s, #1\n", regs.t3, regs.t3);
    printf("\tbne\t.L%d\n", top_label);

    /* Save the state to the output buffer */
    printf("\tstr\t%s, [r1, #0]\n", regs.s0);
    printf("\tstr\t%s, [r1, #4]\n", regs.s1);
    printf("\tstr\t%s, [r1, #8]\n", regs.s2);
    printf("\tstr\t%s, [r1, #12]\n", regs.s3);

    /* Pop the stack frame and return */
    printf("\tmov\tsp, fp\n");
    printf("\tpop\t{r4, r5, r6, r7, r8, r9, r10, fp, pc}\n");
}

/* Generates the round constant table for the fixsliced version of SKINNY */
static void gen_fixsliced_rc(const char *name)
{
    static uint32_t const skinny_fixsliced_rc[160] = {
        0x00000004U, 0xFFFFFFBFU, 0x00000000U, 0x00000000U, 0x00000000U,
        0x00000000U, 0x10000100U, 0xFFFFFEFFU, 0x44000000U, 0xFBFFFFFFU,
        0x00000000U, 0x04000000U, 0x00100000U, 0x00100000U, 0x00100001U,
        0xFFEFFFFFU, 0x00440000U, 0xFFAFFFFFU, 0x00400000U, 0x00400000U,
        0x01000000U, 0x01000000U, 0x01401000U, 0xFFBFFFFFU, 0x01004000U,
        0xFEFFFBFFU, 0x00000400U, 0x00000400U, 0x00000010U, 0x00000000U,
        0x00010410U, 0xFFFFFBEFU, 0x00000054U, 0xFFFFFFAFU, 0x00000000U,
        0x00000040U, 0x00000100U, 0x00000100U, 0x10000140U, 0xFFFFFEFFU,
        0x44000000U, 0xFFFFFEFFU, 0x04000000U, 0x04000000U, 0x00100000U,
        0x00100000U, 0x04000001U, 0xFBFFFFFFU, 0x00140000U, 0xFFAFFFFFU,
        0x00400000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x01401000U,
        0xFEBFFFFFU, 0x01004400U, 0xFFFFFBFFU, 0x00000000U, 0x00000400U,
        0x00000010U, 0x00000010U, 0x00010010U, 0xFFFFFFFFU, 0x00000004U,
        0xFFFFFFAFU, 0x00000040U, 0x00000040U, 0x00000100U, 0x00000000U,
        0x10000140U, 0xFFFFFFBFU, 0x40000100U, 0xFBFFFEFFU, 0x00000000U,
        0x04000000U, 0x00100000U, 0x00000000U, 0x04100001U, 0xFFEFFFFFU,
        0x00440000U, 0xFFEFFFFFU, 0x00000000U, 0x00400000U, 0x01000000U,
        0x01000000U, 0x00401000U, 0xFFFFFFFFU, 0x00004000U, 0xFEFFFFFFU,
        0x00000400U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00010400U,
        0xFFFFFBFFU, 0x00000014U, 0xFFFFFFBFU, 0x00000000U, 0x00000000U,
        0x00000000U, 0x00000000U, 0x10000100U, 0xFFFFFFFFU, 0x40000000U,
        0xFBFFFFFFU, 0x00000000U, 0x04000000U, 0x00100000U, 0x00000000U,
        0x00100001U, 0xFFEFFFFFU, 0x00440000U, 0xFFAFFFFFU, 0x00000000U,
        0x00400000U, 0x01000000U, 0x01000000U, 0x01401000U, 0xFFFFFFFFU,
        0x00004000U, 0xFEFFFFFFU, 0x00000400U, 0x00000400U, 0x00000010U,
        0x00000000U, 0x00010400U, 0xFFFFFBFFU, 0x00000014U, 0xFFFFFFAFU,
        0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x10000140U,
        0xFFFFFEFFU, 0x44000000U, 0xFFFFFFFFU, 0x00000000U, 0x04000000U,
        0x00100000U, 0x00100000U, 0x00000001U, 0xFFEFFFFFU, 0x00440000U,
        0xFFAFFFFFU, 0x00400000U, 0x00000000U, 0x00000000U, 0x01000000U,
        0x01401000U, 0xFFBFFFFFU, 0x01004000U, 0xFFFFFBFFU, 0x00000400U,
        0x00000400U, 0x00000010U, 0x00000000U, 0x00010010U, 0xFFFFFBFFU
    };
    int index;
    printf("\n\t.align\t4\n");
    printf("\t.type\t%s, %%object\n", name);
    printf("%s:\n", name);
    for (index = 0; index < 160; ++index) {
        printf("\t.word\t0x%08lx\n",
               (unsigned long)(skinny_fixsliced_rc[index]));
    }
    printf("\t.size\t%s, .-%s\n", name, name);
}

int main(int argc, char *argv[])
{
    const char *prefix = "skinny_plus";
    const char *variant_name;

    /* Determine which variant to generate */
    if (argc < 2) {
        fprintf(stderr, "Usage: %s (full|small|tiny) [plus]\n",
                argv[0]);
        return 1;
    }
    if (!strcmp(argv[1], "full")) {
        variant = SKINNY128_VARIANT_FULL;
        variant_name = "SKINNY_PLUS_VARIANT_FULL";
    } else if (!strcmp(argv[1], "small")) {
        variant = SKINNY128_VARIANT_SMALL;
        variant_name = "SKINNY_PLUS_VARIANT_SMALL";
    } else {
        variant = SKINNY128_VARIANT_TINY;
        variant_name = "SKINNY_PLUS_VARIANT_TINY";
    }
    if (argc > 2 && !strcmp(argv[2], "plus")) {
        round_count = 40;
    }

    /* Output the file header */
    printf("#if defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7\n");
    fputs(copyright_message, stdout);
    printf("#include \"internal-skinny-plus-config.h\"\n");
    printf("#if SKINNY_PLUS_VARIANT == %s\n", variant_name);
    printf("\t.syntax unified\n");
    printf("\t.thumb\n");
    printf("\t.text\n");

#if 0 /* Not used any more */
    /* Output the SKINNY-128-384+ key setup function */
    function_header(prefix, "init");
    if (variant == SKINNY128_VARIANT_TINY)
        gen_skinny_128_384_init_tiny(0);
    else if (variant == SKINNY128_VARIANT_FULL)
        gen_skinny_128_384_init_full(0);
    else
        gen_skinny_128_384_init_standard(0);
    function_footer(prefix, "init");
#endif

    /* Output the SKINNY-128-384+ key setup function with TK2/TK3 only */
    function_header(prefix, "init_without_tk1");
    if (variant == SKINNY128_VARIANT_TINY)
        gen_skinny_128_384_init_tiny(1);
    else if (variant == SKINNY128_VARIANT_FULL)
        gen_skinny_128_384_init_full(1);
    else
        gen_skinny_128_384_init_standard(1);
    function_footer(prefix, "init_without_tk1");

    /* Output the round constant table for full fixsliced version */
    if (variant == SKINNY128_VARIANT_FULL)
        gen_fixsliced_rc("rconst");

    /* Output the primary SKINNY-128-384+ encryption function */
    function_header(prefix, "encrypt");
    if (variant == SKINNY128_VARIANT_TINY)
        gen_skinny_128_384_encrypt_full();
    else if (variant == SKINNY128_VARIANT_FULL)
        gen_skinny_128_384_encrypt_fixsliced();
    else
        gen_skinny_128_384_encrypt_standard();
    function_footer(prefix, "encrypt");

    /* Output the TK2 SKINNY-128-384+ encryption function */
    if (0 && variant != SKINNY128_VARIANT_TINY) { /* Not used any more */
        function_header(prefix, "encrypt_tk2");
        gen_skinny_128_384_encrypt_tk2();
        function_footer(prefix, "encrypt_tk2");
    }

    /* Output the TK-FULL SKINNY-128-384+ encryption function for the
     * "small" and "tiny" variants.  Not needed for "full" because
     * romulus-hash.c uses skinny_plus_encrypt() instead. */
    if (variant == SKINNY128_VARIANT_SMALL) {
        function_header(prefix, "encrypt_tk_full");
        gen_skinny_128_384_encrypt_full();
        function_footer(prefix, "encrypt_tk_full");
    } else if (variant == SKINNY128_VARIANT_TINY) {
        /* In the tiny variant, encrypt_tk_full() is the same as encrypt() */
        printf("\t.global\t%s_encrypt_tk_full\n", prefix);
        printf("\t.set\t%s_encrypt_tk_full,%s_encrypt\n", prefix, prefix);
    }

    /* Output the file footer */
    printf("\n");
    printf("#endif\n");
    printf("#endif\n");
    return 0;
}
