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
static void gen_skinny_128_384_init_tiny(void)
{
    /*
     * r0 holds the pointer to the output key schedule.
     * r1 points to the input key.
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

    /* Copy the 48 bytes of the tweakey directly to the key schedule */
    for (index = 0; index < 48; index += 8) {
        printf("\tldr\t%s, [r1, #%d]\n", regs.t1, index);
        printf("\tldr\t%s, [r1, #%d]\n", regs.t2, index + 4);
        printf("\tstr\t%s, [r0, #%d]\n", regs.t1, index);
        printf("\tstr\t%s, [r0, #%d]\n", regs.t2, index + 4);
    }

    printf("\tbx\tlr\n");
}

/* Generate the key setup function for the standard version */
static void gen_skinny_128_384_init_standard(void)
{
    /*
     * r0 holds the pointer to the output key schedule.
     * r1 points to the input key.
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
    regs.tk2[0] = "r2";
    regs.tk2[1] = "r3";
    regs.tk2[2] = "r4";
    regs.tk2[3] = "r5";
    regs.tk3[0] = "r6";
    regs.tk3[1] = "r7";
    regs.tk3[2] = "r8";
    regs.tk3[3] = "r9";
    regs.t1 = "r10";
    regs.t2 = "ip";
    regs.t3 = "lr";

    /* Save callee-preserved registers on the stack */
    printf("\tpush\t{r4, r5, r6, r7, r8, r9, r10, lr}\n");

    /* Copy the value of TK1 directly to the key schedule */
    printf("\tldr\t%s, [r1, #0]\n", regs.t1);
    printf("\tldr\t%s, [r1, #4]\n", regs.t2);
    printf("\tstr\t%s, [r0, #0]\n", regs.t1);
    printf("\tstr\t%s, [r0, #4]\n", regs.t2);
    printf("\tldr\t%s, [r1, #8]\n", regs.t1);
    printf("\tldr\t%s, [r1, #12]\n", regs.t2);
    printf("\tstr\t%s, [r0, #8]\n", regs.t1);
    printf("\tstr\t%s, [r0, #12]\n", regs.t2);

    /* Load the initial values of TK2 and TK3 into registers */
    printf("\tldr\t%s, [r1, #16]\n", regs.tk2[0]);
    printf("\tldr\t%s, [r1, #20]\n", regs.tk2[1]);
    printf("\tldr\t%s, [r1, #24]\n", regs.tk2[2]);
    printf("\tldr\t%s, [r1, #28]\n", regs.tk2[3]);
    printf("\tldr\t%s, [r1, #32]\n", regs.tk3[0]);
    printf("\tldr\t%s, [r1, #36]\n", regs.tk3[1]);
    printf("\tldr\t%s, [r1, #40]\n", regs.tk3[2]);
    printf("\tldr\t%s, [r1, #44]\n", regs.tk3[3]);

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
    printf("#include \"internal-skinny-plus-config.h\"\n");
    printf("#if SKINNY_PLUS_VARIANT == %s\n", variant_name);
    printf("\t.syntax unified\n");
    printf("\t.thumb\n");
    printf("\t.text\n");

    /* Output the SKINNY-128-384+ key setup function */
    function_header(prefix, "init");
    if (variant == SKINNY128_VARIANT_TINY)
        gen_skinny_128_384_init_tiny();
    else
        gen_skinny_128_384_init_standard();
    function_footer(prefix, "init");

    /* Output the primary SKINNY-128-384+ encryption function */
    function_header(prefix, "encrypt");
    if (variant == SKINNY128_VARIANT_TINY)
        gen_skinny_128_384_encrypt_full();
    else
        gen_skinny_128_384_encrypt_standard();
    function_footer(prefix, "encrypt");

    /* Output the TK2 SKINNY-128-384+ encryption function */
    if (variant != SKINNY128_VARIANT_TINY) {
        function_header(prefix, "encrypt_tk2");
        gen_skinny_128_384_encrypt_tk2();
        function_footer(prefix, "encrypt_tk2");
    }

    /* Output the TK-FULL SKINNY-128-384+ encryption function */
    if (variant != SKINNY128_VARIANT_TINY) {
        function_header(prefix, "encrypt_tk_full");
        gen_skinny_128_384_encrypt_full();
        function_footer(prefix, "encrypt_tk_full");
    } else {
        /* In this variant, encrypt_tk_full() is the same as encrypt() */
        printf("\t.global\t%s_encrypt_tk_full\n", prefix);
        printf("\t.set\t%s_encrypt_tk_full,%s_encrypt\n", prefix, prefix);
    }

    /* Output the file footer */
    printf("\n");
    printf("#endif\n");
    printf("#endif\n");
    return 0;
}
