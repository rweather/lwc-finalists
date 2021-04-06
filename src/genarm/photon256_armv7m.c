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
 * PHOTON-256 permutation for ARM v7m microprocessors.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Round constants for PHOTON-256 prior to being split into slices */
static uint32_t const RC[12] = {
    0x96d2f0e1, 0xb4f0d2c3, 0xf0b49687, 0x692d0f1e,
    0x5a1e3c2d, 0x3c785a4b, 0xe1a58796, 0x4b0f2d3c,
    0x1e5a7869, 0xa5e1c3d2, 0xd296b4a5, 0x2d694b5a
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
    const char *s0;
    const char *s1;
    const char *s2;
    const char *s3;
    const char *t0;
    const char *t1;
    const char *t2;
    const char *t3;
    const char *t4;
    const char *t5;
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

/* Perform a bit permutation step */
static void bit_permute_step
    (const reg_names *regs, const char *y, uint32_t mask, int shift)
{
    /* t = ((y >> shift) ^ y) & mask */
    printf("\teor\t%s, %s, %s, lsr #%d\n", regs->t4, y, y, shift);
    if (is_op2_constant(mask)) {
        printf("\tand\t%s, %s, #%lu\n", regs->t4, regs->t4,
               (unsigned long)mask);
    } else {
        loadimm(regs->t5, mask);
        printf("\tand\t%s, %s, %s\n", regs->t4, regs->t4, regs->t5);
    }

    /* y = (y ^ t) ^ (t << shift) */
    printf("\teor\t%s, %s, %s\n", y, y, regs->t4);
    printf("\teor\t%s, %s, %s, lsl #%d\n", y, y, regs->t4, shift);
}

/* Converts a 32-bit word into bit-sliced form */
static void photon256_to_sliced_word(const reg_names *regs, const char *x)
{
    bit_permute_step(regs, x, 0x0a0a0a0a, 3);
    bit_permute_step(regs, x, 0x00cc00cc, 6);
    bit_permute_step(regs, x, 0x0000f0f0, 12);
    bit_permute_step(regs, x, 0x0000ff00, 8);
}

/* Converts a 32-bit word from bit-sliced form */
static void photon256_from_sliced_word(const reg_names *regs, const char *x)
{
    bit_permute_step(regs, x, 0x00aa00aa, 7);
    bit_permute_step(regs, x, 0x0000cccc, 14);
    bit_permute_step(regs, x, 0x00f000f0, 4);
    bit_permute_step(regs, x, 0x0000ff00, 8);
}

/* Loads half of the input state and converts into bit-sliced form */
static void photon256_to_sliced_half(const reg_names *regs, int offset)
{
    printf("\tldr\t%s, [r0, #%d]\n", regs->t0, offset);
    printf("\tldr\t%s, [r0, #%d]\n", regs->t1, offset + 4);
    printf("\tldr\t%s, [r0, #%d]\n", regs->t2, offset + 8);
    printf("\tldr\t%s, [r0, #%d]\n", regs->t3, offset + 12);

    photon256_to_sliced_word(regs, regs->t0);
    photon256_to_sliced_word(regs, regs->t1);
    photon256_to_sliced_word(regs, regs->t2);
    photon256_to_sliced_word(regs, regs->t3);

    printf("\tuxtb\t%s, %s\n", regs->s0, regs->t0);
    printf("\tuxtb\t%s, %s, ror #8\n", regs->s1, regs->t0);
    printf("\tuxtb\t%s, %s, ror #16\n", regs->s2, regs->t0);
    printf("\tuxtb\t%s, %s, ror #24\n", regs->s3, regs->t0);

    printf("\tbfi\t%s, %s, #8, #8\n", regs->s0, regs->t1);
    printf("\tbfi\t%s, %s, #16, #8\n", regs->s0, regs->t2);
    printf("\tbfi\t%s, %s, #24, #8\n", regs->s0, regs->t3);

    printf("\tlsr\t%s, %s, #8\n", regs->t1, regs->t1);
    printf("\tlsr\t%s, %s, #8\n", regs->t2, regs->t2);
    printf("\tlsr\t%s, %s, #8\n", regs->t3, regs->t3);

    printf("\tbfi\t%s, %s, #8, #8\n", regs->s1, regs->t1);
    printf("\tbfi\t%s, %s, #16, #8\n", regs->s1, regs->t2);
    printf("\tbfi\t%s, %s, #24, #8\n", regs->s1, regs->t3);

    printf("\tlsr\t%s, %s, #8\n", regs->t1, regs->t1);
    printf("\tlsr\t%s, %s, #8\n", regs->t2, regs->t2);
    printf("\tlsr\t%s, %s, #8\n", regs->t3, regs->t3);

    printf("\tbfi\t%s, %s, #8, #8\n", regs->s2, regs->t1);
    printf("\tbfi\t%s, %s, #16, #8\n", regs->s2, regs->t2);
    printf("\tbfi\t%s, %s, #24, #8\n", regs->s2, regs->t3);

    printf("\tlsr\t%s, %s, #8\n", regs->t1, regs->t1);
    printf("\tlsr\t%s, %s, #8\n", regs->t2, regs->t2);
    printf("\tlsr\t%s, %s, #8\n", regs->t3, regs->t3);

    printf("\tbfi\t%s, %s, #8, #8\n", regs->s3, regs->t1);
    printf("\tbfi\t%s, %s, #16, #8\n", regs->s3, regs->t2);
    printf("\tbfi\t%s, %s, #24, #8\n", regs->s3, regs->t3);
}

/* Store half of the output state and converts from bit-sliced form */
static void photon256_from_sliced_half(const reg_names *regs, int offset)
{
    printf("\tuxtb\t%s, %s\n", regs->t0, regs->s0);
    printf("\tuxtb\t%s, %s, ror #8\n", regs->t1, regs->s0);
    printf("\tuxtb\t%s, %s, ror #16\n", regs->t2, regs->s0);
    printf("\tuxtb\t%s, %s, ror #24\n", regs->t3, regs->s0);

    printf("\tbfi\t%s, %s, #8, #8\n", regs->t0, regs->s1);
    printf("\tbfi\t%s, %s, #16, #8\n", regs->t0, regs->s2);
    printf("\tbfi\t%s, %s, #24, #8\n", regs->t0, regs->s3);

    printf("\tlsr\t%s, %s, #8\n", regs->s1, regs->s1);
    printf("\tlsr\t%s, %s, #8\n", regs->s2, regs->s2);
    printf("\tlsr\t%s, %s, #8\n", regs->s3, regs->s3);

    printf("\tbfi\t%s, %s, #8, #8\n", regs->t1, regs->s1);
    printf("\tbfi\t%s, %s, #16, #8\n", regs->t1, regs->s2);
    printf("\tbfi\t%s, %s, #24, #8\n", regs->t1, regs->s3);

    printf("\tlsr\t%s, %s, #8\n", regs->s1, regs->s1);
    printf("\tlsr\t%s, %s, #8\n", regs->s2, regs->s2);
    printf("\tlsr\t%s, %s, #8\n", regs->s3, regs->s3);

    printf("\tbfi\t%s, %s, #8, #8\n", regs->t2, regs->s1);
    printf("\tbfi\t%s, %s, #16, #8\n", regs->t2, regs->s2);
    printf("\tbfi\t%s, %s, #24, #8\n", regs->t2, regs->s3);

    printf("\tlsr\t%s, %s, #8\n", regs->s1, regs->s1);
    printf("\tlsr\t%s, %s, #8\n", regs->s2, regs->s2);
    printf("\tlsr\t%s, %s, #8\n", regs->s3, regs->s3);

    printf("\tbfi\t%s, %s, #8, #8\n", regs->t3, regs->s1);
    printf("\tbfi\t%s, %s, #16, #8\n", regs->t3, regs->s2);
    printf("\tbfi\t%s, %s, #24, #8\n", regs->t3, regs->s3);

    photon256_from_sliced_word(regs, regs->t0);
    photon256_from_sliced_word(regs, regs->t1);
    photon256_from_sliced_word(regs, regs->t2);
    photon256_from_sliced_word(regs, regs->t3);

    printf("\tstr\t%s, [r0, #%d]\n", regs->t0, offset);
    printf("\tstr\t%s, [r0, #%d]\n", regs->t1, offset + 4);
    printf("\tstr\t%s, [r0, #%d]\n", regs->t2, offset + 8);
    printf("\tstr\t%s, [r0, #%d]\n", regs->t3, offset + 12);
}

/* Generate the code for the PHOTON-256 sbox */
static void photon256_sbox(const reg_names *regs)
{
    /* s1 ^= s2; */
    binop("eor", regs->s1, regs->s2);
    /* s3 ^= (s2 & s1); */
    printf("\tand\t%s, %s, %s\n", regs->t0, regs->s2, regs->s1);
    binop("eor", regs->s3, regs->t0);
    /* t1 = s3; */
    binop("mov", regs->t1, regs->s3);
    /* s3 = (s3 & s1) ^ s2; */
    binop("and", regs->s3, regs->s1);
    binop("eor", regs->s3, regs->s2);
    /* t2 = s3; */
    binop("mov", regs->t2, regs->s3);
    /* s3 ^= s0; */
    binop("eor", regs->s3, regs->s0);
    /* s3 = ~(s3); */
    binop("mvn", regs->s3, regs->s3);
    /* s2 = s3; */
    binop("mov", regs->s2, regs->s3);
    /* t2 |= s0; */
    binop("orr", regs->t2, regs->s0);
    /* s0 ^= t1; */
    binop("eor", regs->s0, regs->t1);
    /* s1 ^= s0; */
    binop("eor", regs->s1, regs->s0);
    /* s2 |= s1; */
    binop("orr", regs->s2, regs->s1);
    /* s2 ^= t1; */
    binop("eor", regs->s2, regs->t1);
    /* s1 ^= t2; */
    binop("eor", regs->s1, regs->t2);
    /* s3 ^= s1; */
    binop("eor", regs->s3, regs->s1);
}

/* Permute the top half of the state to rotate the rows left by 0..3 bits */
static void photon256_top_perm(const reg_names *regs, const char *x)
{
    bit_permute_step(regs, x, 0x07030100, 4);
    bit_permute_step(regs, x, 0x22331100, 2);
    bit_permute_step(regs, x, 0x55005500, 1);
}

/* Permute the bottom half of the state to rotate the rows left by 4..7 bits */
static void photon256_bottom_perm(const reg_names *regs, const char *x)
{
    bit_permute_step(regs, x, 0x080c0e0f, 4);
    bit_permute_step(regs, x, 0x22331100, 2);
    bit_permute_step(regs, x, 0x55005500, 1);
}

/* Load a row from the local stack space */
static void photon256_load_row
    (const reg_names *regs, const char *dest, int offset)
{
    printf("\tldrb\t%s, [fp, #%d]\n", dest, offset);
    printf("\tldrb\t%s, [fp, #%d]\n", regs->t4, offset + 4);
    printf("\tldrb\t%s, [fp, #%d]\n", regs->t5, offset + 8);
    printf("\torr\t%s, %s, %s, lsl #8\n", dest, dest, regs->t4);
    printf("\tldrb\t%s, [fp, #%d]\n", regs->t4, offset + 12);
    printf("\torr\t%s, %s, %s, lsl #16\n", dest, dest, regs->t5);
    printf("\torr\t%s, %s, %s, lsl #24\n", dest, dest, regs->t4);
}

/* Load the left half of the state in row-major order from locals */
static void photon256_load_left(const reg_names *regs, int stack_base)
{
    photon256_load_row(regs, regs->s0, stack_base);
    photon256_load_row(regs, regs->s1, stack_base + 1);
    photon256_load_row(regs, regs->s2, stack_base + 2);
    photon256_load_row(regs, regs->s3, stack_base + 3);
}

/* Load the right half of the state in row-major order from locals */
static void photon256_load_right(const reg_names *regs, int stack_base)
{
    photon256_load_row(regs, regs->s0, stack_base + 16);
    photon256_load_row(regs, regs->s1, stack_base + 17);
    photon256_load_row(regs, regs->s2, stack_base + 18);
    photon256_load_row(regs, regs->s3, stack_base + 19);
}

/* Store a row to the state */
static void photon256_store_row
    (const reg_names *regs, const char *src, int offset)
{
    printf("\tstrb\t%s, [r0, #%d]\n", src, offset);
    printf("\tlsr\t%s, %s, #8\n", regs->t4, src);
    printf("\tlsr\t%s, %s, #16\n", regs->t5, src);
    printf("\tstrb\t%s, [r0, #%d]\n", regs->t4, offset + 4);
    printf("\tstrb\t%s, [r0, #%d]\n", regs->t5, offset + 8);
    printf("\tlsr\t%s, %s, #24\n", regs->t4, src);
    printf("\tstrb\t%s, [r0, #%d]\n", regs->t4, offset + 12);
}

/* Store the left half of the state in row-major order to the state */
static void photon256_store_left(const reg_names *regs)
{
    photon256_store_row(regs, regs->t0, 0);
    photon256_store_row(regs, regs->t1, 1);
    photon256_store_row(regs, regs->t2, 2);
    photon256_store_row(regs, regs->t3, 3);
}

/* Store the right half of the state in row-major order to the state */
static void photon256_store_right(const reg_names *regs)
{
    photon256_store_row(regs, regs->t0, 16);
    photon256_store_row(regs, regs->t1, 17);
    photon256_store_row(regs, regs->t2, 18);
    photon256_store_row(regs, regs->t3, 19);
}

/* Perform a single field multiplication for PHOTON-256 */
static void photon256_field_multiply
    (const reg_names *regs, const char *out, const char *in, int a, int xor_in)
{
    int bit;
    int loaded = 0;
    for (bit = 0; bit < 4; ++bit) {
        if (a & 1) {
            if (loaded) {
                if (xor_in)
                    binop("eor", out, regs->t4);
                else
                    binop("mov", out, regs->t4);
            } else {
                if (xor_in)
                    binop("eor", out, in);
                else
                    binop("mov", out, in);
            }
            xor_in = 1;
        }
        a >>= 1;
        if (!a)
            break;
        if (!loaded) {
            printf("\teor\t%s, %s, %s, lsr #24\n", regs->t4, in, in);
            printf("\tror\t%s, %s, #24\n", regs->t4, regs->t4);
            loaded = 1;
        } else {
            printf("\teor\t%s, %s, %s, lsr #24\n",
                   regs->t4, regs->t4, regs->t4);
            printf("\tror\t%s, %s, #24\n", regs->t4, regs->t4);
        }
    }
}

/* Mix 4 columns together using PHOTON-256 field multiplication */
static void photon256_mix_columns
    (const reg_names *regs, const char *out,
     int a0, int a1, int a2, int a3, int xor_in)
{
    photon256_field_multiply(regs, out, regs->s0, a0, xor_in);
    photon256_field_multiply(regs, out, regs->s1, a1, 1);
    photon256_field_multiply(regs, out, regs->s2, a2, 1);
    photon256_field_multiply(regs, out, regs->s3, a3, 1);
}

/* Generate the body of the PHOTON-256 permutation function */
static void gen_photon256_permute(void)
{
    /*
     * r0 holds the pointer to the PHOTON-256 state on entry and exit.
     *
     * r0, r1, r2, r3, and ip can be used as scratch registers without saving,
     * but the value of ip may not survive across a branch instruction.
     *
     * r4, r5, r6, r7, r8, r9, r10, fp, and lr must be callee-saved.
     */
    int stack_base;
    reg_names regs;
    regs.s0 = "r2";
    regs.s1 = "r3";
    regs.s2 = "r4";
    regs.s3 = "r5";
    regs.t0 = "r6";
    regs.t1 = "r7";
    regs.t2 = "r8";
    regs.t3 = "r9";
    regs.t4 = "ip";
    regs.t5 = "lr";
    regs.rc = "r10";
    regs.round = "r1";

    /* Save callee-preserved registers on the stack */
    printf("\tpush\t{r4, r5, r6, r7, r8, r9, r10, fp, lr}\n");

    /* Need 32 bytes of local stack space to hold the state temporarily
     * when peforming the mix columns operation.  Need another 16 bytes
     * to spill some of the temporary variables during the mix. */
    printf("\tmov\tfp, sp\n");
    printf("\tsub\tsp, sp, #48\n");
    stack_base = -48;

    /* Convert the state into bit-sliced form in-place.  The top half of
     * the state ends up in s0...s3 with the bottom half left in memory */
    photon256_to_sliced_half(&regs, 16);
    printf("\tstr\t%s, [r0, #16]\n", regs.s0);
    printf("\tstr\t%s, [r0, #20]\n", regs.s1);
    printf("\tstr\t%s, [r0, #24]\n", regs.s2);
    printf("\tstr\t%s, [r0, #28]\n", regs.s3);
    photon256_to_sliced_half(&regs, 0);

    /* Top of the round loop */
    printf("\tadr\t%s, rconst\n", regs.rc);
    loadimm(regs.round, 12);
    printf(".L1:\n");

    /* Apply the round constants to the top half of the state */
    printf("\tldr\t%s, [%s], #4\n", regs.t0, regs.rc);
    printf("\tldr\t%s, [%s], #4\n", regs.t1, regs.rc);
    printf("\tldr\t%s, [%s], #4\n", regs.t2, regs.rc);
    printf("\tldr\t%s, [%s], #4\n", regs.t3, regs.rc);
    binop("eor", regs.s0, regs.t0);
    binop("eor", regs.s1, regs.t1);
    binop("eor", regs.s2, regs.t2);
    binop("eor", regs.s3, regs.t3);

    /* Apply the sbox to the top half of the state */
    photon256_sbox(&regs);

    /* Rotate the rows of the top half by 0..3 bit positions and store */
    photon256_top_perm(&regs, regs.s0);
    photon256_top_perm(&regs, regs.s1);
    photon256_top_perm(&regs, regs.s2);
    photon256_top_perm(&regs, regs.s3);
    printf("\tstr\t%s, [fp, #%d]\n", regs.s0, stack_base + 0);
    printf("\tstr\t%s, [fp, #%d]\n", regs.s1, stack_base + 4);
    printf("\tstr\t%s, [fp, #%d]\n", regs.s2, stack_base + 8);
    printf("\tstr\t%s, [fp, #%d]\n", regs.s3, stack_base + 12);

    /* Load the bottom half of the state */
    printf("\tldr\t%s, [r0, #16]\n", regs.s0);
    printf("\tldr\t%s, [r0, #20]\n", regs.s1);
    printf("\tldr\t%s, [r0, #24]\n", regs.s2);
    printf("\tldr\t%s, [r0, #28]\n", regs.s3);

    /* Apply the round constants to the bottom half of the state */
    printf("\tldr\t%s, [%s], #4\n", regs.t0, regs.rc);
    printf("\tldr\t%s, [%s], #4\n", regs.t1, regs.rc);
    printf("\tldr\t%s, [%s], #4\n", regs.t2, regs.rc);
    printf("\tldr\t%s, [%s], #4\n", regs.t3, regs.rc);
    binop("eor", regs.s0, regs.t0);
    binop("eor", regs.s1, regs.t1);
    binop("eor", regs.s2, regs.t2);
    binop("eor", regs.s3, regs.t3);

    /* Apply the sbox to the bottom half of the state */
    photon256_sbox(&regs);

    /* Rotate the rows of the bottom half by 4..7 bit positions and store */
    photon256_bottom_perm(&regs, regs.s0);
    photon256_bottom_perm(&regs, regs.s1);
    photon256_bottom_perm(&regs, regs.s2);
    photon256_bottom_perm(&regs, regs.s3);
    printf("\tstr\t%s, [fp, #%d]\n", regs.s0, stack_base + 16);
    printf("\tstr\t%s, [fp, #%d]\n", regs.s1, stack_base + 20);
    printf("\tstr\t%s, [fp, #%d]\n", regs.s2, stack_base + 24);
    printf("\tstr\t%s, [fp, #%d]\n", regs.s3, stack_base + 28);

    /* Mixing the columns; process the left half of the state */
    photon256_load_left(&regs, stack_base);
    photon256_mix_columns(&regs, regs.t0, 0x02, 0x04, 0x02, 0x0b, 0);
    photon256_mix_columns(&regs, regs.t1, 0x0c, 0x09, 0x08, 0x0d, 0);
    photon256_mix_columns(&regs, regs.t2, 0x04, 0x04, 0x0d, 0x0d, 0);
    photon256_mix_columns(&regs, regs.t3, 0x01, 0x06, 0x05, 0x01, 0);
    printf("\tstr\t%s, [fp, #%d]\n", regs.t0, stack_base + 32);
    printf("\tstr\t%s, [fp, #%d]\n", regs.t1, stack_base + 36);
    printf("\tstr\t%s, [fp, #%d]\n", regs.t2, stack_base + 40);
    printf("\tstr\t%s, [fp, #%d]\n", regs.t3, stack_base + 44);
    photon256_mix_columns(&regs, regs.t0, 0x0f, 0x0c, 0x09, 0x0d, 0);
    photon256_mix_columns(&regs, regs.t1, 0x09, 0x0e, 0x05, 0x0f, 0);
    photon256_mix_columns(&regs, regs.t2, 0x0c, 0x02, 0x02, 0x0a, 0);
    photon256_mix_columns(&regs, regs.t3, 0x0f, 0x01, 0x0d, 0x0a, 0);

    /* Mixing the columns; process the right half of the state */
    photon256_load_right(&regs, stack_base);
    photon256_mix_columns(&regs, regs.t0, 0x0e, 0x05, 0x0e, 0x0d, 1);
    photon256_mix_columns(&regs, regs.t1, 0x04, 0x0c, 0x09, 0x06, 1);
    photon256_mix_columns(&regs, regs.t2, 0x03, 0x01, 0x01, 0x0e, 1);
    photon256_mix_columns(&regs, regs.t3, 0x05, 0x0a, 0x02, 0x03, 1);
    photon256_store_right(&regs);
    printf("\tldr\t%s, [fp, #%d]\n", regs.t0, stack_base + 32);
    printf("\tldr\t%s, [fp, #%d]\n", regs.t1, stack_base + 36);
    printf("\tldr\t%s, [fp, #%d]\n", regs.t2, stack_base + 40);
    printf("\tldr\t%s, [fp, #%d]\n", regs.t3, stack_base + 44);
    photon256_mix_columns(&regs, regs.t0, 0x02, 0x08, 0x05, 0x06, 1);
    photon256_mix_columns(&regs, regs.t1, 0x07, 0x07, 0x05, 0x02, 1);
    photon256_mix_columns(&regs, regs.t2, 0x09, 0x04, 0x0d, 0x09, 1);
    photon256_mix_columns(&regs, regs.t3, 0x0c, 0x0d, 0x0f, 0x0e, 1);
    photon256_store_left(&regs);

    /* Reload the top half of the state for the next round */
    printf("\tldr\t%s, [r0, #0]\n", regs.s0);
    printf("\tldr\t%s, [r0, #4]\n", regs.s1);
    printf("\tldr\t%s, [r0, #8]\n", regs.s2);
    printf("\tldr\t%s, [r0, #12]\n", regs.s3);

    /* Bottom of the round loop */
    printf("\tsubs\t%s, %s, #1\n", regs.round, regs.round);
    printf("\tbne\t.L1\n");

    /* Convert the state from bit-sliced form back into regular form */
    photon256_from_sliced_half(&regs, 0);
    printf("\tldr\t%s, [r0, #16]\n", regs.s0);
    printf("\tldr\t%s, [r0, #20]\n", regs.s1);
    printf("\tldr\t%s, [r0, #24]\n", regs.s2);
    printf("\tldr\t%s, [r0, #28]\n", regs.s3);
    photon256_from_sliced_half(&regs, 16);

    /* Pop the stack frame and return */
    printf("\tmov\tsp, fp\n");
    printf("\tpop\t{r4, r5, r6, r7, r8, r9, r10, fp, pc}\n");
}

/* Generates the round constant table for PHOTON-256 */
static void gen_photon256_rc(const char *name)
{
    int index, bit;
    printf("\n\t.align\t4\n");
    printf("\t.type\t%s, %%object\n", name);
    printf("%s:\n", name);
    for (index = 0; index < 12; ++index) {
        for (bit = 0; bit < 8; ++bit) {
            unsigned long rc = (RC[index] >> bit) & 0x01010101U;
            printf("\t.word\t0x%08lx\n", rc);
        }
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

    /* Output the round constant table */
    gen_photon256_rc("rconst");

    /* Output the PHOTON-256 permutation function */
    function_header("photon256_permute");
    gen_photon256_permute();
    function_footer("photon256_permute");

    /* Output the file footer */
    printf("\n");
    printf("#endif\n");
    return 0;
}
