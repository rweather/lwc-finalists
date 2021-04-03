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
 * Keccak-p[200] permutation for ARM v7m microprocessors.
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
    const char *r0_l;
    const char *r0_r;
    const char *r1_l;
    const char *r1_r;
    const char *r2_l;
    const char *r2_r;
    const char *r3_l;
    const char *r3_r;
    const char *r4_l;
    const char *r4_r;
    const char *C_l;
    const char *C_r;
    const char *t1;
    const char *t2;

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

/* Generates a "bic" instruction: dest = src1 & ~src2 */
static void bic(const char *dest, const char *src1, const char *src2)
{
    if (!strcmp(dest, src1) && is_low_reg(src1) && is_low_reg(src2))
        printf("\tbics\t%s, %s\n", src1, src2);
    else
        printf("\tbic\t%s, %s, %s\n", dest, src1, src2);
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

/* Generate the round constant table for Keccak-p[200] */
static void gen_keccakp_200_rc(void)
{
    static unsigned char const rc[18] = {
        0x01, 0x82, 0x8A, 0x00, 0x8B, 0x01, 0x81, 0x09,
        0x8A, 0x88, 0x09, 0x0A, 0x8B, 0x8B, 0x89, 0x03,
        0x02, 0x80
    };
    const char *name = "rconst";
    int index;
    printf("\n\t.align\t2\n");
    printf("\t.type\t%s, %%object\n", name);
    printf("%s:\n", name);
    for (index = 0; index < 18; ++index)
        printf("\t.byte\t0x%02x\n", rc[index]);
    printf("\t.size\t%s, .-%s\n", name, name);

}

/* Generate the code for step mappings rho and pi */
static void rho_pi
    (const reg_names *regs, const char *dest, int destcol,
     const char *src, int srccol, int rot)
{
    destcol = (destcol & 3) * 8;
    srccol = (srccol & 3) * 8;
    if (rot == 0) {
        if (srccol != 0) {
            printf("\tlsr\t%s, %s, #%d\n", regs->t2, src, srccol);
            printf("\tbfi\t%s, %s, #%d, #8\n", dest, regs->t2, destcol);
        } else {
            printf("\tbfi\t%s, %s, #%d, #8\n", dest, src, destcol);
        }
    } else {
        if (srccol != 0) {
            printf("\tlsr\t%s, %s, #%d\n", regs->t2, src, srccol + 8 - rot);
            printf("\tlsr\t%s, %s, #%d\n", regs->C_l, src, srccol);
            printf("\tbfi\t%s, %s, #%d, #%d\n", dest, regs->t2, destcol, rot);
            printf("\tbfi\t%s, %s, #%d, #%d\n", dest, regs->C_l, destcol + rot, 8 - rot);
        } else {
            printf("\tlsr\t%s, %s, #%d\n", regs->t2, src, 8 - rot);
            printf("\tbfi\t%s, %s, #%d, #%d\n", dest, src, destcol + rot, 8 - rot);
            printf("\tbfi\t%s, %s, #%d, #%d\n", dest, regs->t2, destcol, rot);
        }
    }
}

/* Generate the code for step mapping chi */
static void chi(const reg_names *regs, const char *rl, const char *rr)
{
    /* C_l = (~((rl >> 8) | (rr << 24))) &
     *     ((rl >> 16) | (rl << 24) | (rr << 16));
     * C_r = ((~rl) & (rl >> 8)) & 0xFF;
     * rl ^= C_l;
     * rr ^= C_r; */
    printf("\tlsr\t%s, %s, #8\n", regs->t2, rl);
    printf("\tlsr\t%s, %s, #16\n", regs->C_l, rl);
    printf("\torr\t%s, %s, %s, lsl #24\n", regs->t2, regs->t2, rr);
    printf("\torr\t%s, %s, %s, lsl #24\n", regs->C_l, regs->C_l, rl);
    printf("\tlsr\t%s, %s, #8\n", regs->C_r, rl);
    printf("\torr\t%s, %s, %s, lsl #16\n", regs->C_l, regs->C_l, rr);
    bic(regs->C_r, regs->C_r, rl);
    bic(regs->C_l, regs->C_l, regs->t2);
    printf("\tubfx\t%s, %s, #0, #8\n", regs->C_r, regs->C_r);
    binop("eor", rl, regs->C_l);
    binop("eor", rr, regs->C_r);
}

/* Generate the body of the Keccak-p[200] permutation function */
static void gen_keccakp_200_permute(void)
{
    /*
     * This implementation is inspired by:
     * https://github.com/XKCP/XKCP/blob/master/lib/low/KeccakP-200/ARM/KeccakP-200-armv7m-le-gcc.s
     */
    /*
     * r0 holds the pointer to the Keccak-p[200] state on entry and exit.
     *
     * r0, r1, r2, r3, and ip can be used as scratch registers without saving,
     * but the value of ip may not survive across a branch instruction.
     *
     * r4, r5, r6, r7, r8, r9, r10, fp, and lr must be callee-saved.
     */
    reg_names regs;
    regs.r0_l = "r1";
    regs.r1_l = "r2";
    regs.r2_l = "r3";
    regs.r3_l = "r4";
    regs.r4_l = "r5";
    regs.r0_r = "r6";
    regs.r1_r = "r7";
    regs.r2_r = "r8";
    regs.r3_r = "r9";
    regs.r4_r = "r10";
    regs.C_l = "fp";
    regs.C_r = "lr";
    regs.t1 = "r0";
    regs.t2 = "ip";
    printf("\tpush\t{r4, r5, r6, r7, r8, r9, r10, fp, lr}\n");

    /* Load all bytes of the state into registers */
    printf("\tldr\t%s, [r0, #%d]\n", regs.r0_l, 0);
    printf("\tldr\t%s, [r0, #%d]\n", regs.r1_l, 5);
    printf("\tldr\t%s, [r0, #%d]\n", regs.r2_l, 10);
    printf("\tldr\t%s, [r0, #%d]\n", regs.r3_l, 15);
    printf("\tldr\t%s, [r0, #%d]\n", regs.r4_l, 20);
    printf("\tldrb\t%s, [r0, #%d]\n", regs.r0_r, 4);
    printf("\tldrb\t%s, [r0, #%d]\n", regs.r1_r, 9);
    printf("\tldrb\t%s, [r0, #%d]\n", regs.r2_r, 14);
    printf("\tldrb\t%s, [r0, #%d]\n", regs.r3_r, 19);
    printf("\tldrb\t%s, [r0, #%d]\n", regs.r4_r, 24);
    printf("\tpush\t{r0}\n"); /* Free up r0 for use as an extra temporary */

    /* Top of the round loop */
    loadimm(regs.t1, 0);
    printf(".L1:\n");

    /* Step mapping theta */
    /* C_l = r0_l ^ r1_l ^ r2_l ^ r3_l ^ r4_l; */
    /* C_r = r0_r ^ r1_r ^ r2_r ^ r3_r ^ r4_r; */
    printf("\teor\t%s, %s, %s\n", regs.C_l, regs.r0_l, regs.r1_l);
    printf("\teor\t%s, %s, %s\n", regs.C_r, regs.r0_r, regs.r1_r);
    binop("eor", regs.C_l, regs.r2_l);
    binop("eor", regs.C_r, regs.r2_r);
    binop("eor", regs.C_l, regs.r3_l);
    binop("eor", regs.C_r, regs.r3_r);
    binop("eor", regs.C_l, regs.r4_l);
    binop("eor", regs.C_r, regs.r4_r);
    /* C_r = (((C_l & 0x7F7F7F7FUL) >> 7) | ((C_l & 0x80808080UL) >> 15) |
     *        ((C_r & 0x7FUL) << 25) | ((C_r & 0x80UL) << 17)) ^
     *       ((C_l << 8) | C_r); */
    printf("\tubfx\t%s, %s, #0, #7\n", regs.t2, regs.C_r);
    printf("\teor\t%s, %s, %s, lsl #25\n", regs.C_r, regs.C_r, regs.t2);
    printf("\tand\t%s, %s, #0x80\n", regs.t2, regs.C_r);
    printf("\teor\t%s, %s, %s, lsl #17\n", regs.C_r, regs.C_r, regs.t2);
    printf("\teor\t%s, %s, %s, lsl #8\n", regs.C_r, regs.C_r, regs.C_l);
    printf("\tand\t%s, %s, #0x7F7F7F7F\n", regs.t2, regs.C_l);
    printf("\teor\t%s, %s, %s, lsr #7\n", regs.C_r, regs.C_r, regs.t2);
    printf("\tand\t%s, %s, #0x80808080\n", regs.t2, regs.C_l);
    printf("\teor\t%s, %s, %s, lsr #15\n", regs.C_r, regs.C_r, regs.t2);
    /* C_l = (((C_l & 0x7FL) << 1) | ((C_l & 0x80UL) >> 7)) ^ (C_l >> 24); */
    printf("\tubfx\t%s, %s, #0, #7\n", regs.t2, regs.C_l);
    printf("\teor\t%s, %s, %s, lsl #25\n", regs.C_l, regs.C_l, regs.t2);
    printf("\tubfx\t%s, %s, #7, #1\n", regs.t2, regs.C_l);
    printf("\teor\t%s, %s, %s, lsl #24\n", regs.C_l, regs.C_l, regs.t2);
    printf("\tlsr\t%s, %s, #24\n", regs.C_l, regs.C_l);
    /* r0_l ^= C_r; r1_l ^= C_r; r2_l ^= C_r; r3_l ^= C_r; r4_l ^= C_r; */
    /* r0_r ^= C_l; r1_r ^= C_l; r2_r ^= C_l; r3_r ^= C_l; r4_r ^= C_l; */
    binop("eor", regs.r0_l, regs.C_r);
    binop("eor", regs.r0_r, regs.C_l);
    binop("eor", regs.r1_l, regs.C_r);
    binop("eor", regs.r1_r, regs.C_l);
    binop("eor", regs.r2_l, regs.C_r);
    binop("eor", regs.r2_r, regs.C_l);
    binop("eor", regs.r3_l, regs.C_r);
    binop("eor", regs.r3_r, regs.C_l);
    binop("eor", regs.r4_l, regs.C_r);
    binop("eor", regs.r4_r, regs.C_l);

    /* Step mapping rho and pi combined into a single step.
     * Rotate all lanes by a specific offset and rearrange */
    printf("\tlsr\t%s, %s, #8\n", regs.C_r, regs.r0_l);
    rho_pi(&regs, regs.r0_l, 1, regs.r1_l, 1, 4);
    rho_pi(&regs, regs.r1_l, 1, regs.r1_r, 4, 4);
    rho_pi(&regs, regs.r1_r, 4, regs.r4_l, 2, 5);
    rho_pi(&regs, regs.r4_l, 2, regs.r2_r, 4, 7);
    rho_pi(&regs, regs.r2_r, 4, regs.r4_l, 0, 2);
    rho_pi(&regs, regs.r4_l, 0, regs.r0_l, 2, 6);
    rho_pi(&regs, regs.r0_l, 2, regs.r2_l, 2, 3);
    rho_pi(&regs, regs.r2_l, 2, regs.r2_l, 3, 1);
    rho_pi(&regs, regs.r2_l, 3, regs.r3_r, 4, 0);
    rho_pi(&regs, regs.r3_r, 4, regs.r4_l, 3, 0);
    rho_pi(&regs, regs.r4_l, 3, regs.r3_l, 0, 1);
    rho_pi(&regs, regs.r3_l, 0, regs.r0_r, 4, 3);
    rho_pi(&regs, regs.r0_r, 4, regs.r4_r, 4, 6);
    rho_pi(&regs, regs.r4_r, 4, regs.r4_l, 1, 2);
    rho_pi(&regs, regs.r4_l, 1, regs.r1_l, 3, 7);
    rho_pi(&regs, regs.r1_l, 3, regs.r3_l, 1, 5);
    rho_pi(&regs, regs.r3_l, 1, regs.r1_l, 0, 4);
    rho_pi(&regs, regs.r1_l, 0, regs.r0_l, 3, 4);
    rho_pi(&regs, regs.r0_l, 3, regs.r3_l, 3, 5);
    rho_pi(&regs, regs.r3_l, 3, regs.r3_l, 2, 7);
    rho_pi(&regs, regs.r3_l, 2, regs.r2_l, 1, 2);
    rho_pi(&regs, regs.r2_l, 1, regs.r1_l, 2, 6);
    rho_pi(&regs, regs.r1_l, 2, regs.r2_l, 0, 3);
    printf("\tlsr\t%s, %s, #7\n", regs.t2, regs.C_r);
    printf("\tbfi\t%s, %s, #1, #7\n", regs.r2_l, regs.C_r);
    printf("\tbfi\t%s, %s, #0, #1\n", regs.r2_l, regs.t2);

    /* Step mapping chi.  Combine each lane with two others in its row */
    chi(&regs, regs.r0_l, regs.r0_r);
    chi(&regs, regs.r1_l, regs.r1_r);
    chi(&regs, regs.r2_l, regs.r2_r);
    chi(&regs, regs.r3_l, regs.r3_r);
    chi(&regs, regs.r4_l, regs.r4_r);

    /* Step mapping iota.  XOR A[0][0] with the round constant */
    printf("\tadr\t%s, rconst\n", regs.C_l);
    printf("\tldrb\t%s, [%s, %s]\n", regs.t2, regs.C_l, regs.t1);
    binop("eor", regs.r0_l, regs.t2);

    /* Bottom of the round loop */
    printf("\tadd\t%s, #1\n", regs.t1);
    printf("\tcmp\t%s, #18\n", regs.t1);
    printf("\tbne\t.L1\n");

    /* Store the bytes back to the state and exit */
    printf("\tpop\t{r0}\n");
    printf("\tstr\t%s, [r0, #%d]\n", regs.r0_l, 0);
    printf("\tstr\t%s, [r0, #%d]\n", regs.r1_l, 5);
    printf("\tstr\t%s, [r0, #%d]\n", regs.r2_l, 10);
    printf("\tstr\t%s, [r0, #%d]\n", regs.r3_l, 15);
    printf("\tstr\t%s, [r0, #%d]\n", regs.r4_l, 20);
    printf("\tstrb\t%s, [r0, #%d]\n", regs.r0_r, 4);
    printf("\tstrb\t%s, [r0, #%d]\n", regs.r1_r, 9);
    printf("\tstrb\t%s, [r0, #%d]\n", regs.r2_r, 14);
    printf("\tstrb\t%s, [r0, #%d]\n", regs.r3_r, 19);
    printf("\tstrb\t%s, [r0, #%d]\n", regs.r4_r, 24);
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

    /* Output the round constant table */
    gen_keccakp_200_rc();

    /* Output the permutation function */
    function_header("keccakp_200_permute");
    gen_keccakp_200_permute();
    function_footer("keccakp_200_permute");

    /* Output the file footer */
    printf("\n");
    printf("#endif\n");
    return 0;
}
