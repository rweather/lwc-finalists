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
 * Keccak-p[400] permutation for ARM v7m microprocessors.  With minor
 * modifications, this can probably also be used to generate assembly
 * code versions for other Cortex M variants such as M4, M7, M33, etc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Offset of a particular lane in the Keccak-p[400] state */
#define A(row, col) ((row) * 10 + (col) * 2)

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
    const char *B[5];
    const char *C[5];
    const char *D;
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

/* Generate the round constant table for Keccak-p[400] */
static void gen_keccakp_400_rc(void)
{
    static uint16_t const rc[20] = {
        0x0001, 0x8082, 0x808A, 0x8000, 0x808B, 0x0001, 0x8081, 0x8009,
        0x008A, 0x0088, 0x8009, 0x000A, 0x808B, 0x008B, 0x8089, 0x8003,
        0x8002, 0x0080, 0x800A, 0x000A
    };
    const char *name = "rconst";
    int index;
    printf("\n\t.align\t2\n");
    printf("\t.type\t%s, %%object\n", name);
    printf("%s:\n", name);
    for (index = 0; index < 20; ++index) {
        printf("\t.byte\t0x%02x\n", rc[index] & 0xFF);
        printf("\t.byte\t0x%02x\n", (rc[index] >> 8) & 0xFF);
    }
    printf("\t.size\t%s, .-%s\n", name, name);

}

/* Generate the code for step mappings rho and pi.  As an optimization,
 * we don't reduce the results to 16-bit yet.  Results that end up in
 * memory are implicitly reduced when they are stored.  Results that
 * end up in registers for the first row will be reduced later. */
static void rho_pi
    (const reg_names *regs, int destrow, int destcol,
     int srcrow, int srccol, int rot)
{
    const char *srcreg;
    const char *destreg;
    if (srcrow == 0) {
        srcreg = regs->B[srccol];
    } else {
        srcreg = regs->C[1];
        printf("\tldrh\t%s, [r0, #%d]\n", srcreg, A(srcrow, srccol));
    }
    if (rot == 8) {
        if (destrow == 0) {
            destreg = regs->B[destcol];
            printf("\trev16\t%s, %s\n", destreg, srcreg);
        } else {
            printf("\trev16\t%s, %s\n", regs->C[2], srcreg);
            printf("\tstrh\t%s, [r0, #%d]\n", regs->C[2], A(destrow, destcol));
        }
    } else {
        printf("\tlsl\t%s, %s, #%d\n", srcreg, srcreg, rot);
        if (destrow == 0) {
            destreg = regs->B[destcol];
            printf("\torr\t%s, %s, %s, lsr #16\n", destreg, srcreg, srcreg);
        } else {
            printf("\torr\t%s, %s, %s, lsr #16\n", regs->C[2], srcreg, srcreg);
            printf("\tstrh\t%s, [r0, #%d]\n", regs->C[2], A(destrow, destcol));
        }
    }
}

/* Generate the body of the Keccak-p[400] permutation function */
static void gen_keccakp_400_permute(void)
{
    /*
     * This implementation is inspired by:
     * https://github.com/XKCP/XKCP/blob/master/lib/low/KeccakP-400/ARM/KeccakP-400-armv7m-le-gcc.s
     */
    /*
     * r0 holds the pointer to the Keccak-p[400] state on entry and exit.
     *
     * r1 holds the number of rounds to perform on entry.
     *
     * r0, r1, r2, r3, and ip can be used as scratch registers without saving,
     * but the value of ip may not survive across a branch instruction.
     *
     * r4, r5, r6, r7, r8, r9, r10, fp, and lr must be callee-saved.
     */
    int index, index2;
    reg_names regs;
    regs.B[0] = "r7";
    regs.B[1] = "r8";
    regs.B[2] = "r9";
    regs.B[3] = "r10";
    regs.B[4] = "fp";
    regs.C[0] = "r1";
    regs.C[1] = "r2";
    regs.C[2] = "r3";
    regs.C[3] = "r4";
    regs.C[4] = "ip";
    regs.D = "r5";
    regs.t1 = "lr";
    regs.t2 = "r6";
    printf("\tpush\t{r4, r5, r6, r7, r8, r9, r10, fp, lr}\n");

    /* Load the first row into registers.  The other rows are
     * kept in state memory when they aren't being used. */
    printf("\tldrh\t%s, [r0, #%d]\n", regs.B[0], A(0, 0));
    printf("\tldrh\t%s, [r0, #%d]\n", regs.B[1], A(0, 1));
    printf("\tldrh\t%s, [r0, #%d]\n", regs.B[2], A(0, 2));
    printf("\tldrh\t%s, [r0, #%d]\n", regs.B[3], A(0, 3));
    printf("\tldrh\t%s, [r0, #%d]\n", regs.B[4], A(0, 4));

    /* Top of the round loop */
    /* t1 = (20 - rounds) * 2 */
    loadimm(regs.t1, 40);
    printf("\tsub\t%s, %s, r1, lsl #1\n", regs.t1, regs.t1);
    printf(".L1:\n");

    /* Step mapping theta */
    /* for (index = 0; index < 5; ++index) {
     *     C[index] = state->A[0][index] ^ state->A[1][index] ^
     *                state->A[2][index] ^ state->A[3][index] ^
     *                state->A[4][index];
     * } */
    for (index = 0; index < 5; ++index) {
        /* Row 0 is in the B array but the rest must be loaded from memory */
        printf("\tldrh\t%s, [r0, #%d]\n", regs.C[index], A(1, index));
        binop("eor", regs.C[index], regs.B[index]);
        printf("\tldrh\t%s, [r0, #%d]\n", regs.t2, A(2, index));
        binop("eor", regs.C[index], regs.t2);
        printf("\tldrh\t%s, [r0, #%d]\n", regs.t2, A(3, index));
        binop("eor", regs.C[index], regs.t2);
        printf("\tldrh\t%s, [r0, #%d]\n", regs.t2, A(4, index));
        binop("eor", regs.C[index], regs.t2);
    }
    /* for (index = 0; index < 5; ++index) {
     *     D = C[(index + 4) % 5] ^ leftRotate1_16(C[(index + 1) % 5]);
     *     for (index2 = 0; index2 < 5; ++index2)
     *         state->A[index2][index] ^= D;
     * } */
    for (index = 4; index >= 0; --index) {
        /* Compute the D value for this column */
        printf("\tlsl\t%s, %s, #1\n", regs.D, regs.C[(index + 1) % 5]);
        printf("\torr\t%s, %s, %s, lsr #15\n",
               regs.D, regs.D, regs.C[(index + 1) % 5]);
        binop("eor", regs.D, regs.C[(index + 4) % 5]);

        /* Restrict the D value to 16 bits, as the lsl above introduced
         * an extra bit in the high part of the word */
        printf("\tuxth\t%s, %s\n", regs.D, regs.D);

        /* XOR with the first row which is in the B register array */
        binop("eor", regs.B[index], regs.D);

        /* Handle the remaining rows.  Note that A(4, 4) was left in
         * regs.t2 at the end of the previous step so we can save an
         * instruction by processing it first */
        for (index2 = 4; index2 >= 1; --index2) {
            if (!(index == 4 && index2 == 4))
                printf("\tldrh\t%s, [r0, #%d]\n", regs.t2, A(index2, index));
            binop("eor", regs.t2, regs.D);
            printf("\tstrh\t%s, [r0, #%d]\n", regs.t2, A(index2, index));
        }
    }

    /* Step mapping rho and pi combined into a single step.
     * Rotate all lanes by a specific offset and rearrange */
    printf("\tlsl\t%s, %s, #1\n", regs.C[0], regs.B[1]);
    printf("\torr\t%s, %s, %s, lsr #15\n", regs.C[0], regs.C[0], regs.B[1]);
    rho_pi(&regs, 0, 1, 1, 1, 12);
    rho_pi(&regs, 1, 1, 1, 4, 4);
    rho_pi(&regs, 1, 4, 4, 2, 13);
    rho_pi(&regs, 4, 2, 2, 4, 7);
    rho_pi(&regs, 2, 4, 4, 0, 2);
    rho_pi(&regs, 4, 0, 0, 2, 14);
    rho_pi(&regs, 0, 2, 2, 2, 11);
    rho_pi(&regs, 2, 2, 2, 3, 9);
    rho_pi(&regs, 2, 3, 3, 4, 8);
    rho_pi(&regs, 3, 4, 4, 3, 8);
    rho_pi(&regs, 4, 3, 3, 0, 9);
    rho_pi(&regs, 3, 0, 0, 4, 11);
    rho_pi(&regs, 0, 4, 4, 4, 14);
    rho_pi(&regs, 4, 4, 4, 1, 2);
    rho_pi(&regs, 4, 1, 1, 3, 7);
    rho_pi(&regs, 1, 3, 3, 1, 13);
    rho_pi(&regs, 3, 1, 1, 0, 4);
    rho_pi(&regs, 1, 0, 0, 3, 12);
    rho_pi(&regs, 0, 3, 3, 3, 5);
    rho_pi(&regs, 3, 3, 3, 2, 15);
    rho_pi(&regs, 3, 2, 2, 1, 10);
    rho_pi(&regs, 2, 1, 1, 2, 6);
    rho_pi(&regs, 1, 2, 2, 0, 3);
    printf("\tstrh\t%s, [r0, #%d]\n", regs.C[0], A(2, 0));

    /* Step mapping chi.  Combine each lane with two others in its row */
    /* for (index = 0; index < 5; ++index) {
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
     * } */
    for (index = 4; index >= 0; --index) {
        if (index == 0) {
            for (index2 = 0; index2 < 5; ++index2) {
                printf("\tbic\t%s, %s, %s\n", regs.C[index2],
                       regs.B[(index2 + 2) % 5], regs.B[(index2 + 1) % 5]);
            }
            for (index2 = 0; index2 < 5; ++index2) {
                binop("eor", regs.C[index2], regs.B[index2]);
            }
        } else {
            for (index2 = 0; index2 < 5; ++index2) {
                printf("\tldrh\t%s, [r0, #%d]\n", regs.C[index2],
                       A(index, index2));
            }
            for (index2 = 0; index2 < 5; ++index2) {
                printf("\tbic\t%s, %s, %s\n", regs.t2,
                       regs.C[(index2 + 2) % 5], regs.C[(index2 + 1) % 5]);
                binop("eor", regs.t2, regs.C[index2]);
                printf("\tstrh\t%s, [r0, #%d]\n", regs.t2, A(index, index2));
            }
        }
    }

    /* Step mapping iota.  XOR A[0][0] with the round constant.
     * Note that the first row is still in C after the last step
     * so we also need to move it back to B and reduce to 16-bit.
     * The reduction to 16-bit has been deferred since rho_pi(). */
    printf("\tadr\t%s, rconst\n", regs.D);
    printf("\tuxth\t%s, %s\n", regs.B[1], regs.C[1]);
    printf("\tldrh\t%s, [%s, %s]\n", regs.t2, regs.D, regs.t1);
    printf("\tuxth\t%s, %s\n", regs.B[2], regs.C[2]);
    printf("\teor\t%s, %s, %s\n", regs.B[0], regs.C[0], regs.t2);
    printf("\tuxth\t%s, %s\n", regs.B[3], regs.C[3]);
    printf("\tuxth\t%s, %s\n", regs.B[0], regs.B[0]);
    printf("\tuxth\t%s, %s\n", regs.B[4], regs.C[4]);

    /* Bottom of the round loop */
    printf("\tadd\t%s, #2\n", regs.t1);
    printf("\tcmp\t%s, #40\n", regs.t1);
    printf("\tbne\t.L1\n");

    /* Store the first row back to the state and exit */
    printf("\tstrh\t%s, [r0, #%d]\n", regs.B[0], A(0, 0));
    printf("\tstrh\t%s, [r0, #%d]\n", regs.B[1], A(0, 1));
    printf("\tstrh\t%s, [r0, #%d]\n", regs.B[2], A(0, 2));
    printf("\tstrh\t%s, [r0, #%d]\n", regs.B[3], A(0, 3));
    printf("\tstrh\t%s, [r0, #%d]\n", regs.B[4], A(0, 4));
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
    gen_keccakp_400_rc();

    /* Output the permutation function */
    function_header("keccakp_400_permute");
    gen_keccakp_400_permute();
    function_footer("keccakp_400_permute");

    /* Output the file footer */
    printf("\n");
    printf("#endif\n");
    return 0;
}
