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
 * SHA256 transformation function for ARM v7m microprocessors.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "copyright.h"

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
    const char *a;
    const char *b;
    const char *c;
    const char *d;
    const char *e;
    const char *f;
    const char *g;
    const char *h;
    const char *temp1;
    const char *temp2;
    const char *temp3;

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

/* Expand the code for a single round */
static void sha256_round(const reg_names *regs, int index)
{
    /* Round constants for SHA256 */
    static uint32_t const k[64] = {
        0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
        0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
        0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
        0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
        0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
        0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
        0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
        0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
        0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
        0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
        0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
        0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
        0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
        0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
        0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
        0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
    };

    /* Load the current round key or expand based on the previous keys */
    if (index >= 16) {
        /* temp1 = state->w[(index - 15) & 0x0F]; */
        printf("\tldr\t%s, [r0, #%d]\n", regs->temp1,
               (((index - 15) * 4) & 0x3F) + 32);

        /* temp2 = state->w[(index - 2) & 0x0F]; */
        printf("\tldr\t%s, [r0, #%d]\n", regs->temp2,
               (((index - 2) * 4) & 0x3F) + 32);

        /* temp1 = state->w[index & 0x0F] =
         *    state->w[(index - 16) & 0x0F] + state->w[(index - 7) & 0x0F] +
         *        (rightRotate7(temp1) ^ rightRotate18(temp1) ^ (temp1 >> 3)) +
         *        (rightRotate17(temp2) ^ rightRotate19(temp2) ^ (temp2 >> 10));
         */
        printf("\tlsr\t%s, %s, #3\n", regs->temp3, regs->temp1);
        printf("\teor\t%s, %s, %s, ror #7\n",
               regs->temp3, regs->temp3, regs->temp1);
        printf("\teor\t%s, %s, %s, ror #18\n",
               regs->temp1, regs->temp3, regs->temp1);
        printf("\tlsr\t%s, %s, #10\n", regs->temp3, regs->temp2);
        printf("\teor\t%s, %s, %s, ror #17\n",
               regs->temp3, regs->temp3, regs->temp2);
        printf("\teor\t%s, %s, %s, ror #19\n",
               regs->temp2, regs->temp3, regs->temp2);
        binop("add", regs->temp1, regs->temp2);
        printf("\tldr\t%s, [r0, #%d]\n", regs->temp3,
               (((index - 16) * 4) & 0x3F) + 32);
        printf("\tldr\t%s, [r0, #%d]\n", regs->temp2,
               (((index - 7) * 4) & 0x3F) + 32);
        binop("add", regs->temp1, regs->temp3);
        binop("add", regs->temp1, regs->temp2);
    } else {
        /* Loading from the original state which is in big-endian order.
         * Store the reversed value back to the state so that it is
         * ready in host byte order when we need to expand it later. */
        printf("\tldr\t%s, [r0, #%d]\n", regs->temp1, ((index * 4) & 0x3F) + 32);
        printf("\trev\t%s, %s\n", regs->temp1, regs->temp1);
    }
    printf("\tstr\t%s, [r0, #%d]\n", regs->temp1, ((index * 4) & 0x3F) + 32);

    /* Perform the round */

    /* temp1 = h + k[index] + temp1 +
     *         (rightRotate6(e) ^ rightRotate11(e) ^ rightRotate25(e)) +
     *         ((e & f) ^ ((~e) & g)); */
    printf("\tmovw\t%s, #%d\n", regs->temp3, (int)(k[index] & 0xFFFF));
    printf("\tmovt\t%s, #%d\n", regs->temp3, (int)((k[index] >> 16) & 0xFFFF));
    printf("\tadd\t%s, %s, %s\n", regs->temp1, regs->h, regs->temp1);
    binop("add", regs->temp1, regs->temp3);
    printf("\tror\t%s, %s, #6\n", regs->temp2, regs->e);
    printf("\teor\t%s, %s, %s, ror #11\n", regs->temp2, regs->temp2, regs->e);
    printf("\teor\t%s, %s, %s, ror #25\n", regs->temp2, regs->temp2, regs->e);
    binop("add", regs->temp1, regs->temp2);
    printf("\tand\t%s, %s, %s\n", regs->temp2, regs->e, regs->f);
    printf("\tbic\t%s, %s, %s\n", regs->temp3, regs->g, regs->e);
    binop("eor", regs->temp2, regs->temp3);
    binop("add", regs->temp1, regs->temp2);

    /* temp2 = (rightRotate2(a) ^ rightRotate13(a) ^ rightRotate22(a)) +
     *         ((a & b) ^ (a & c) ^ (b & c)); */
    printf("\tand\t%s, %s, %s\n", regs->temp2, regs->a, regs->b);
    printf("\tand\t%s, %s, %s\n", regs->temp3, regs->a, regs->c);
    binop("eor", regs->temp2, regs->temp3);
    printf("\tand\t%s, %s, %s\n", regs->temp3, regs->b, regs->c);
    binop("eor", regs->temp2, regs->temp3);
    printf("\tror\t%s, %s, #2\n", regs->temp3, regs->a);
    printf("\teor\t%s, %s, %s, ror #13\n", regs->temp3, regs->temp3, regs->a);
    printf("\teor\t%s, %s, %s, ror #22\n", regs->temp3, regs->temp3, regs->a);
    binop("add", regs->temp2, regs->temp3);

    /* Final rotation, which is mostly done virtually in the caller */
    /* h = g; */
    /* g = f; */
    /* f = e; */
    /* e = d + temp1; -- result left in d */
    binop("add", regs->d, regs->temp1);
    /* d = c; */
    /* c = b; */
    /* b = a; */
    /* a = temp1 + temp2; -- result left in h */
    printf("\tadd\t%s, %s, %s\n", regs->h, regs->temp1, regs->temp2);
}

/* Generate the body of the SHA256 transform function */
static void gen_sha256_transform(void)
{
    /*
     * r0 holds the pointer to the SHA256 state on entry and exit,
     * which consists of the 8 words of "h" in host byte order,
     * and the 16 words of the current block in big endian byte order.
     *
     * r0, r1, r2, r3, and ip can be used as scratch registers without saving,
     * but the value of ip may not survive across a branch instruction.
     *
     * r4, r5, r6, r7, r8, r9, r10, fp, and lr must be callee-saved.
     */
    reg_names regs;
    const char *rot;
    int index;
    regs.a = "r1";
    regs.b = "r2";
    regs.c = "r3";
    regs.d = "r4";
    regs.e = "r5";
    regs.f = "r6";
    regs.g = "r7";
    regs.h = "r8";
    regs.temp1 = "r9";
    regs.temp2 = "r10";
    regs.temp3 = "ip";
    printf("\tpush\t{r4, r5, r6, r7, r8, r9, r10, lr}\n");

    /* Load all words of the state into registers */
    printf("\tldr\t%s, [r0, #%d]\n", regs.a, 0);
    printf("\tldr\t%s, [r0, #%d]\n", regs.b, 4);
    printf("\tldr\t%s, [r0, #%d]\n", regs.c, 8);
    printf("\tldr\t%s, [r0, #%d]\n", regs.d, 12);
    printf("\tldr\t%s, [r0, #%d]\n", regs.e, 16);
    printf("\tldr\t%s, [r0, #%d]\n", regs.f, 20);
    printf("\tldr\t%s, [r0, #%d]\n", regs.g, 24);
    printf("\tldr\t%s, [r0, #%d]\n", regs.h, 28);

    /* Unroll the rounds */
    for (index = 0; index < 64; ++index) {
        /* Perform the round */
        sha256_round(&regs, index);

        /* Rotate the state virtually.  Repeats every 8 rounds */
        rot = regs.h;
        regs.h = regs.g;
        regs.g = regs.f;
        regs.f = regs.e;
        regs.e = regs.d;
        regs.d = regs.c;
        regs.c = regs.b;
        regs.b = regs.a;
        regs.a = rot;
    }

    /* Add the final hash state to the original */
    printf("\tldr\t%s, [r0, #%d]\n", regs.temp1, 0);
    printf("\tldr\t%s, [r0, #%d]\n", regs.temp2, 4);
    binop("add", regs.a, regs.temp1);
    binop("add", regs.b, regs.temp2);
    printf("\tstr\t%s, [r0, #%d]\n", regs.a, 0);
    printf("\tstr\t%s, [r0, #%d]\n", regs.b, 4);
    printf("\tldr\t%s, [r0, #%d]\n", regs.temp1, 8);
    printf("\tldr\t%s, [r0, #%d]\n", regs.temp2, 12);
    binop("add", regs.c, regs.temp1);
    binop("add", regs.d, regs.temp2);
    printf("\tstr\t%s, [r0, #%d]\n", regs.c, 8);
    printf("\tstr\t%s, [r0, #%d]\n", regs.d, 12);
    printf("\tldr\t%s, [r0, #%d]\n", regs.temp1, 16);
    printf("\tldr\t%s, [r0, #%d]\n", regs.temp2, 20);
    binop("add", regs.e, regs.temp1);
    binop("add", regs.f, regs.temp2);
    printf("\tstr\t%s, [r0, #%d]\n", regs.e, 16);
    printf("\tstr\t%s, [r0, #%d]\n", regs.f, 20);
    printf("\tldr\t%s, [r0, #%d]\n", regs.temp1, 24);
    printf("\tldr\t%s, [r0, #%d]\n", regs.temp2, 28);
    binop("add", regs.g, regs.temp1);
    binop("add", regs.h, regs.temp2);
    printf("\tstr\t%s, [r0, #%d]\n", regs.g, 24);
    printf("\tstr\t%s, [r0, #%d]\n", regs.h, 28);
    printf("\tpop\t{r4, r5, r6, r7, r8, r9, r10, pc}\n");
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    /* Output the file header */
    printf("#if defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7\n");
    fputs(copyright_message, stdout);
    printf("\t.syntax unified\n");
    printf("\t.thumb\n");
    printf("\t.text\n");

    /* Output the SHA256 block transformation function */
    function_header("sha256_transform");
    gen_sha256_transform();
    function_footer("sha256_transform");

    /* Output the file footer */
    printf("\n");
    printf("#endif\n");
    return 0;
}
