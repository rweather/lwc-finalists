
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

#include "gen.h"
#include <cstring>

void gen_ghash_init(Code &code)
{
    int offset;

    // Set up the function prologue with 0 bytes of local variable storage.
    // Z points to the GHASH state and X points to the 16 bytes of the key.
    code.prologue_setup_key("ghash_init", 0);
    code.setFlag(Code::NoLocals);

    // Copy the key value as-is in big endian order.  The multiplication
    // routine can do the byte swapping when it loads the value.
    Reg temp = code.allocateReg(4);
    for (offset = 0; offset < 16; offset += 4) {
        code.ldx(temp, POST_INC);
        code.stz(temp, offset);
    }

    // Zero the Y and "posn" fields.
    code.stz_zero(16, 20);
}

void gen_ghash_mul(Code &code)
{
    // Simple bit-by-bit implementation for AVR which is more efficient
    // than trying to perform the multiplication 4 bits at a time.

    // Set up the function prologue with 16 bytes of local variable storage.
    // Z points to the GHASH state on input and output.
    code.prologue_permutation("ghash_mul", 16);

    // Put Z in local variables and initialize it to zero.
    code.stlocal_zero(0, 16);

    // Allocate the registers we need.
    Reg counter = code.allocateHighReg(1);
    Reg temp1 = code.allocateHighReg(1);
    Reg V = code.allocateReg(16);
    Reg value = code.allocateReg(1);
    Reg mask = code.allocateReg(1);
    Reg temp2 = code.allocateReg(1);

    // Load V = H into registers and convert from big-endian byte order.
    code.ldz(V.reversed(), POST_INC);

    // Loop over the 16 bytes in the input "Y" value.
    code.move(counter, 16);
    unsigned char top_label = 0;
    unsigned char end_label = 0;
    unsigned char subroutine = 0;
    code.label(top_label);
    code.ldz(value, POST_INC);

    // Iterate over the bits in the byte.
    for (int bit = 0; bit < 8; ++bit) {
        code.move(mask, 0);
        code.lsl(value, 1);
        code.tworeg(Insn::SBC, mask.reg(0), ZERO_REG);
        code.call(subroutine);
    }

    // Bottom of the byte loop.
    code.dec(counter);
    code.brne(top_label);
    code.jmp(end_label);

    // Subroutine that conditionally XOR's V with Z and then rotates V right.
    code.label(subroutine);
    for (int offset = 0; offset < 16; ++offset) {
        code.ldlocal(temp1, offset);
        code.move(temp2, Reg(V, offset, 1));
        code.logand(temp2, mask);
        code.logxor(temp1, temp2);
        code.stlocal(temp1, offset);
    }
    code.move(temp1, 0);
    code.lsr(V, 1);
    code.tworeg(Insn::SBC, temp1.reg(0), ZERO_REG);
    code.logand(temp1, 0xE1);
    code.logxor(Reg(V, 15, 1), temp1);
    code.ret();

    // Store the result back to the state as the new value of "Y".
    code.label(end_label);
    code.ldlocal(V, 0);
    code.stz(V.reversed(), PRE_DEC);
}

bool test_ghash_mul(Code &code)
{
    static unsigned char const input[36] = {
        0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
        0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e,
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
        0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
        0x00, 0x00, 0x00, 0x00
    };
    static unsigned char const output[36] = {
        0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
        0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e,
        0x5e, 0x2e, 0xc7, 0x46, 0x91, 0x70, 0x62, 0x88,
        0x2c, 0x85, 0xb0, 0x68, 0x53, 0x53, 0xde, 0xb7,
        0x00, 0x00, 0x00, 0x00
    };
    unsigned char state[36];
    memcpy(state, input, 36);
    code.exec_permutation(state, 36);
    return !memcmp(output, state, 36);
}
