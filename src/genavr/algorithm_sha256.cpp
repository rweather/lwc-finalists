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

// Round constants for SHA256.
static unsigned long const k[64] = {
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

void gen_sha256_transform(Code &code)
{
    int index;
    int b, c, d, f, g, h;

    // Set up the function prologue with 24 bytes of local variable storage.
    // Z points to the SHA256 state on input and output.
    code.prologue_permutation("sha256_transform", 24);

    // Allocate the registers we will need later.
    Reg temp3 = code.allocateHighReg(4);
    Reg temp1 = code.allocateReg(4);
    Reg temp2 = code.allocateReg(4);
    Reg temp4 = code.allocateReg(4);
    Reg areg = code.allocateReg(4);
    Reg ereg = code.allocateReg(4);

    // Offsets of the hash state words in local storage.
    // The "a" and "e" words are kept in registers, so not stored.
    b = 0;
    c = 4;
    d = 8;
    f = 12;
    g = 16;
    h = 20;

    // Load the hash state into local variables as we need to
    // preserve the original state until the end of the function.
    code.ldz(areg, 0);          // a
    code.ldz(temp1, 4);         // b
    code.stlocal(temp1, b);
    code.ldz(temp1, 8);         // c
    code.stlocal(temp1, c);
    code.ldz(temp1, 12);        // d
    code.stlocal(temp1, d);
    code.ldz(ereg, 16);         // e
    code.ldz(temp1, 20);        // f
    code.stlocal(temp1, f);
    code.ldz(temp1, 24);        // g
    code.stlocal(temp1, g);
    code.ldz(temp1, 28);        // h
    code.stlocal(temp1, h);

    // Advance Z to point to the "w" state array so that we can index it
    // with offsets between 0 and 63.
    code.add_ptr_z(32);

    // Unroll all rounds, expanding the "w" state array on the fly.
    // The state array is in big endian byte order which we take care
    // of transparently during the loads and stores to "w".
    for (index = 0; index < 64; ++index) {
        // Load or derive the next word from the "w" state array.
        if (index < 16) {
            // temp1 = state->w[index];
            code.ldz(temp1.reversed(), index * 4);
        } else {
            // temp1 = state->w[(index - 15) & 0x0F];
            code.ldz(temp1.reversed(), ((index - 15) * 4) & 0x3F);

            // temp2 = state->w[(index - 2) & 0x0F];
            code.ldz(temp2.reversed(), ((index - 2) * 4) & 0x3F);

            // temp1 = state->w[index & 0x0F] =
            //   state->w[(index - 16) & 0x0F] + state->w[(index - 7) & 0x0F] +
            //   (rightRotate7(temp1) ^ rightRotate18(temp1) ^ (temp1 >> 3)) +
            //   (rightRotate17(temp2) ^ rightRotate19(temp2) ^ (temp2 >> 10));
            code.move(temp3, temp1);
            code.rol(temp3, 1); // 7 = 8 - 1
            code.move(temp4, temp1);
            code.ror(temp4, 2); // 18 = 16 + 2
            code.lsr(temp1, 3);
            code.logxor(temp1, temp3.shuffle(1, 2, 3, 0));
            code.logxor(temp1, temp4.shuffle(2, 3, 0, 1));
            code.move(temp3, temp2);
            code.ror(temp3, 1); // 17 = 16 + 1
            code.move(temp4, temp2);
            code.ror(temp4, 3); // 19 = 16 + 3
            code.lsr(temp2, 10);
            code.logxor(temp2, temp3.shuffle(2, 3, 0, 1));
            code.logxor(temp2, temp4.shuffle(2, 3, 0, 1));
            code.add(temp1, temp2);
            code.ldz(temp3.reversed(), ((index - 16) * 4) & 0x3F);
            code.add(temp1, temp3);
            code.ldz(temp3.reversed(), ((index - 7) * 4) & 0x3F);
            code.add(temp1, temp3);
            code.stz(temp1.reversed(), (index * 4) & 0x3F);
        }

        // Compute the temp1 and temp2 values for this round.

        // temp1 = h + k[index] + temp1 +
        //    (rightRotate6(e) ^ rightRotate11(e) ^ rightRotate25(e)) +
        //    ((e & f) ^ ((~e) & g));
        code.move(temp3, k[index]);
        code.add(temp1, temp3);
        code.ldlocal(temp2, h);
        code.add(temp1, temp2);
        // temp1 += rightRotate6(e) ^ rightRotate11(e) ^ rightRotate25(e);
        code.move(temp2, ereg);
        code.rol(temp2, 2); // 6 = 8 - 2
        code.move(temp3, ereg);
        code.ror(temp3, 3); // 11 = 8 + 3
        code.logxor(temp2.shuffle(1, 2, 3, 0), temp3.shuffle(1, 2, 3, 0));
        code.move(temp3, ereg);
        code.ror(temp3, 1); // 25 = 24 + 1
        code.logxor(temp2.shuffle(1, 2, 3, 0), temp3.shuffle(3, 0, 1, 2));
        code.add(temp1, temp2.shuffle(1, 2, 3, 0));
        // temp1 += ((e & f) ^ ((~e) & g));
        code.ldlocal(temp2, f);
        code.logand(temp2, ereg);
        code.ldlocal(temp3, g);
        code.move(temp4, ereg);
        code.lognot(temp4);
        code.logand(temp3, temp4);
        code.logxor(temp2, temp3);
        code.add(temp1, temp2);

        // temp2 = (rightRotate2(a) ^ rightRotate13(a) ^ rightRotate22(a)) +
        //    ((a & b) ^ (a & c) ^ (b & c));
        code.move(temp2, areg);
        code.ror(temp2, 2);
        code.move(temp3, areg);
        code.rol(temp3, 3); // 13 = 16 - 3
        code.logxor(temp2, temp3.shuffle(2, 3, 0, 1));
        code.move(temp3, areg);
        code.rol(temp3, 2); // 22 = 24 - 2
        code.logxor(temp2, temp3.shuffle(3, 0, 1, 2));
        code.ldlocal(temp3, b);
        code.ldlocal(temp4, c);
        code.logand(temp4, temp3);
        code.logand(temp3, areg);
        code.logxor(temp3, temp4);
        code.ldlocal(temp4, c);
        code.logand(temp4, areg);
        code.logxor(temp3, temp4);
        code.add(temp2, temp3);

        // Rotate the hash state, keeping "a" and "e" in registers.
        // This can mostly be done virtually by changing offsets.
        int hh = h;
        h = g;
        g = f;
        // f = e;
        f = hh;
        code.stlocal(ereg, f);
        // e = d + temp1;
        code.ldlocal(ereg, d);
        code.add(ereg, temp1);
        int dd = d;
        d = c;
        c = b;
        // b = a;
        b = dd;
        code.stlocal(areg, b);
        // a = temp1 + temp2;
        code.move(areg, temp1);
        code.add(areg, temp2);
    }

    // Add the local hash state to the original hash state.
    // Note that "a" and "e" are still in registers.
    code.sub_ptr_z(32);
    code.ldz(temp1, 0);     // a
    code.add(areg, temp1);
    code.stz(areg, 0);
    code.ldz(temp1, 4);     // b
    code.ldlocal(temp2, b);
    code.add(temp1, temp2);
    code.stz(temp1, 4);
    code.ldz(temp1, 8);     // c
    code.ldlocal(temp2, c);
    code.add(temp1, temp2);
    code.stz(temp1, 8);
    code.ldz(temp1, 12);    // d
    code.ldlocal(temp2, d);
    code.add(temp1, temp2);
    code.stz(temp1, 12);
    code.ldz(temp1, 16);    // e
    code.add(ereg, temp1);
    code.stz(ereg, 16);
    code.ldz(temp1, 20);    // f
    code.ldlocal(temp2, f);
    code.add(temp1, temp2);
    code.stz(temp1, 20);
    code.ldz(temp1, 24);    // g
    code.ldlocal(temp2, g);
    code.add(temp1, temp2);
    code.stz(temp1, 24);
    code.ldz(temp1, 28);    // h
    code.ldlocal(temp2, h);
    code.add(temp1, temp2);
    code.stz(temp1, 28);
}

bool test_sha256_transform(Code &code)
{
    static unsigned char const input[] = {
        0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb,
        0x72, 0xf3, 0x6e, 0x3c, 0x3a, 0xf5, 0x4f, 0xa5,
        0x7f, 0x52, 0x0e, 0x51, 0x8c, 0x68, 0x05, 0x9b,
        0xab, 0xd9, 0x83, 0x1f, 0x19, 0xcd, 0xe0, 0x5b,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
    };
    static unsigned char const output[] = {
        0xdf, 0xa2, 0x99, 0xfc, 0x7a, 0x2a, 0xf4, 0x88,
        0x80, 0xd1, 0xb9, 0x7b, 0xa2, 0xc6, 0xcd, 0x33,
        0x5f, 0x75, 0x56, 0x02, 0x50, 0x9a, 0x5b, 0x9d,
        0x31, 0xcc, 0xa9, 0x44, 0xa7, 0x84, 0xbe, 0x5a
    };
    unsigned char state[96];
    memcpy(state, input, 96);
    code.exec_permutation(state, 96);
    return !memcmp(output, state, 32);
}
