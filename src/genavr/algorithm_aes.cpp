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

// AES S-box (https://en.wikipedia.org/wiki/Rijndael_S-box)
static unsigned char const sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,     /* 0x00 */
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,     /* 0x10 */
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,     /* 0x20 */
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,     /* 0x30 */
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,     /* 0x40 */
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,     /* 0x50 */
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,     /* 0x60 */
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,     /* 0x70 */
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,     /* 0x80 */
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,     /* 0x90 */
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,     /* 0xA0 */
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,     /* 0xB0 */
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,     /* 0xC0 */
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,     /* 0xD0 */
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,     /* 0xE0 */
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,     /* 0xF0 */
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

// Rcon(i), 2^i in the Rijndael finite field, for i = 1..10.
// https://en.wikipedia.org/wiki/Rijndael_key_schedule
static unsigned char const rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

Sbox get_aes_sbox()
{
    return Sbox(sbox, sizeof(sbox));
}

void gen_aes128_setup_key(Code &code)
{
    // Shuffle pattern to rearrange the registers each round.
    static unsigned char const pattern[] = {
        4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3
    };

    // Set up the function prologue with 0 bytes of local variable storage.
    // X points to the key, and Z points to the key schedule.
    code.prologue_setup_key("aes_128_init", 0);

    // Load the key and write it to the first 16 bytes of the schedule.
    Reg sched = code.allocateReg(16);
    code.ldx(sched, POST_INC);
    code.stz(sched, 0);
    code.setFlag(Code::TempX);

    // We need the S-box pointer in Z, so move the schedule pointer to Y.
    code.move(Reg::y_ptr(), Reg::z_ptr());
    code.sbox_setup(0, get_aes_sbox());

    // Expand the key schedule until we have 176 bytes of expanded key.
    int iteration = 0;
    int n, w;
    Reg temp = code.allocateHighReg(1);
    for (n = 16, w = 4; n < 176; n += 4, ++w) {
        Reg s0  = Reg(sched, 0, 4);
        Reg s12 = Reg(sched, 12, 4);
        if (w == 4) {
            // Apply the key schedule core every 16 bytes / 4 words.
            code.sbox_lookup(temp, Reg(s12, 0, 1));
            code.logxor(Reg(s0, 3, 1), temp);

            code.sbox_lookup(temp, Reg(s12, 1, 1));
            code.logxor(Reg(s0, 0, 1), temp);
            code.move(temp, rcon[iteration++]);
            code.logxor(Reg(s0, 0, 1), temp);

            code.sbox_lookup(temp, Reg(s12, 2, 1));
            code.logxor(Reg(s0, 1, 1), temp);

            code.sbox_lookup(temp, Reg(s12, 3, 1));
            code.logxor(Reg(s0, 2, 1), temp);
            w = 0;
        } else {
            // XOR the word with the one 16 bytes previous.
            code.logxor(s0, s12);
        }
        code.sty(s0, 16);
        if ((n + 4) < 176)
            code.add_ptr_y(4);
        sched = sched.shuffle(pattern);
    }

    // Set the number of rounds.
    code.move(Reg(sched, 0, 4), 10);
    code.add_ptr_y(20 + (240 - 176));
    code.sty(Reg(sched, 0, 4), 0);

    // Clean up and exit.
    code.sbox_cleanup();
}

void gen_aes192_setup_key(Code &code)
{
    // Shuffle pattern to rearrange the registers each round.
    static unsigned char const pattern[] = {
        4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 0, 1, 2, 3
    };

    // Set up the function prologue with 0 bytes of local variable storage.
    // X points to the key, and Z points to the key schedule.
    code.prologue_setup_key("aes_192_init", 0);

    // Load the key and write it to the first 24 bytes of the schedule.
    Reg sched = code.allocateReg(24);
    code.ldx(sched, POST_INC);
    code.stz(sched, 0);
    code.setFlag(Code::TempX);

    // We need the S-box pointer in Z, so move the schedule pointer to Y.
    code.move(Reg::y_ptr(), Reg::z_ptr());
    code.sbox_setup(0, get_aes_sbox());

    // Expand the key schedule until we have 208 bytes of expanded key.
    int iteration = 0;
    int n, w;
    Reg temp = code.allocateHighReg(1);
    for (n = 24, w = 6; n < 208; n += 4, ++w) {
        Reg s0  = Reg(sched, 0, 4);
        Reg s20 = Reg(sched, 20, 4);
        if (w == 6) {
            // Apply the key schedule core every 24 bytes / 6 words.
            code.sbox_lookup(temp, Reg(s20, 0, 1));
            code.logxor(Reg(s0, 3, 1), temp);

            code.sbox_lookup(temp, Reg(s20, 1, 1));
            code.logxor(Reg(s0, 0, 1), temp);
            code.move(temp, rcon[iteration++]);
            code.logxor(Reg(s0, 0, 1), temp);

            code.sbox_lookup(temp, Reg(s20, 2, 1));
            code.logxor(Reg(s0, 1, 1), temp);

            code.sbox_lookup(temp, Reg(s20, 3, 1));
            code.logxor(Reg(s0, 2, 1), temp);
            w = 0;
        } else {
            // XOR the word with the one 24 bytes previous.
            code.logxor(s0, s20);
        }
        code.sty(s0, 24);
        if ((n + 4) < 208)
            code.add_ptr_y(4);
        sched = sched.shuffle(pattern);
    }

    // Set the number of rounds.
    code.move(Reg(sched, 0, 4), 12);
    code.add_ptr_y(28 + (240 - 208));
    code.sty(Reg(sched, 0, 4), 0);

    // Clean up and exit.
    code.sbox_cleanup();
}

void gen_aes256_setup_key(Code &code)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    // X points to the key, and Z points to the key schedule.
    code.prologue_setup_key("aes_256_init", 0);

    // Load the key and write it to the first 32 bytes of the schedule.
    Reg s0 = code.allocateReg(4);
    Reg s28 = code.allocateReg(4);
    for (int offset = 0; offset < 32; offset += 4) {
        if (offset == 0) {
            code.ldx(s0, POST_INC);
            code.stz(s0, offset);
        } else {
            code.ldx(s28, POST_INC);
            code.stz(s28, offset);
        }
    }
    code.setFlag(Code::TempX);

    // We need the S-box pointer in Z, so move the schedule pointer to Y.
    code.move(Reg::y_ptr(), Reg::z_ptr());
    code.sbox_setup(0, get_aes_sbox());

    // Expand the key schedule until we have 240 bytes of expanded key.
    int iteration = 0;
    int n, w;
    Reg temp = code.allocateHighReg(1);
    for (n = 32, w = 8; n < 240; n += 4, ++w) {
        if (w == 8) {
            // Apply the key schedule core every 32 bytes / 8 words.
            code.sbox_lookup(temp, Reg(s28, 0, 1));
            code.logxor(Reg(s0, 3, 1), temp);

            code.sbox_lookup(temp, Reg(s28, 1, 1));
            code.logxor(Reg(s0, 0, 1), temp);
            code.move(temp, rcon[iteration++]);
            code.logxor(Reg(s0, 0, 1), temp);

            code.sbox_lookup(temp, Reg(s28, 2, 1));
            code.logxor(Reg(s0, 1, 1), temp);

            code.sbox_lookup(temp, Reg(s28, 3, 1));
            code.logxor(Reg(s0, 2, 1), temp);
            w = 0;
        } else if (w == 4) {
            // At the 16 byte mark we need to apply the S-box.
            code.sbox_lookup(temp, Reg(s28, 0, 1));
            code.logxor(Reg(s0, 0, 1), temp);

            code.sbox_lookup(temp, Reg(s28, 1, 1));
            code.logxor(Reg(s0, 1, 1), temp);

            code.sbox_lookup(temp, Reg(s28, 2, 1));
            code.logxor(Reg(s0, 2, 1), temp);

            code.sbox_lookup(temp, Reg(s28, 3, 1));
            code.logxor(Reg(s0, 3, 1), temp);
        } else {
            // XOR the word with the one 32 bytes previous.
            code.logxor(s0, s28);
        }

        // Store the word to the schedule and load the new schedule words.
        code.sty(s0, 32);
        if ((n + 4) < 240) {
            code.add_ptr_y(4);
            code.ldy(s0, 0);
            code.ldy(s28, 28);
        }
    }

    // Set the number of rounds.
    code.move(s0, 14);
    code.sty(s0, 36);

    // Clean up and exit.
    code.sbox_cleanup();
}

// Applies the next round key to the state.
static void applyRoundKey(Code &code, const Reg &state, const Reg &temp)
{
    for (int offset = 0; offset < 16; ++offset) {
        code.ldx(temp, POST_INC);
        code.logxor(Reg(state, offset, 1), temp);
    }
}

// Index a byte in the state by column and row.
#define S(col, row) (Reg(state, (col) * 4 + (row), 1))

// Apply the S-box and then shift the bytes of the rows.
static void subBytesAndShiftRows(Code &code, const Reg &state, const Reg &temp)
{
    // Map the bytes using the S-box and rearrange the state in-place.
    code.sbox_lookup(S(0, 0), S(0, 0));     // row0 <<<= 0
    code.sbox_lookup(S(1, 0), S(1, 0));
    code.sbox_lookup(S(2, 0), S(2, 0));
    code.sbox_lookup(S(3, 0), S(3, 0));

    code.sbox_lookup(temp, S(0, 1));        // row1 <<<= 8
    code.sbox_lookup(S(0, 1), S(1, 1));
    code.sbox_lookup(S(1, 1), S(2, 1));
    code.sbox_lookup(S(2, 1), S(3, 1));
    code.move(S(3, 1), temp);

    code.sbox_lookup(temp, S(0, 2));        // row2 <<<= 16
    code.sbox_lookup(S(0, 2), S(2, 2));
    code.move(S(2, 2), temp);
    code.sbox_lookup(temp, S(1, 2));
    code.sbox_lookup(S(1, 2), S(3, 2));
    code.move(S(3, 2), temp);

    code.sbox_lookup(temp, S(0, 3));        // row3 <<<= 24
    code.sbox_lookup(S(0, 3), S(3, 3));
    code.sbox_lookup(S(3, 3), S(2, 3));
    code.sbox_lookup(S(2, 3), S(1, 3));
    code.move(S(1, 3), temp);
}

// Double a byte value in the GF(2^8) field; "temp" must be a high register.
static void gdouble(Code &code, const Reg &a2, const Reg &a, const Reg &temp)
{
    code.move(a2, a);
    code.tworeg(Insn::MOV, temp.reg(0), ZERO_REG);
    code.lsl(a2, 1);
    code.tworeg(Insn::SBC, temp.reg(0), ZERO_REG);
    code.logand(temp, 0x1B);
    code.logxor(a2, temp);
}

// Apply MixColumns to a single column.
static void mixColumn(Code &code, const Reg &state, int col, const Reg &temp)
{
    Reg a = S(col, 0);
    Reg b = S(col, 1);
    Reg c = S(col, 2);
    Reg d = S(col, 3);
    Reg a2 = code.allocateReg(1);
    Reg b2 = code.allocateReg(1);
    Reg c2 = code.allocateReg(1);

    gdouble(code, a2, a, temp);
    gdouble(code, b2, b, temp);
    gdouble(code, c2, c, temp);

    // s0 = a2 ^ b2 ^ b ^ c ^ d;
    Reg s0_out = code.allocateReg(1);
    code.move(s0_out, a2);
    code.logxor(s0_out, b2);
    code.logxor(s0_out, b);
    code.logxor(s0_out, c);
    code.logxor(s0_out, d);

    // s1 = a ^ b2 ^ c2 ^ c ^ d;
    Reg s1_out = code.allocateReg(1);
    code.move(s1_out, a);
    code.logxor(s1_out, b2);
    code.logxor(s1_out, c2);
    code.logxor(s1_out, c);
    code.logxor(s1_out, d);

    // Can discard b2 now and reuse the register for d2.
    Reg d2 = b2;
    gdouble(code, d2, d, temp);

    // s2 = a ^ b ^ c2 ^ d2 ^ d;
    Reg s2_out = temp;
    code.move(s2_out, a);
    code.logxor(s2_out, b);
    code.logxor(s2_out, c2);
    code.logxor(s2_out, d2);
    code.logxor(s2_out, d);

    // s3 = a2 ^ a ^ b ^ c ^ d2;
    code.move(d, a2);
    code.logxor(d, a);
    code.logxor(d, b);
    code.logxor(d, c);
    code.logxor(d, d2);

    // Move the final s0, s1, and s2 values into place.
    code.move(a, s0_out);
    code.move(b, s1_out);
    code.move(c, s2_out);

    // Release all temporary registers.
    code.releaseReg(a2);
    code.releaseReg(b2);
    code.releaseReg(c2);
    code.releaseReg(s0_out);
    code.releaseReg(s1_out);
}

void gen_aes_ecb_encrypt(Code &code)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    // X will point to the input and Z points to the key schedule.
    code.prologue_encrypt_block("aes_ecb_encrypt", 0);

    // Allocate the registers that we need.
    Reg temp1 = code.allocateHighReg(1);
    Reg temp2 = code.allocateHighReg(1);
    Reg state = code.allocateReg(16);

    // Load the state into registers.
    code.ldx(state, POST_INC);

    // Transfer the key schedule to the X pointer and load the S-box pointer.
    code.move(Reg::x_ptr(), Reg::z_ptr());
    code.add_ptr_z(240);
    code.ldz(temp1, 0);
    code.sbox_setup(0, get_aes_sbox(), temp2);

    // XOR the state with the first round key.
    applyRoundKey(code, state, temp2);
    code.releaseReg(temp2);
    temp2 = Reg();

    // Determine the number of rounds to perform and skip ahead.
    unsigned char rounds_10 = 0;
    unsigned char rounds_12 = 0;
    code.compare(temp1, 10);
    code.breq(rounds_10);
    code.compare(temp1, 12);
    code.breq(rounds_12);

    // Unroll the outer part of the round loop.
    unsigned char subroutine = 0;
    unsigned char end_label = 0;
    for (int round = 0; round < 13; ++round) {
        if (round == 2)
            code.label(rounds_12);
        if (round == 4)
            code.label(rounds_10);
        code.call(subroutine);
    }
    subBytesAndShiftRows(code, state, temp1);
    applyRoundKey(code, state, temp1);
    code.jmp(end_label);

    // Subroutine for performing a main round.
    code.label(subroutine);
    subBytesAndShiftRows(code, state, temp1);
    mixColumn(code, state, 0, temp1);
    mixColumn(code, state, 1, temp1);
    mixColumn(code, state, 2, temp1);
    mixColumn(code, state, 3, temp1);
    applyRoundKey(code, state, temp1);
    code.ret();

    // Store the state to the output buffer.
    code.label(end_label);
    code.sbox_cleanup();
    code.load_output_ptr();
    code.stx(state, POST_INC);
}

// Test vectors for AES.
static unsigned char const aes_key[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static unsigned char const aes_128_key_schedule[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0xd6, 0xaa, 0x74, 0xfd, 0xd2, 0xaf, 0x72, 0xfa,
    0xda, 0xa6, 0x78, 0xf1, 0xd6, 0xab, 0x76, 0xfe, 0xb6, 0x92, 0xcf, 0x0b,
    0x64, 0x3d, 0xbd, 0xf1, 0xbe, 0x9b, 0xc5, 0x00, 0x68, 0x30, 0xb3, 0xfe,
    0xb6, 0xff, 0x74, 0x4e, 0xd2, 0xc2, 0xc9, 0xbf, 0x6c, 0x59, 0x0c, 0xbf,
    0x04, 0x69, 0xbf, 0x41, 0x47, 0xf7, 0xf7, 0xbc, 0x95, 0x35, 0x3e, 0x03,
    0xf9, 0x6c, 0x32, 0xbc, 0xfd, 0x05, 0x8d, 0xfd, 0x3c, 0xaa, 0xa3, 0xe8,
    0xa9, 0x9f, 0x9d, 0xeb, 0x50, 0xf3, 0xaf, 0x57, 0xad, 0xf6, 0x22, 0xaa,
    0x5e, 0x39, 0x0f, 0x7d, 0xf7, 0xa6, 0x92, 0x96, 0xa7, 0x55, 0x3d, 0xc1,
    0x0a, 0xa3, 0x1f, 0x6b, 0x14, 0xf9, 0x70, 0x1a, 0xe3, 0x5f, 0xe2, 0x8c,
    0x44, 0x0a, 0xdf, 0x4d, 0x4e, 0xa9, 0xc0, 0x26, 0x47, 0x43, 0x87, 0x35,
    0xa4, 0x1c, 0x65, 0xb9, 0xe0, 0x16, 0xba, 0xf4, 0xae, 0xbf, 0x7a, 0xd2,
    0x54, 0x99, 0x32, 0xd1, 0xf0, 0x85, 0x57, 0x68, 0x10, 0x93, 0xed, 0x9c,
    0xbe, 0x2c, 0x97, 0x4e, 0x13, 0x11, 0x1d, 0x7f, 0xe3, 0x94, 0x4a, 0x17,
    0xf3, 0x07, 0xa7, 0x8b, 0x4d, 0x2b, 0x30, 0xc5, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0x0a, 0x00, 0x00, 0x00
};
static unsigned char const aes_192_key_schedule[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x58, 0x46, 0xf2, 0xf9, 0x5c, 0x43, 0xf4, 0xfe, 0x54, 0x4a, 0xfe, 0xf5,
    0x58, 0x47, 0xf0, 0xfa, 0x48, 0x56, 0xe2, 0xe9, 0x5c, 0x43, 0xf4, 0xfe,
    0x40, 0xf9, 0x49, 0xb3, 0x1c, 0xba, 0xbd, 0x4d, 0x48, 0xf0, 0x43, 0xb8,
    0x10, 0xb7, 0xb3, 0x42, 0x58, 0xe1, 0x51, 0xab, 0x04, 0xa2, 0xa5, 0x55,
    0x7e, 0xff, 0xb5, 0x41, 0x62, 0x45, 0x08, 0x0c, 0x2a, 0xb5, 0x4b, 0xb4,
    0x3a, 0x02, 0xf8, 0xf6, 0x62, 0xe3, 0xa9, 0x5d, 0x66, 0x41, 0x0c, 0x08,
    0xf5, 0x01, 0x85, 0x72, 0x97, 0x44, 0x8d, 0x7e, 0xbd, 0xf1, 0xc6, 0xca,
    0x87, 0xf3, 0x3e, 0x3c, 0xe5, 0x10, 0x97, 0x61, 0x83, 0x51, 0x9b, 0x69,
    0x34, 0x15, 0x7c, 0x9e, 0xa3, 0x51, 0xf1, 0xe0, 0x1e, 0xa0, 0x37, 0x2a,
    0x99, 0x53, 0x09, 0x16, 0x7c, 0x43, 0x9e, 0x77, 0xff, 0x12, 0x05, 0x1e,
    0xdd, 0x7e, 0x0e, 0x88, 0x7e, 0x2f, 0xff, 0x68, 0x60, 0x8f, 0xc8, 0x42,
    0xf9, 0xdc, 0xc1, 0x54, 0x85, 0x9f, 0x5f, 0x23, 0x7a, 0x8d, 0x5a, 0x3d,
    0xc0, 0xc0, 0x29, 0x52, 0xbe, 0xef, 0xd6, 0x3a, 0xde, 0x60, 0x1e, 0x78,
    0x27, 0xbc, 0xdf, 0x2c, 0xa2, 0x23, 0x80, 0x0f, 0xd8, 0xae, 0xda, 0x32,
    0xa4, 0x97, 0x0a, 0x33, 0x1a, 0x78, 0xdc, 0x09, 0xc4, 0x18, 0xc2, 0x71,
    0xe3, 0xa4, 0x1d, 0x5d, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0x0c, 0x00, 0x00, 0x00
};
static unsigned char const aes_256_key_schedule[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0xa5, 0x73, 0xc2, 0x9f,
    0xa1, 0x76, 0xc4, 0x98, 0xa9, 0x7f, 0xce, 0x93, 0xa5, 0x72, 0xc0, 0x9c,
    0x16, 0x51, 0xa8, 0xcd, 0x02, 0x44, 0xbe, 0xda, 0x1a, 0x5d, 0xa4, 0xc1,
    0x06, 0x40, 0xba, 0xde, 0xae, 0x87, 0xdf, 0xf0, 0x0f, 0xf1, 0x1b, 0x68,
    0xa6, 0x8e, 0xd5, 0xfb, 0x03, 0xfc, 0x15, 0x67, 0x6d, 0xe1, 0xf1, 0x48,
    0x6f, 0xa5, 0x4f, 0x92, 0x75, 0xf8, 0xeb, 0x53, 0x73, 0xb8, 0x51, 0x8d,
    0xc6, 0x56, 0x82, 0x7f, 0xc9, 0xa7, 0x99, 0x17, 0x6f, 0x29, 0x4c, 0xec,
    0x6c, 0xd5, 0x59, 0x8b, 0x3d, 0xe2, 0x3a, 0x75, 0x52, 0x47, 0x75, 0xe7,
    0x27, 0xbf, 0x9e, 0xb4, 0x54, 0x07, 0xcf, 0x39, 0x0b, 0xdc, 0x90, 0x5f,
    0xc2, 0x7b, 0x09, 0x48, 0xad, 0x52, 0x45, 0xa4, 0xc1, 0x87, 0x1c, 0x2f,
    0x45, 0xf5, 0xa6, 0x60, 0x17, 0xb2, 0xd3, 0x87, 0x30, 0x0d, 0x4d, 0x33,
    0x64, 0x0a, 0x82, 0x0a, 0x7c, 0xcf, 0xf7, 0x1c, 0xbe, 0xb4, 0xfe, 0x54,
    0x13, 0xe6, 0xbb, 0xf0, 0xd2, 0x61, 0xa7, 0xdf, 0xf0, 0x1a, 0xfa, 0xfe,
    0xe7, 0xa8, 0x29, 0x79, 0xd7, 0xa5, 0x64, 0x4a, 0xb3, 0xaf, 0xe6, 0x40,
    0x25, 0x41, 0xfe, 0x71, 0x9b, 0xf5, 0x00, 0x25, 0x88, 0x13, 0xbb, 0xd5,
    0x5a, 0x72, 0x1c, 0x0a, 0x4e, 0x5a, 0x66, 0x99, 0xa9, 0xf2, 0x4f, 0xe0,
    0x7e, 0x57, 0x2b, 0xaa, 0xcd, 0xf8, 0xcd, 0xea, 0x24, 0xfc, 0x79, 0xcc,
    0xbf, 0x09, 0x79, 0xe9, 0x37, 0x1a, 0xc2, 0x3c, 0x6d, 0x68, 0xde, 0x36,
    0x0e, 0x00, 0x00, 0x00
};
static unsigned char const aes_plaintext[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};
static unsigned char const aes_128_ciphertext[] = {
    0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30,
    0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A
};
static unsigned char const aes_192_ciphertext[] = {
    0xDD, 0xA9, 0x7C, 0xA4, 0x86, 0x4C, 0xDF, 0xE0,
    0x6E, 0xAF, 0x70, 0xA0, 0xEC, 0x0D, 0x71, 0x91
};
static unsigned char const aes_256_ciphertext[] = {
    0x8E, 0xA2, 0xB7, 0xCA, 0x51, 0x67, 0x45, 0xBF,
    0xEA, 0xFC, 0x49, 0x90, 0x4B, 0x49, 0x60, 0x89
};

bool test_aes128_setup_key(Code &code)
{
    unsigned char schedule[sizeof(aes_128_key_schedule)];
    code.exec_setup_key(schedule, sizeof(schedule), aes_key, 16);
    if (memcmp(schedule, aes_128_key_schedule, sizeof(schedule)) != 0)
        return false;
    return true;
}

bool test_aes192_setup_key(Code &code)
{
    unsigned char schedule[sizeof(aes_192_key_schedule)];
    code.exec_setup_key(schedule, sizeof(schedule), aes_key, 24);
    if (memcmp(schedule, aes_192_key_schedule, sizeof(schedule)) != 0)
        return false;
    return true;
}

bool test_aes256_setup_key(Code &code)
{
    unsigned char schedule[sizeof(aes_256_key_schedule)];
    code.exec_setup_key(schedule, sizeof(schedule), aes_key, 32);
    if (memcmp(schedule, aes_256_key_schedule, sizeof(schedule)) != 0)
        return false;
    return true;
}

bool test_aes_ecb_encrypt(Code &code)
{
    unsigned char output[16];
    bool ok = true;

    code.exec_encrypt_block(aes_128_key_schedule, sizeof(aes_128_key_schedule),
                            output, sizeof(output),
                            aes_plaintext, sizeof(aes_plaintext));
    if (memcmp(output, aes_128_ciphertext, sizeof(output)) != 0)
        ok = false;

    code.exec_encrypt_block(aes_192_key_schedule, sizeof(aes_192_key_schedule),
                            output, sizeof(output),
                            aes_plaintext, sizeof(aes_plaintext));
    if (memcmp(output, aes_192_ciphertext, sizeof(output)) != 0)
        ok = false;

    code.exec_encrypt_block(aes_256_key_schedule, sizeof(aes_256_key_schedule),
                            output, sizeof(output),
                            aes_plaintext, sizeof(aes_plaintext));
    if (memcmp(output, aes_256_ciphertext, sizeof(output)) != 0)
        ok = false;

    return ok;
}
