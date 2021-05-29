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

#include "test-cipher.h"
#include "aead-random.h"

void test_aes(void);
void test_aesgcm(void);
void test_ascon(void);
void test_blake2s(void);
void test_chachapoly(void);
void test_ghash(void);
void test_gift128(void);
void test_gift128_masked(void);
void test_grain128(void);
void test_hkdf(void);
void test_hmac(void);
void test_keccak(void);
void test_kmac(void);
void test_masking(void);
void test_pbkdf2(void);
void test_photon256(void);
void test_romulus_xof(void);
void test_sha256(void);
void test_sha3(void);
void test_skinny128(void);
void test_sparkle(void);
void test_spongent(void);
void test_tinyjambu(void);
void test_xoodoo(void);

int main(int argc, char *argv[])
{
    aead_random_init();
    test_aes();
    test_aesgcm();
    test_ascon();
    test_blake2s();
    test_chachapoly();
    test_ghash();
    test_gift128();
    test_gift128_masked();
    test_grain128();
    test_hkdf();
    test_hmac();
    test_keccak();
    test_kmac();
    test_masking();
    test_pbkdf2();
    test_photon256();
    test_romulus_xof();
    test_sha256();
    test_sha3();
    test_skinny128();
    test_sparkle();
    test_spongent();
    test_tinyjambu();
    test_xoodoo();
    return test_exit_result;
}
