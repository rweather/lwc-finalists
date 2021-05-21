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

/* Very basic test harness for verifying that a SUPERCOP AEAD algorithm
 * can be compiled and also generates KAT vectors for it on stdout. */

#include "api.h"
#include "crypto_aead.h"
#include <stdio.h>
#include <string.h>

static void set_vec(unsigned char *vec, unsigned size)
{
    unsigned index;
    for (index = 0; index < size; ++index)
        vec[index] = (unsigned char)index;
}

static void print_vec(const char *name, const unsigned char *vec, unsigned size)
{
    printf("%s = ", name);
    while (size > 0) {
        printf("%02X", vec[0]);
        ++vec;
        --size;
    }
    printf("\n");
}

static int gen_kat_aead(unsigned mlen, unsigned adlen)
{
    unsigned char k[CRYPTO_KEYBYTES];
    unsigned char npub[CRYPTO_NPUBBYTES];
    unsigned char m[mlen];
    unsigned char p[mlen];
    unsigned char ad[adlen];
    unsigned char c[mlen + CRYPTO_ABYTES];
    unsigned long long clen = 1000000ULL;
    unsigned long long plen = 1000000ULL;
    int result;

    set_vec(k, CRYPTO_KEYBYTES);
    set_vec(npub, CRYPTO_NPUBBYTES);
    set_vec(m, mlen);
    set_vec(ad, adlen);

    memset(c, 0xAA, mlen + CRYPTO_ABYTES);
    result = crypto_aead_encrypt(c, &clen, m, mlen, ad, adlen, 0, npub, k);
    if (result != 0)
        return 0;
    if (clen != (mlen + CRYPTO_ABYTES))
        return 0;

    memset(p, 0x55, mlen);
    result = crypto_aead_decrypt(p, &plen, 0, c, clen, ad, adlen, npub, k);
    if (result != 0)
        return 0;
    if (plen != mlen)
        return 0;
    if (memcmp(p, m, mlen) != 0)
        return 0;

    print_vec("Key", k, CRYPTO_KEYBYTES);
    print_vec("Nonce", npub, CRYPTO_NPUBBYTES);
    print_vec("PT", m, mlen);
    print_vec("AD", ad, adlen);
    print_vec("CT", c, clen);

    return 1;
}

int main(int argc, char *argv[])
{
    unsigned mlen, adlen;
    unsigned count = 1;
    int exit_val = 0;
    (void)argc;
    (void)argv;
    for (mlen = 0; mlen <= 32; ++mlen) {
        for (adlen = 0; adlen <= 32; ++adlen) {
            printf("Count = %u\n", count++);
            if (!gen_kat_aead(mlen, adlen)) {
                fprintf(stderr, "vector %u failed\n", count - 1);
                exit_val = 1;
            }
            printf("\n");
        }
    }
    return exit_val;
}
