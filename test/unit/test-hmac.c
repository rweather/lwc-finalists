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

#include "aead-metadata.h"
#include "ascon-hmac.h"
#include "photon-beetle-hmac.h"
#include "romulus-hmac.h"
#include "sparkle-hmac.h"
#include "xoodyak-hmac.h"
#include "test-cipher.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct
{
    const char *name;
    const char *key;
    const char *data;

} TestHMACVector;

static TestHMACVector const testVectorHMAC_1 = {
    "HMAC Test Vector 1",
    "",
    ""
};
static TestHMACVector const testVectorHMAC_2 = {
    "HMAC Test Vector 2",
    "key",
    "The quick brown fox jumps over the lazy dog"
};
static TestHMACVector const testVectorHMAC_3 = {
    "HMAC Test Vector 3",
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
};

typedef void (*hmac_func_t)
    (unsigned char *out,
     const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen);

/* Simple implementation of HMAC for a hash algorithm to cross-check
 * the fancier version in the library. */
static void hmac
    (const aead_hash_algorithm_t *alg, unsigned char *out,
     unsigned hmac_size, unsigned block_size,
     const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen)
{
    unsigned char block[block_size];
    void *state;
    unsigned index;

    /* We need some memory for a hashing context */
    state = malloc(alg->state_size);
    if (!state)
        exit(1);

    /* Format the inner key block and hash it */
    if (keylen <= block_size) {
        memcpy(block, key, keylen);
        memset(block + keylen, 0, block_size - keylen);
    } else {
        (*(alg->hash))(block, key, keylen);
        memset(block + hmac_size, 0, block_size - hmac_size);
    }
    for (index = 0; index < block_size; ++index)
        block[index] ^= 0x36;
    (*(alg->init))(state);
    (*(alg->update))(state, block, block_size);

    /* Hash the input data and finalize the inner layer */
    (*(alg->update))(state, in, inlen);
    (*(alg->finalize))(state, out);

    /* Format the outer key block and hash it */
    for (index = 0; index < block_size; ++index)
        block[index] ^= (0x36 ^ 0x5C);
    (*(alg->init))(state);
    (*(alg->update))(state, block, block_size);

    /* Add the inner hash value and finalize */
    (*(alg->update))(state, out, hmac_size);
    (*(alg->finalize))(state, out);

    /* Clean up */
    free(state);
}

static void test_hmac_vector
    (const aead_hash_algorithm_t *alg, const char *name,
     hmac_func_t func, const TestHMACVector *test_vector,
     unsigned hmac_size, unsigned block_size)
{
    unsigned char expected[hmac_size];
    unsigned char actual[hmac_size];

    printf("    %s-%s ... ", name, test_vector->name);
    fflush(stdout);

    hmac(alg, expected, hmac_size, block_size,
         (const unsigned char *)(test_vector->key),
         strlen(test_vector->key),
         (const unsigned char *)(test_vector->data),
         strlen(test_vector->data));

    (*func)(actual,
            (const unsigned char *)(test_vector->key),
            strlen(test_vector->key),
            (const unsigned char *)(test_vector->data),
            strlen(test_vector->data));

    if (!test_memcmp(actual, expected, hmac_size)) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }
}

void test_hmac(void)
{
    printf("HMAC:\n");

    test_hmac_vector
        (&ascon_hash_algorithm, "ASCON", ascon_hmac,
         &testVectorHMAC_1, 32, 64);
    test_hmac_vector
        (&ascon_hash_algorithm, "ASCON", ascon_hmac,
         &testVectorHMAC_2, 32, 64);
    test_hmac_vector
        (&ascon_hash_algorithm, "ASCON", ascon_hmac,
         &testVectorHMAC_3, 32, 64);

    test_hmac_vector
        (&esch_256_hash_algorithm, "Esch256", esch_256_hmac,
         &testVectorHMAC_1, 32, 64);
    test_hmac_vector
        (&esch_256_hash_algorithm, "Esch256", esch_256_hmac,
         &testVectorHMAC_2, 32, 64);
    test_hmac_vector
        (&esch_256_hash_algorithm, "Esch256", esch_256_hmac,
         &testVectorHMAC_3, 32, 64);

    test_hmac_vector
        (&esch_384_hash_algorithm, "Esch384", esch_384_hmac,
         &testVectorHMAC_1, 48, 128);
    test_hmac_vector
        (&esch_384_hash_algorithm, "Esch384", esch_384_hmac,
         &testVectorHMAC_2, 48, 128);
    test_hmac_vector
        (&esch_384_hash_algorithm, "Esch384", esch_384_hmac,
         &testVectorHMAC_3, 48, 128);

    test_hmac_vector
        (&photon_beetle_hash_algorithm, "PHOTON-Beetle", photon_beetle_hmac,
         &testVectorHMAC_1, 32, 64);
    test_hmac_vector
        (&photon_beetle_hash_algorithm, "PHOTON-Beetle", photon_beetle_hmac,
         &testVectorHMAC_2, 32, 64);
    test_hmac_vector
        (&photon_beetle_hash_algorithm, "PHOTON-Beetle", photon_beetle_hmac,
         &testVectorHMAC_3, 32, 64);

    test_hmac_vector
        (&romulus_hash_algorithm, "Romulus", romulus_hmac,
         &testVectorHMAC_1, 32, 64);
    test_hmac_vector
        (&romulus_hash_algorithm, "Romulus", romulus_hmac,
         &testVectorHMAC_2, 32, 64);
    test_hmac_vector
        (&romulus_hash_algorithm, "Romulus", romulus_hmac,
         &testVectorHMAC_3, 32, 64);

    test_hmac_vector
        (&xoodyak_hash_algorithm, "Xoodyak", xoodyak_hmac,
         &testVectorHMAC_1, 32, 64);
    test_hmac_vector
        (&xoodyak_hash_algorithm, "Xoodyak", xoodyak_hmac,
         &testVectorHMAC_2, 32, 64);
    test_hmac_vector
        (&xoodyak_hash_algorithm, "Xoodyak", xoodyak_hmac,
         &testVectorHMAC_3, 32, 64);

    printf("\n");
}
