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

#include "internal-sha256.h"
#include "test-cipher.h"
#include <stdio.h>
#include <string.h>

#define SHA256_HASH_SIZE 32

typedef struct
{
    const char *name;
    const char *key;
    const char *data;
    uint8_t hash[SHA256_HASH_SIZE];

} TestHashVector;

static TestHashVector const testVectorSHA256_1 = {
    "Test Vector 1",
    "",
    "",
    {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
     0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
     0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
     0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55}
};
static TestHashVector const testVectorSHA256_2 = {
    "Test Vector 2",
    "",
    "abc",
    {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
     0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
     0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
     0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad}
};
static TestHashVector const testVectorSHA256_3 = {
    "Test Vector 3",
    "",
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    {0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
     0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
     0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
     0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1}
};
static TestHashVector const testVectorHMAC_SHA256_1 = {
    "HMAC Test Vector 1",
    "",
    "",
    {0xb6, 0x13, 0x67, 0x9a, 0x08, 0x14, 0xd9, 0xec,
     0x77, 0x2f, 0x95, 0xd7, 0x78, 0xc3, 0x5f, 0xc5,
     0xff, 0x16, 0x97, 0xc4, 0x93, 0x71, 0x56, 0x53,
     0xc6, 0xc7, 0x12, 0x14, 0x42, 0x92, 0xc5, 0xad}
};
static TestHashVector const testVectorHMAC_SHA256_2 = {
    "HMAC Test Vector 2",
    "key",
    "The quick brown fox jumps over the lazy dog",
    {0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24,
     0xb1, 0x32, 0x98, 0xe6, 0xaa, 0x6f, 0xb1, 0x43,
     0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46, 0x17, 0x59,
     0x97, 0x47, 0x9d, 0xbc, 0x2d, 0x1a, 0x3c, 0xd8}
};
static TestHashVector const testVectorHMAC_SHA256_3 = {
    "HMAC Test Vector 3",
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    {0x8e, 0xd0, 0x8e, 0x42, 0x02, 0xbd, 0xbe, 0x20,
     0xda, 0xc8, 0x50, 0x92, 0xb8, 0xc4, 0xe0, 0xc4,
     0x07, 0xa7, 0x02, 0xd7, 0xbc, 0x6a, 0x6c, 0x05,
     0xe0, 0x15, 0x9a, 0x1d, 0x7b, 0xab, 0x8f, 0x4f}
};

static int test_sha256_vector_inner(const TestHashVector *test_vector)
{
    unsigned char out[SHA256_HASH_SIZE];
    int result;
    memset(out, 0xAA, sizeof(out));
    result = internal_sha256_hash
        (out, (unsigned char *)(test_vector->data),
         strlen(test_vector->data));
    if (result != 0 ||
            test_memcmp(out, test_vector->hash, SHA256_HASH_SIZE) != 0)
        return 0;
    return 1;
}

static void test_sha256_vector(const TestHashVector *test_vector)
{
    printf("    %s ... ", test_vector->name);
    fflush(stdout);

    if (test_sha256_vector_inner(test_vector)) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }
}

/* We test HMAC-SHA256 so that we can validate the templated
 * implementation in the "internal-hmac.h" file to make sure that
 * it is algorithmically correct against public test vectors. */
static int test_sha256_hmac_vector_inner(const TestHashVector *test_vector)
{
    unsigned char out[SHA256_HASH_SIZE];
    unsigned len;
    sha256_state_t state;

    /* Test the all-in-one HMAC function */
    memset(out, 0xAA, sizeof(out));
    internal_sha256_hmac
        (out, (unsigned char *)(test_vector->key),
         strlen(test_vector->key),
         (unsigned char *)(test_vector->data),
         strlen(test_vector->data));
    if (test_memcmp(out, test_vector->hash, SHA256_HASH_SIZE) != 0)
        return 0;

    /* Test the incremental HMAC functions */
    memset(out, 0xAA, sizeof(out));
    internal_sha256_hmac_init
        (&state, (unsigned char *)(test_vector->key),
         strlen(test_vector->key));
    len = strlen(test_vector->data);
    internal_sha256_hmac_update
        (&state, (unsigned char *)(test_vector->data), len / 2);
    internal_sha256_hmac_update
        (&state, ((unsigned char *)(test_vector->data)) + len / 2,
         len - (len / 2));
    internal_sha256_hmac_finalize
        (&state, (unsigned char *)(test_vector->key),
         strlen(test_vector->key), out);
    if (test_memcmp(out, test_vector->hash, SHA256_HASH_SIZE) != 0)
        return 0;

    return 1;
}

static void test_sha256_hmac_vector(const TestHashVector *test_vector)
{
    printf("    %s ... ", test_vector->name);
    fflush(stdout);

    if (test_sha256_hmac_vector_inner(test_vector)) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }
}

void test_sha256(void)
{
    printf("SHA256:\n");

    test_sha256_vector(&testVectorSHA256_1);
    test_sha256_vector(&testVectorSHA256_2);
    test_sha256_vector(&testVectorSHA256_3);

    test_sha256_hmac_vector(&testVectorHMAC_SHA256_1);
    test_sha256_hmac_vector(&testVectorHMAC_SHA256_2);
    test_sha256_hmac_vector(&testVectorHMAC_SHA256_3);

    printf("\n");
}
