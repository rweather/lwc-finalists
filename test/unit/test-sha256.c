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

#define HASH_SIZE 32

typedef struct
{
    const char *name;
    const char *data;
    uint8_t hash[HASH_SIZE];

} TestHashVector;

static TestHashVector const testVectorSHA256_1 = {
    "Test Vector 1",
    "",
    {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
     0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
     0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
     0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55}
};
static TestHashVector const testVectorSHA256_2 = {
    "Test Vector 2",
    "abc",
    {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
     0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
     0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
     0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad}
};
static TestHashVector const testVectorSHA256_3 = {
    "Test Vector 3",
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    {0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
     0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
     0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
     0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1}
};

static int test_sha256_vector_inner(const TestHashVector *test_vector)
{
    unsigned char out[HASH_SIZE];
    int result;
    memset(out, 0xAA, sizeof(out));
    result = internal_sha256_hash
        (out, (unsigned char *)(test_vector->data),
         strlen(test_vector->data));
    if (result != 0 || test_memcmp(out, test_vector->hash, HASH_SIZE) != 0)
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

void test_sha256(void)
{
    printf("SHA256:\n");
    test_sha256_vector(&testVectorSHA256_1);
    test_sha256_vector(&testVectorSHA256_2);
    test_sha256_vector(&testVectorSHA256_3);
    printf("\n");
}
