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

#include "internal-chachapoly.h"
#include "test-cipher.h"
#include <stdio.h>
#include <string.h>

#define MAX_PLAINTEXT_LEN 265

typedef struct
{
    const char *name;
    uint8_t key[32];
    uint8_t plaintext[MAX_PLAINTEXT_LEN];
    uint8_t ciphertext[MAX_PLAINTEXT_LEN + CHACHAPOLY_TAG_SIZE];
    uint8_t authdata[16];
    uint8_t nonce[16];
    size_t authsize;
    size_t datasize;
    size_t noncesize;

} TestVector;

/* Test vector for ChaChaPoly from draft-nir-cfrg-chacha20-poly1305-04.txt */
static TestVector const testVectorChaChaPoly_1 = {
    "Test Vector 1",
    {0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a,    /* key */
     0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
     0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09,
     0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0},
    {0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74,    /* plaintext */
     0x2d, 0x44, 0x72, 0x61, 0x66, 0x74, 0x73, 0x20,
     0x61, 0x72, 0x65, 0x20, 0x64, 0x72, 0x61, 0x66,
     0x74, 0x20, 0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65,
     0x6e, 0x74, 0x73, 0x20, 0x76, 0x61, 0x6c, 0x69,
     0x64, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x61, 0x20,
     0x6d, 0x61, 0x78, 0x69, 0x6d, 0x75, 0x6d, 0x20,
     0x6f, 0x66, 0x20, 0x73, 0x69, 0x78, 0x20, 0x6d,
     0x6f, 0x6e, 0x74, 0x68, 0x73, 0x20, 0x61, 0x6e,
     0x64, 0x20, 0x6d, 0x61, 0x79, 0x20, 0x62, 0x65,
     0x20, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64,
     0x2c, 0x20, 0x72, 0x65, 0x70, 0x6c, 0x61, 0x63,
     0x65, 0x64, 0x2c, 0x20, 0x6f, 0x72, 0x20, 0x6f,
     0x62, 0x73, 0x6f, 0x6c, 0x65, 0x74, 0x65, 0x64,
     0x20, 0x62, 0x79, 0x20, 0x6f, 0x74, 0x68, 0x65,
     0x72, 0x20, 0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65,
     0x6e, 0x74, 0x73, 0x20, 0x61, 0x74, 0x20, 0x61,
     0x6e, 0x79, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x2e,
     0x20, 0x49, 0x74, 0x20, 0x69, 0x73, 0x20, 0x69,
     0x6e, 0x61, 0x70, 0x70, 0x72, 0x6f, 0x70, 0x72,
     0x69, 0x61, 0x74, 0x65, 0x20, 0x74, 0x6f, 0x20,
     0x75, 0x73, 0x65, 0x20, 0x49, 0x6e, 0x74, 0x65,
     0x72, 0x6e, 0x65, 0x74, 0x2d, 0x44, 0x72, 0x61,
     0x66, 0x74, 0x73, 0x20, 0x61, 0x73, 0x20, 0x72,
     0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65,
     0x20, 0x6d, 0x61, 0x74, 0x65, 0x72, 0x69, 0x61,
     0x6c, 0x20, 0x6f, 0x72, 0x20, 0x74, 0x6f, 0x20,
     0x63, 0x69, 0x74, 0x65, 0x20, 0x74, 0x68, 0x65,
     0x6d, 0x20, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x20,
     0x74, 0x68, 0x61, 0x6e, 0x20, 0x61, 0x73, 0x20,
     0x2f, 0xe2, 0x80, 0x9c, 0x77, 0x6f, 0x72, 0x6b,
     0x20, 0x69, 0x6e, 0x20, 0x70, 0x72, 0x6f, 0x67,
     0x72, 0x65, 0x73, 0x73, 0x2e, 0x2f, 0xe2, 0x80,
     0x9d},
    {0x64, 0xa0, 0x86, 0x15, 0x75, 0x86, 0x1a, 0xf4,    /* ciphertext */
     0x60, 0xf0, 0x62, 0xc7, 0x9b, 0xe6, 0x43, 0xbd,
     0x5e, 0x80, 0x5c, 0xfd, 0x34, 0x5c, 0xf3, 0x89,
     0xf1, 0x08, 0x67, 0x0a, 0xc7, 0x6c, 0x8c, 0xb2,
     0x4c, 0x6c, 0xfc, 0x18, 0x75, 0x5d, 0x43, 0xee,
     0xa0, 0x9e, 0xe9, 0x4e, 0x38, 0x2d, 0x26, 0xb0,
     0xbd, 0xb7, 0xb7, 0x3c, 0x32, 0x1b, 0x01, 0x00,
     0xd4, 0xf0, 0x3b, 0x7f, 0x35, 0x58, 0x94, 0xcf,
     0x33, 0x2f, 0x83, 0x0e, 0x71, 0x0b, 0x97, 0xce,
     0x98, 0xc8, 0xa8, 0x4a, 0xbd, 0x0b, 0x94, 0x81,
     0x14, 0xad, 0x17, 0x6e, 0x00, 0x8d, 0x33, 0xbd,
     0x60, 0xf9, 0x82, 0xb1, 0xff, 0x37, 0xc8, 0x55,
     0x97, 0x97, 0xa0, 0x6e, 0xf4, 0xf0, 0xef, 0x61,
     0xc1, 0x86, 0x32, 0x4e, 0x2b, 0x35, 0x06, 0x38,
     0x36, 0x06, 0x90, 0x7b, 0x6a, 0x7c, 0x02, 0xb0,
     0xf9, 0xf6, 0x15, 0x7b, 0x53, 0xc8, 0x67, 0xe4,
     0xb9, 0x16, 0x6c, 0x76, 0x7b, 0x80, 0x4d, 0x46,
     0xa5, 0x9b, 0x52, 0x16, 0xcd, 0xe7, 0xa4, 0xe9,
     0x90, 0x40, 0xc5, 0xa4, 0x04, 0x33, 0x22, 0x5e,
     0xe2, 0x82, 0xa1, 0xb0, 0xa0, 0x6c, 0x52, 0x3e,
     0xaf, 0x45, 0x34, 0xd7, 0xf8, 0x3f, 0xa1, 0x15,
     0x5b, 0x00, 0x47, 0x71, 0x8c, 0xbc, 0x54, 0x6a,
     0x0d, 0x07, 0x2b, 0x04, 0xb3, 0x56, 0x4e, 0xea,
     0x1b, 0x42, 0x22, 0x73, 0xf5, 0x48, 0x27, 0x1a,
     0x0b, 0xb2, 0x31, 0x60, 0x53, 0xfa, 0x76, 0x99,
     0x19, 0x55, 0xeb, 0xd6, 0x31, 0x59, 0x43, 0x4e,
     0xce, 0xbb, 0x4e, 0x46, 0x6d, 0xae, 0x5a, 0x10,
     0x73, 0xa6, 0x72, 0x76, 0x27, 0x09, 0x7a, 0x10,
     0x49, 0xe6, 0x17, 0xd9, 0x1d, 0x36, 0x10, 0x94,
     0xfa, 0x68, 0xf0, 0xff, 0x77, 0x98, 0x71, 0x30,
     0x30, 0x5b, 0xea, 0xba, 0x2e, 0xda, 0x04, 0xdf,
     0x99, 0x7b, 0x71, 0x4d, 0x6c, 0x6f, 0x2c, 0x29,
     0xa6, 0xad, 0x5c, 0xb4, 0x02, 0x2b, 0x02, 0x70,
     0x9b, 0xee, 0xad, 0x9d, 0x67, 0x89, 0x0c, 0xbb,
     0x22, 0x39, 0x23, 0x36, 0xfe, 0xa1, 0x85, 0x1f,
     0x38},
    {0xf3, 0x33, 0x88, 0x86, 0x00, 0x00, 0x00, 0x00,    /* authdata */
     0x00, 0x00, 0x4e, 0x91},
    {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},   /* nonce */
    12,                                                 /* authsize */
    265,                                                /* datasize */
    8                                                   /* noncesize */
};

static int test_chachapoly_vector_inner
    (const aead_cipher_t *cipher, const TestVector *test_vector)
{
    unsigned char temp[MAX_PLAINTEXT_LEN + CHACHAPOLY_TAG_SIZE];
    unsigned char temp2[MAX_PLAINTEXT_LEN + CHACHAPOLY_TAG_SIZE];
    unsigned ciphertext_len = test_vector->datasize + cipher->tag_len;
    unsigned long long len;
    int result;

    /* Test encryption */
    memset(temp, 0xAA, sizeof(temp));
    len = 0xBADBEEF;
    result = (*(cipher->encrypt))
        (temp, &len, test_vector->plaintext, test_vector->datasize,
         test_vector->authdata, test_vector->authsize, 0, test_vector->nonce,
         test_vector->key);
    if (result != 0 || len != ciphertext_len ||
            test_memcmp(temp, test_vector->ciphertext, len) != 0) {
        printf("encryption ... ");
        return 0;
    }

    /* Test in-place encryption */
    memset(temp, 0xAA, sizeof(temp));
    memcpy(temp, test_vector->plaintext, test_vector->datasize);
    len = 0xBADBEEF;
    result = (*(cipher->encrypt))
        (temp, &len, temp, test_vector->datasize,
         test_vector->authdata, test_vector->authsize, 0, test_vector->nonce,
         test_vector->key);
    if (result != 0 || len != ciphertext_len ||
            test_memcmp(temp, test_vector->ciphertext, len) != 0) {
        printf("in-place encryption ... ");
        return 0;
    }

    /* Test decryption */
    memset(temp, 0xAA, sizeof(temp));
    len = 0xBADBEEF;
    result = (*(cipher->decrypt))
        (temp, &len, 0, test_vector->ciphertext, ciphertext_len,
         test_vector->authdata, test_vector->authsize, test_vector->nonce,
         test_vector->key);
    if (result != 0 || len != test_vector->datasize ||
            test_memcmp(temp, test_vector->plaintext, len) != 0) {
        printf("decryption ... ");
        return 0;
    }

    /* Test in-place decryption */
    memset(temp, 0xAA, sizeof(temp));
    memcpy(temp, test_vector->ciphertext, ciphertext_len);
    len = 0xBADBEEF;
    result = (*(cipher->decrypt))
        (temp, &len, 0, temp, ciphertext_len,
         test_vector->authdata, test_vector->authsize, test_vector->nonce,
         test_vector->key);
    if (result != 0 ||
            len != test_vector->datasize ||
            test_memcmp(temp, test_vector->plaintext, len) != 0) {
        printf("in-place decryption ... ");
        return 0;
    }

    /* Test decryption with a failed tag check */
    memset(temp, 0xAA, sizeof(temp));
    memcpy(temp2, test_vector->ciphertext, ciphertext_len);
    temp2[0] ^= 0x01; // Corrupt the first byte of the ciphertext.
    len = 0xBADBEEF;
    result = (*(cipher->decrypt))
        (temp, &len, 0, temp2, ciphertext_len,
         test_vector->authdata, test_vector->authsize, test_vector->nonce,
         test_vector->key);
    if (result != -1) {
        printf("corrupt data ... ");
        return 0;
    }
    memset(temp, 0xAA, sizeof(temp));
    memcpy(temp2, test_vector->ciphertext, ciphertext_len);
    temp2[test_vector->datasize] ^= 0x01; // Corrupt first byte of the tag.
    len = 0xBADBEEF;
    result = (*(cipher->decrypt))
        (temp, &len, 0, temp2, ciphertext_len,
         test_vector->authdata, test_vector->authsize, test_vector->nonce,
         test_vector->key);
    if (result != -1) {
        printf("corrupt tag ... ");
        return 0;
    }

    return 1;
}

static void test_chachapoly_vector
    (const aead_cipher_t *cipher, const TestVector *test_vector)
{
    printf("    %s ... ", test_vector->name);
    fflush(stdout);

    if (test_chachapoly_vector_inner(cipher, test_vector)) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }
}

void test_chachapoly(void)
{
    test_aead_cipher_start(&internal_chachapoly_cipher);
    test_chachapoly_vector
        (&internal_chachapoly_cipher, &testVectorChaChaPoly_1);
    test_aead_cipher_end(&internal_chachapoly_cipher);
}
