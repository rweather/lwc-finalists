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
#include "ascon-kmac.h"
#include "romulus-kmac.h"
#include "sparkle-kmac.h"
#include "xoodyak-kmac.h"
#include "test-cipher.h"
#include "internal-util.h"
#include "test-sha3.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* KMAC is implemented as a generic template in "internal-kmac.h" and then
 * instantiated with a specific XOF algorithm.  To check that our template
 * has the correct structure, we instantiate with SHA3 and check some of
 * the test vectors for NIST.SP.800-185. */

/* Test vectors from: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMAC_samples.pdf */
static aead_mac_test_vector_t const testVectorNIST_1 = {
    "Test Vector 1",
    {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
     0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
     0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
     0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F},
    32,
    {0x00, 0x01, 0x02, 0x03},
    4,
    "",
    {0xE5, 0x78, 0x0B, 0x0D, 0x3E, 0xA6, 0xF7, 0xD3,
     0xA4, 0x29, 0xC5, 0x70, 0x6A, 0xA4, 0x3A, 0x00,
     0xFA, 0xDB, 0xD7, 0xD4, 0x96, 0x28, 0x83, 0x9E,
     0x31, 0x87, 0x24, 0x3F, 0x45, 0x6E, 0xE1, 0x4E},
    32
};
static aead_mac_test_vector_t const testVectorNIST_2 = {
    "Test Vector 2",
    {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
     0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
     0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
     0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F},
    32,
    {0x00, 0x01, 0x02, 0x03},
    4,
    "My Tagged Application",
    {0x3B, 0x1F, 0xBA, 0x96, 0x3C, 0xD8, 0xB0, 0xB5,
     0x9E, 0x8C, 0x1A, 0x6D, 0x71, 0x88, 0x8B, 0x71,
     0x43, 0x65, 0x1A, 0xF8, 0xBA, 0x0A, 0x70, 0x70,
     0xC0, 0x97, 0x9E, 0x28, 0x11, 0x32, 0x4A, 0xA5},
    32
};

/* Instantiate the standard NIST version of KMAC that uses SHA3 */
void nist_kmac
    (const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen,
     const unsigned char *custom, size_t customlen,
     unsigned char *out, size_t outlen);
void nist_kmac_init
    (sha3_state_t *state, const unsigned char *key, size_t keylen,
     const unsigned char *custom, size_t customlen);
void nist_kmac_absorb
    (sha3_state_t *state, const unsigned char *in, size_t inlen);
void nist_kmac_set_output_length(sha3_state_t *state, size_t outlen);
void nist_kmac_squeeze(sha3_state_t *state, unsigned char *out, size_t outlen);
#define KMAC_ALG_NAME nist_kmac
#define KMAC_SIZE 32
#define KMAC_STATE sha3_state_t
#define KMAC_RATE 168
#define KMAC_XOF_INIT cshake128_init
#define KMAC_XOF_ABSORB sha3_absorb
#define KMAC_XOF_SQUEEZE sha3_squeeze
#define KMAC_XOF_PAD sha3_pad
#define KMAC_XOF_IS_ABSORBING(state) ((state)->absorbing)
#include "internal-kmac.h"

/* Left-encoding of a bit count between 0 and 65535 */
static size_t left_encode_length
    (const aead_hash_algorithm_t *alg, void *state, size_t value)
{
    unsigned char buf[3];
    size_t len;
    if (value < 0x0100) {
        len = 2;
        buf[0] = 0x01;
        buf[1] = (unsigned char)value;
    } else {
        len = 3;
        buf[0] = 0x02;
        buf[1] = (unsigned char)(value >> 8);
        buf[2] = (unsigned char)value;
    }
    (*(alg->absorb))(state, buf, len);
    return len;
}

/* Right-encoding of a bit count between 0 and 65535 */
static size_t right_encode_length
    (const aead_hash_algorithm_t *alg, void *state, size_t value)
{
    unsigned char buf[3];
    size_t len;
    if (value < 0x0100) {
        len = 2;
        buf[0] = (unsigned char)value;
        buf[1] = 0x01;
    } else {
        len = 3;
        buf[0] = (unsigned char)(value >> 8);
        buf[1] = (unsigned char)value;
        buf[2] = 0x02;
    }
    (*(alg->absorb))(state, buf, len);
    return len;
}

/* Simple implementation of KMAC based on a configurable XOF algorithm
 * for cross-checking the implementation in the library */
static void simple_kmac
    (const aead_hash_algorithm_t *alg, unsigned rate,
     const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen,
     const unsigned char *custom, size_t customlen,
     unsigned char *out, size_t outlen)
{
    unsigned char prefix[8] = {
        0x01, (unsigned char)rate, 0x01, 0x20, 0x4B, 0x4D, 0x41, 0x43
    };
    unsigned char padding[rate];
    void *state;
    size_t len;

    /* Allocate space for the XOF state */
    state = malloc(alg->state_size);
    if (!state)
        exit(1);

    /* Initialize the XOF context with the KMAC prefix */
    (*(alg->init))(state);
    (*(alg->absorb))(state, prefix, sizeof(prefix));
    len = sizeof(prefix);

    /* Absorb the customization string and pad */
    len += left_encode_length(alg, state, customlen * 8);
    (*(alg->absorb))(state, custom, customlen);
    len += customlen;
    memset(padding, 0, rate);
    if ((len % rate) != 0) {
        (*(alg->absorb))(state, padding, rate - (len % rate));
        len = 0;
    }

    /* Absorb the key and pad */
    (*(alg->absorb))(state, prefix, 2);
    len += 2;
    len += left_encode_length(alg, state, keylen * 8);
    (*(alg->absorb))(state, key, keylen);
    len += keylen;
    if ((len % rate) != 0)
        (*(alg->absorb))(state, padding, rate - (len % rate));

    /* Absorb the input data */
    (*(alg->absorb))(state, in, inlen);

    /* Set the desired output length, right-encoded */
    right_encode_length(alg, state, outlen * 8);

    /* Squeeze out the result */
    (*(alg->squeeze))(state, out, outlen);

    /* Clean up */
    free(state);
}

static void test_nist_kmac(const aead_mac_test_vector_t *test)
{
    unsigned char out[AEAD_MAX_HASH_LEN];

    printf("    SHA3 KMAC %s ... ", test->name);
    fflush(stdout);

    /* Check the instantiation of "internal-kmac.h" */
    memset(out, 0xAA, sizeof(out));
    nist_kmac(test->key, test->key_len, test->input, test->input_len,
              (const unsigned char *)(test->salt),
              strlen(test->salt), out, test->output_len);

    if (!test_memcmp(out, test->output, test->output_len)) {
        /* Check the simple version of KMAC computation */
        memset(out, 0x66, sizeof(out));
        simple_kmac(&cshake128_xof_algorithm, 168,
                    test->key, test->key_len, test->input, test->input_len,
                    (const unsigned char *)(test->salt),
                    strlen(test->salt), out, test->output_len);
        if (!test_memcmp(out, test->output, test->output_len)) {
            printf("ok\n");
        } else {
            printf("failed\n");
            test_exit_result = 1;
        }
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }
}

typedef void (*kmac_allinone_t)
    (const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen,
     const unsigned char *custom, size_t customlen,
     unsigned char *out, size_t outlen);
typedef void (*kmac_init_t)
    (void *state, const unsigned char *key, size_t keylen,
     const unsigned char *custom, size_t customlen);
typedef void (*kmac_absorb_t)
    (void *state, const unsigned char *in, size_t inlen);
typedef void (*kmac_squeeze_t)
    (void *state, unsigned char *out, size_t outlen);
typedef void (*kmac_set_output_length_t)(void *state, size_t outlen);
typedef aead_hash_finalize_t kmac_finalize_t;

static void test_kmac_alg
    (const char *name, const aead_hash_algorithm_t *alg,
     unsigned rate, unsigned state_size,
     kmac_allinone_t allinone, kmac_init_t init,
     kmac_absorb_t absorb, kmac_squeeze_t squeeze,
     kmac_set_output_length_t setoutlen, kmac_finalize_t finalize,
     const aead_mac_test_vector_t *test)
{
    unsigned char expected[AEAD_MAX_HASH_LEN];
    unsigned char out[AEAD_MAX_HASH_LEN];
    void *state;
    int ok;

    printf("    %s %s ... ", name, test->name);
    fflush(stdout);

    /* Use the simple implementation to get the output we're looking for */
    memset(expected, 0xAA, sizeof(expected));
    simple_kmac(alg, rate, test->key, test->key_len,
                test->input, test->input_len,
                (const unsigned char *)(test->salt),
                strlen(test->salt), expected, test->output_len);

    /* Check the all-in-one instantiation of "internal-kmac.h" */
    memset(out, 0x66, sizeof(out));
    (*allinone)(test->key, test->key_len,
                test->input, test->input_len,
                (const unsigned char *)(test->salt),
                strlen(test->salt), out, test->output_len);
    ok = (test_memcmp(out, expected, test->output_len) == 0);

    /* Check the incremental instantiation of "internal-kmac.h" */
    memset(out, 0xBB, sizeof(out));
    state = malloc(state_size);
    if (!state)
        exit(1);
    (*init)(state, test->key, test->key_len,
            (const unsigned char *)(test->salt), strlen(test->salt));
    (*absorb)(state, test->input, test->input_len);
    (*setoutlen)(state, test->output_len);
    (*squeeze)(state, out, test->output_len);
    if (test_memcmp(out, expected, test->output_len) != 0)
        ok = 0;

    /* Check the finalizable instantiation of "internal-kmac.h" */
    memset(out, 0x55, sizeof(out));
    (*init)(state, test->key, test->key_len,
            (const unsigned char *)(test->salt), strlen(test->salt));
    (*absorb)(state, test->input, test->input_len);
    if (test->output_len != alg->hash_len) {
        /* Mismatch between the test output and the underlying hash length,
         * so force the output length to be set explicitly before finalize. */
        (*setoutlen)(state, test->output_len);
    }
    (*finalize)(state, out);
    if (test_memcmp(out, expected, test->output_len) != 0)
        ok = 0;
    free(state);

    /* Report the results */
    if (ok) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }
}

void test_kmac(void)
{
    printf("KMAC:\n");

    test_nist_kmac(&testVectorNIST_1);
    test_nist_kmac(&testVectorNIST_2);

    test_kmac_alg("ASCON KMAC", &ascon_xof_algorithm,
                  ASCON_XOF_RATE, sizeof(ascon_kmac_state_t),
                  (kmac_allinone_t)ascon_kmac,
                  (kmac_init_t)ascon_kmac_init,
                  (kmac_absorb_t)ascon_kmac_absorb,
                  (kmac_squeeze_t)ascon_kmac_squeeze,
                  (kmac_set_output_length_t)ascon_kmac_set_output_length,
                  (kmac_finalize_t)ascon_kmac_finalize,
                  &testVectorNIST_1);
    test_kmac_alg("ASCON KMAC", &ascon_xof_algorithm,
                  ASCON_XOF_RATE, sizeof(ascon_kmac_state_t),
                  (kmac_allinone_t)ascon_kmac,
                  (kmac_init_t)ascon_kmac_init,
                  (kmac_absorb_t)ascon_kmac_absorb,
                  (kmac_squeeze_t)ascon_kmac_squeeze,
                  (kmac_set_output_length_t)ascon_kmac_set_output_length,
                  (kmac_finalize_t)ascon_kmac_finalize,
                  &testVectorNIST_2);

    test_kmac_alg("ASCON-A KMAC", &ascon_xofa_algorithm,
                  ASCON_XOF_RATE, sizeof(ascon_kmac_state_t),
                  (kmac_allinone_t)ascon_kmaca,
                  (kmac_init_t)ascon_kmaca_init,
                  (kmac_absorb_t)ascon_kmaca_absorb,
                  (kmac_squeeze_t)ascon_kmaca_squeeze,
                  (kmac_set_output_length_t)ascon_kmaca_set_output_length,
                  (kmac_finalize_t)ascon_kmaca_finalize,
                  &testVectorNIST_1);
    test_kmac_alg("ASCON-A KMAC", &ascon_xofa_algorithm,
                  ASCON_XOF_RATE, sizeof(ascon_kmac_state_t),
                  (kmac_allinone_t)ascon_kmaca,
                  (kmac_init_t)ascon_kmaca_init,
                  (kmac_absorb_t)ascon_kmaca_absorb,
                  (kmac_squeeze_t)ascon_kmaca_squeeze,
                  (kmac_set_output_length_t)ascon_kmaca_set_output_length,
                  (kmac_finalize_t)ascon_kmaca_finalize,
                  &testVectorNIST_2);

    test_kmac_alg("Romulus-H KMAC", &romulus_xof_algorithm,
                  ROMULUS_HASH_RATE, sizeof(romulus_kmac_state_t),
                  (kmac_allinone_t)romulus_kmac,
                  (kmac_init_t)romulus_kmac_init,
                  (kmac_absorb_t)romulus_kmac_absorb,
                  (kmac_squeeze_t)romulus_kmac_squeeze,
                  (kmac_set_output_length_t)romulus_kmac_set_output_length,
                  (kmac_finalize_t)romulus_kmac_finalize,
                  &testVectorNIST_1);
    test_kmac_alg("Romulus-H KMAC", &romulus_xof_algorithm,
                  ROMULUS_HASH_RATE, sizeof(romulus_kmac_state_t),
                  (kmac_allinone_t)romulus_kmac,
                  (kmac_init_t)romulus_kmac_init,
                  (kmac_absorb_t)romulus_kmac_absorb,
                  (kmac_squeeze_t)romulus_kmac_squeeze,
                  (kmac_set_output_length_t)romulus_kmac_set_output_length,
                  (kmac_finalize_t)romulus_kmac_finalize,
                  &testVectorNIST_2);

    test_kmac_alg("Xoodyak KMAC", &xoodyak_hash_algorithm,
                  XOODYAK_HASH_RATE, sizeof(xoodyak_kmac_state_t),
                  (kmac_allinone_t)xoodyak_kmac,
                  (kmac_init_t)xoodyak_kmac_init,
                  (kmac_absorb_t)xoodyak_kmac_absorb,
                  (kmac_squeeze_t)xoodyak_kmac_squeeze,
                  (kmac_set_output_length_t)xoodyak_kmac_set_output_length,
                  (kmac_finalize_t)xoodyak_kmac_finalize,
                  &testVectorNIST_1);
    test_kmac_alg("Xoodyak KMAC", &xoodyak_hash_algorithm,
                  XOODYAK_HASH_RATE, sizeof(xoodyak_kmac_state_t),
                  (kmac_allinone_t)xoodyak_kmac,
                  (kmac_init_t)xoodyak_kmac_init,
                  (kmac_absorb_t)xoodyak_kmac_absorb,
                  (kmac_squeeze_t)xoodyak_kmac_squeeze,
                  (kmac_set_output_length_t)xoodyak_kmac_set_output_length,
                  (kmac_finalize_t)xoodyak_kmac_finalize,
                  &testVectorNIST_2);

    test_kmac_alg("XOEsch256 KMAC", &esch_256_xof_algorithm,
                  ESCH_256_RATE, sizeof(esch_256_kmac_state_t),
                  (kmac_allinone_t)esch_256_kmac,
                  (kmac_init_t)esch_256_kmac_init,
                  (kmac_absorb_t)esch_256_kmac_absorb,
                  (kmac_squeeze_t)esch_256_kmac_squeeze,
                  (kmac_set_output_length_t)esch_256_kmac_set_output_length,
                  (kmac_finalize_t)esch_256_kmac_finalize,
                  &testVectorNIST_1);
    test_kmac_alg("XOEsch256 KMAC", &esch_256_xof_algorithm,
                  ESCH_256_RATE, sizeof(esch_256_kmac_state_t),
                  (kmac_allinone_t)esch_256_kmac,
                  (kmac_init_t)esch_256_kmac_init,
                  (kmac_absorb_t)esch_256_kmac_absorb,
                  (kmac_squeeze_t)esch_256_kmac_squeeze,
                  (kmac_set_output_length_t)esch_256_kmac_set_output_length,
                  (kmac_finalize_t)esch_256_kmac_finalize,
                  &testVectorNIST_2);

    test_kmac_alg("XOEsch384 KMAC", &esch_384_xof_algorithm,
                  ESCH_384_RATE, sizeof(esch_384_kmac_state_t),
                  (kmac_allinone_t)esch_384_kmac,
                  (kmac_init_t)esch_384_kmac_init,
                  (kmac_absorb_t)esch_384_kmac_absorb,
                  (kmac_squeeze_t)esch_384_kmac_squeeze,
                  (kmac_set_output_length_t)esch_384_kmac_set_output_length,
                  (kmac_finalize_t)esch_384_kmac_finalize,
                  &testVectorNIST_1);
    test_kmac_alg("XOEsch384 KMAC", &esch_384_xof_algorithm,
                  ESCH_384_RATE, sizeof(esch_384_kmac_state_t),
                  (kmac_allinone_t)esch_384_kmac,
                  (kmac_init_t)esch_384_kmac_init,
                  (kmac_absorb_t)esch_384_kmac_absorb,
                  (kmac_squeeze_t)esch_384_kmac_squeeze,
                  (kmac_set_output_length_t)esch_384_kmac_set_output_length,
                  (kmac_finalize_t)esch_384_kmac_finalize,
                  &testVectorNIST_2);

    printf("\n");
}
