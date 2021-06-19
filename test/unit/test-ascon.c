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

#include "ascon-aead.h"
#include "ascon-permutation.h"
#include "internal-ascon.h"
#include "internal-ascon-m2.h"
#include "test-cipher.h"
#include "aead-random.h"
#include <stdio.h>
#include <string.h>

/* Test vectors generated with the reference code */
static uint8_t const ascon_input[40] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
};
static uint8_t const ascon_output_12[40] = {
    /* Output after 12 rounds */
    0x06, 0x05, 0x87, 0xe2, 0xd4, 0x89, 0xdd, 0x43,
    0x1c, 0xc2, 0xb1, 0x7b, 0x0e, 0x3c, 0x17, 0x64,
    0x95, 0x73, 0x42, 0x53, 0x18, 0x44, 0xa6, 0x74,
    0x96, 0xb1, 0x71, 0x75, 0xb4, 0xcb, 0x68, 0x63,
    0x29, 0xb5, 0x12, 0xd6, 0x27, 0xd9, 0x06, 0xe5
};
static uint8_t const ascon_output_8[40] = {
    /* Output after 8 rounds */
    0x83, 0x0d, 0x26, 0x0d, 0x33, 0x5f, 0x3b, 0xed,
    0xda, 0x0b, 0xba, 0x91, 0x7b, 0xcf, 0xca, 0xd7,
    0xdd, 0x0d, 0x88, 0xe7, 0xdc, 0xb5, 0xec, 0xd0,
    0x89, 0x2a, 0x02, 0x15, 0x1f, 0x95, 0x94, 0x6e,
    0x3a, 0x69, 0xcb, 0x3c, 0xf9, 0x82, 0xf6, 0xf7
};

static void test_ascon_permutation(void)
{
    ascon_state_t state;

    printf("    Permutation 12 ... ");
    fflush(stdout);
    memcpy(state.B, ascon_input, sizeof(ascon_input));
    ascon_permute(&state, 0);
    if (memcmp(state.B, ascon_output_12, sizeof(ascon_output_12)) != 0) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    printf("    Permutation 8 ... ");
    fflush(stdout);
    memcpy(state.B, ascon_input, sizeof(ascon_input));
    ascon_permute(&state, 4);
    if (memcmp(state.B, ascon_output_8, sizeof(ascon_output_8)) != 0) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }
}

#if ASCON_SLICED

static void test_ascon_sliced(void)
{
    ascon_state_t state;

    printf("    Sliced Permutation 12 ... ");
    fflush(stdout);
    memcpy(state.B, ascon_input, sizeof(ascon_input));
    ascon_to_sliced(&state);
    ascon_permute_sliced(&state, 0);
    ascon_from_sliced(&state);
    if (memcmp(state.B, ascon_output_12, sizeof(ascon_output_12)) != 0) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    printf("    Sliced Permutation 8 ... ");
    fflush(stdout);
    memcpy(state.B, ascon_input, sizeof(ascon_input));
    ascon_to_sliced(&state);
    ascon_permute_sliced(&state, 4);
    ascon_from_sliced(&state);
    if (memcmp(state.B, ascon_output_8, sizeof(ascon_output_8)) != 0) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }
}

static void ascon_mask_x2_sliced
    (ascon_masked_state_x2_t *output, const ascon_state_t *input)
{
    int index;
    aead_random_generate_32_multiple(output->b.W, 10);
    for (index = 0; index < 10; ++index)
        output->a.W[index] = input->W[index] ^ output->b.W[index];
}

static void ascon_unmask_x2_sliced
    (ascon_state_t *output, const ascon_masked_state_x2_t *input)
{
    int index;
    for (index = 0; index < 10; ++index)
        output->W[index] = input->a.W[index] ^ input->b.W[index];
}

#else /* !ASCON_SLICED */

static void ascon_mask_x2
    (ascon_masked_state_x2_t *output, const ascon_state_t *input)
{
    aead_random_generate_64_multiple(output->b.S, 5);
    output->a.S[0] = be_load_word64((const unsigned char *)&(input->S[0])) ^
                     output->b.S[0];
    output->a.S[1] = be_load_word64((const unsigned char *)&(input->S[1])) ^
                     output->b.S[1];
    output->a.S[2] = be_load_word64((const unsigned char *)&(input->S[2])) ^
                     output->b.S[2];
    output->a.S[3] = be_load_word64((const unsigned char *)&(input->S[3])) ^
                     output->b.S[3];
    output->a.S[4] = be_load_word64((const unsigned char *)&(input->S[4])) ^
                     output->b.S[4];
}

static void ascon_unmask_x2
    (ascon_state_t *output, const ascon_masked_state_x2_t *input)
{
    be_store_word64((unsigned char *)&(output->S[0]),
                    input->a.S[0] ^ input->b.S[0]);
    be_store_word64((unsigned char *)&(output->S[1]),
                    input->a.S[1] ^ input->b.S[1]);
    be_store_word64((unsigned char *)&(output->S[2]),
                    input->a.S[2] ^ input->b.S[2]);
    be_store_word64((unsigned char *)&(output->S[3]),
                    input->a.S[3] ^ input->b.S[3]);
    be_store_word64((unsigned char *)&(output->S[4]),
                    input->a.S[4] ^ input->b.S[4]);
}

#endif /* !ASCON_SLICED */

static void test_ascon_masked_m2(void)
{
    ascon_masked_state_x2_t state;
    ascon_masked_key_x2_t mk;
    ascon_state_t unmasked;
    ascon_state_t unmasked2;

    printf("    Masked Permutation 12, 2-share ... ");
    fflush(stdout);
    memcpy(unmasked.B, ascon_input, sizeof(ascon_input));
#if ASCON_SLICED
    ascon_to_sliced(&unmasked);
    ascon_mask_x2_sliced(&state, &unmasked);
    ascon_permute_masked_x2(&state, 0);
    ascon_unmask_x2_sliced(&unmasked, &state);
    ascon_from_sliced(&unmasked);
#else
    ascon_mask_x2(&state, &unmasked);
    ascon_permute_masked_x2(&state, 0);
    ascon_unmask_x2(&unmasked, &state);
#endif
    if (test_memcmp(unmasked.B, ascon_output_12, sizeof(ascon_output_12)) != 0) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    printf("    Masked Permutation 8, 2-share ... ");
    fflush(stdout);
    memcpy(unmasked.B, ascon_input, sizeof(ascon_input));
#if ASCON_SLICED
    ascon_to_sliced(&unmasked);
    ascon_mask_x2_sliced(&state, &unmasked);
    ascon_permute_masked_x2(&state, 4);
    ascon_unmask_x2_sliced(&unmasked, &state);
    ascon_from_sliced(&unmasked);
#else
    ascon_mask_x2(&state, &unmasked);
    ascon_permute_masked_x2(&state, 4);
    ascon_unmask_x2(&unmasked, &state);
#endif
    if (test_memcmp(unmasked.B, ascon_output_8, sizeof(ascon_output_8)) != 0) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    /* Test masked initialization */
    printf("    Masked Init, 128-bit key, 2-share ... ");
    fflush(stdout);
    ascon_mask_key_128_x2(&mk, ASCON128_IV, ascon_input);
    ascon_masked_init_key_x2(&state, &mk, ascon_output_12, 0);
    be_store_word64(unmasked.B, ASCON128_IV);
    memcpy(unmasked.B + 8, ascon_input, 16);
    memcpy(unmasked.B + 24, ascon_output_12, 16);
#if ASCON_SLICED
    ascon_to_sliced(&unmasked);
    ascon_permute_sliced(&unmasked, 0);
    ascon_from_sliced(&unmasked);
    lw_xor_block(unmasked.B + 24, ascon_input, 16);
    ascon_to_sliced(&unmasked);
    ascon_unmask_x2_sliced(&unmasked2, &state);
#else
    ascon_permute(&unmasked, 0);
    lw_xor_block(unmasked.B + 24, ascon_input, 16);
    ascon_unmask_x2(&unmasked2, &state);
#endif
    if (test_memcmp(unmasked.B, unmasked2.B, sizeof(unmasked.B)) != 0) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    printf("    Masked Init, 160-bit key, 2-share ... ");
    fflush(stdout);
    ascon_mask_key_160_x2(&mk, ASCON80PQ_IV, ascon_input);
    ascon_masked_init_key_x2(&state, &mk, ascon_output_12, 1);
    be_store_word32(unmasked.B, ASCON80PQ_IV);
    memcpy(unmasked.B + 4, ascon_input, 20);
    memcpy(unmasked.B + 24, ascon_output_12, 16);
#if ASCON_SLICED
    ascon_to_sliced(&unmasked);
    ascon_permute_sliced(&unmasked, 0);
    ascon_from_sliced(&unmasked);
    lw_xor_block(unmasked.B + 20, ascon_input, 20);
    ascon_to_sliced(&unmasked);
    ascon_unmask_x2_sliced(&unmasked2, &state);
#else
    ascon_permute(&unmasked, 0);
    lw_xor_block(unmasked.B + 20, ascon_input, 20);
    ascon_unmask_x2(&unmasked2, &state);
#endif
    if (test_memcmp(unmasked.B, unmasked2.B, sizeof(unmasked.B)) != 0) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }
}

/* Permutes the public and private ASCON states in parallel */
static void snp_permute(ascon_permutation_state_t *state, ascon_state_t *state2)
{
    ascon_permute_all_rounds(state);
#if ASCON_SLICED
    ascon_to_sliced(state2);
    ascon_permute_sliced(state2, 0);
    ascon_from_sliced(state2);
#else
    ascon_permute(state2, 0);
#endif
}

/* Set up for an SnP test that compares the public vs private API's */
static void snp_setup(ascon_permutation_state_t *state, ascon_state_t *state2)
{
    /* Use a counter and run the permutation to make the starting
     * state different every time this function is called. */
    static unsigned counter = 0;
    memcpy(state->B, ascon_output_12, ASCON_STATE_SIZE);
    state->B[38] ^= (unsigned char)(counter >> 8);
    state->B[39] ^= (unsigned char)counter;
    memcpy(state2->B, ascon_output_12, ASCON_STATE_SIZE);
    state2->B[38] ^= (unsigned char)(counter >> 8);
    state2->B[39] ^= (unsigned char)counter;
    ascon_to_operational(state);
    snp_permute(state, state2);
    ++counter;
}

/* Check that the public and private states are still identical */
static int snp_check
    (int ok, const ascon_permutation_state_t *state,
     const ascon_state_t *state2)
{
    ascon_permutation_state_t temp = *state;
    ascon_from_operational(&temp);
    if (test_memcmp(temp.B, state2->B, ASCON_STATE_SIZE) != 0)
        ok = 0;
    return ok;
}

/* Test the SnP version of the ASCON API */
static void test_ascon_snp(void)
{
    ascon_permutation_state_t state;
    ascon_state_t state2;
    int ok = 1;
    unsigned offset, length, temp;
    unsigned char buf[ASCON_STATE_SIZE];
    unsigned char buf2[ASCON_STATE_SIZE];

    printf("    SnP ... ");
    fflush(stdout);

    /* Check that initialization zeroes the state */
    memset(&state, 0xAA, sizeof(state));
    ascon_init(&state);
    for (offset = 0; offset < ASCON_STATE_SIZE; ++offset) {
        if (state.B[offset] != 0)
            ok = 0;
    }

    /* Basic permutation test - 12 rounds */
    memcpy(state.B, ascon_input, sizeof(ascon_input));
    ascon_to_operational(&state);
    ascon_permute_all_rounds(&state);
    ascon_from_operational(&state);
    if (test_memcmp(state.B, ascon_output_12, sizeof(ascon_output_12)) != 0)
        ok = 0;

    /* Basic permutation test - 8 rounds */
    memcpy(state.B, ascon_input, sizeof(ascon_input));
    ascon_to_operational(&state);
    ascon_permute_n_rounds(&state, 8);
    ascon_from_operational(&state);
    if (test_memcmp(state.B, ascon_output_8, sizeof(ascon_output_8)) != 0)
        ok = 0;

    /* Adding bytes to the state individually */
    for (offset = 0; offset < ASCON_STATE_SIZE; ++offset) {
        snp_setup(&state, &state2);
        ascon_add_byte(&state, 0x6A, offset);
        state2.B[offset] ^= 0x6A;
        ok = snp_check(ok, &state, &state2);
    }

    /* Adding bytes to the state in groups */
    for (offset = 0; offset < ASCON_STATE_SIZE; ++offset) {
        for (length = 0; length < ASCON_STATE_SIZE; ++length) {
            snp_setup(&state, &state2);
            ascon_add_bytes(&state, ascon_input, offset, length);
            if ((offset + length) > ASCON_STATE_SIZE)
                temp = ASCON_STATE_SIZE - offset;
            else
                temp = length;
            lw_xor_block(state2.B + offset, ascon_input, temp);
            snp_permute(&state, &state2);
            ok = snp_check(ok, &state, &state2);
        }
    }

    /* Overwriting bytes in the state in groups */
    for (offset = 0; offset < ASCON_STATE_SIZE; ++offset) {
        for (length = 0; length < ASCON_STATE_SIZE; ++length) {
            snp_setup(&state, &state2);
            ascon_overwrite_bytes(&state, ascon_input, offset, length);
            if ((offset + length) > ASCON_STATE_SIZE)
                temp = ASCON_STATE_SIZE - offset;
            else
                temp = length;
            memcpy(state2.B + offset, ascon_input, temp);
            snp_permute(&state, &state2);
            ok = snp_check(ok, &state, &state2);
        }
    }

    /* Overwriting the leading part of the state with zeroes */
    for (offset = 0; offset < ASCON_STATE_SIZE; ++offset) {
        snp_setup(&state, &state2);
        ascon_overwrite_with_zeroes(&state, offset);
        memset(state2.B, 0, offset);
        snp_permute(&state, &state2);
        ok = snp_check(ok, &state, &state2);
    }

    /* Extracting bytes from the state */
    for (offset = 0; offset < ASCON_STATE_SIZE; ++offset) {
        for (length = 0; length < ASCON_STATE_SIZE; ++length) {
            /* Extract the bytes directly */
            snp_setup(&state, &state2);
            ascon_extract_bytes(&state, buf, offset, length);
            if ((offset + length) > ASCON_STATE_SIZE)
                temp = ASCON_STATE_SIZE - offset;
            else
                temp = length;
            ok = snp_check(ok, &state, &state2);
            ok &= !memcmp(buf, state2.B + offset, temp);

            /* Extract the bytes and XOR them with a buffer */
            snp_permute(&state, &state2);
            memcpy(buf, ascon_input, ASCON_STATE_SIZE);
            memset(buf2, 0xA6, ASCON_STATE_SIZE);
            ascon_extract_and_add_bytes(&state, buf, buf2, offset, length);
            if ((offset + length) > ASCON_STATE_SIZE)
                temp = ASCON_STATE_SIZE - offset;
            else
                temp = length;
            ok = snp_check(ok, &state, &state2);
            lw_xor_block(state2.B + offset, ascon_input, temp);
            ok &= !memcmp(buf2, state2.B + offset, temp);
        }
    }

    /* Encrypting and encrypting data with the state */
    for (offset = 0; offset < ASCON_STATE_SIZE; ++offset) {
        for (length = 0; length < ASCON_STATE_SIZE; ++length) {
            /* Encrypting */
            snp_setup(&state, &state2);
            ascon_encrypt_bytes(&state, ascon_input, buf, offset, length, 0);
            if ((offset + length) > ASCON_STATE_SIZE)
                temp = ASCON_STATE_SIZE - offset;
            else
                temp = length;
            lw_xor_block_2_dest(buf2, state2.B + offset, ascon_input, temp);
            ok = snp_check(ok, &state, &state2);
            ok &= !memcmp(buf, buf2, temp);

            /* Decrypting */
            snp_permute(&state, &state2);
            ascon_decrypt_bytes(&state, ascon_input, buf, offset, length, 0);
            lw_xor_block_swap(buf2, state2.B + offset, ascon_input, temp);
            ok = snp_check(ok, &state, &state2);
            ok &= !memcmp(buf, buf2, temp);

            /* Skip the rest if not enough room for a padding byte */
            if ((offset + length) >= ASCON_STATE_SIZE)
                continue;

            /* Reduce the truncated length by 1 for the padding */
            if ((offset + length) >= ASCON_STATE_SIZE)
                temp = ASCON_STATE_SIZE - 1 - offset;
            else
                temp = length;

            /* Encrypt again, this time with padding */
            snp_permute(&state, &state2);
            ascon_encrypt_bytes(&state, ascon_input, buf, offset, temp, 1);
            lw_xor_block_2_dest(buf2, state2.B + offset, ascon_input, temp);
            state2.B[offset + temp] ^= (unsigned char)0x80;
            ok = snp_check(ok, &state, &state2);
            ok &= !memcmp(buf, buf2, temp);

            /* Decrypt again, this time with padding */
            snp_permute(&state, &state2);
            ascon_decrypt_bytes(&state, ascon_input, buf, offset, temp, 1);
            lw_xor_block_swap(buf2, state2.B + offset, ascon_input, temp);
            state2.B[offset + temp] ^= (unsigned char)0x80;
            ok = snp_check(ok, &state, &state2);
            ok &= !memcmp(buf, buf2, temp);
        }
    }

    /* Report the results */
    if (!ok) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }
}

void test_ascon(void)
{
    printf("ASCON:\n");
    aead_random_init();
    test_ascon_permutation();
#if ASCON_SLICED
    test_ascon_sliced();
#endif
    test_ascon_masked_m2();
    test_ascon_snp();
    aead_random_finish();
    printf("\n");
}
