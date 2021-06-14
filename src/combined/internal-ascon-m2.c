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

#include "internal-ascon-m2.h"
#include "aead-random.h"

/*
 * This implementation uses ideas from "Protecting against Statistical
 * Ineffective Fault Attacks", J. Daemen, C. Dobraunig, M. Eichlseder,
 * H. Gross, F. Mendel, and R. Primas: https://eprint.iacr.org/2019/536.pdf
 *
 * That paper shows how to implement the 5-bit S-box Chi5 that is used in
 * ASCON with a relatively small amount of randomness.  Because Chi5 uses
 * invertible Toffoli gates, randomness does not need to be injected
 * continuously during the computation of the AND-NOT operations.
 * Randomness can be injected once at the start of each S-box computation.
 *
 * The paper also indicates that the randomness can be reused from
 * round to round.  The state is randomized when it is split into shares,
 * and then fresh random material is generated to mask the first S-box
 * computation.  After that, the S-box randomness can be reused for the
 * S-box computations in all subsequent rounds.
 *
 * What's going on here is that ASCON itself is being used as a PRNG
 * to expand the first S-box mask to additional masks for each
 * subsequent round.  The "t0 ^= (~x0) & x1" term iterates the PRNG
 * using the random input t0 and part of the ASCON state (x0 and x1).
 *
 * For good measure, we refresh the randomness of the entire state
 * each permutation call.  This means that each permutation call needs
 * 6 x 64 bits = 384 bits of new randomness for the 2-share version.
 *
 * If we were to mask every AND-NOT operation individually, then we
 * would need up to (12 rounds + 1) x 5 words x 64 bits = 4160 bits
 * of new randomness including the refresh at the start.  Even without
 * the refresh, 3840 bits of new randomness are required.
 */

/**
 * \brief Computes x ^= (~y & z) with a 2-share masked representation
 * and XOR's the result with the output variable.
 *
 * \param x Output variable to XOR with.
 * \param y First input variable.
 * \param z Second input variable.
 */
#define and_not_xor(x, y, z) \
    do { \
        x##_a ^= ((~y##_a) & z##_b); \
        x##_a ^= ((~y##_a) & z##_a); \
        x##_b ^= (y##_b & z##_b); \
        x##_b ^= (y##_b & z##_a); \
    } while (0)

void ascon_permute_masked_2(ascon_masked_state_2_t *state, uint8_t first_round)
{
    uint64_t x0_a, x1_a, x2_a, x3_a, x4_a;
    uint64_t x0_b, x1_b, x2_b, x3_b, x4_b;
    uint64_t t0_a, t0_b, t1_a, t1_b;

    /* Load the state into local variables and refresh the randomness */
    x0_b = aead_random_generate_64();
    x1_b = aead_random_generate_64();
    x2_b = aead_random_generate_64();
    x3_b = aead_random_generate_64();
    x4_b = aead_random_generate_64();
    x0_a = state->a.S[0] ^ x0_b;
    x1_a = state->a.S[1] ^ x1_b;
    x2_a = state->a.S[2] ^ x2_b;
    x3_a = state->a.S[3] ^ x3_b;
    x4_a = state->a.S[4] ^ x4_b;
    x0_b = state->b.S[0] ^ x0_b;
    x1_b = state->b.S[1] ^ x1_b;
    x2_b = state->b.S[2] ^ x2_b;
    x3_b = state->b.S[3] ^ x3_b;
    x4_b = state->b.S[4] ^ x4_b;

    /* We need one extra word of randomness for use in the Chi5 layer. */
    t0_a = aead_random_generate_64();

    /* Perform all requested rounds */
    for (; first_round < 12; ++first_round) {
        /* Add the round constant to the state (first share only) */
        x2_a ^= ((0x0F - first_round) << 4) | first_round;

        /* Start of the substitution layer, first share */
        x0_a ^= x4_a;
        x4_a ^= x3_a;
        x2_a ^= x1_a;
        t1_a  = x0_a;

        /* Start of the substitution layer, second share */
        x0_b ^= x4_b;
        x4_b ^= x3_b;
        x2_b ^= x1_b;
        t1_b  = x0_b;

        /* Middle part of the substitution layer, Chi5 */
        t0_b = t0_a;                    /* t0 = random shares */
        and_not_xor(t0, x0, x1);        /* t0 ^= (~x0) & x1; */
        and_not_xor(x0, x1, x2);        /* x0 ^= (~x1) & x2; */
        and_not_xor(x1, x2, x3);        /* x1 ^= (~x2) & x3; */
        and_not_xor(x2, x3, x4);        /* x2 ^= (~x3) & x4; */
        and_not_xor(x3, x4, t1);        /* x3 ^= (~x4) & t1; */
        x4_a ^= t0_a;
        x4_b ^= t0_b;

        /* End of the substitution layer, first share */
        x1_a ^= x0_a;
        x0_a ^= x4_a;
        x3_a ^= x2_a;
        x2_a = ~x2_a;

        /* Linear diffusion layer, first share */
        x0_a ^= rightRotate19_64(x0_a) ^ rightRotate28_64(x0_a);
        x1_a ^= rightRotate61_64(x1_a) ^ rightRotate39_64(x1_a);
        x2_a ^= rightRotate1_64(x2_a)  ^ rightRotate6_64(x2_a);
        x3_a ^= rightRotate10_64(x3_a) ^ rightRotate17_64(x3_a);
        x4_a ^= rightRotate7_64(x4_a)  ^ rightRotate41_64(x4_a);

        /* End of the substitution layer, second share */
        x1_b ^= x0_b;
        x0_b ^= x4_b;
        x3_b ^= x2_b;

        /* Linear diffusion layer, second share */
        x0_b ^= rightRotate19_64(x0_b) ^ rightRotate28_64(x0_b);
        x1_b ^= rightRotate61_64(x1_b) ^ rightRotate39_64(x1_b);
        x2_b ^= rightRotate1_64(x2_b)  ^ rightRotate6_64(x2_b);
        x3_b ^= rightRotate10_64(x3_b) ^ rightRotate17_64(x3_b);
        x4_b ^= rightRotate7_64(x4_b)  ^ rightRotate41_64(x4_b);
    }

    /* Store the local variables back to the state */
    state->a.S[0] = x0_a;
    state->a.S[1] = x1_a;
    state->a.S[2] = x2_a;
    state->a.S[3] = x3_a;
    state->a.S[4] = x4_a;
    state->b.S[0] = x0_b;
    state->b.S[1] = x1_b;
    state->b.S[2] = x2_b;
    state->b.S[3] = x3_b;
    state->b.S[4] = x4_b;
}

void ascon_init_key_128_masked_2
    (ascon_masked_state_2_t *state, uint64_t iv,
     const unsigned char *k, const unsigned char *npub)
{
    uint64_t k0_a, k0_b, k1_a, k1_b;

    /* Load the key and mask it */
    k0_b = aead_random_generate_64();
    k1_b = aead_random_generate_64();
    k0_a = be_load_word64(k) ^ k0_b;
    k1_a = be_load_word64(k + 8) ^ k1_b;

    /* Initialize the masked ASCON state with the IV, key, and nonce */
    state->b.S[0] = aead_random_generate_64();
    state->b.S[1] = aead_random_generate_64();
    state->b.S[2] = aead_random_generate_64();
    state->b.S[3] = aead_random_generate_64();
    state->b.S[4] = aead_random_generate_64();
    state->a.S[0] = iv ^ state->b.S[0];
    state->a.S[1] = k0_a ^ state->b.S[1];
    state->a.S[2] = k1_a ^ state->b.S[2];
    state->a.S[3] = be_load_word64(npub) ^ state->b.S[3];
    state->a.S[4] = be_load_word64(npub + 8) ^ state->b.S[4];
    state->b.S[1] ^= k0_b;
    state->b.S[2] ^= k1_b;

    /* Permute the initial state */
    ascon_permute_masked_2(state, 0);

    /* XOR the key back into the state in masked form */
    state->a.S[3] ^= k0_a;
    state->a.S[4] ^= k1_a;
    state->b.S[3] ^= k0_b;
    state->b.S[4] ^= k1_b;
}

void ascon_mask_2(ascon_masked_state_2_t *output, const ascon_state_t *input)
{
    output->b.S[0] = aead_random_generate_64();
    output->b.S[1] = aead_random_generate_64();
    output->b.S[2] = aead_random_generate_64();
    output->b.S[3] = aead_random_generate_64();
    output->b.S[4] = aead_random_generate_64();
#if defined(LW_UTIL_LITTLE_ENDIAN)
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
#else
    output->a.S[0] = input->S[0] ^ output->b.S[0];
    output->a.S[1] = input->S[1] ^ output->b.S[1];
    output->a.S[2] = input->S[2] ^ output->b.S[2];
    output->a.S[3] = input->S[3] ^ output->b.S[3];
    output->a.S[4] = input->S[4] ^ output->b.S[4];
#endif
}

void ascon_unmask_2(ascon_state_t *output, const ascon_masked_state_2_t *input)
{
#if defined(LW_UTIL_LITTLE_ENDIAN)
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
#else
    output->S[0] = input->a.S[0] ^ input->b.S[0];
    output->S[1] = input->a.S[1] ^ input->b.S[1];
    output->S[2] = input->a.S[2] ^ input->b.S[2];
    output->S[3] = input->a.S[3] ^ input->b.S[3];
    output->S[4] = input->a.S[4] ^ input->b.S[4];
#endif
}

void ascon_refresh_2(ascon_masked_state_2_t *state)
{
    uint64_t temp = aead_random_generate_64();
    state->a.S[0] ^= temp;
    state->b.S[0] ^= temp;
    temp = aead_random_generate_64();
    state->a.S[1] ^= temp;
    state->b.S[1] ^= temp;
    temp = aead_random_generate_64();
    state->a.S[2] ^= temp;
    state->b.S[2] ^= temp;
    temp = aead_random_generate_64();
    state->a.S[3] ^= temp;
    state->b.S[3] ^= temp;
    temp = aead_random_generate_64();
    state->a.S[4] ^= temp;
    state->b.S[4] ^= temp;
}
