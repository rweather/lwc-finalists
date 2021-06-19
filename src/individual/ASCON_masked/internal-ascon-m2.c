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
 * If we were to mask every AND-NOT operation individually, then we
 * would need up to 12 rounds x 5 words x 64 bits = 3840 bits of new
 * randomness for each permutation call instead of only 64 bits here.
 *
 * We also add randomness whenever data is injected into or squeezed
 * from the masked ASCON permutation state.
 */

#if !ASCON_SLICED

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

void ascon_permute_masked_x2
    (ascon_masked_state_x2_t *state, uint8_t first_round)
{
    uint64_t x0_a, x1_a, x2_a, x3_a, x4_a;
    uint64_t x0_b, x1_b, x2_b, x3_b, x4_b;
    uint64_t t0_a, t0_b, t1_a, t1_b;

    /* We need one word of new randomness for use in the Chi5 layer. */
    t0_a = aead_random_generate_64();

    /* Load the state into local variables */
    x0_a = state->a.S[0];
    x1_a = state->a.S[1];
    x2_a = state->a.S[2];
    x3_a = state->a.S[3];
    x4_a = state->a.S[4];
    x0_b = state->b.S[0];
    x1_b = state->b.S[1];
    x2_b = state->b.S[2];
    x3_b = state->b.S[3];
    x4_b = state->b.S[4];

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

void ascon_mask_key_128_x2
    (ascon_masked_key_x2_t *mk, uint64_t iv, const unsigned char *k)
{
    aead_random_generate_64_multiple(mk->S + 3, 3);
    mk->S[0] = iv ^ mk->S[3];
    mk->S[1] = be_load_word64(k) ^ mk->S[4];
    mk->S[2] = be_load_word64(k + 8) ^ mk->S[5];
}

void ascon_mask_key_160_x2
    (ascon_masked_key_x2_t *mk, uint32_t iv, const unsigned char *k)
{
    aead_random_generate_64_multiple(mk->S + 3, 3);
    mk->S[0] = (((uint64_t)iv) << 32) ^ mk->S[3] ^ be_load_word32(k);
    mk->S[1] = be_load_word64(k + 4) ^ mk->S[4];
    mk->S[2] = be_load_word64(k + 12) ^ mk->S[5];
}

void ascon_masked_init_key_x2
    (ascon_masked_state_x2_t *state, const ascon_masked_key_x2_t *mk,
     const unsigned char *npub, int is_160_bit)
{
    /* Initialize the masked ASCON state with the IV, key, and nonce */
    aead_random_generate_64_multiple(state->b.S, 5);
    state->a.S[0] = mk->S[0] ^ state->b.S[0];
    state->a.S[1] = mk->S[1] ^ state->b.S[1];
    state->a.S[2] = mk->S[2] ^ state->b.S[2];
    state->b.S[0] ^= mk->S[3];
    state->b.S[1] ^= mk->S[4];
    state->b.S[2] ^= mk->S[5];
    state->a.S[3] = be_load_word64(npub) ^ state->b.S[3];
    state->a.S[4] = be_load_word64(npub + 8) ^ state->b.S[4];

    /* Permute the initial state */
    ascon_permute_masked_x2(state, 0);

    /* XOR the key back into the state in masked form */
    if (is_160_bit) {
        /* Exclude the IV part of the masked key words */
        state->a.S[2] ^= mk->S[0] & 0xFFFFFFFFULL;
        state->b.S[2] ^= mk->S[3] & 0xFFFFFFFFULL;
    }
    state->a.S[3] ^= mk->S[1];
    state->a.S[4] ^= mk->S[2];
    state->b.S[3] ^= mk->S[4];
    state->b.S[4] ^= mk->S[5];
}

void ascon_masked_finalize_128_x2
    (ascon_masked_state_x2_t *state, const ascon_masked_key_x2_t *mk,
     unsigned char tag[16])
{
    /* Refresh the randomness in the entire state and absorb the key */
    uint64_t m[5];
    aead_random_generate_64_multiple(m, 5);
    state->a.S[0] ^= m[0];
    state->a.S[1] ^= m[1] ^ mk->S[1];
    state->a.S[2] ^= m[2] ^ mk->S[2];
    state->a.S[3] ^= m[3];
    state->a.S[4] ^= m[4];
    state->b.S[0] ^= m[0];
    state->b.S[1] ^= m[1] ^ mk->S[4];
    state->b.S[2] ^= m[2] ^ mk->S[5];
    state->b.S[3] ^= m[3];
    state->b.S[4] ^= m[4];

    /* Permute the state and absorb the key one more time */
    ascon_permute_masked_x2(state, 0);
    state->a.S[3] ^= mk->S[1];
    state->a.S[4] ^= mk->S[2];
    state->b.S[3] ^= mk->S[4];
    state->b.S[4] ^= mk->S[5];

    /* Generate the authentication tag */
    be_store_word64(tag, state->a.S[3] ^ state->b.S[3]);
    be_store_word64(tag + 8, state->a.S[4] ^ state->b.S[4]);
}

void ascon_masked_finalize_128a_x2
    (ascon_masked_state_x2_t *state, const ascon_masked_key_x2_t *mk,
     unsigned char tag[16])
{
    /* Refresh the randomness in the entire state and absorb the key */
    uint64_t m[5];
    aead_random_generate_64_multiple(m, 5);
    state->a.S[0] ^= m[0];
    state->a.S[1] ^= m[1];
    state->a.S[2] ^= m[2] ^ mk->S[1];
    state->a.S[3] ^= m[3] ^ mk->S[2];
    state->b.S[2] ^= m[2] ^ mk->S[4];
    state->b.S[3] ^= m[3] ^ mk->S[5];
    state->a.S[4] ^= m[4];
    state->b.S[0] ^= m[0];
    state->b.S[1] ^= m[1];
    state->b.S[4] ^= m[4];

    /* Permute the state and absorb the key one more time */
    ascon_permute_masked_x2(state, 0);
    state->a.S[3] ^= mk->S[1];
    state->a.S[4] ^= mk->S[2];
    state->b.S[3] ^= mk->S[4];
    state->b.S[4] ^= mk->S[5];

    /* Generate the authentication tag */
    be_store_word64(tag, state->a.S[3] ^ state->b.S[3]);
    be_store_word64(tag + 8, state->a.S[4] ^ state->b.S[4]);
}

void ascon_masked_finalize_80pq_x2
    (ascon_masked_state_x2_t *state, const ascon_masked_key_x2_t *mk,
     unsigned char tag[16])
{
    /* Refresh the randomness in the entire state and absorb the key */
    uint64_t m[5];
    aead_random_generate_64_multiple(m, 5);
    state->a.S[0] ^= m[0];
    state->a.S[1] ^= m[1] ^ (mk->S[0] << 32) ^ (mk->S[1] >> 32);
    state->a.S[2] ^= m[2] ^ (mk->S[1] << 32) ^ (mk->S[2] >> 32);
    state->a.S[3] ^= m[3] ^ (mk->S[2] << 32);
    state->a.S[4] ^= m[4];
    state->b.S[0] ^= m[0];
    state->b.S[1] ^= m[1] ^ (mk->S[3] << 32) ^ (mk->S[4] >> 32);
    state->b.S[2] ^= m[2] ^ (mk->S[4] << 32) ^ (mk->S[5] >> 32);
    state->b.S[3] ^= m[3] ^ (mk->S[5] << 32);
    state->b.S[4] ^= m[4];

    /* Permute the state and absorb the key one more time */
    ascon_permute_masked_x2(state, 0);
    state->a.S[3] ^= mk->S[1];
    state->a.S[4] ^= mk->S[2];
    state->b.S[3] ^= mk->S[4];
    state->b.S[4] ^= mk->S[5];

    /* Generate the authentication tag */
    be_store_word64(tag, state->a.S[3] ^ state->b.S[3]);
    be_store_word64(tag + 8, state->a.S[4] ^ state->b.S[4]);
}

void ascon_masked_absorb_8_x2
    (ascon_masked_state_x2_t *state, const unsigned char *data,
     size_t len, uint8_t first_round)
{
    uint64_t m, m2;
    size_t posn;
    while (len >= 8) {
        m = aead_random_generate_64();
        state->a.S[0] ^= be_load_word64(data) ^ m;
        state->b.S[0] ^= m;
        ascon_permute_masked_x2(state, first_round);
        data += 8;
        len -= 8;
    }
    m2 = m = aead_random_generate_64();
    for (posn = 0; posn < len; ++posn) {
        m ^= ((uint64_t)(data[posn])) << (56 - posn * 8);
    }
    m ^= 0x80ULL << (56 - len * 8);
    state->a.S[0] ^= m;
    state->b.S[0] ^= m2;
    ascon_permute_masked_x2(state, first_round);
}

void ascon_masked_absorb_16_x2
    (ascon_masked_state_x2_t *state, const unsigned char *data,
     size_t len, uint8_t first_round)
{
    uint64_t m[4];
    size_t posn;
    while (len >= 16) {
        aead_random_generate_64_multiple(m, 2);
        state->a.S[0] ^= be_load_word64(data) ^ m[0];
        state->b.S[0] ^= m[0];
        state->a.S[1] ^= be_load_word64(data + 8) ^ m[1];
        state->b.S[1] ^= m[1];
        ascon_permute_masked_x2(state, first_round);
        data += 16;
        len -= 16;
    }
    aead_random_generate_64_multiple(m, 2);
    m[2] = m[0];
    m[3] = m[1];
    if (len < 8) {
        for (posn = 0; posn < len; ++posn) {
            m[0] ^= ((uint64_t)(data[posn])) << (56 - posn * 8);
        }
        m[0] ^= 0x80ULL << (56 - len * 8);
    } else {
        m[0] ^= be_load_word64(data);
        data += 8;
        len -= 8;
        for (posn = 0; posn < len; ++posn) {
            m[1] ^= ((uint64_t)(data[posn])) << (56 - posn * 8);
        }
        m[1] ^= 0x80ULL << (56 - len * 8);
    }
    state->a.S[0] ^= m[0];
    state->a.S[1] ^= m[1];
    state->b.S[0] ^= m[2];
    state->b.S[1] ^= m[3];
    ascon_permute_masked_x2(state, first_round);
}

void ascon_masked_encrypt_8_x2
    (ascon_masked_state_x2_t *state, unsigned char *dest,
     const unsigned char *src, size_t len, uint8_t first_round)
{
    uint64_t m, m2;
    size_t posn;
    while (len >= 8) {
        m = aead_random_generate_64();
        state->a.S[0] ^= be_load_word64(src) ^ m;
        state->b.S[0] ^= m;
        be_store_word64(dest, state->a.S[0] ^ state->b.S[0]);
        ascon_permute_masked_x2(state, first_round);
        dest += 8;
        src += 8;
        len -= 8;
    }
    m2 = m = aead_random_generate_64();
    for (posn = 0; posn < len; ++posn) {
        m ^= ((uint64_t)(src[posn])) << (56 - posn * 8);
    }
    m ^= 0x80ULL << (56 - len * 8);
    state->a.S[0] ^= m;
    state->b.S[0] ^= m2;
    m = state->a.S[0] ^ state->b.S[0];
    for (posn = 0; posn < len; ++posn) {
        dest[posn] = (unsigned char)(m >> (56 - posn * 8));
    }
}

void ascon_masked_decrypt_8_x2
    (ascon_masked_state_x2_t *state, unsigned char *dest,
     const unsigned char *src, size_t len, uint8_t first_round)
{
    uint64_t m, m2;
    size_t posn;
    while (len >= 8) {
        m2 = aead_random_generate_64();
        m = (be_load_word64(src) ^ state->a.S[0]) ^ state->b.S[0];
        state->a.S[0] ^= m ^ m2;
        state->b.S[0] ^= m2;
        be_store_word64(dest, m);
        ascon_permute_masked_x2(state, first_round);
        dest += 8;
        src += 8;
        len -= 8;
    }
    m2 = aead_random_generate_64();
    m = state->a.S[0];
    for (posn = 0; posn < len; ++posn) {
        m ^= ((uint64_t)(src[posn])) << (56 - posn * 8);
        dest[posn] = (unsigned char)(m >> (56 - posn * 8));
    }
    m ^= state->b.S[0];
    for (posn = 0; posn < len; ++posn) {
        dest[posn] = (unsigned char)(m >> (56 - posn * 8));
    }
    if (len > 0) {
        m &= (~0ULL) << (64 - len * 8);
        m ^= 0x80ULL << (56 - len * 8);
    } else {
        m = 0x8000000000000000ULL;
    }
    state->a.S[0] ^= m ^ m2;
    state->b.S[0] ^= m2;
}

void ascon_masked_encrypt_16_x2
    (ascon_masked_state_x2_t *state, unsigned char *dest,
     const unsigned char *src, size_t len, uint8_t first_round)
{
    uint64_t m[4];
    size_t posn;
    while (len >= 16) {
        aead_random_generate_64_multiple(m, 2);
        state->a.S[0] ^= be_load_word64(src) ^ m[0];
        state->b.S[0] ^= m[0];
        state->a.S[1] ^= be_load_word64(src + 8) ^ m[1];
        state->b.S[1] ^= m[1];
        be_store_word64(dest, state->a.S[0] ^ state->b.S[0]);
        be_store_word64(dest + 8, state->a.S[1] ^ state->b.S[1]);
        ascon_permute_masked_x2(state, first_round);
        dest += 16;
        src += 16;
        len -= 16;
    }
    if (len < 8) {
        m[1] = m[0] = aead_random_generate_64();
        for (posn = 0; posn < len; ++posn) {
            m[0] ^= ((uint64_t)(src[posn])) << (56 - posn * 8);
        }
        m[0] ^= 0x80ULL << (56 - len * 8);
        state->a.S[0] ^= m[0];
        state->b.S[0] ^= m[1];
        m[0] = state->a.S[0] ^ state->b.S[0];
        for (posn = 0; posn < len; ++posn) {
            dest[posn] = (unsigned char)(m[0] >> (56 - posn * 8));
        }
    } else {
        aead_random_generate_64_multiple(m, 2);
        m[2] = m[0];
        m[3] = m[1];
        m[0] ^= be_load_word64(src);
        state->a.S[0] ^= m[0];
        state->b.S[0] ^= m[2];
        be_store_word64(dest, state->a.S[0] ^ state->b.S[0]);
        dest += 8;
        src += 8;
        len -= 8;
        for (posn = 0; posn < len; ++posn) {
            m[1] ^= ((uint64_t)(src[posn])) << (56 - posn * 8);
        }
        m[1] ^= 0x80ULL << (56 - len * 8);
        state->a.S[1] ^= m[1];
        state->b.S[1] ^= m[3];
        m[1] = state->a.S[1] ^ state->b.S[1];
        for (posn = 0; posn < len; ++posn) {
            dest[posn] = (unsigned char)(m[1] >> (56 - posn * 8));
        }
    }
}

void ascon_masked_decrypt_16_x2
    (ascon_masked_state_x2_t *state, unsigned char *dest,
     const unsigned char *src, size_t len, uint8_t first_round)
{
    uint64_t m[4];
    size_t posn;
    while (len >= 16) {
        aead_random_generate_64_multiple(m, 2);
        m[2] = (be_load_word64(src) ^ state->a.S[0]) ^ state->b.S[0];
        m[3] = (be_load_word64(src + 8) ^ state->a.S[1]) ^ state->b.S[1];
        state->a.S[0] ^= m[0] ^ m[2];
        state->a.S[1] ^= m[1] ^ m[3];
        state->b.S[0] ^= m[0];
        state->b.S[1] ^= m[1];
        be_store_word64(dest, m[2]);
        be_store_word64(dest + 8, m[3]);
        ascon_permute_masked_x2(state, first_round);
        dest += 16;
        src += 16;
        len -= 16;
    }
    if (len < 8) {
        m[1] = aead_random_generate_64();
        m[0] = state->a.S[0];
        for (posn = 0; posn < len; ++posn) {
            m[0] ^= ((uint64_t)(src[posn])) << (56 - posn * 8);
        }
        m[0] ^= state->b.S[0];
        if (len > 0) {
            m[0] &= (~0ULL) << (64 - len * 8);
            m[0] ^= 0x80ULL << (56 - len * 8);
        } else {
            m[0] = 0x8000000000000000ULL;
        }
        state->a.S[0] ^= m[0] ^ m[1];
        state->b.S[0] ^= m[1];
        for (posn = 0; posn < len; ++posn) {
            dest[posn] = (unsigned char)(m[0] >> (56 - posn * 8));
        }
    } else {
        aead_random_generate_64_multiple(m, 2);
        m[2] = (be_load_word64(src) ^ state->a.S[0]) ^ state->b.S[0];
        state->a.S[0] ^= m[0] ^ m[2];
        state->b.S[0] ^= m[0];
        be_store_word64(dest, m[2]);
        dest += 8;
        src += 8;
        len -= 8;
        m[3] = state->a.S[1];
        for (posn = 0; posn < len; ++posn) {
            m[3] ^= ((uint64_t)(src[posn])) << (56 - posn * 8);
        }
        m[3] ^= state->b.S[1];
        for (posn = 0; posn < len; ++posn) {
            dest[posn] = (unsigned char)(m[3] >> (56 - posn * 8));
        }
        if (len > 0) {
            m[3] &= (~0ULL) << (64 - len * 8);
            m[3] ^= 0x80ULL << (56 - len * 8);
        } else {
            m[3] = 0x8000000000000000ULL;
        }
        state->a.S[1] ^= m[3] ^ m[1];
        state->b.S[1] ^= m[1];
    }
}

void ascon_masked_refresh_x2(ascon_masked_state_x2_t *state)
{
    uint64_t m[5];
    aead_random_generate_64_multiple(m, 5);
    state->a.S[0] ^= m[0];
    state->a.S[1] ^= m[1];
    state->a.S[2] ^= m[2];
    state->a.S[3] ^= m[3];
    state->a.S[4] ^= m[4];
    state->b.S[0] ^= m[0];
    state->b.S[1] ^= m[1];
    state->b.S[2] ^= m[2];
    state->b.S[3] ^= m[3];
    state->b.S[4] ^= m[4];
}

void ascon_masked_key_refresh_x2(ascon_masked_key_x2_t *mk)
{
    uint64_t m[3];
    aead_random_generate_64_multiple(m, 3);
    mk->S[0] ^= m[0];
    mk->S[1] ^= m[1];
    mk->S[2] ^= m[2];
    mk->S[3] ^= m[0];
    mk->S[4] ^= m[1];
    mk->S[5] ^= m[2];
}

#else /* ASCON_SLICED */

/**
 * \brief Computes x ^= (~y & z) with a 2-share masked representation
 * and XOR's the result with the output variable (sliced version).
 *
 * \param half e or o for the half to apply to.
 * \param x Output variable to XOR with.
 * \param y First input variable.
 * \param z Second input variable.
 */
#define and_not_xor_sliced(half, x, y, z) \
    do { \
        a_##x##_##half ^= ((~a_##y##_##half) & b_##z##_##half); \
        a_##x##_##half ^= ((~a_##y##_##half) & a_##z##_##half); \
        b_##x##_##half ^= (b_##y##_##half & b_##z##_##half); \
        b_##x##_##half ^= (b_##y##_##half & a_##z##_##half); \
    } while (0)

void ascon_permute_masked_x2
    (ascon_masked_state_x2_t *state, uint8_t first_round)
{
    static const unsigned char RC[12 * 2] = {
        12, 12, 9, 12, 12, 9, 9, 9, 6, 12, 3, 12,
        6, 9, 3, 9, 12, 6, 9, 6, 12, 3, 9, 3
    };
    const unsigned char *rc = RC + first_round * 2;
    uint32_t a_x0_e, a_x1_e, a_x2_e, a_x3_e, a_x4_e;
    uint32_t a_x0_o, a_x1_o, a_x2_o, a_x3_o, a_x4_o;
    uint32_t b_x0_e, b_x1_e, b_x2_e, b_x3_e, b_x4_e;
    uint32_t b_x0_o, b_x1_o, b_x2_o, b_x3_o, b_x4_o;
    uint32_t a_t0_e, a_t0_o, a_t1_e, a_t1_o;
    uint32_t b_t0_e, b_t0_o, b_t1_e, b_t1_o;

    /* We need two words of new randomness for use in the AND-NOT's below. */
    a_t0_e = aead_random_generate_32();
    a_t0_o = aead_random_generate_32();

    /* Load the state into local variables */
    a_x0_e = state->a.W[0];
    a_x0_o = state->a.W[1];
    a_x1_e = state->a.W[2];
    a_x1_o = state->a.W[3];
    a_x2_e = state->a.W[4];
    a_x2_o = state->a.W[5];
    a_x3_e = state->a.W[6];
    a_x3_o = state->a.W[7];
    a_x4_e = state->a.W[8];
    a_x4_o = state->a.W[9];
    b_x0_e = state->b.W[0];
    b_x0_o = state->b.W[1];
    b_x1_e = state->b.W[2];
    b_x1_o = state->b.W[3];
    b_x2_e = state->b.W[4];
    b_x2_o = state->b.W[5];
    b_x3_e = state->b.W[6];
    b_x3_o = state->b.W[7];
    b_x4_e = state->b.W[8];
    b_x4_o = state->b.W[9];

    /* Perform all permutation rounds */
    for (; first_round < 12; ++first_round, rc += 2) {
        /* Add the round constant to the state (even half) */
        a_x2_e ^= rc[0];

        /* Substitution layer (even half) */
        a_x0_e ^= a_x4_e;                   /* x0 ^= x4; */
        b_x0_e ^= b_x4_e;
        a_x4_e ^= a_x3_e;                   /* x4 ^= x3; */
        b_x4_e ^= b_x3_e;
        a_x2_e ^= a_x1_e;                   /* x2 ^= x1; */
        b_x2_e ^= b_x1_e;
        a_t1_e = a_x0_e;                    /* t1 = x0; */
        b_t1_e = b_x0_e;
        b_t0_e = a_t0_e;                    /* t0 = random shares */
        and_not_xor_sliced(e, t0, x0, x1);  /* t0 ^= (~x0) & x1; */
        and_not_xor_sliced(e, x0, x1, x2);  /* x0 ^= (~x1) & x2; */
        and_not_xor_sliced(e, x1, x2, x3);  /* x1 ^= (~x2) & x3; */
        and_not_xor_sliced(e, x2, x3, x4);  /* x2 ^= (~x3) & x4; */
        and_not_xor_sliced(e, x3, x4, t1);  /* x3 ^= (~x4) & t1; */
        a_x4_e ^= a_t0_e;                   /* x4 ^= t0; */
        b_x4_e ^= b_t0_e;
        a_x1_e ^= a_x0_e;                   /* x1 ^= x0; */
        b_x1_e ^= b_x0_e;
        a_x0_e ^= a_x4_e;                   /* x0 ^= x4; */
        b_x0_e ^= b_x4_e;
        a_x3_e ^= a_x2_e;                   /* x3 ^= x2; */
        b_x3_e ^= b_x2_e;
        a_x2_e = ~a_x2_e;                   /* x2 = ~x2; */

        /* Add the round constant to the state (odd half) */
        a_x2_o ^= rc[1];

        /* Substitution layer (odd half) */
        a_x0_o ^= a_x4_o;                   /* x0 ^= x4; */
        b_x0_o ^= b_x4_o;
        a_x4_o ^= a_x3_o;                   /* x4 ^= x3; */
        b_x4_o ^= b_x3_o;
        a_x2_o ^= a_x1_o;                   /* x2 ^= x1; */
        b_x2_o ^= b_x1_o;
        a_t1_o = a_x0_o;                    /* t1 = x0; */
        b_t1_o = b_x0_o;
        b_t0_o = a_t0_o;                    /* t0 = random shares */
        and_not_xor_sliced(o, t0, x0, x1);  /* t0 ^= (~x0) & x1; */
        and_not_xor_sliced(o, x0, x1, x2);  /* x0 ^= (~x1) & x2; */
        and_not_xor_sliced(o, x1, x2, x3);  /* x1 ^= (~x2) & x3; */
        and_not_xor_sliced(o, x2, x3, x4);  /* x2 ^= (~x3) & x4; */
        and_not_xor_sliced(o, x3, x4, t1);  /* x3 ^= (~x4) & t1; */
        a_x4_o ^= a_t0_o;                   /* x4 ^= t0; */
        b_x4_o ^= b_t0_o;
        a_x1_o ^= a_x0_o;                   /* x1 ^= x0; */
        b_x1_o ^= b_x0_o;
        a_x0_o ^= a_x4_o;                   /* x0 ^= x4; */
        b_x0_o ^= b_x4_o;
        a_x3_o ^= a_x2_o;                   /* x3 ^= x2; */
        b_x3_o ^= b_x2_o;
        a_x2_o = ~a_x2_o;                   /* x2 = ~x2; */

        /* Linear diffusion layer */
        #define ascon_linear_sliced_share(share) \
            do { \
                /* x0 ^= rightRotate19_64(x0) ^ rightRotate28_64(x0); */ \
                a_t1_e = share##_x0_e ^ rightRotate4(share##_x0_o); \
                a_t1_o = share##_x0_o ^ rightRotate5(share##_x0_e); \
                share##_x0_e ^= rightRotate9(a_t1_o); \
                share##_x0_o ^= rightRotate10(a_t1_e); \
                /* x1 ^= rightRotate61_64(x1) ^ rightRotate39_64(x1); */ \
                a_t1_e = share##_x1_e ^ rightRotate11(share##_x1_e); \
                a_t1_o = share##_x1_o ^ rightRotate11(share##_x1_o); \
                share##_x1_e ^= rightRotate19(a_t1_o); \
                share##_x1_o ^= rightRotate20(a_t1_e); \
                /* x2 ^= rightRotate1_64(x2)  ^ rightRotate6_64(x2); */ \
                a_t1_e = share##_x2_e ^ rightRotate2(share##_x2_o); \
                a_t1_o = share##_x2_o ^ rightRotate3(share##_x2_e); \
                share##_x2_e ^= a_t1_o; \
                share##_x2_o ^= rightRotate1(a_t1_e); \
                /* x3 ^= rightRotate10_64(x3) ^ rightRotate17_64(x3); */ \
                a_t1_e = share##_x3_e ^ rightRotate3(share##_x3_o); \
                a_t1_o = share##_x3_o ^ rightRotate4(share##_x3_e); \
                share##_x3_e ^= rightRotate5(a_t1_e); \
                share##_x3_o ^= rightRotate5(a_t1_o); \
                /* x4 ^= rightRotate7_64(x4)  ^ rightRotate41_64(x4); */ \
                a_t1_e = share##_x4_e ^ rightRotate17(share##_x4_e); \
                a_t1_o = share##_x4_o ^ rightRotate17(share##_x4_o); \
                share##_x4_e ^= rightRotate3(a_t1_o); \
                share##_x4_o ^= rightRotate4(a_t1_e); \
            } while (0)
        ascon_linear_sliced_share(a);
        ascon_linear_sliced_share(b);
    }

    /* Write the local variables back to the state */
    state->a.W[0] = a_x0_e;
    state->a.W[1] = a_x0_o;
    state->a.W[2] = a_x1_e;
    state->a.W[3] = a_x1_o;
    state->a.W[4] = a_x2_e;
    state->a.W[5] = a_x2_o;
    state->a.W[6] = a_x3_e;
    state->a.W[7] = a_x3_o;
    state->a.W[8] = a_x4_e;
    state->a.W[9] = a_x4_o;
    state->b.W[0] = b_x0_e;
    state->b.W[1] = b_x0_o;
    state->b.W[2] = b_x1_e;
    state->b.W[3] = b_x1_o;
    state->b.W[4] = b_x2_e;
    state->b.W[5] = b_x2_o;
    state->b.W[6] = b_x3_e;
    state->b.W[7] = b_x3_o;
    state->b.W[8] = b_x4_e;
    state->b.W[9] = b_x4_o;
}

/**
 * \brief Separate the bits in an array of masked words to convert
 * into the bit-sliced representation.
 *
 * \param W Points to the array of words.
 * \param count Number of words to separate, must be even.
 */
static void ascon_masked_separate(uint32_t *W, unsigned count)
{
    uint32_t high, low;
    for (; count >= 2; count -= 2, W += 2) {
        high = W[0];
        low = W[1];
        ascon_separate(high);
        ascon_separate(low);
        W[0] = (high << 16) | (low & 0x0000FFFFU);
        W[1] = (high & 0xFFFF0000U) | (low >> 16);
    }
}

/**
 * \brief Combine the bits in an array of masked words to convert
 * from the bit-sliced representation.
 *
 * \param W Points to the array of words.
 * \param count Number of words to combine, must be even.
 */
static void ascon_masked_combine(uint32_t *W, unsigned count)
{
    uint32_t high, low;
    for (; count >= 2; count -= 2, W += 2) {
        high = (W[0] >> 16) | (W[1] & 0xFFFF0000U);;
        low = (W[0] & 0x0000FFFFU) | (W[1] << 16);;
        ascon_combine(high);
        ascon_combine(low);
        W[0] = high;
        W[1] = low;
    }
}

void ascon_mask_key_128_x2
    (ascon_masked_key_x2_t *mk, uint64_t iv, const unsigned char *k)
{
    aead_random_generate_32_multiple(mk->W + 6, 6);
    mk->W[0] = ((uint32_t)(iv >> 32)) ^ mk->W[6];
    mk->W[1] = ((uint32_t)iv)         ^ mk->W[7];
    mk->W[2] = be_load_word32(k)      ^ mk->W[8];
    mk->W[3] = be_load_word32(k + 4)  ^ mk->W[9];
    mk->W[4] = be_load_word32(k + 8)  ^ mk->W[10];
    mk->W[5] = be_load_word32(k + 12) ^ mk->W[11];
    ascon_masked_separate(mk->W, 12);
}

void ascon_mask_key_160_x2
    (ascon_masked_key_x2_t *mk, uint32_t iv, const unsigned char *k)
{
    aead_random_generate_32_multiple(mk->W + 6, 6);
    mk->W[0] = iv ^ mk->W[6];
    mk->W[1] = be_load_word32(k)      ^ mk->W[7];
    mk->W[2] = be_load_word32(k + 4)  ^ mk->W[8];
    mk->W[3] = be_load_word32(k + 8)  ^ mk->W[9];
    mk->W[4] = be_load_word32(k + 12) ^ mk->W[10];
    mk->W[5] = be_load_word32(k + 16) ^ mk->W[11];
    ascon_masked_separate(mk->W, 12);
}

void ascon_masked_init_key_x2
    (ascon_masked_state_x2_t *state, const ascon_masked_key_x2_t *mk,
     const unsigned char *npub, int is_160_bit)
{
    /* Initialize the masked ASCON state with the IV, key, and nonce */
    aead_random_generate_32_multiple(state->b.W, 10);
    state->a.W[0] = mk->W[0] ^ state->b.W[0];
    state->a.W[1] = mk->W[1] ^ state->b.W[1];
    state->a.W[2] = mk->W[2] ^ state->b.W[2];
    state->a.W[3] = mk->W[3] ^ state->b.W[3];
    state->a.W[4] = mk->W[4] ^ state->b.W[4];
    state->a.W[5] = mk->W[5] ^ state->b.W[5];
    state->b.W[0] ^= mk->W[6];
    state->b.W[1] ^= mk->W[7];
    state->b.W[2] ^= mk->W[8];
    state->b.W[3] ^= mk->W[9];
    state->b.W[4] ^= mk->W[10];
    state->b.W[5] ^= mk->W[11];
    state->a.W[6] = be_load_word32(npub)      ^ state->b.W[6];
    state->a.W[7] = be_load_word32(npub + 4)  ^ state->b.W[7];
    state->a.W[8] = be_load_word32(npub + 8)  ^ state->b.W[8];
    state->a.W[9] = be_load_word32(npub + 12) ^ state->b.W[9];
    ascon_masked_separate(state->a.W + 6, 4);
    ascon_masked_separate(state->b.W + 6, 4);

    /* Permute the initial state */
    ascon_permute_masked_x2(state, 0);

    /* XOR the key back into the state in masked form */
    if (is_160_bit) {
        /* Exclude the IV part of the masked key words */
        state->a.W[4] ^= mk->W[0] & 0x0000FFFFU;
        state->a.W[5] ^= mk->W[1] & 0x0000FFFFU;
        state->b.W[4] ^= mk->W[6] & 0x0000FFFFU;
        state->b.W[5] ^= mk->W[7] & 0x0000FFFFU;
    }
    state->a.W[6] ^= mk->W[2];
    state->a.W[7] ^= mk->W[3];
    state->a.W[8] ^= mk->W[4];
    state->a.W[9] ^= mk->W[5];
    state->b.W[6] ^= mk->W[8];
    state->b.W[7] ^= mk->W[9];
    state->b.W[8] ^= mk->W[10];
    state->b.W[9] ^= mk->W[11];
}

void ascon_masked_finalize_128_x2
    (ascon_masked_state_x2_t *state, const ascon_masked_key_x2_t *mk,
     unsigned char tag[16])
{
    /* Refresh the randomness in the entire state and absorb the key */
    uint32_t m[10];
    aead_random_generate_32_multiple(m, 10);
    state->a.W[0] ^= m[0];
    state->a.W[1] ^= m[1];
    state->a.W[2] ^= m[2] ^ mk->W[2];
    state->a.W[3] ^= m[3] ^ mk->W[3];
    state->a.W[4] ^= m[4] ^ mk->W[4];
    state->a.W[5] ^= m[5] ^ mk->W[5];
    state->a.W[6] ^= m[6];
    state->a.W[7] ^= m[7];
    state->a.W[8] ^= m[8];
    state->a.W[9] ^= m[9];
    state->b.W[0] ^= m[0];
    state->b.W[1] ^= m[1];
    state->b.W[2] ^= m[2] ^ mk->W[8];
    state->b.W[3] ^= m[3] ^ mk->W[9];
    state->b.W[4] ^= m[4] ^ mk->W[10];
    state->b.W[5] ^= m[5] ^ mk->W[11];
    state->b.W[6] ^= m[6];
    state->b.W[7] ^= m[7];
    state->b.W[8] ^= m[8];
    state->b.W[9] ^= m[9];

    /* Permute the state and absorb the key one more time */
    ascon_permute_masked_x2(state, 0);
    state->a.W[6] ^= mk->W[2];
    state->a.W[7] ^= mk->W[3];
    state->a.W[8] ^= mk->W[4];
    state->a.W[9] ^= mk->W[5];
    state->b.W[6] ^= mk->W[8];
    state->b.W[7] ^= mk->W[9];
    state->b.W[8] ^= mk->W[10];
    state->b.W[9] ^= mk->W[11];

    /* Generate the authentication tag */
    m[0] = state->a.W[6] ^ state->b.W[6];
    m[1] = state->a.W[7] ^ state->b.W[7];
    m[2] = state->a.W[8] ^ state->b.W[8];
    m[3] = state->a.W[9] ^ state->b.W[9];
    ascon_masked_combine(m, 4);
    be_store_word32(tag,      m[0]);
    be_store_word32(tag + 4,  m[1]);
    be_store_word32(tag + 8,  m[2]);
    be_store_word32(tag + 12, m[3]);
}

void ascon_masked_finalize_128a_x2
    (ascon_masked_state_x2_t *state, const ascon_masked_key_x2_t *mk,
     unsigned char tag[16])
{
    /* Refresh the randomness in the entire state and absorb the key */
    uint32_t m[10];
    aead_random_generate_32_multiple(m, 10);
    state->a.W[0] ^= m[0];
    state->a.W[1] ^= m[1];
    state->a.W[2] ^= m[2];
    state->a.W[3] ^= m[3];
    state->a.W[4] ^= m[4] ^ mk->W[2];
    state->a.W[5] ^= m[5] ^ mk->W[3];
    state->a.W[6] ^= m[6] ^ mk->W[4];
    state->a.W[7] ^= m[7] ^ mk->W[5];
    state->a.W[8] ^= m[8];
    state->a.W[9] ^= m[9];
    state->b.W[0] ^= m[0];
    state->b.W[1] ^= m[1];
    state->b.W[2] ^= m[2];
    state->b.W[3] ^= m[3];
    state->b.W[4] ^= m[4] ^ mk->W[8];
    state->b.W[5] ^= m[5] ^ mk->W[9];
    state->b.W[6] ^= m[6] ^ mk->W[10];
    state->b.W[7] ^= m[7] ^ mk->W[11];
    state->b.W[8] ^= m[8];
    state->b.W[9] ^= m[9];

    /* Permute the state and absorb the key one more time */
    ascon_permute_masked_x2(state, 0);
    state->a.W[6] ^= mk->W[2];
    state->a.W[7] ^= mk->W[3];
    state->a.W[8] ^= mk->W[4];
    state->a.W[9] ^= mk->W[5];
    state->b.W[6] ^= mk->W[8];
    state->b.W[7] ^= mk->W[9];
    state->b.W[8] ^= mk->W[10];
    state->b.W[9] ^= mk->W[11];

    /* Generate the authentication tag */
    m[0] = state->a.W[6] ^ state->b.W[6];
    m[1] = state->a.W[7] ^ state->b.W[7];
    m[2] = state->a.W[8] ^ state->b.W[8];
    m[3] = state->a.W[9] ^ state->b.W[9];
    ascon_masked_combine(m, 4);
    be_store_word32(tag,      m[0]);
    be_store_word32(tag + 4,  m[1]);
    be_store_word32(tag + 8,  m[2]);
    be_store_word32(tag + 12, m[3]);
}

void ascon_masked_finalize_80pq_x2
    (ascon_masked_state_x2_t *state, const ascon_masked_key_x2_t *mk,
     unsigned char tag[16])
{
    /* Refresh the randomness in the entire state and absorb the key */
    uint32_t m[10];
    aead_random_generate_32_multiple(m, 10);
    state->a.W[0] ^= m[0];
    state->a.W[1] ^= m[1];
    state->a.W[2] ^= m[2] ^ (mk->W[0] << 16) ^ (mk->W[2] >> 16);
    state->a.W[3] ^= m[3] ^ (mk->W[1] << 16) ^ (mk->W[3] >> 16);
    state->a.W[4] ^= m[4] ^ (mk->W[2] << 16) ^ (mk->W[4] >> 16);
    state->a.W[5] ^= m[5] ^ (mk->W[3] << 16) ^ (mk->W[5] >> 16);
    state->a.W[6] ^= m[6] ^ (mk->W[4] << 16);
    state->a.W[7] ^= m[7] ^ (mk->W[5] << 16);
    state->a.W[8] ^= m[8];
    state->a.W[9] ^= m[9];
    state->b.W[0] ^= m[0];
    state->b.W[1] ^= m[1];
    state->b.W[2] ^= m[2] ^ (mk->W[6]  << 16) ^ (mk->W[8]  >> 16);
    state->b.W[3] ^= m[3] ^ (mk->W[7]  << 16) ^ (mk->W[9]  >> 16);
    state->b.W[4] ^= m[4] ^ (mk->W[8]  << 16) ^ (mk->W[10] >> 16);
    state->b.W[5] ^= m[5] ^ (mk->W[9]  << 16) ^ (mk->W[11] >> 16);
    state->b.W[6] ^= m[6] ^ (mk->W[10] << 16);
    state->b.W[7] ^= m[7] ^ (mk->W[11] << 16);
    state->b.W[8] ^= m[8];
    state->b.W[9] ^= m[9];

    /* Permute the state and absorb the key one more time */
    ascon_permute_masked_x2(state, 0);
    state->a.W[6] ^= mk->W[2];
    state->a.W[7] ^= mk->W[3];
    state->a.W[8] ^= mk->W[4];
    state->a.W[9] ^= mk->W[5];
    state->b.W[6] ^= mk->W[8];
    state->b.W[7] ^= mk->W[9];
    state->b.W[8] ^= mk->W[10];
    state->b.W[9] ^= mk->W[11];

    /* Generate the authentication tag */
    m[0] = state->a.W[6] ^ state->b.W[6];
    m[1] = state->a.W[7] ^ state->b.W[7];
    m[2] = state->a.W[8] ^ state->b.W[8];
    m[3] = state->a.W[9] ^ state->b.W[9];
    ascon_masked_combine(m, 4);
    be_store_word32(tag,      m[0]);
    be_store_word32(tag + 4,  m[1]);
    be_store_word32(tag + 8,  m[2]);
    be_store_word32(tag + 12, m[3]);
}

void ascon_masked_absorb_8_x2
    (ascon_masked_state_x2_t *state, const unsigned char *data,
     size_t len, uint8_t first_round)
{
    uint32_t m[4];
    while (len >= 8) {
        aead_random_generate_32_multiple(m, 2);
        m[2] = m[0];
        m[3] = m[1];
        m[0] ^= be_load_word32(data);
        m[1] ^= be_load_word32(data + 4);
        ascon_masked_separate(m, 4);
        state->a.W[0] ^= m[0];
        state->a.W[1] ^= m[1];
        state->b.W[0] ^= m[2];
        state->b.W[1] ^= m[3];
        ascon_permute_masked_x2(state, first_round);
        data += 8;
        len -= 8;
    }
    aead_random_generate_32_multiple(m, 2);
    m[2] = m[0];
    m[3] = m[1];
    lw_xor_block((unsigned char *)m, data, len);
    ((unsigned char *)m)[len] ^= 0x80;
#if defined(LW_UTIL_LITTLE_ENDIAN)
    m[0] = reverse_word32(m[0]);
    m[1] = reverse_word32(m[1]);
    m[2] = reverse_word32(m[2]);
    m[3] = reverse_word32(m[3]);
#endif
    ascon_masked_separate(m, 4);
    state->a.W[0] ^= m[0];
    state->a.W[1] ^= m[1];
    state->b.W[0] ^= m[2];
    state->b.W[1] ^= m[3];
    ascon_permute_masked_x2(state, first_round);
}

void ascon_masked_absorb_16_x2
    (ascon_masked_state_x2_t *state, const unsigned char *data,
     size_t len, uint8_t first_round)
{
    uint32_t m[8];
    while (len >= 16) {
        aead_random_generate_32_multiple(m, 4);
        m[4] = m[0];
        m[5] = m[1];
        m[6] = m[2];
        m[7] = m[3];
        m[0] ^= be_load_word32(data);
        m[1] ^= be_load_word32(data + 4);
        m[2] ^= be_load_word32(data + 8);
        m[3] ^= be_load_word32(data + 12);
        ascon_masked_separate(m, 8);
        state->a.W[0] ^= m[0];
        state->a.W[1] ^= m[1];
        state->a.W[2] ^= m[2];
        state->a.W[3] ^= m[3];
        state->b.W[0] ^= m[4];
        state->b.W[1] ^= m[5];
        state->b.W[2] ^= m[6];
        state->b.W[3] ^= m[7];
        ascon_permute_masked_x2(state, first_round);
        data += 16;
        len -= 16;
    }
    aead_random_generate_32_multiple(m, 4);
    m[4] = m[0];
    m[5] = m[1];
    m[6] = m[2];
    m[7] = m[3];
    lw_xor_block((unsigned char *)m, data, len);
    ((unsigned char *)m)[len] ^= 0x80;
#if defined(LW_UTIL_LITTLE_ENDIAN)
    m[0] = reverse_word32(m[0]);
    m[1] = reverse_word32(m[1]);
    m[2] = reverse_word32(m[2]);
    m[3] = reverse_word32(m[3]);
    m[4] = reverse_word32(m[4]);
    m[5] = reverse_word32(m[5]);
    m[6] = reverse_word32(m[6]);
    m[7] = reverse_word32(m[7]);
#endif
    ascon_masked_separate(m, 8);
    state->a.W[0] ^= m[0];
    state->a.W[1] ^= m[1];
    state->a.W[2] ^= m[2];
    state->a.W[3] ^= m[3];
    state->b.W[0] ^= m[4];
    state->b.W[1] ^= m[5];
    state->b.W[2] ^= m[6];
    state->b.W[3] ^= m[7];
    ascon_permute_masked_x2(state, first_round);
}

void ascon_masked_encrypt_8_x2
    (ascon_masked_state_x2_t *state, unsigned char *dest,
     const unsigned char *src, size_t len, uint8_t first_round)
{
    uint32_t m[4];
    while (len >= 8) {
        aead_random_generate_32_multiple(m, 2);
        m[2] = m[0];
        m[3] = m[1];
        m[0] ^= be_load_word32(src);
        m[1] ^= be_load_word32(src + 4);
        ascon_masked_separate(m, 4);
        m[0] ^= state->a.W[0];
        m[1] ^= state->a.W[1];
        m[2] ^= state->b.W[0];
        m[3] ^= state->b.W[1];
        state->a.W[0] = m[0];
        state->a.W[1] = m[1];
        state->b.W[0] = m[2];
        state->b.W[1] = m[3];
        ascon_masked_combine(m, 4);
        be_store_word32(dest,     m[0] ^ m[2]);
        be_store_word32(dest + 4, m[1] ^ m[3]);
        ascon_permute_masked_x2(state, first_round);
        dest += 8;
        src += 8;
        len -= 8;
    }
    aead_random_generate_32_multiple(m, 2);
    m[2] = m[0];
    m[3] = m[1];
    lw_xor_block((unsigned char *)m, src, len);
    ((unsigned char *)m)[len] ^= 0x80;
#if defined(LW_UTIL_LITTLE_ENDIAN)
    m[0] = reverse_word32(m[0]);
    m[1] = reverse_word32(m[1]);
    m[2] = reverse_word32(m[2]);
    m[3] = reverse_word32(m[3]);
#endif
    ascon_masked_separate(m, 4);
    m[0] ^= state->a.W[0];
    m[1] ^= state->a.W[1];
    m[2] ^= state->b.W[0];
    m[3] ^= state->b.W[1];
    state->a.W[0] = m[0];
    state->a.W[1] = m[1];
    state->b.W[0] = m[2];
    state->b.W[1] = m[3];
    ascon_masked_combine(m, 4);
#if defined(LW_UTIL_LITTLE_ENDIAN)
    m[0] = reverse_word32(m[0]);
    m[1] = reverse_word32(m[1]);
    m[2] = reverse_word32(m[2]);
    m[3] = reverse_word32(m[3]);
#endif
    lw_xor_block_2_src(dest, (const unsigned char *)&(m[0]),
                       (const unsigned char *)&(m[2]), len);
}

void ascon_masked_decrypt_8_x2
    (ascon_masked_state_x2_t *state, unsigned char *dest,
     const unsigned char *src, size_t len, uint8_t first_round)
{
    uint32_t m[4];
    uint32_t mask;
    while (len >= 8) {
        aead_random_generate_32_multiple(m, 2);
        m[2] = m[0];
        m[3] = m[1];
        m[0] ^= be_load_word32(src);
        m[1] ^= be_load_word32(src + 4);
        ascon_masked_separate(m, 4);
        m[0] = (m[0] ^ state->a.W[0]) ^ state->b.W[0];
        m[1] = (m[1] ^ state->a.W[1]) ^ state->b.W[1];
        state->a.W[0] ^= m[0];
        state->a.W[1] ^= m[1];
        state->b.W[0] ^= m[2];
        state->b.W[1] ^= m[3];
        ascon_masked_combine(m, 4);
        be_store_word32(dest,     m[0] ^ m[2]);
        be_store_word32(dest + 4, m[1] ^ m[3]);
        ascon_permute_masked_x2(state, first_round);
        dest += 8;
        src += 8;
        len -= 8;
    }
    aead_random_generate_32_multiple(m, 2);
    m[2] = m[0];
    m[3] = m[1];
    lw_xor_block((unsigned char *)m, src, len);
#if defined(LW_UTIL_LITTLE_ENDIAN)
    m[0] = reverse_word32(m[0]);
    m[1] = reverse_word32(m[1]);
    m[2] = reverse_word32(m[2]);
    m[3] = reverse_word32(m[3]);
#endif
    ascon_masked_separate(m, 4);
    m[0] = (m[0] ^ state->a.W[0]) ^ state->b.W[0];
    m[1] = (m[1] ^ state->a.W[1]) ^ state->b.W[1];
    mask = ~(0xFFFFFFFFU >> (len * 4));
    state->a.W[0] ^= m[0] & mask;
    state->a.W[1] ^= (m[1] & mask) ^ (0x80000000 >> (len * 4));
    state->b.W[0] ^= m[2] & mask;
    state->b.W[1] ^= m[3] & mask;
    ascon_masked_combine(m, 4);
#if defined(LW_UTIL_LITTLE_ENDIAN)
    m[0] = reverse_word32(m[0]);
    m[1] = reverse_word32(m[1]);
    m[2] = reverse_word32(m[2]);
    m[3] = reverse_word32(m[3]);
#endif
    lw_xor_block_2_src(dest, (const unsigned char *)&(m[0]),
                       (const unsigned char *)&(m[2]), len);
}

void ascon_masked_encrypt_16_x2
    (ascon_masked_state_x2_t *state, unsigned char *dest,
     const unsigned char *src, size_t len, uint8_t first_round)
{
    uint32_t m[8];
    while (len >= 16) {
        aead_random_generate_32_multiple(m, 4);
        m[4] = m[0];
        m[5] = m[1];
        m[6] = m[2];
        m[7] = m[3];
        m[0] ^= be_load_word32(src);
        m[1] ^= be_load_word32(src + 4);
        m[2] ^= be_load_word32(src + 8);
        m[3] ^= be_load_word32(src + 12);
        ascon_masked_separate(m, 8);
        m[0] ^= state->a.W[0];
        m[1] ^= state->a.W[1];
        m[2] ^= state->a.W[2];
        m[3] ^= state->a.W[3];
        m[4] ^= state->b.W[0];
        m[5] ^= state->b.W[1];
        m[6] ^= state->b.W[2];
        m[7] ^= state->b.W[3];
        state->a.W[0] = m[0];
        state->a.W[1] = m[1];
        state->a.W[2] = m[2];
        state->a.W[3] = m[3];
        state->b.W[0] = m[4];
        state->b.W[1] = m[5];
        state->b.W[2] = m[6];
        state->b.W[3] = m[7];
        ascon_masked_combine(m, 8);
        be_store_word32(dest,      m[0] ^ m[4]);
        be_store_word32(dest + 4,  m[1] ^ m[5]);
        be_store_word32(dest + 8,  m[2] ^ m[6]);
        be_store_word32(dest + 12, m[3] ^ m[7]);
        ascon_permute_masked_x2(state, first_round);
        dest += 16;
        src += 16;
        len -= 16;
    }
    aead_random_generate_32_multiple(m, 4);
    m[4] = m[0];
    m[5] = m[1];
    m[6] = m[2];
    m[7] = m[3];
    lw_xor_block((unsigned char *)m, src, len);
    ((unsigned char *)m)[len] ^= 0x80;
#if defined(LW_UTIL_LITTLE_ENDIAN)
    m[0] = reverse_word32(m[0]);
    m[1] = reverse_word32(m[1]);
    m[2] = reverse_word32(m[2]);
    m[3] = reverse_word32(m[3]);
    m[4] = reverse_word32(m[4]);
    m[5] = reverse_word32(m[5]);
    m[6] = reverse_word32(m[6]);
    m[7] = reverse_word32(m[7]);
#endif
    ascon_masked_separate(m, 8);
    m[0] ^= state->a.W[0];
    m[1] ^= state->a.W[1];
    m[2] ^= state->a.W[2];
    m[3] ^= state->a.W[3];
    m[4] ^= state->b.W[0];
    m[5] ^= state->b.W[1];
    m[6] ^= state->b.W[2];
    m[7] ^= state->b.W[3];
    state->a.W[0] = m[0];
    state->a.W[1] = m[1];
    state->a.W[2] = m[2];
    state->a.W[3] = m[3];
    state->b.W[0] = m[4];
    state->b.W[1] = m[5];
    state->b.W[2] = m[6];
    state->b.W[3] = m[7];
    ascon_masked_combine(m, 8);
#if defined(LW_UTIL_LITTLE_ENDIAN)
    m[0] = reverse_word32(m[0]);
    m[1] = reverse_word32(m[1]);
    m[2] = reverse_word32(m[2]);
    m[3] = reverse_word32(m[3]);
    m[4] = reverse_word32(m[4]);
    m[5] = reverse_word32(m[5]);
    m[6] = reverse_word32(m[6]);
    m[7] = reverse_word32(m[7]);
#endif
    lw_xor_block_2_src(dest, (const unsigned char *)&(m[0]),
                       (const unsigned char *)&(m[4]), len);
}

void ascon_masked_decrypt_16_x2
    (ascon_masked_state_x2_t *state, unsigned char *dest,
     const unsigned char *src, size_t len, uint8_t first_round)
{
    uint32_t m[8];
    uint32_t mask;
    while (len >= 16) {
        aead_random_generate_32_multiple(m, 4);
        m[4] = m[0];
        m[5] = m[1];
        m[6] = m[2];
        m[7] = m[3];
        m[0] ^= be_load_word32(src);
        m[1] ^= be_load_word32(src + 4);
        m[2] ^= be_load_word32(src + 8);
        m[3] ^= be_load_word32(src + 12);
        ascon_masked_separate(m, 8);
        m[0] = (m[0] ^ state->a.W[0]) ^ state->b.W[0];
        m[1] = (m[1] ^ state->a.W[1]) ^ state->b.W[1];
        m[2] = (m[2] ^ state->a.W[2]) ^ state->b.W[2];
        m[3] = (m[3] ^ state->a.W[3]) ^ state->b.W[3];
        state->a.W[0] ^= m[0];
        state->a.W[1] ^= m[1];
        state->a.W[2] ^= m[2];
        state->a.W[3] ^= m[3];
        state->b.W[0] ^= m[4];
        state->b.W[1] ^= m[5];
        state->b.W[2] ^= m[6];
        state->b.W[3] ^= m[7];
        ascon_masked_combine(m, 8);
        be_store_word32(dest,      m[0] ^ m[4]);
        be_store_word32(dest + 4,  m[1] ^ m[5]);
        be_store_word32(dest + 8,  m[2] ^ m[6]);
        be_store_word32(dest + 12, m[3] ^ m[7]);
        ascon_permute_masked_x2(state, first_round);
        dest += 16;
        src += 16;
        len -= 16;
    }
    aead_random_generate_32_multiple(m, 4);
    m[4] = m[0];
    m[5] = m[1];
    m[6] = m[2];
    m[7] = m[3];
    lw_xor_block((unsigned char *)m, src, len);
#if defined(LW_UTIL_LITTLE_ENDIAN)
    m[0] = reverse_word32(m[0]);
    m[1] = reverse_word32(m[1]);
    m[2] = reverse_word32(m[2]);
    m[3] = reverse_word32(m[3]);
    m[4] = reverse_word32(m[4]);
    m[5] = reverse_word32(m[5]);
    m[6] = reverse_word32(m[6]);
    m[7] = reverse_word32(m[7]);
#endif
    ascon_masked_separate(m, 8);
    m[0] = (m[0] ^ state->a.W[0]) ^ state->b.W[0];
    m[1] = (m[1] ^ state->a.W[1]) ^ state->b.W[1];
    m[2] = (m[2] ^ state->a.W[2]) ^ state->b.W[2];
    m[3] = (m[3] ^ state->a.W[3]) ^ state->b.W[3];
    if (len < 8) {
        mask = ~(0xFFFFFFFFU >> (len * 4));
        state->a.W[0] ^= m[0] & mask;
        state->a.W[1] ^= (m[1] & mask) ^ (0x80000000 >> (len * 4));
        state->b.W[0] ^= m[4] & mask;
        state->b.W[1] ^= m[5] & mask;
    } else {
        mask = ~(0xFFFFFFFFU >> ((len - 8) * 4));
        state->a.W[0] ^= m[0];
        state->a.W[1] ^= m[1];
        state->a.W[2] ^= m[2] & mask;
        state->a.W[3] ^= (m[3] & mask) ^ (0x80000000 >> ((len - 8) * 4));
        state->b.W[0] ^= m[4];
        state->b.W[1] ^= m[5];
        state->b.W[2] ^= m[6] & mask;
        state->b.W[3] ^= m[7] & mask;
    }
    ascon_masked_combine(m, 8);
#if defined(LW_UTIL_LITTLE_ENDIAN)
    m[0] = reverse_word32(m[0]);
    m[1] = reverse_word32(m[1]);
    m[2] = reverse_word32(m[2]);
    m[3] = reverse_word32(m[3]);
    m[4] = reverse_word32(m[4]);
    m[5] = reverse_word32(m[5]);
    m[6] = reverse_word32(m[6]);
    m[7] = reverse_word32(m[7]);
#endif
    lw_xor_block_2_src(dest, (const unsigned char *)&(m[0]),
                       (const unsigned char *)&(m[4]), len);
}

void ascon_masked_refresh_x2(ascon_masked_state_x2_t *state)
{
    uint32_t m[10];
    int index;
    aead_random_generate_32_multiple(m, 10);
    for (index = 0; index < 10; ++index) {
        state->a.W[index] ^= m[index];
        state->b.W[index] ^= m[index];
    }
}

void ascon_masked_key_refresh_x2(ascon_masked_key_x2_t *mk)
{
    uint32_t m[6];
    aead_random_generate_32_multiple(m, 6);
    mk->W[0]  ^= m[0];
    mk->W[1]  ^= m[1];
    mk->W[2]  ^= m[2];
    mk->W[3]  ^= m[3];
    mk->W[4]  ^= m[4];
    mk->W[5]  ^= m[5];
    mk->W[6]  ^= m[0];
    mk->W[7]  ^= m[1];
    mk->W[8]  ^= m[2];
    mk->W[9]  ^= m[3];
    mk->W[10] ^= m[4];
    mk->W[11] ^= m[5];
}

#endif /* ASCON_SLICED */
