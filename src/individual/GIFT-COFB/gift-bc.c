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

#include "gift-bc.h"
#include "internal-gift128.h"
#include "internal-util.h"

size_t gift128_get_key_schedule_size(void)
{
    return sizeof(gift128b_key_schedule_t);
}

size_t gift128_get_parallel_size(void)
{
    return GIFT128_BLOCK_SIZE;
}

void gift128_setup_key
    (gift128_key_schedule_t *ks, const unsigned char *k)
{
    gift128b_init((gift128b_key_schedule_t *)ks, k);
}

void gift128_ecb_encrypt
    (const gift128_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, size_t len)
{
    uint32_t b[4];
    while (len >= GIFT128_BLOCK_SIZE) {
        b[0] = be_load_word32(input);
        b[1] = be_load_word32(input + 4);
        b[2] = be_load_word32(input + 8);
        b[3] = be_load_word32(input + 12);
        gift128_nibbles_to_words(b);
        gift128b_encrypt_preloaded
            ((const gift128b_key_schedule_t *)ks, b, b);
        gift128_words_to_nibbles(b);
        be_store_word32(output,      b[0]);
        be_store_word32(output + 4,  b[1]);
        be_store_word32(output + 8,  b[2]);
        be_store_word32(output + 12, b[3]);
        input += GIFT128_BLOCK_SIZE;
        output += GIFT128_BLOCK_SIZE;
        len -= GIFT128_BLOCK_SIZE;
    }
}

void gift128_ecb_decrypt
    (const gift128_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, size_t len)
{
    uint32_t b[4];
    while (len >= GIFT128_BLOCK_SIZE) {
        b[0] = be_load_word32(input);
        b[1] = be_load_word32(input + 4);
        b[2] = be_load_word32(input + 8);
        b[3] = be_load_word32(input + 12);
        gift128_nibbles_to_words(b);
        gift128b_decrypt_preloaded
            ((const gift128b_key_schedule_t *)ks, b, b);
        gift128_words_to_nibbles(b);
        be_store_word32(output,      b[0]);
        be_store_word32(output + 4,  b[1]);
        be_store_word32(output + 8,  b[2]);
        be_store_word32(output + 12, b[3]);
        input += GIFT128_BLOCK_SIZE;
        output += GIFT128_BLOCK_SIZE;
        len -= GIFT128_BLOCK_SIZE;
    }
}

void gift128_le_setup_key
    (gift128_key_schedule_t *ks, const unsigned char *k)
{
    /* Reverse the key for the back end and set up the schedule */
    unsigned char rk[GIFT128_KEY_SIZE];
    unsigned index;
    for (index = 0; index < GIFT128_KEY_SIZE; ++index)
        rk[index] = k[GIFT128_KEY_SIZE - 1 - index];
    gift128b_init((gift128b_key_schedule_t *)ks, rk);
    aead_clean(rk, sizeof(rk));
}

void gift128_le_ecb_encrypt
    (const gift128_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, size_t len)
{
    uint32_t b[4];
    while (len >= GIFT128_BLOCK_SIZE) {
        b[0] = le_load_word32(input + 12);
        b[1] = le_load_word32(input + 8);
        b[2] = le_load_word32(input + 4);
        b[3] = le_load_word32(input);
        gift128_nibbles_to_words(b);
        gift128b_encrypt_preloaded
            ((const gift128b_key_schedule_t *)ks, b, b);
        gift128_words_to_nibbles(b);
        le_store_word32(output + 12, b[0]);
        le_store_word32(output + 8,  b[1]);
        le_store_word32(output + 4,  b[2]);
        le_store_word32(output,      b[3]);
        input += GIFT128_BLOCK_SIZE;
        output += GIFT128_BLOCK_SIZE;
        len -= GIFT128_BLOCK_SIZE;
    }
}

void gift128_le_ecb_decrypt
    (const gift128_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, size_t len)
{
    uint32_t b[4];
    while (len >= GIFT128_BLOCK_SIZE) {
        b[0] = le_load_word32(input + 12);
        b[1] = le_load_word32(input + 8);
        b[2] = le_load_word32(input + 4);
        b[3] = le_load_word32(input);
        gift128_nibbles_to_words(b);
        gift128b_decrypt_preloaded
            ((const gift128b_key_schedule_t *)ks, b, b);
        gift128_words_to_nibbles(b);
        le_store_word32(output + 12, b[0]);
        le_store_word32(output + 8,  b[1]);
        le_store_word32(output + 4,  b[2]);
        le_store_word32(output,      b[3]);
        input += GIFT128_BLOCK_SIZE;
        output += GIFT128_BLOCK_SIZE;
        len -= GIFT128_BLOCK_SIZE;
    }
}

void gift128b_setup_key
    (gift128_key_schedule_t *ks, const unsigned char *k)
{
    gift128b_init((gift128b_key_schedule_t *)ks, k);
}

void gift128b_ecb_encrypt
    (const gift128_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, size_t len)
{
    uint32_t b[4];
    while (len >= GIFT128_BLOCK_SIZE) {
        b[0] = be_load_word32(input);
        b[1] = be_load_word32(input + 4);
        b[2] = be_load_word32(input + 8);
        b[3] = be_load_word32(input + 12);
        gift128b_encrypt_preloaded
            ((const gift128b_key_schedule_t *)ks, b, b);
        be_store_word32(output,      b[0]);
        be_store_word32(output + 4,  b[1]);
        be_store_word32(output + 8,  b[2]);
        be_store_word32(output + 12, b[3]);
        input += GIFT128_BLOCK_SIZE;
        output += GIFT128_BLOCK_SIZE;
        len -= GIFT128_BLOCK_SIZE;
    }
}

void gift128b_ecb_decrypt
    (const gift128_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, size_t len)
{
    uint32_t b[4];
    while (len >= GIFT128_BLOCK_SIZE) {
        b[0] = be_load_word32(input);
        b[1] = be_load_word32(input + 4);
        b[2] = be_load_word32(input + 8);
        b[3] = be_load_word32(input + 12);
        gift128b_decrypt_preloaded
            ((const gift128b_key_schedule_t *)ks, b, b);
        be_store_word32(output,      b[0]);
        be_store_word32(output + 4,  b[1]);
        be_store_word32(output + 8,  b[2]);
        be_store_word32(output + 12, b[3]);
        input += GIFT128_BLOCK_SIZE;
        output += GIFT128_BLOCK_SIZE;
        len -= GIFT128_BLOCK_SIZE;
    }
}

void gift128_free_schedule(gift128_key_schedule_t *ks)
{
    if (ks)
        aead_clean(ks, sizeof(gift128b_key_schedule_t));
}
