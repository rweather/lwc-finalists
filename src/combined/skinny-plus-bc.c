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

#include "skinny-plus-bc.h"
#include "internal-skinny-plus.h"
#include "internal-util.h"
#include <string.h>

size_t skinny_128_384_plus_get_key_schedule_size(void)
{
    return sizeof(skinny_plus_key_schedule_t);
}

size_t skinny_128_384_plus_get_parallel_size(void)
{
    return SKINNY_128_384_PLUS_BLOCK_SIZE;
}

void skinny_128_384_plus_setup_key
    (skinny_128_384_plus_key_schedule_t *ks,
     const unsigned char k[SKINNY_128_384_PLUS_KEY_SIZE])
{
    skinny_plus_init((skinny_plus_key_schedule_t *)ks, k);
}

void skinny_128_384_plus_setup_tk23
    (skinny_128_384_plus_key_schedule_t *ks, const unsigned char *tk2,
     const unsigned char *tk3)
{
    skinny_plus_init_without_tk1((skinny_plus_key_schedule_t *)ks, tk2, tk3);
}

void skinny_128_384_plus_ecb_encrypt
    (const skinny_128_384_plus_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, size_t len)
{
    while (len >= SKINNY_128_384_PLUS_BLOCK_SIZE) {
        skinny_plus_encrypt
            ((const skinny_plus_key_schedule_t *)ks, output, input);
        input += SKINNY_128_384_PLUS_BLOCK_SIZE;
        output += SKINNY_128_384_PLUS_BLOCK_SIZE;
        len -= SKINNY_128_384_PLUS_BLOCK_SIZE;
    }
}

void skinny_128_384_plus_ecb_decrypt
    (const skinny_128_384_plus_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, size_t len)
{
    while (len >= SKINNY_128_384_PLUS_BLOCK_SIZE) {
        skinny_plus_decrypt
            ((const skinny_plus_key_schedule_t *)ks, output, input);
        input += SKINNY_128_384_PLUS_BLOCK_SIZE;
        output += SKINNY_128_384_PLUS_BLOCK_SIZE;
        len -= SKINNY_128_384_PLUS_BLOCK_SIZE;
    }
}

void skinny_128_384_plus_ecb_encrypt_tk1
    (skinny_128_384_plus_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, const unsigned char *tk1, size_t len)
{
    while (len >= SKINNY_128_384_PLUS_BLOCK_SIZE) {
        memcpy(ks->TK1, tk1, 16);
        skinny_plus_encrypt
            ((const skinny_plus_key_schedule_t *)ks, output, input);
        input += SKINNY_128_384_PLUS_BLOCK_SIZE;
        output += SKINNY_128_384_PLUS_BLOCK_SIZE;
        tk1 += SKINNY_128_384_PLUS_BLOCK_SIZE;
        len -= SKINNY_128_384_PLUS_BLOCK_SIZE;
    }
}

void skinny_128_384_plus_ecb_decrypt_tk1
    (skinny_128_384_plus_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, const unsigned char *tk1, size_t len)
{
    while (len >= SKINNY_128_384_PLUS_BLOCK_SIZE) {
        memcpy(ks->TK1, tk1, 16);
        skinny_plus_decrypt
            ((const skinny_plus_key_schedule_t *)ks, output, input);
        input += SKINNY_128_384_PLUS_BLOCK_SIZE;
        output += SKINNY_128_384_PLUS_BLOCK_SIZE;
        tk1 += SKINNY_128_384_PLUS_BLOCK_SIZE;
        len -= SKINNY_128_384_PLUS_BLOCK_SIZE;
    }
}

void skinny_128_384_plus_free_schedule(skinny_128_384_plus_key_schedule_t *ks)
{
    if (ks)
        aead_clean(ks, sizeof(skinny_plus_key_schedule_t));
}

void skinny_128_384_plus_expand_and_encrypt
    (const unsigned char k[SKINNY_128_384_PLUS_KEY_SIZE],
     unsigned char *output, const unsigned char *input, size_t len)
{
    while (len >= SKINNY_128_384_PLUS_BLOCK_SIZE) {
        skinny_plus_encrypt_tk_full(k, output, input);
        input += SKINNY_128_384_PLUS_BLOCK_SIZE;
        output += SKINNY_128_384_PLUS_BLOCK_SIZE;
        len -= SKINNY_128_384_PLUS_BLOCK_SIZE;
    }
}

void skinny_128_384_plus_expand_and_decrypt
    (const unsigned char k[SKINNY_128_384_PLUS_KEY_SIZE],
     unsigned char *output, const unsigned char *input, size_t len)
{
    while (len >= SKINNY_128_384_PLUS_BLOCK_SIZE) {
        skinny_plus_decrypt_tk_full(k, output, input);
        input += SKINNY_128_384_PLUS_BLOCK_SIZE;
        output += SKINNY_128_384_PLUS_BLOCK_SIZE;
        len -= SKINNY_128_384_PLUS_BLOCK_SIZE;
    }
}
