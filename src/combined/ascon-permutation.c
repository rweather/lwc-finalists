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

#include "ascon-permutation.h"
#include "internal-ascon.h"
#include <string.h>

/* Convert from the public API version of the ASCON state to the internal one */
#define ASCON(s) ((ascon_state_t *)(s))

void ascon_init(ascon_permutation_state_t *state)
{
    memset(state, 0, sizeof(ascon_permutation_state_t));
}

void ascon_from_operational(ascon_permutation_state_t *state)
{
#if ASCON_SLICED
    ascon_from_sliced(ASCON(state));
#else
    (void)state;
#endif
}

void ascon_to_operational(ascon_permutation_state_t *state)
{
#if ASCON_SLICED
    ascon_to_sliced(ASCON(state));
#else
    (void)state;
#endif
}

void ascon_add_byte
    (ascon_permutation_state_t *state, unsigned char data, unsigned offset)
{
#if ASCON_SLICED
    unsigned char buf[4] = {0, 0, 0, 0};
    unsigned relative = offset & 7U;
    if (offset >= ASCON_STATE_SIZE)
        return;
    offset >>= 3;
    if (relative < 4U) {
        buf[relative] = data;
        ascon_absorb32_high_sliced(ASCON(state), buf, offset);
    } else {
        buf[relative - 4U] = data;
        ascon_absorb32_low_sliced(ASCON(state), buf, offset);
    }
#else
    if (offset < ASCON_STATE_SIZE)
        state->B[offset] ^= data;
#endif
}

void ascon_add_bytes
    (ascon_permutation_state_t *state, const unsigned char *data,
     unsigned offset, unsigned length)
{
#if ASCON_SLICED
    unsigned char buf[8];
    unsigned relative = offset & 7U;
#endif
    if (offset >= ASCON_STATE_SIZE)
        return;
    if ((ASCON_STATE_SIZE - offset) < length)
        length = ASCON_STATE_SIZE - offset;
#if ASCON_SLICED
    if (relative != 0) {
        unsigned temp = 8U - relative;
        if (temp > length)
            temp = length;
        memset(buf, 0, sizeof(buf));
        memcpy(buf + relative, data, temp);
        offset >>= 3;
        ascon_absorb_sliced(ASCON(state), buf, offset);
        data += temp;
        length -= temp;
        ++offset;
    } else {
        offset >>= 3;
    }
    while (length >= 8U) {
        ascon_absorb_sliced(ASCON(state), data, offset);
        data += 8U;
        ++offset;
        length -= 8U;
    }
    if (length > 0U) {
        memcpy(buf, data, length);
        memset(buf + length, 0, sizeof(buf) - length);
        ascon_absorb_sliced(ASCON(state), buf, offset);
    }
#else
    lw_xor_block(state->B + offset, data, length);
#endif
}

void ascon_overwrite_bytes
    (ascon_permutation_state_t *state, const unsigned char *data,
     unsigned offset, unsigned length)
{
#if ASCON_SLICED
    unsigned char buf[8];
    unsigned relative = offset & 7U;
#endif
    if (offset >= ASCON_STATE_SIZE)
        return;
    if ((ASCON_STATE_SIZE - offset) < length)
        length = ASCON_STATE_SIZE - offset;
#if ASCON_SLICED
    if (relative != 0) {
        unsigned temp = 8U - relative;
        if (temp > length)
            temp = length;
        offset >>= 3;
        ascon_squeeze_sliced(ASCON(state), buf, offset);
        memcpy(buf + relative, data, temp);
        ascon_set_sliced(ASCON(state), buf, offset);
        data += temp;
        length -= temp;
        ++offset;
    } else {
        offset >>= 3;
    }
    while (length >= 8U) {
        ascon_set_sliced(ASCON(state), data, offset);
        data += 8U;
        ++offset;
        length -= 8U;
    }
    if (length > 0U) {
        ascon_squeeze_sliced(ASCON(state), buf, offset);
        memcpy(buf, data, length);
        ascon_set_sliced(ASCON(state), buf, offset);
    }
#else
    memcpy(state->B + offset, data, length);
#endif
}

void ascon_overwrite_with_zeroes
    (ascon_permutation_state_t *state, unsigned count)
{
    if (count >= ASCON_STATE_SIZE) {
        memset(state, 0, sizeof(ascon_permutation_state_t));
    } else {
#if ASCON_SLICED
        unsigned offset = 0;
        while (count >= 8U) {
            state->S[offset] = 0;
            ++offset;
            count -= 8U;
        }
        if (count > 0U) {
            unsigned char buf[8];
            ascon_squeeze_sliced(ASCON(state), buf, offset);
            memset(buf, 0, count);
            ascon_set_sliced(ASCON(state), buf, offset);
        }
#else
        memset(state->B, 0, count);
#endif
    }
}

void ascon_permute_n_rounds(ascon_permutation_state_t *state, unsigned rounds)
{
    uint8_t first_round;
    if (rounds < ASCON_MAX_ROUNDS)
        first_round = (uint8_t)(ASCON_MAX_ROUNDS - rounds);
    else
        first_round = 0;
#if ASCON_SLICED
    ascon_permute_sliced(ASCON(state), first_round);
#else
    ascon_permute(ASCON(state), first_round);
#endif
}

void ascon_permute_all_rounds(ascon_permutation_state_t *state)
{
#if ASCON_SLICED
    ascon_permute_sliced(ASCON(state), 0);
#else
    ascon_permute(ASCON(state), 0);
#endif
}

void ascon_extract_bytes
    (const ascon_permutation_state_t *state, unsigned char *data,
     unsigned offset, unsigned length)
{
#if ASCON_SLICED
    unsigned char buf[8];
    unsigned relative = offset & 7U;
#endif
    if (offset >= ASCON_STATE_SIZE)
        return;
    if ((ASCON_STATE_SIZE - offset) < length)
        length = ASCON_STATE_SIZE - offset;
#if ASCON_SLICED
    if (relative != 0) {
        unsigned temp = 8U - relative;
        if (temp > length)
            temp = length;
        offset >>= 3;
        ascon_squeeze_sliced(ASCON(state), buf, offset);
        memcpy(data, buf + relative, temp);
        data += temp;
        length -= temp;
        ++offset;
    } else {
        offset >>= 3;
    }
    while (length >= 8U) {
        ascon_squeeze_sliced(ASCON(state), data, offset);
        data += 8U;
        ++offset;
        length -= 8U;
    }
    if (length > 0U) {
        ascon_squeeze_sliced(ASCON(state), buf, offset);
        memcpy(data, buf, length);
    }
#else
    memcpy(data, state->B + offset, length);
#endif
}

void ascon_extract_and_add_bytes
    (const ascon_permutation_state_t *state, const unsigned char *input,
     unsigned char *output, unsigned offset, unsigned length)
{
#if ASCON_SLICED
    unsigned char buf[8];
    unsigned relative = offset & 7U;
#endif
    if (offset >= ASCON_STATE_SIZE)
        return;
    if ((ASCON_STATE_SIZE - offset) < length)
        length = ASCON_STATE_SIZE - offset;
#if ASCON_SLICED
    if (relative != 0) {
        unsigned temp = 8U - relative;
        if (temp > length)
            temp = length;
        offset >>= 3;
        ascon_squeeze_sliced(ASCON(state), buf, offset);
        lw_xor_block_2_src(output, input, buf + relative, temp);
        input += temp;
        output += temp;
        length -= temp;
        ++offset;
    } else {
        offset >>= 3;
    }
    while (length >= 8U) {
        ascon_squeeze_sliced(ASCON(state), buf, offset);
        lw_xor_block_2_src(output, input, buf, 8U);
        input += 8U;
        output += 8U;
        ++offset;
        length -= 8U;
    }
    if (length > 0U) {
        ascon_squeeze_sliced(ASCON(state), buf, offset);
        lw_xor_block_2_src(output, input, buf, length);
    }
#else
    lw_xor_block_2_src(output, state->B + offset, input, length);
#endif
}

void ascon_encrypt_bytes
    (ascon_permutation_state_t *state, const unsigned char *input,
     unsigned char *output, unsigned offset, unsigned length, int padded)
{
#if ASCON_SLICED
    unsigned char buf[8];
    unsigned relative = offset & 7U;
#endif
    if (padded) {
        if (offset >= ASCON_STATE_SIZE)
            return;
        if ((ASCON_STATE_SIZE - 1 - offset) < length)
            length = ASCON_STATE_SIZE - 1 - offset;
    } else {
        if (offset >= ASCON_STATE_SIZE)
            return;
        if ((ASCON_STATE_SIZE - offset) < length)
            length = ASCON_STATE_SIZE - offset;
    }
#if ASCON_SLICED
    if (relative != 0) {
        unsigned temp = 8U - relative;
        if (temp > length)
            temp = length;
        offset >>= 3;
        memset(buf, 0, sizeof(buf));
        memcpy(buf + relative, input, temp);
        if ((relative + temp) != 8U && padded) {
            buf[relative + temp] = (unsigned char)0x80;
            ascon_encrypt_sliced(ASCON(state), buf, buf, offset);
            memcpy(output, buf + relative, temp);
            return;
        } else {
            ascon_encrypt_sliced(ASCON(state), buf, buf, offset);
            memcpy(output, buf + relative, temp);
        }
        input += temp;
        output += temp;
        length -= temp;
        ++offset;
    } else {
        offset >>= 3;
    }
    while (length >= 8U) {
        ascon_encrypt_sliced(ASCON(state), output, input, offset);
        input += 8U;
        output += 8U;
        ++offset;
        length -= 8U;
    }
    if (length > 0U || padded) {
        memcpy(buf, input, length);
        if (padded) {
            buf[length] = (unsigned char)0x80;
            memset(buf + length + 1, 0, 7U - length);
        } else {
            memset(buf + length, 0, 8U - length);
        }
        ascon_encrypt_sliced(ASCON(state), buf, buf, offset);
        memcpy(output, buf, length);
    }
#else
    lw_xor_block_2_dest(output, state->B + offset, input, length);
    if (padded)
        state->B[offset + length] ^= (unsigned char)0x80;
#endif
}

void ascon_decrypt_bytes
    (ascon_permutation_state_t *state, const unsigned char *input,
     unsigned char *output, unsigned offset, unsigned length, int padded)
{
#if ASCON_SLICED
    unsigned char buf[8];
    unsigned relative = offset & 7U;
#endif
    if (padded) {
        if (offset >= ASCON_STATE_SIZE)
            return;
        if ((ASCON_STATE_SIZE - 1 - offset) < length)
            length = ASCON_STATE_SIZE - 1 - offset;
    } else {
        if (offset >= ASCON_STATE_SIZE)
            return;
        if ((ASCON_STATE_SIZE - offset) < length)
            length = ASCON_STATE_SIZE - offset;
    }
#if ASCON_SLICED
    if (relative != 0) {
        unsigned temp = 8U - relative;
        if (temp > length)
            temp = length;
        offset >>= 3;
        if ((relative + temp) != 8U && padded) {
            ascon_squeeze_sliced(ASCON(state), buf, offset);
            lw_xor_block_2_dest(output, buf + relative, input, temp);
            memset(buf, 0, relative);
            buf[relative + temp] = (unsigned char)0x80;
            memset(buf + relative + temp + 1, 0, 7U - relative - temp);
            ascon_absorb_sliced(ASCON(state), buf, offset);
            return;
        } else {
            ascon_squeeze_sliced(ASCON(state), buf, offset);
            lw_xor_block_2_dest(output, buf + relative, input, temp);
            memset(buf, 0, relative);
            memset(buf + relative + temp, 0, 8U - relative - temp);
            ascon_absorb_sliced(ASCON(state), buf, offset);
        }
        input += temp;
        output += temp;
        length -= temp;
        ++offset;
    } else {
        offset >>= 3;
    }
    while (length >= 8U) {
        ascon_decrypt_sliced(ASCON(state), output, input, offset);
        input += 8U;
        output += 8U;
        ++offset;
        length -= 8U;
    }
    if (length > 0U || padded) {
        ascon_squeeze_sliced(ASCON(state), buf, offset);
        lw_xor_block_2_dest(output, buf, input, length);
        if (padded) {
            buf[length] = (unsigned char)0x80;
            memset(buf + length + 1, 0, 7U - length);
        } else {
            memset(buf + length, 0, 8U - length);
        }
        ascon_absorb_sliced(ASCON(state), buf, offset);
    }
#else
    lw_xor_block_swap(output, state->B + offset, input, length);
    if (padded)
        state->B[offset + length] ^= (unsigned char)0x80;
#endif
}
