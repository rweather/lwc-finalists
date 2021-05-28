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

#include "ascon-kmac.h"
#include "internal-util.h"
#include <string.h>

/**
 * \brief Intializes a ASCON-KMAC context with the prefix pre-computed.
 *
 * \param state Points to the KMAC state to initialize.
 */
static void ascon_kmac_init_precomputed(ascon_kmac_state_t *state)
{
    static unsigned char const kmac_iv[40] = {
        0xe9, 0x9c, 0x8c, 0x07, 0x34, 0xea, 0x50, 0x0d,
        0x47, 0xdb, 0x5a, 0xef, 0xc7, 0x14, 0x5c, 0x7d,
        0xa9, 0x83, 0x39, 0x87, 0x9e, 0x0d, 0x0a, 0x5e,
        0x6f, 0xfa, 0x41, 0x35, 0x0e, 0x80, 0x7e, 0x09,
        0x73, 0x27, 0x88, 0x0d, 0x8b, 0x76, 0x4c, 0x34
    };
    memcpy(state->s.state, kmac_iv, sizeof(kmac_iv));
    state->s.count = 0;
    state->s.mode = 0;
}

/**
 * \brief Intializes a ASCON-KMACA context with the prefix pre-computed.
 *
 * \param state Points to the KMAC state to initialize.
 */
static void ascon_kmaca_init_precomputed(ascon_kmac_state_t *state)
{
    static unsigned char const kmac_iv[40] = {
        0xcd, 0xec, 0xd0, 0x06, 0x9c, 0xdd, 0x34, 0x6d,
        0x85, 0x05, 0x91, 0xbd, 0x8b, 0xec, 0x55, 0xce,
        0x7e, 0x37, 0xb5, 0x5f, 0xd2, 0xed, 0x0f, 0x93,
        0x3a, 0xbf, 0xa5, 0x65, 0x20, 0xf6, 0x27, 0xf9,
        0x3b, 0xdc, 0xaa, 0x5c, 0x4b, 0x50, 0x7b, 0x82
    };
    memcpy(state->s.state, kmac_iv, sizeof(kmac_iv));
    state->s.count = 0;
    state->s.mode = 0;
}

/* The actual implementation is in the common "internal-kmac.h" file */

/* ASCON-XOF */
#define KMAC_ALG_NAME ascon_kmac
#define KMAC_SIZE ASCON_KMAC_SIZE
#define KMAC_STATE ascon_kmac_state_t
#define KMAC_RATE ASCON_XOF_RATE
#define KMAC_XOF_INIT ascon_xof_init
#define KMAC_XOF_PREINIT ascon_kmac_init_precomputed
#define KMAC_XOF_ABSORB ascon_xof_absorb
#define KMAC_XOF_SQUEEZE ascon_xof_squeeze
#define KMAC_XOF_PAD ascon_xof_pad
#define KMAC_XOF_IS_ABSORBING(state) ((state)->s.mode == 0)
#include "internal-kmac.h"

/* ASCON-XOFA */
#define KMAC_ALG_NAME ascon_kmaca
#define KMAC_SIZE ASCON_KMAC_SIZE
#define KMAC_STATE ascon_kmac_state_t
#define KMAC_RATE ASCON_XOF_RATE
#define KMAC_XOF_INIT ascon_xofa_init
#define KMAC_XOF_PREINIT ascon_kmaca_init_precomputed
#define KMAC_XOF_ABSORB ascon_xofa_absorb
#define KMAC_XOF_SQUEEZE ascon_xofa_squeeze
#define KMAC_XOF_PAD ascon_xofa_pad
#define KMAC_XOF_IS_ABSORBING(state) ((state)->s.mode == 0)
#include "internal-kmac.h"
