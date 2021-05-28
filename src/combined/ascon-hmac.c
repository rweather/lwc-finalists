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

#include "ascon-hmac.h"
#include "internal-util.h"
#include <string.h>

/* The actual implementation is in the common "internal-hmac.h" file */

/* ASCON-HMAC */
#define HMAC_ALG_NAME ascon_hmac
#define HMAC_HASH_SIZE ASCON_HASH_SIZE
#define HMAC_BLOCK_SIZE 64
#define HMAC_STATE ascon_hmac_state_t
#define HMAC_HASH_INIT ascon_hash_init
#define HMAC_HASH_UPDATE ascon_xof_absorb
#define HMAC_HASH_FINALIZE ascon_hash_finalize
#include "internal-hmac.h"

/* ASCON-HMACA */
#define HMAC_ALG_NAME ascon_hmaca
#define HMAC_HASH_SIZE ASCON_HASH_SIZE
#define HMAC_BLOCK_SIZE 64
#define HMAC_STATE ascon_hmac_state_t
#define HMAC_HASH_INIT ascon_hasha_init
#define HMAC_HASH_UPDATE ascon_xofa_absorb
#define HMAC_HASH_FINALIZE ascon_hasha_finalize
#include "internal-hmac.h"
