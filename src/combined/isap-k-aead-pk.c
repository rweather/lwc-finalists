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

#include "isap-k-aead-pk.h"
#include "internal-keccakp-400.h"
#include <string.h>

/* ISAP-K-128A */
#define ISAP_ALG_NAME isap_keccak_128a
#define ISAP_KEY_STATE isap_keccak_128a_key_t
#define ISAP_RATE (144 / 8)
#define ISAP_sH 16
#define ISAP_sE 8
#define ISAP_sB 1
#define ISAP_sK 8
#define ISAP_STATE keccakp_400_state_t
#define ISAP_PERMUTE(s,r) keccakp_400_permute((s), (r))
#include "internal-isap-pk.h"

/* ISAP-K-128 */
#define ISAP_ALG_NAME isap_keccak_128
#define ISAP_KEY_STATE isap_keccak_128_key_t
#define ISAP_RATE (144 / 8)
#define ISAP_sH 20
#define ISAP_sE 12
#define ISAP_sB 12
#define ISAP_sK 12
#define ISAP_STATE keccakp_400_state_t
#define ISAP_PERMUTE(s,r) keccakp_400_permute((s), (r))
#include "internal-isap-pk.h"
