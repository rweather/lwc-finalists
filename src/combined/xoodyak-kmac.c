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

#include "xoodyak-kmac.h"
#include "internal-util.h"
#include <string.h>

/* The actual implementation is in the common "internal-kmac.h" file */
#define KMAC_ALG_NAME xoodyak_kmac
#define KMAC_SIZE XOODYAK_KMAC_SIZE
#define KMAC_STATE xoodyak_kmac_state_t
#define KMAC_RATE XOODYAK_HASH_RATE
#define KMAC_XOF_INIT xoodyak_hash_init
#define KMAC_XOF_ABSORB xoodyak_hash_absorb
#define KMAC_XOF_SQUEEZE xoodyak_hash_squeeze
#define KMAC_XOF_PAD xoodyak_hash_pad
#define KMAC_XOF_IS_ABSORBING(state) ((state)->s.mode != 2)
#include "internal-kmac.h"
