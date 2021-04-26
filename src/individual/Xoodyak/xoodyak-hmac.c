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

#include "xoodyak-hmac.h"
#include "internal-util.h"
#include <string.h>

/* The actual implementation is in the common "internal-hmac.h" file */
#define HMAC_ALG_NAME xoodyak_hmac
#define HMAC_HASH_SIZE XOODYAK_HASH_SIZE
#define HMAC_BLOCK_SIZE 64
#define HMAC_STATE xoodyak_hmac_state_t
#define HMAC_HASH_INIT xoodyak_hash_init
#define HMAC_HASH_UPDATE xoodyak_hash_absorb
#define HMAC_HASH_FINALIZE xoodyak_hash_finalize
#include "internal-hmac.h"
