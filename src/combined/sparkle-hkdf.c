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

#include "sparkle-hkdf.h"
#include "sparkle-hmac.h"
#include "internal-util.h"
#include <string.h>

/* The actual implementation is in the common "internal-hkdf.h" file */

/* HKDF version based on Esch256 */
#define HKDF_ALG_NAME esch_256_hkdf
#define HKDF_STATE esch_256_hkdf_state_t
#define HKDF_HMAC_SIZE ESCH_256_HMAC_SIZE
#define HKDF_HMAC_STATE esch_256_hmac_state_t
#define HKDF_HMAC_INIT esch_256_hmac_init
#define HKDF_HMAC_UPDATE esch_256_hmac_update
#define HKDF_HMAC_FINALIZE esch_256_hmac_finalize
#include "internal-hkdf.h"

/* HKDF version based on Esch384 */
#define HKDF_ALG_NAME esch_384_hkdf
#define HKDF_STATE esch_384_hkdf_state_t
#define HKDF_HMAC_SIZE ESCH_384_HMAC_SIZE
#define HKDF_HMAC_STATE esch_384_hmac_state_t
#define HKDF_HMAC_INIT esch_384_hmac_init
#define HKDF_HMAC_UPDATE esch_384_hmac_update
#define HKDF_HMAC_FINALIZE esch_384_hmac_finalize
#include "internal-hkdf.h"
