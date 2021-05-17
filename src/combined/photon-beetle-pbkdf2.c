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

#include "photon-beetle-pbkdf2.h"
#include "photon-beetle-hmac.h"
#include "internal-util.h"
#include <string.h>

/* The actual implementation is in the common "internal-pbkdf2.h" file */
#define PBKDF2_ALG_NAME photon_beetle_pbkdf2
#define PBKDF2_HMAC_SIZE PHOTON_BEETLE_HMAC_SIZE
#define PBKDF2_HMAC_STATE photon_beetle_hmac_state_t
#define PBKDF2_HMAC_INIT photon_beetle_hmac_init
#define PBKDF2_HMAC_UPDATE photon_beetle_hmac_update
#define PBKDF2_HMAC_FINALIZE photon_beetle_hmac_finalize
#include "internal-pbkdf2.h"
