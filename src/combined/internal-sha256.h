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

#ifndef LW_INTERNAL_SHA256_H
#define LW_INTERNAL_SHA256_H

#include "aead-metadata.h"

/**
 * \file internal-sha256.h
 * \brief SHA256 implementation for performance comparisons.
 *
 * SHA256 is not one of the NIST lightweight submissions.  We use
 * it as a comparison to evaluate the performance of other hash algorithsm.
 *
 * This SHA256 implementation is based on the one from the
 * <a href="http://rweather.github.com/arduinolibs/crypto.html">Arduino
 * Cryptography Library</a>.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the hash for SHA256.
 */
#define SHA256_HASH_SIZE 32

/**
 * \brief Meta-information block for the SHA256 hash algorithm.
 */
extern aead_hash_algorithm_t const internal_sha256_hash_algorithm;

/**
 * \brief Hashes a block of input data with SHA256 to generate a hash value.
 *
 * \param out Buffer to receive the hash output which must be at least
 * SHA256_HASH_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 */
int internal_sha256_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen);

#ifdef __cplusplus
}
#endif

#endif
