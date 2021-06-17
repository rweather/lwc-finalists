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

#ifndef LWCRYPTO_AEAD_RANDOM_H
#define LWCRYPTO_AEAD_RANDOM_H

#include <stdint.h>

/**
 * \file aead-random.h
 * \brief Utilities that help with the generation of random masking data.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Initializes the system random number generator for the
 * generation of masking material.
 */
void aead_random_init(void);

/**
 * \brief Finishes using the random number source.
 *
 * If the random API has internal state, then this function will
 * destroy the internal state to protect forward secrecy.
 */
void aead_random_finish(void);

/**
 * \brief Generates a single random 32-bit word.
 *
 * \return The random word.
 */
uint32_t aead_random_generate_32(void);

/**
 * \brief Generates a single random 64-bit word.
 *
 * \return The random word.
 */
uint64_t aead_random_generate_64(void);

/**
 * \brief Generates multiple random 32-bit words for masking purposes.
 *
 * \param out Output buffer to receive the words.
 * \param count Number of words to generate.
 */
void aead_random_generate_32_multiple(uint32_t *out, unsigned count);

/**
 * \brief Generates multiple random 64-bit words for masking purposes.
 *
 * \param out Output buffer to receive the words.
 * \param count Number of words to generate.
 */
void aead_random_generate_64_multiple(uint64_t *out, unsigned count);

#ifdef __cplusplus
}
#endif

#endif
