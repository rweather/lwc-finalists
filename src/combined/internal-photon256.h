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

#ifndef LW_INTERNAL_PHOTON256_H
#define LW_INTERNAL_PHOTON256_H

/**
 * \file internal-photon256.h
 * \brief Internal implementation of the PHOTON-256 permutation.
 */

#include "internal-util.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the PHOTON-256 permutation state in bytes.
 */
#define PHOTON256_STATE_SIZE 32

/**
 * \brief Structure of the internal state of the PHOTON-256 permutation.
 */
typedef union
{
    uint32_t W[PHOTON256_STATE_SIZE / 4];   /**< 32-bit words of the state */
    uint8_t B[PHOTON256_STATE_SIZE];        /**< Bytes of the state */

} photon256_state_t;

/**
 * \brief Permutes the PHOTON-256 state.
 *
 * \param state The state to be permuted.
 */
void photon256_permute(photon256_state_t *state);

#ifdef __cplusplus
}
#endif

#endif
