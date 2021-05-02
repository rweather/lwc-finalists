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

#ifndef LWCRYPTO_ASCON_PRNG_H
#define LWCRYPTO_ASCON_PRNG_H

#include "ascon-xof.h"

/**
 * \file ascon-prng.h
 * \brief Pseudorandom number generator (PRNG) built around ASCON.
 *
 * This PRNG implementation uses the SpongePRNG construction with
 * ASCON as the sponge permutation.
 *
 * Reference: "Sponge-based pseudo-random number generators",
 * Guido Bertoni et al, https://keccak.team/files/SpongePRNG.pdf
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief State information for an ASCON-based PRNG.
 */
typedef union
{
    struct {
        unsigned char state[40]; /**< Current PRNG state */
        size_t count; /**< Number of bytes generated since last reseed */
        size_t limit; /**< Limit on generated bytes before a reseed */
    } s;
    unsigned long long align; /**< For alignment of this structure */

} ascon_prng_state_t;

/**
 * \brief Adds unique identification information for this device to
 * the global pool.
 *
 * \param data Points to the identification information.
 * \param size Number of bytes of identification information.
 *
 * The application should use this function at startup to add serial
 * numbers and other unique identification information to the global
 * pool for the PRNG.  This data does not need to be secret but can
 * help make the generated output unique for each device.
 *
 * \note This function is not thread-safe so it should be called at
 * startup before threads start using the PRNG to generate random data.
 */
void ascon_prng_add_ident(const unsigned char *data, size_t size);

/**
 * \brief Initializes an ASCON-based PRNG.
 *
 * \param state PRNG state to be initialized.
 *
 * This function will fetch fresh data from the system TRNG to prepare
 * the PRNG state to generate random data.
 */
void ascon_prng_init(ascon_prng_state_t *state);

/**
 * \brief Frees an ASCON-based PRNG and destroys all sensitive information.
 *
 * \param state PRNG state to be freed.
 */
void ascon_prng_free(ascon_prng_state_t *state);

/**
 * \brief Forces an ASCON-based PRNG to re-seed from the system TRNG.
 *
 * \param state PRNG state to be re-seeded.
 */
void ascon_prng_reseed(ascon_prng_state_t *state);

/**
 * \brief Feeds data into an ASCON-based PRNG state to seed it from
 * other sources besides the system TRNG.
 *
 * \param state PRNG state to be feed new seed data.
 * \param data Points to the data to be fed into the PRNG state.
 * \param size Number of bytes of data to be fed into the PRNG state.
 */
void ascon_prng_feed
    (ascon_prng_state_t *state, const unsigned char *data, size_t size);

/**
 * \brief Fetches data from an ASCON-based PRNG state.
 *
 * \param state PRNG state to fetch data from.
 * \param data Points to a buffer to receive the generated random data.
 * \param size Number of bytes of random data to be generated.
 */
void ascon_prng_fetch
    (ascon_prng_state_t *state, unsigned char *data, size_t size);

/**
 * \brief Fetches random data using an ASCON-based PRNG.
 *
 * \param data Points to a buffer to receive the generated random data.
 * \param size Number of bytes of random data to be generated.
 *
 * This function will create a temporary PRNG state object, seed it from
 * the system TRNG, and then generate \a size bytes of random data.
 * It is intended for quick one-off generation of random material.
 */
void ascon_prng_generate(unsigned char *data, size_t size);

#ifdef __cplusplus
}
#endif

#endif
