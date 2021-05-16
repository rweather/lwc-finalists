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

#ifndef LWCRYPTO_SPARKLE_HKDF_H
#define LWCRYPTO_SPARKLE_HKDF_H

#include <stddef.h>

/**
 * \file sparkle-hkdf.h
 * \brief HMAC-based key derivation function based on SPARKLE-HMAC.
 *
 * Reference: https://tools.ietf.org/html/rfc5869
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Default output block size for Ecsh256-HKDF.  Key material is
 * generated in blocks of this size.
 */
#define ESCH_256_HKDF_OUTPUT_SIZE 32

/**
 * \brief State for incremental generation of key material from Esch256-HKDF.
 */
typedef struct
{
    /** Hashed key from esch_256_hkdf_extract() */
    unsigned char prk[ESCH_256_HKDF_OUTPUT_SIZE];

    /** Last output block that was generated for esch_256_hkdf_expand() */
    unsigned char out[ESCH_256_HKDF_OUTPUT_SIZE];

    /** Counter for the next output block to generate */
    unsigned char counter;

    /** Current position in the output block */
    unsigned char posn;

} esch_256_hkdf_state_t;

/**
 * \brief Derives key material using Esch256-HKDF.
 *
 * \param out Points to the output buffer to receive the key material.
 * \param outlen Number of bytes of key material to generate, maximum of
 * ESCH_256_HKDF_OUTPUT_SIZE * 255 bytes.
 * \param key Points to the bytes of the key.
 * \param keylen Number of bytes in the key.
 * \param salt Points to the bytes of the salt.
 * \param saltlen Number of bytes in the salt.
 * \param info Points to the bytes of the informational data.
 * \param infolen Number of bytes in the informational data.
 *
 * \return Zero on success or -1 if \a outlen is out of range.
 *
 * \sa esch_256_hkdf_extract(), esch_256_hkdf_expand()
 */
int esch_256_hkdf
    (unsigned char *out, size_t outlen,
     const unsigned char *key, size_t keylen,
     const unsigned char *salt, size_t saltlen,
     const unsigned char *info, size_t infolen);

/**
 * \brief Extracts entropy from a key and salt for Esch256-HKDF.
 *
 * \param state HKDF state to be initialized.
 * \param key Points to the bytes of the key.
 * \param keylen Number of bytes in the key.
 * \param salt Points to the bytes of the salt.
 * \param saltlen Number of bytes in the salt.
 *
 * \sa esch_256_hkdf_expand(), esch_256_hkdf()
 */
void esch_256_hkdf_extract
    (esch_256_hkdf_state_t *state,
     const unsigned char *key, size_t keylen,
     const unsigned char *salt, size_t saltlen);

/**
 * \brief Expands key material using a Esch256-HKDF state.
 *
 * \param state HKDF state to use to expand key material.
 * \param info Points to the bytes of the informational data.
 * \param infolen Number of bytes in the informational data.
 * \param out Points to the output buffer to receive the key material.
 * \param outlen Number of bytes of key material to generate.
 *
 * \return Zero on success or -1 if too many bytes have been generated so far.
 * There is a limit of ESCH_256_HKDF_OUTPUT_SIZE * 255 bytes.
 */
int esch_256_hkdf_expand
    (esch_256_hkdf_state_t *state,
     const unsigned char *info, size_t infolen,
     unsigned char *out, size_t outlen);

/**
 * \brief Frees all sensitive material in a Esch256-HKDF state.
 *
 * \param state Points to the HKDF state.
 */
void esch_256_hkdf_free(esch_256_hkdf_state_t *state);

/**
 * \brief Default output block size for Ecsh384-HKDF.  Key material is
 * generated in blocks of this size.
 */
#define ESCH_384_HKDF_OUTPUT_SIZE 48

/**
 * \brief State for incremental generation of key material from Esch384-HKDF.
 */
typedef struct
{
    /** Hashed key from esch_384_hkdf_extract() */
    unsigned char prk[ESCH_384_HKDF_OUTPUT_SIZE];

    /** Last output block that was generated for esch_384_hkdf_expand() */
    unsigned char out[ESCH_384_HKDF_OUTPUT_SIZE];

    /** Counter for the next output block to generate */
    unsigned char counter;

    /** Current position in the output block */
    unsigned char posn;

} esch_384_hkdf_state_t;

/**
 * \brief Derives key material using Esch384-HKDF.
 *
 * \param out Points to the output buffer to receive the key material.
 * \param outlen Number of bytes of key material to generate, maximum of
 * ESCH_384_HKDF_OUTPUT_SIZE * 255 bytes.
 * \param key Points to the bytes of the key.
 * \param keylen Number of bytes in the key.
 * \param salt Points to the bytes of the salt.
 * \param saltlen Number of bytes in the salt.
 * \param info Points to the bytes of the informational data.
 * \param infolen Number of bytes in the informational data.
 *
 * \return Zero on success or -1 if \a outlen is out of range.
 *
 * \sa esch_384_hkdf_extract(), esch_384_hkdf_expand()
 */
int esch_384_hkdf
    (unsigned char *out, size_t outlen,
     const unsigned char *key, size_t keylen,
     const unsigned char *salt, size_t saltlen,
     const unsigned char *info, size_t infolen);

/**
 * \brief Extracts entropy from a key and salt for Esch384-HKDF.
 *
 * \param state HKDF state to be initialized.
 * \param key Points to the bytes of the key.
 * \param keylen Number of bytes in the key.
 * \param salt Points to the bytes of the salt.
 * \param saltlen Number of bytes in the salt.
 *
 * \sa esch_384_hkdf_expand(), esch_384_hkdf()
 */
void esch_384_hkdf_extract
    (esch_384_hkdf_state_t *state,
     const unsigned char *key, size_t keylen,
     const unsigned char *salt, size_t saltlen);

/**
 * \brief Expands key material using a Esch384-HKDF state.
 *
 * \param state HKDF state to use to expand key material.
 * \param info Points to the bytes of the informational data.
 * \param infolen Number of bytes in the informational data.
 * \param out Points to the output buffer to receive the key material.
 * \param outlen Number of bytes of key material to generate.
 *
 * \return Zero on success or -1 if too many bytes have been generated so far.
 * There is a limit of ESCH_384_HKDF_OUTPUT_SIZE * 255 bytes.
 */
int esch_384_hkdf_expand
    (esch_384_hkdf_state_t *state,
     const unsigned char *info, size_t infolen,
     unsigned char *out, size_t outlen);

/**
 * \brief Frees all sensitive material in a Esch384-HKDF state.
 *
 * \param state Points to the HKDF state.
 */
void esch_384_hkdf_free(esch_384_hkdf_state_t *state);

#ifdef __cplusplus
}
#endif

#endif
