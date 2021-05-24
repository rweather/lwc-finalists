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

#ifndef LWCRYPTO_ASCON_PERMUTATION_H
#define LWCRYPTO_ASCON_PERMUTATION_H

#include <stdint.h>

/**
 * \file ascon-permutation.h
 * \brief API for raw access to the ASCON permutation.
 *
 * This API implements the SnP "state and permutation" representation
 * for the ASCON state.  Functions are provided for adding input data
 * to the state, performing permutations, and extracting output data.
 *
 * The ASCON state has two modes: "traditional" and "operational".
 * In the traditional mode, the bytes are laid out in the standard
 * big-endian order.  In the "operational" mode, the bytes may be
 * laid out in a different machine-dependent order for greater efficiency.
 *
 * Most functions expect the state to be in operational mode.
 * The application can call ascon_from_operational() to convert to
 * the traditional order so that it can more easily extract data
 * from the state directly.
 *
 * The application can also populate data into the state in the
 * traditional order and call ascon_to_operational() to convert
 * it into operational mode for other functions.  This may be useful
 * when initializing the state with a starting arrangement of
 * keys, nonces, and initialization vector values.
 *
 * References: http://competitions.cr.yp.to/round3/asconv12.pdf,
 * http://ascon.iaik.tugraz.at/
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the ASCON permutation state in bytes.
 */
#define ASCON_STATE_SIZE 40

/**
 * \brief Maximum number of rounds for the ASCON permutation.
 */
#define ASCON_MAX_ROUNDS 12

/**
 * \brief Structure of the internal state of the ASCON permutation.
 *
 * Normally the state is in "operational" mode where the position of
 * the traditional bytes will be determined by the back end.
 */
typedef union
{
    uint64_t S[5];      /**< 64-bit words of the state */
    uint32_t W[10];     /**< 32-bit words of the state */
    uint8_t B[40];      /**< Bytes of the state */

} ascon_permutation_state_t;

/**
 * \brief Initializes an ASCON state to all-zeroes.
 *
 * \param state The state to be initialized.
 *
 * On exit, the state will be in the "operational" mode.
 */
void ascon_init(ascon_permutation_state_t *state);

/**
 * \brief Converts an ASCON state from operational mode to traditional mode.
 *
 * \param state The state to be converted.
 *
 * \sa ascon_to_operational()
 */
void ascon_from_operational(ascon_permutation_state_t *state);

/**
 * \brief Converts an ASCON state from traditional mode to operational mode.
 *
 * \param state The state to be converted.
 *
 * \sa ascon_from_operational()
 */
void ascon_to_operational(ascon_permutation_state_t *state);

/**
 * \brief Adds a single byte to the state by XOR'ing it with the existing byte.
 *
 * \param state The state to add the bytes to.
 * \param data The data byte to add to the state.
 * \param offset The offset into the state for adding the byte, between 0
 * and ASCON_STATE_SIZE - 1.
 *
 * If \a offset is out of range, the function call will be ignored.
 *
 * The \a state is assumed to be in the "operational" mode.
 *
 * \sa ascon_add_bytes()
 */
void ascon_add_byte
    (ascon_permutation_state_t *state, unsigned char data, unsigned offset);

/**
 * \brief Adds bytes to the state by XOR'ing them with the existing bytes.
 *
 * \param state The state to add the bytes to.
 * \param data Points to the bytes to be added to the state.
 * \param offset The offset into the state for adding the bytes, between 0
 * and ASCON_STATE_SIZE - 1.
 * \param length The number of bytes to add to the state, between 0 and
 * ASCON_STATE_SIZE - \a offset.
 *
 * If \a offset is out of range, the function call will be ignored.
 * If \a offset + \a length would extend beyond the end of the state,
 * then extra bytes will be ignored.
 *
 * The \a state is assumed to be in the "operational" mode.  Best performance
 * is achieved when \a offset and \a length are a multiple of 8.
 *
 * \sa ascon_add_byte(), ascon_extract_bytes(), ascon_overwrite_bytes()
 */
void ascon_add_bytes
    (ascon_permutation_state_t *state, const unsigned char *data,
     unsigned offset, unsigned length);

/**
 * \brief Writes bytes to the state, overwriting any existing bytes.
 *
 * \param state The state to write the bytes to.
 * \param data Points to the bytes to be written to the state.
 * \param offset The offset into the state for writing the bytes, between 0
 * and ASCON_STATE_SIZE - 1.
 * \param length The number of bytes to write to the state, between 0 and
 * ASCON_STATE_SIZE - \a offset.
 *
 * If \a offset is out of range, the function call will be ignored.
 * If \a offset + \a length would extend beyond the end of the state,
 * then extra bytes will be ignored.
 *
 * The \a state is assumed to be in the "operational" mode.  Best performance
 * is achieved when \a offset and \a length are a multiple of 8.
 *
 * \sa ascon_add_bytes(), ascon_overwrite_with_zeroes()
 */
void ascon_overwrite_bytes
    (ascon_permutation_state_t *state, const unsigned char *data,
     unsigned offset, unsigned length);

/**
 * \brief Overwrites the leading part of the state with zeroes.
 *
 * \param state The state to overwrite.
 * \param count The number of bytes to overwrite, between 0 and
 * ASCON_STATE_SIZE.
 *
 * If \a count is greater than or equal to ASCON_STATE_SIZE, then this
 * function is equivalent to calling ascon_init().
 *
 * The \a state is assumed to be in the "operational" mode.  Best performance
 * is achieved when \a count is a multiple of 8.
 *
 * \sa ascon_overwrite_bytes(), ascon_add_bytes()
 */
void ascon_overwrite_with_zeroes
    (ascon_permutation_state_t *state, unsigned count);

/**
 * \brief Performs N rounds of the ASCON permutation.
 *
 * \param state The state to be permuted.
 * \param rounds The number of rounds to be performed between 0 and
 * ASCON_MAX_ROUNDS.
 *
 * If \a rounds is greater than ASCON_MAX_ROUNDS, then it will be
 * clamped to that value.
 *
 * \sa ascon_permute_all_rounds()
 */
void ascon_permute_n_rounds(ascon_permutation_state_t *state, unsigned rounds);

/**
 * \brief Performs all 12 rounds of the ASCON permutation.
 *
 * \param state The state to be permuted.
 *
 * \sa ascon_permute_n_rounds()
 */
void ascon_permute_all_rounds(ascon_permutation_state_t *state);

/**
 * \brief Extracts bytes from an ASCON state.
 *
 * \param state The state to extract the bytes from.
 * \param data Points to the buffer to receive the extracted bytes.
 * \param offset The offset into the state for extracting the bytes,
 * between 0 and ASCON_STATE_SIZE - 1.
 * \param length The number of bytes to extract from the state, between
 * 0 and ASCON_STATE_SIZE - \a offset.
 *
 * If \a offset is out of range, the function call will be ignored.
 * If \a offset + \a length would extend beyond the end of the state,
 * then extra bytes will be ignored.
 *
 * The \a state is assumed to be in the "operational" mode.  Best performance
 * is achieved when \a offset and \a length are a multiple of 8.
 *
 * \sa ascon_add_bytes(), ascon_extract_and_add_bytes()
 */
void ascon_extract_bytes
    (const ascon_permutation_state_t *state, unsigned char *data,
     unsigned offset, unsigned length);

/**
 * \brief Extracts bytes from an ASCON state and XOR's them with input data.
 *
 * \param state The state to extract the bytes from.
 * \param input Points to the buffer that contains the input data to
 * XOR the extracted bytes against.
 * \param output Points to the buffer to receive the final data.
 * \param offset The offset into the state for extracting the bytes,
 * between 0 and ASCON_STATE_SIZE - 1.
 * \param length The number of bytes to extract from the state, between
 * 0 and ASCON_STATE_SIZE - \a offset.
 *
 * If \a offset is out of range, the function call will be ignored.
 * If \a offset + \a length would extend beyond the end of the state,
 * then extra bytes will be ignored.  For each byte, this function computes:
 *
 * \code
 * output[i] = input[i] ^ state[i + offset]
 * \endcode
 *
 * If your intention is to encrypt plaintext data and then re-absorb
 * the ciphertext into the state for authentication, then ascon_encrypt_bytes()
 * is a better option than this function.
 *
 * The \a state is assumed to be in the "operational" mode.  Best performance
 * is achieved when \a offset and \a length are a multiple of 8.
 *
 * \sa ascon_add_bytes(), ascon_extract_bytes(), ascon_encrypt_bytes()
 */
void ascon_extract_and_add_bytes
    (const ascon_permutation_state_t *state, const unsigned char *input,
     unsigned char *output, unsigned offset, unsigned length);

/**
 * \brief Encrypts bytes by XOR'ing them with the state and then
 * adding the encrypted version back to the state.
 *
 * \param state The state to use to encrypt the bytes.
 * \param input Points to the buffer that contains the input plaintext data
 * to be encrypted.
 * \param output Points to the buffer to receive the ciphertext data.
 * \param offset The offset into the state for extracting the bytes,
 * between 0 and ASCON_STATE_SIZE - 1.
 * \param length The number of bytes to extract from the state, between
 * 0 and ASCON_STATE_SIZE - \a offset.
 * \param padded Non-zero to pad the input data with a 0x80 byte.
 *
 * If \a offset is out of range, the function call will be ignored.
 * If \a offset + \a length would extend beyond the end of the state,
 * then extra bytes will be ignored.  For each byte, this function computes:
 *
 * \code
 * output[i] = input[i] ^ state[i + offset]
 * state[i + offset] = output[i]
 * \endcode
 *
 * This function is useful when implementing AEAD modes with ASCON
 * where the ciphertext needs to be re-absorbed into the state
 * for authentication purposes.
 *
 * The \a state is assumed to be in the "operational" mode.  Best performance
 * is achieved when \a offset and \a length are a multiple of 8.
 *
 * \sa ascon_decrypt_bytes(), ascon_extract_and_add_bytes()
 */
void ascon_encrypt_bytes
    (ascon_permutation_state_t *state, const unsigned char *input,
     unsigned char *output, unsigned offset, unsigned length, int padded);

/**
 * \brief Decrypts bytes by XOR'ing them with the state and then
 * overwriting the state with the original ciphertext.
 *
 * \param state The state to use to encrypt the bytes.
 * \param input Points to the buffer that contains the input ciphertext
 * data to be encrypted.
 * \param output Points to the buffer to receive the plaintext data.
 * \param offset The offset into the state for extracting the bytes,
 * between 0 and ASCON_STATE_SIZE - 1.
 * \param length The number of bytes to extract from the state, between
 * 0 and ASCON_STATE_SIZE - \a offset.
 * \param padded Non-zero to pad the input data with a 0x80 byte.
 *
 * If \a offset is out of range, the function call will be ignored.
 * If \a offset + \a length would extend beyond the end of the state,
 * then extra bytes will be ignored.  For each byte, this function computes:
 *
 * \code
 * output[i] = input[i] ^ state[i + offset]
 * state[i + offset] = input[i]
 * \endcode
 *
 * This function is useful when implementing AEAD modes with ASCON
 * where the ciphertext needs to be re-absorbed into the state
 * for authentication purposes.
 *
 * The \a state is assumed to be in the "operational" mode.  Best performance
 * is achieved when \a offset and \a length are a multiple of 8.
 *
 * \sa ascon_encrypt_bytes(), ascon_extract_and_add_bytes()
 */
void ascon_decrypt_bytes
    (ascon_permutation_state_t *state, const unsigned char *input,
     unsigned char *output, unsigned offset, unsigned length, int padded);

#ifdef __cplusplus
}
#endif

#endif
