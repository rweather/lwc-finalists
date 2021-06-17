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

#ifndef LW_INTERNAL_ASCON_M2_H
#define LW_INTERNAL_ASCON_M2_H

#include "internal-ascon.h"

/**
 * \file internal-ascon-m2.h
 * \brief Masked implementation of the ASCON permutation with 2 shares.
 *
 * References: http://competitions.cr.yp.to/round3/asconv12.pdf,
 * http://ascon.iaik.tugraz.at/
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Structure of the internal state of the masked ASCON
 * permutation with two shares.
 */
typedef struct
{
    ascon_state_t a;    /**< First share */
    ascon_state_t b;    /**< Second share */

} ascon_masked_state_x2_t;

/**
 * \brief Structure of an ASCON key that has been masked with 2 shares.
 */
typedef union
{
    uint64_t S[6];      /**< 64-bit words of the masked key */
    uint32_t W[12];     /**< 32-bit words of the masked key */

} ascon_masked_key_x2_t;

/**
 * \brief Permutes the 2-share version of the masked ASCON state.
 *
 * \param state The masked ASCON state to be permuted.
 * \param first_round The first round (of 12) to be performed; 0, 4, or 6.
 *
 * The input and output \a state will be in host byte order.
 */
void ascon_permute_masked_x2
    (ascon_masked_state_x2_t *state, uint8_t first_round);

/**
 * \brief Masks a 128-bit key plus a 64-bit initialization vector
 *
 * \param mk Masked version of the key.
 * \param iv Initialization vector which identifies the AEAD variant.
 * \param k Points to the 128 bits of the key.
 */
void ascon_mask_key_128_x2
    (ascon_masked_key_x2_t *mk, uint64_t iv, const unsigned char *k);

/**
 * \brief Masks a 160-bit key plus a 32-bit initialization vector
 *
 * \param mk Masked version of the key.
 * \param iv Initialization vector which identifies the AEAD variant.
 * \param k Points to the 160 bits of the key.
 */
void ascon_mask_key_160_x2
    (ascon_masked_key_x2_t *mk, uint32_t iv, const unsigned char *k);

/**
 * \brief Initializes the 2-share version of a masked ASCON state with a
 * 128-bit key and a 128-bit nonce.
 *
 * \param state The masked ASCON state to be initialized.
 * \param mk Points to the masked key value.
 * \param npub Points to the 128 bits of the nonce.
 * \param is_160_bit Non-zero if the key is 160 bits in size.
 */
void ascon_masked_init_key_x2
    (ascon_masked_state_x2_t *state, const ascon_masked_key_x2_t *mk,
     const unsigned char *npub, int is_160_bit);

/**
 * \brief Finalizes the 2-share version of a masked ASCON state and
 * computes the final authentication tag for ASCON-128.
 *
 * \param The masked ASCON state to be finalized.
 * \param mk Points to the masked key value.
 * \param tag Points to the buffer to receive the authentication tag.
 */
void ascon_masked_finalize_128_x2
    (ascon_masked_state_x2_t *state, const ascon_masked_key_x2_t *mk,
     unsigned char tag[16]);

/**
 * \brief Finalizes the 2-share version of a masked ASCON state and
 * computes the final authentication tag for ASCON-128a.
 *
 * \param The masked ASCON state to be finalized.
 * \param mk Points to the masked key value.
 * \param tag Points to the buffer to receive the authentication tag.
 */
void ascon_masked_finalize_128a_x2
    (ascon_masked_state_x2_t *state, const ascon_masked_key_x2_t *mk,
     unsigned char tag[16]);

/**
 * \brief Finalizes the 2-share version of a masked ASCON state and
 * computes the final authentication tag for ASCON-80pq.
 *
 * \param The masked ASCON state to be finalized.
 * \param mk Points to the masked key value.
 * \param tag Points to the buffer to receive the authentication tag.
 */
void ascon_masked_finalize_80pq_x2
    (ascon_masked_state_x2_t *state, const ascon_masked_key_x2_t *mk,
     unsigned char tag[16]);

/**
 * \brief Absorbs data into a 2-share masked ASCON state with an
 * 8-byte block rate.
 *
 * \param state The state to absorb the data into.
 * \param data Points to the data to be absorbed.
 * \param len Length of the data to be absorbed.
 * \param first_round First round of the permutation to apply each block.
 *
 * Each 8-byte block of data is XOR'ed with the state and then a
 * permutation call is performed.  The last block is padded.
 */
void ascon_masked_absorb_8_x2
    (ascon_masked_state_x2_t *state, const unsigned char *data,
     size_t len, uint8_t first_round);

/**
 * \brief Absorbs data into a 2-share masked ASCON state with a
 * 16-byte block rate.
 *
 * \param state The state to absorb the data into.
 * \param data Points to the data to be absorbed.
 * \param len Length of the data to be absorbed.
 * \param first_round First round of the permutation to apply each block.
 *
 * Each 16-byte block of data is XOR'ed with the state and then a
 * permutation call is performed.  The last block is padded.
 */
void ascon_masked_absorb_16_x2
    (ascon_masked_state_x2_t *state, const unsigned char *data,
     size_t len, uint8_t first_round);

/**
 * \brief Encrypts a block of data with a 2-share masked ASCON state
 * and an 8-byte block rate.
 *
 * \param state The state to encrypt with.
 * \param dest Points to the destination buffer.
 * \param src Points to the source buffer.
 * \param len Length of the data to encrypt from \a src into \a dest.
 * \param first_round First round of the permutation to apply each block.
 */
void ascon_masked_encrypt_8_x2
    (ascon_masked_state_x2_t *state, unsigned char *dest,
     const unsigned char *src, size_t len, uint8_t first_round);

/**
 * \brief Decrypts a block of data with a 2-share masked ASCON state
 * and an 8-byte block rate.
 *
 * \param state The state to encrypt with.
 * \param dest Points to the destination buffer.
 * \param src Points to the source buffer.
 * \param len Length of the data to decrypt from \a src into \a dest.
 * \param first_round First round of the permutation to apply each block.
 */
void ascon_masked_decrypt_8_x2
    (ascon_masked_state_x2_t *state, unsigned char *dest,
     const unsigned char *src, size_t len, uint8_t first_round);

/**
 * \brief Encrypts a block of data with a 2-share masked ASCON state
 * and a 16-byte block rate.
 *
 * \param state The state to encrypt with.
 * \param dest Points to the destination buffer.
 * \param src Points to the source buffer.
 * \param len Length of the data to encrypt from \a src into \a dest.
 * \param first_round First round of the permutation to apply each block.
 */
void ascon_masked_encrypt_16_x2
    (ascon_masked_state_x2_t *state, unsigned char *dest,
     const unsigned char *src, size_t len, uint8_t first_round);

/**
 * \brief Decrypts a block of data with a 2-share masked ASCON state
 * and a 16-byte block rate.
 *
 * \param state The state to encrypt with.
 * \param dest Points to the destination buffer.
 * \param src Points to the source buffer.
 * \param len Length of the data to decrypt from \a src into \a dest.
 * \param first_round First round of the permutation to apply each block.
 */
void ascon_masked_decrypt_16_x2
    (ascon_masked_state_x2_t *state, unsigned char *dest,
     const unsigned char *src, size_t len, uint8_t first_round);

/**
 * \brief Absorb the domain separator between associated data and plaintext.
 *
 * \param state The masked ASCON state.
 */
#define ascon_masked_separator_x2(state) ((state)->a.S[4] ^= 0x01)

/**
 * \brief Refreshes the randomness in a 2-share masked ASCON state.
 *
 * \param state The masked ASCON state to be refreshed.
 */
void ascon_masked_refresh_x2(ascon_masked_state_x2_t *state);

#ifdef __cplusplus
}
#endif

#endif
