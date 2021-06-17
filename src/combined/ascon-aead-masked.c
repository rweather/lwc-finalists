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

#include "ascon-aead-masked.h"
#include "internal-ascon-m2.h"
#include "aead-random.h"
#include <string.h>

int ascon128_masked_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_masked_state_x2_t state;
    ascon_masked_key_x2_t key;

    /* Set the length of the returned ciphertext */
    *clen = mlen + ASCON128_MASKED_TAG_SIZE;

    /* Initialize the ASCON state in masked form */
    aead_random_init();
    ascon_mask_key_128_x2(&key, ASCON128_IV, k);
    ascon_masked_init_key_x2(&state, &key, npub, 0);

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_masked_absorb_8_x2(&state, ad, adlen, 6);

    /* Separator between the associated data and the payload */
    ascon_masked_separator_x2(&state);

    /* Encrypt the plaintext to create the ciphertext */
    ascon_masked_encrypt_8_x2(&state, c, m, mlen, 6);

    /* Finalize and compute the authentication tag in masked form */
    ascon_masked_finalize_128_x2(&state, &key, c + mlen);
    aead_random_finish();
    return 0;
}

int ascon128_masked_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_masked_state_x2_t state;
    ascon_masked_key_x2_t key;
    unsigned char tag[ASCON128_MASKED_TAG_SIZE];

    /* Set the length of the returned plaintext */
    if (clen < ASCON128_MASKED_TAG_SIZE)
        return -1;
    *mlen = clen - ASCON128_MASKED_TAG_SIZE;

    /* Initialize the ASCON state in masked form */
    aead_random_init();
    ascon_mask_key_128_x2(&key, ASCON128_IV, k);
    ascon_masked_init_key_x2(&state, &key, npub, 0);

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_masked_absorb_8_x2(&state, ad, adlen, 6);

    /* Separator between the associated data and the payload */
    ascon_masked_separator_x2(&state);

    /* Decrypt the ciphertext to create the plaintext */
    ascon_masked_decrypt_8_x2(&state, m, c, *mlen, 6);

    /* Finalize and check the authentication tag in masked form */
    ascon_masked_finalize_128_x2(&state, &key, tag);
    aead_random_finish();
    return aead_check_tag(m, *mlen, tag, c + *mlen, ASCON128_MASKED_TAG_SIZE);
}

int ascon128a_masked_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_masked_state_x2_t state;
    ascon_masked_key_x2_t key;

    /* Set the length of the returned ciphertext */
    *clen = mlen + ASCON128_MASKED_TAG_SIZE;

    /* Initialize the ASCON state in masked form */
    aead_random_init();
    ascon_mask_key_128_x2(&key, ASCON128a_IV, k);
    ascon_masked_init_key_x2(&state, &key, npub, 0);

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_masked_absorb_16_x2(&state, ad, adlen, 4);

    /* Separator between the associated data and the payload */
    ascon_masked_separator_x2(&state);

    /* Encrypt the plaintext to create the ciphertext */
    ascon_masked_encrypt_16_x2(&state, c, m, mlen, 4);

    /* Finalize and compute the authentication tag in masked form */
    ascon_masked_finalize_128a_x2(&state, &key, c + mlen);
    aead_random_finish();
    return 0;
}

int ascon128a_masked_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_masked_state_x2_t state;
    ascon_masked_key_x2_t key;
    unsigned char tag[ASCON128_MASKED_TAG_SIZE];

    /* Set the length of the returned plaintext */
    if (clen < ASCON128_MASKED_TAG_SIZE)
        return -1;
    *mlen = clen - ASCON128_MASKED_TAG_SIZE;

    /* Initialize the ASCON state in masked form */
    aead_random_init();
    ascon_mask_key_128_x2(&key, ASCON128a_IV, k);
    ascon_masked_init_key_x2(&state, &key, npub, 0);

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_masked_absorb_16_x2(&state, ad, adlen, 4);

    /* Separator between the associated data and the payload */
    ascon_masked_separator_x2(&state);

    /* Decrypt the ciphertext to create the plaintext */
    ascon_masked_decrypt_16_x2(&state, m, c, *mlen, 4);

    /* Finalize and check the authentication tag in masked form */
    ascon_masked_finalize_128a_x2(&state, &key, tag);
    aead_random_finish();
    return aead_check_tag(m, *mlen, tag, c + *mlen, ASCON128_MASKED_TAG_SIZE);
}

int ascon80pq_masked_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_masked_state_x2_t state;
    ascon_masked_key_x2_t key;

    /* Set the length of the returned ciphertext */
    *clen = mlen + ASCON80PQ_MASKED_TAG_SIZE;

    /* Initialize the ASCON state in masked form */
    aead_random_init();
    ascon_mask_key_160_x2(&key, ASCON80PQ_IV, k);
    ascon_masked_init_key_x2(&state, &key, npub, 1);

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_masked_absorb_8_x2(&state, ad, adlen, 6);

    /* Separator between the associated data and the payload */
    ascon_masked_separator_x2(&state);

    /* Encrypt the plaintext to create the ciphertext */
    ascon_masked_encrypt_8_x2(&state, c, m, mlen, 6);

    /* Finalize and compute the authentication tag */
    ascon_masked_finalize_80pq_x2(&state, &key, c + mlen);
    aead_random_finish();
    return 0;
}

int ascon80pq_masked_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_masked_state_x2_t state;
    ascon_masked_key_x2_t key;
    unsigned char tag[ASCON80PQ_MASKED_TAG_SIZE];

    /* Set the length of the returned plaintext */
    if (clen < ASCON80PQ_MASKED_TAG_SIZE)
        return -1;
    *mlen = clen - ASCON80PQ_MASKED_TAG_SIZE;

    /* Initialize the ASCON state in masked form */
    aead_random_init();
    ascon_mask_key_160_x2(&key, ASCON80PQ_IV, k);
    ascon_masked_init_key_x2(&state, &key, npub, 1);

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_masked_absorb_8_x2(&state, ad, adlen, 6);

    /* Separator between the associated data and the payload */
    ascon_masked_separator_x2(&state);

    /* Decrypt the ciphertext to create the plaintext */
    ascon_masked_decrypt_8_x2(&state, m, c, *mlen, 6);

    /* Finalize and check the authentication tag in masked form */
    ascon_masked_finalize_80pq_x2(&state, &key, tag);
    aead_random_finish();
    return aead_check_tag(m, *mlen, tag, c + *mlen, ASCON80PQ_MASKED_TAG_SIZE);
}
