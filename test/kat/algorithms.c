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

#include "algorithms.h"
#include "internal-aesgcm.h"
#include <string.h>
#include <stdio.h>

/* List of all AEAD ciphers that we can run KAT tests for */
static const aead_cipher_t *const ciphers[] = {
    &internal_aesgcm128_cipher,
    &internal_aesgcm192_cipher,
    &internal_aesgcm256_cipher,
    &ascon128_cipher,
    &ascon128a_cipher,
    &ascon80pq_cipher,
    &ascon128_masked_cipher,
    &ascon128a_masked_cipher,
    &ascon80pq_masked_cipher,
    &dumbo_cipher,
    &jumbo_cipher,
    &delirium_cipher,
    &gift_cofb_cipher,
    &gift_cofb_masked_cipher,
    &grain128_aead_cipher,
    &isap_keccak_128a_cipher,
    &isap_ascon_128a_cipher,
    &isap_keccak_128_cipher,
    &isap_ascon_128_cipher,
    &photon_beetle_128_cipher,
    &photon_beetle_32_cipher,
    &romulus_m_cipher,
    &romulus_n_cipher,
    &schwaemm_256_128_cipher,
    &schwaemm_192_192_cipher,
    &schwaemm_128_128_cipher,
    &schwaemm_256_256_cipher,
    &tiny_jambu_128_cipher,
    &tiny_jambu_192_cipher,
    &tiny_jambu_256_cipher,
    &tiny_jambu_128_masked_cipher,
    &tiny_jambu_192_masked_cipher,
    &tiny_jambu_256_masked_cipher,
    &xoodyak_cipher,
    &xoodyak_masked_cipher,
    0
};

/* List of all hash algorithms that we can run KAT tests for */
static const aead_hash_algorithm_t *const hashes[] = {
    &ascon_hash_algorithm,
    &ascon_xof_algorithm,
    &esch_256_hash_algorithm,
    &esch_384_hash_algorithm,
    &photon_beetle_hash_algorithm,
    &romulus_hash_algorithm,
    &xoodyak_hash_algorithm,
    0
};

const aead_cipher_t *find_cipher(const char *name)
{
    int index;
    for (index = 0; ciphers[index] != 0; ++index) {
        if (!strcmp(ciphers[index]->name, name))
            return ciphers[index];
    }
    return 0;
}

const aead_hash_algorithm_t *find_hash_algorithm(const char *name)
{
    int index;
    for (index = 0; hashes[index] != 0; ++index) {
        if (!strcmp(hashes[index]->name, name))
            return hashes[index];
    }
    return 0;
}

static void print_cipher_details(const aead_cipher_t *cipher)
{
    printf("%-30s %8u   %8u   %8u\n",
           cipher->name,
           cipher->key_len * 8,
           cipher->nonce_len * 8,
           cipher->tag_len * 8);
}

static void print_hash_details(const aead_hash_algorithm_t *hash)
{
    printf("%-30s %8u\n", hash->name, hash->hash_len * 8);
}

void print_algorithm_names(void)
{
    int index;
    printf("\nCipher                           Key Bits");
    printf("  Nonce Bits  Tag Bits\n");
    for (index = 0; ciphers[index] != 0; ++index)
        print_cipher_details(ciphers[index]);
    printf("\nHash Algorithm                   Hash Bits\n");
    for (index = 0; hashes[index] != 0; ++index)
        print_hash_details(hashes[index]);
}
