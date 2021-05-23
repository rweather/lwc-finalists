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

#ifndef GENAVR_GEN_H
#define GENAVR_GEN_H

#include "code.h"

// Information about a test vector for a block cipher.
typedef struct
{
    const char *name;
    unsigned char key[48];
    unsigned key_len;
    unsigned char plaintext[16];
    unsigned char ciphertext[16];

} block_cipher_test_vector_t;

// AES block cipher.
Sbox get_aes_sbox();
void gen_aes128_setup_key(Code &code);
void gen_aes192_setup_key(Code &code);
void gen_aes256_setup_key(Code &code);
void gen_aes_ecb_encrypt(Code &code);
bool test_aes128_setup_key(Code &code);
bool test_aes192_setup_key(Code &code);
bool test_aes256_setup_key(Code &code);
bool test_aes_ecb_encrypt(Code &code);

// ASCON permutation.
void gen_ascon_permutation(Code &code);
bool test_ascon_permutation(Code &code);

// GHASH hashing algorithm for GCM.
void gen_ghash_init(Code &code);
void gen_ghash_mul(Code &code);
bool test_ghash_mul(Code &code);

// GIFT-128 block cipher (bit-sliced).
Sbox get_gift128_round_constants();
void gen_gift128b_setup_key(Code &code);
void gen_gift128b_encrypt(Code &code);
void gen_gift128b_encrypt_preloaded(Code &code);
void gen_gift128b_decrypt(Code &code);
void gen_gift128b_decrypt_preloaded(Code &code);
void gen_gift128b_setup_key_alt(Code &code);
void gen_gift128b_encrypt_alt(Code &code);
void gen_gift128b_decrypt_alt(Code &code);
void gen_gift128n_setup_key(Code &code);
void gen_gift128n_encrypt(Code &code);
void gen_gift128n_decrypt(Code &code);
void gen_gift128t_encrypt(Code &code);
void gen_gift128t_decrypt(Code &code);
void gen_gift128n_encrypt_alt(Code &code);
void gen_gift128n_decrypt_alt(Code &code);
bool test_gift128b_setup_key(Code &code);
bool test_gift128n_setup_key(Code &code);
bool test_gift128b_encrypt(Code &code);
bool test_gift128b_encrypt_preloaded(Code &code);
bool test_gift128b_decrypt(Code &code);
bool test_gift128b_decrypt_preloaded(Code &code);
bool test_gift128n_setup_key(Code &code);
bool test_gift128n_encrypt(Code &code);
bool test_gift128n_decrypt(Code &code);
bool test_gift128t_encrypt(Code &code);
bool test_gift128t_decrypt(Code &code);
bool test_gift128n_encrypt_alt(Code &code);
bool test_gift128n_decrypt_alt(Code &code);

// GIFT-128 block cipher (fix-sliced).
Sbox get_gift128_fs_round_constants();
void gen_gift128b_fs_setup_key(Code &code, int num_keys);
void gen_gift128b_fs_setup_key_alt(Code &code, int num_keys);
void gen_gift128n_fs_setup_key(Code &code, int num_keys);
void gen_gift128b_fs_encrypt(Code &code, int num_keys);
void gen_gift128b_fs_encrypt_alt(Code &code, int num_keys);
void gen_gift128b_fs_encrypt_preloaded(Code &code, int num_keys);
void gen_gift128n_fs_encrypt(Code &code, int num_keys);
void gen_gift128n_fs_encrypt_alt(Code &code, int num_keys);
void gen_gift128t_fs_encrypt(Code &code, int num_keys);
void gen_gift128b_fs_decrypt(Code &code, int num_keys);
void gen_gift128b_fs_decrypt_alt(Code &code, int num_keys);
void gen_gift128b_fs_decrypt_preloaded(Code &code, int num_keys);
void gen_gift128n_fs_decrypt(Code &code, int num_keys);
void gen_gift128n_fs_decrypt_alt(Code &code, int num_keys);
void gen_gift128t_fs_decrypt(Code &code, int num_keys);
void gen_gift128_nibbles_to_words(Code &code);
void gen_gift128_words_to_nibbles(Code &code);
bool test_gift128b_fs_setup_key(Code &code, int num_keys);
bool test_gift128n_fs_setup_key(Code &code, int num_keys);
bool test_gift128b_fs_encrypt(Code &code, int num_keys);
bool test_gift128b_fs_encrypt_preloaded(Code &code, int num_keys);
bool test_gift128n_fs_encrypt(Code &code, int num_keys);
bool test_gift128n_fs_encrypt_alt(Code &code, int num_keys);
bool test_gift128t_fs_encrypt(Code &code, int num_keys);
bool test_gift128b_fs_decrypt(Code &code, int num_keys);
bool test_gift128b_fs_decrypt_preloaded(Code &code, int num_keys);
bool test_gift128n_fs_decrypt(Code &code, int num_keys);
bool test_gift128n_fs_decrypt_alt(Code &code, int num_keys);
bool test_gift128t_fs_decrypt(Code &code, int num_keys);
bool test_gift128_nibbles_to_words(Code &code);
bool test_gift128_words_to_nibbles(Code &code);

// Grain-128 stream cipher.
void gen_grain128_core(Code &code);
void gen_grain128_preoutput(Code &code);
void gen_grain128_swap_word32(Code &code);
void gen_grain128_compute_tag(Code &code);
void gen_grain128_interleave(Code &code);
bool test_grain128_core(Code &code);
bool test_grain128_preoutput(Code &code);

// Keccak permutation.
void gen_keccakp_200_permutation(Code &code);
void gen_keccakp_400_permutation(Code &code);
bool test_keccakp_200_permutation(Code &code);
bool test_keccakp_400_permutation(Code &code);

// PHOTON-256 permutation.
void gen_photon256_permutation(Code &code);
bool test_photon256_permutation(Code &code);

// SHA-256 transformation function.
void gen_sha256_transform(Code &code);
bool test_sha256_transform(Code &code);

// SKINNY-128 block cipher.
#define SKINNY128_SBOX_COUNT 5
Sbox get_skinny128_sbox(int num);
void gen_skinny128_384_setup_key(Code &code, int rounds = 56);
void gen_skinny128_256_setup_key(Code &code);
void gen_skinny128_384_encrypt(Code &code, int rounds = 56);
void gen_skinny128_256_encrypt(Code &code);
void gen_skinny128_384_decrypt(Code &code, int rounds = 56);
void gen_skinny128_256_decrypt(Code &code);
bool test_skinny128_384_encrypt(Code &code);
bool test_skinny128_256_encrypt(Code &code);
bool test_skinny128_384_decrypt(Code &code);
bool test_skinny128_256_decrypt(Code &code);

// SPARKLE permutation.
void gen_sparkle256_permutation(Code &code);
void gen_sparkle384_permutation(Code &code);
void gen_sparkle512_permutation(Code &code);
bool test_sparkle256_permutation(Code &code);
bool test_sparkle384_permutation(Code &code);
bool test_sparkle512_permutation(Code &code);

// Spongent-pi permutation.
Sbox get_spongent_sbox();
void gen_spongent160_permutation(Code &code);
void gen_spongent176_permutation(Code &code);
bool test_spongent160_permutation(Code &code);
bool test_spongent176_permutation(Code &code);

// TinyJAMBU permutation.
void gen_tinyjambu128_permutation(Code &code);
void gen_tinyjambu192_permutation(Code &code);
void gen_tinyjambu256_permutation(Code &code);
bool test_tinyjambu128_permutation(Code &code);
bool test_tinyjambu192_permutation(Code &code);
bool test_tinyjambu256_permutation(Code &code);

// Xoodoo permutation.
void gen_xoodoo_permutation(Code &code);
bool test_xoodoo_permutation(Code &code);

#endif
