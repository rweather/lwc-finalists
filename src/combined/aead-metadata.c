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

#include "aead-metadata.h"
#include "internal-masking.h"
#include "aesgcm-aead.h"
#include "ascon-aead.h"
#include "ascon-aead-masked.h"
#include "ascon-siv.h"
#include "ascon-hash.h"
#include "ascon-xof.h"
#include "elephant-delirium.h"
#include "elephant-dumbo.h"
#include "elephant-jumbo.h"
#include "gift-cofb-aead.h"
#include "gift-cofb-aead-masked.h"
#include "grain-aead.h"
#include "isap-aead.h"
#include "isap-aead-pk.h"
#include "photon-beetle-aead.h"
#include "photon-beetle-hash.h"
#include "romulus-m-aead.h"
#include "romulus-n-aead.h"
#include "romulus-t-aead.h"
#include "romulus-hash.h"
#include "romulus-xof.h"
#include "sparkle-aead.h"
#include "sparkle-hash.h"
#include "tinyjambu-aead.h"
#include "tinyjambu-aead-masked.h"
#include "xoodyak-aead.h"
#include "xoodyak-hash.h"
#include "xoodyak-masked.h"

/*------------------------ AES-GCM ------------------------*/

aead_cipher_t const aesgcm128_cipher = {
    "AES-128-GCM",
    AES128GCM_KEY_SIZE,
    AESGCM_NONCE_SIZE,
    AESGCM_TAG_SIZE,
    AEAD_FLAG_NONE,
    aesgcm128_aead_encrypt,
    aesgcm128_aead_decrypt,
    0, 0
};

aead_cipher_t const aesgcm192_cipher = {
    "AES-192-GCM",
    AES192GCM_KEY_SIZE,
    AESGCM_NONCE_SIZE,
    AESGCM_TAG_SIZE,
    AEAD_FLAG_NONE,
    aesgcm192_aead_encrypt,
    aesgcm192_aead_decrypt,
    0, 0
};

aead_cipher_t const aesgcm256_cipher = {
    "AES-256-GCM",
    AES256GCM_KEY_SIZE,
    AESGCM_NONCE_SIZE,
    AESGCM_TAG_SIZE,
    AEAD_FLAG_NONE,
    aesgcm256_aead_encrypt,
    aesgcm256_aead_decrypt,
    0, 0
};

/*------------------------- ASCON -------------------------*/

aead_cipher_t const ascon128_cipher = {
    "ASCON-128",
    ASCON128_KEY_SIZE,
    ASCON128_NONCE_SIZE,
    ASCON128_TAG_SIZE,
    AEAD_FLAG_NONE,
    ascon128_aead_encrypt,
    ascon128_aead_decrypt,
    0, 0
};

aead_cipher_t const ascon128a_cipher = {
    "ASCON-128a",
    ASCON128_KEY_SIZE,
    ASCON128_NONCE_SIZE,
    ASCON128_TAG_SIZE,
    AEAD_FLAG_NONE,
    ascon128a_aead_encrypt,
    ascon128a_aead_decrypt,
    0, 0
};

aead_cipher_t const ascon80pq_cipher = {
    "ASCON-80pq",
    ASCON80PQ_KEY_SIZE,
    ASCON80PQ_NONCE_SIZE,
    ASCON80PQ_TAG_SIZE,
    AEAD_FLAG_NONE,
    ascon80pq_aead_encrypt,
    ascon80pq_aead_decrypt,
    0, 0
};

aead_hash_algorithm_t const ascon_hash_algorithm = {
    "ASCON-HASH",
    sizeof(ascon_hash_state_t),
    ASCON_HASH_SIZE,
    AEAD_FLAG_NONE,
    ascon_hash,
    (aead_hash_init_t)ascon_hash_init,
    (aead_hash_update_t)ascon_hash_update,
    (aead_hash_finalize_t)ascon_hash_finalize,
    0, /* absorb */
    0  /* squeeze */
};

aead_hash_algorithm_t const ascon_hasha_algorithm = {
    "ASCON-HASHA",
    sizeof(ascon_hash_state_t),
    ASCON_HASH_SIZE,
    AEAD_FLAG_NONE,
    ascon_hasha,
    (aead_hash_init_t)ascon_hasha_init,
    (aead_hash_update_t)ascon_hasha_update,
    (aead_hash_finalize_t)ascon_hasha_finalize,
    0, /* absorb */
    0  /* squeeze */
};

aead_hash_algorithm_t const ascon_xof_algorithm = {
    "ASCON-XOF",
    sizeof(ascon_xof_state_t),
    ASCON_HASH_SIZE,
    AEAD_FLAG_NONE,
    ascon_xof,
    (aead_hash_init_t)ascon_xof_init,
    0, /* update */
    0, /* finalize */
    (aead_xof_absorb_t)ascon_xof_absorb,
    (aead_xof_squeeze_t)ascon_xof_squeeze
};

aead_hash_algorithm_t const ascon_xofa_algorithm = {
    "ASCON-XOFA",
    sizeof(ascon_xof_state_t),
    ASCON_HASH_SIZE,
    AEAD_FLAG_NONE,
    ascon_xofa,
    (aead_hash_init_t)ascon_xofa_init,
    0, /* update */
    0, /* finalize */
    (aead_xof_absorb_t)ascon_xofa_absorb,
    (aead_xof_squeeze_t)ascon_xofa_squeeze
};

aead_cipher_t const ascon128_masked_cipher = {
    "ASCON-128-Masked",
    ASCON128_MASKED_KEY_SIZE,
    ASCON128_MASKED_NONCE_SIZE,
    ASCON128_MASKED_TAG_SIZE,
#if AEAD_MASKING_KEY_ONLY
    AEAD_FLAG_SC_PROTECT_KEY | AEAD_FLAG_MASKED,
#else
    AEAD_FLAG_SC_PROTECT_ALL | AEAD_FLAG_MASKED,
#endif
    ascon128_masked_aead_encrypt,
    ascon128_masked_aead_decrypt,
    0, 0
};

aead_cipher_t const ascon128a_masked_cipher = {
    "ASCON-128a-Masked",
    ASCON128_MASKED_KEY_SIZE,
    ASCON128_MASKED_NONCE_SIZE,
    ASCON128_MASKED_TAG_SIZE,
#if AEAD_MASKING_KEY_ONLY
    AEAD_FLAG_SC_PROTECT_KEY | AEAD_FLAG_MASKED,
#else
    AEAD_FLAG_SC_PROTECT_ALL | AEAD_FLAG_MASKED,
#endif
    ascon128a_masked_aead_encrypt,
    ascon128a_masked_aead_decrypt,
    0, 0
};

aead_cipher_t const ascon80pq_masked_cipher = {
    "ASCON-80pq-Masked",
    ASCON80PQ_MASKED_KEY_SIZE,
    ASCON80PQ_MASKED_NONCE_SIZE,
    ASCON80PQ_MASKED_TAG_SIZE,
#if AEAD_MASKING_KEY_ONLY
    AEAD_FLAG_SC_PROTECT_KEY | AEAD_FLAG_MASKED,
#else
    AEAD_FLAG_SC_PROTECT_ALL | AEAD_FLAG_MASKED,
#endif
    ascon80pq_masked_aead_encrypt,
    ascon80pq_masked_aead_decrypt,
    0, 0
};

aead_cipher_t const ascon128_siv_cipher = {
    "ASCON-128-SIV",
    ASCON128_KEY_SIZE,
    ASCON128_NONCE_SIZE,
    ASCON128_TAG_SIZE,
    AEAD_FLAG_NONE,
    ascon128_siv_encrypt,
    ascon128_siv_decrypt,
    0, 0
};

aead_cipher_t const ascon128a_siv_cipher = {
    "ASCON-128a-SIV",
    ASCON128_KEY_SIZE,
    ASCON128_NONCE_SIZE,
    ASCON128_TAG_SIZE,
    AEAD_FLAG_NONE,
    ascon128a_siv_encrypt,
    ascon128a_siv_decrypt,
    0, 0
};

aead_cipher_t const ascon80pq_siv_cipher = {
    "ASCON-80pq-SIV",
    ASCON80PQ_KEY_SIZE,
    ASCON80PQ_NONCE_SIZE,
    ASCON80PQ_TAG_SIZE,
    AEAD_FLAG_NONE,
    ascon80pq_siv_encrypt,
    ascon80pq_siv_decrypt,
    0, 0
};

/*----------------------- Elephant ------------------------*/

aead_cipher_t const delirium_cipher = {
    "Delirium",
    DELIRIUM_KEY_SIZE,
    DELIRIUM_NONCE_SIZE,
    DELIRIUM_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN | AEAD_FLAG_SLOW,
    delirium_aead_encrypt,
    delirium_aead_decrypt,
    0, 0
};

aead_cipher_t const dumbo_cipher = {
    "Dumbo",
    DUMBO_KEY_SIZE,
    DUMBO_NONCE_SIZE,
    DUMBO_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN | AEAD_FLAG_SLOW,
    dumbo_aead_encrypt,
    dumbo_aead_decrypt,
    0, 0
};

aead_cipher_t const jumbo_cipher = {
    "Jumbo",
    JUMBO_KEY_SIZE,
    JUMBO_NONCE_SIZE,
    JUMBO_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN | AEAD_FLAG_SLOW,
    jumbo_aead_encrypt,
    jumbo_aead_decrypt,
    0, 0
};

/*----------------------- GIFT-COFB -----------------------*/

aead_cipher_t const gift_cofb_cipher = {
    "GIFT-COFB",
    GIFT_COFB_KEY_SIZE,
    GIFT_COFB_NONCE_SIZE,
    GIFT_COFB_TAG_SIZE,
    AEAD_FLAG_NONE,
    gift_cofb_aead_encrypt,
    gift_cofb_aead_decrypt,
    0, 0
};

aead_cipher_t const gift_cofb_masked_cipher = {
    "GIFT-COFB-Masked",
    GIFT_COFB_MASKED_KEY_SIZE,
    GIFT_COFB_MASKED_NONCE_SIZE,
    GIFT_COFB_MASKED_TAG_SIZE,
    AEAD_FLAG_SC_PROTECT_ALL | AEAD_FLAG_MASKED,
    gift_cofb_masked_aead_encrypt,
    gift_cofb_masked_aead_decrypt,
    0, 0
};

/*--------------------- Grain128-AEAD ---------------------*/

aead_cipher_t const grain128_aead_cipher = {
    "Grain-128AEAD",
    GRAIN128_KEY_SIZE,
    GRAIN128_NONCE_SIZE,
    GRAIN128_TAG_SIZE,
    AEAD_FLAG_NONE,
    grain128_aead_encrypt,
    grain128_aead_decrypt,
    0, 0
};

/*-------------------------- ISAP -------------------------*/

aead_cipher_t const isap_keccak_128a_cipher = {
    "ISAP-K-128A",
    ISAP_KEY_SIZE,
    ISAP_NONCE_SIZE,
    ISAP_TAG_SIZE,
    AEAD_FLAG_SC_PROTECT_KEY | AEAD_FLAG_SLOW,
    isap_keccak_128a_aead_encrypt,
    isap_keccak_128a_aead_decrypt,
    0, 0
};

aead_cipher_t const isap_ascon_128a_cipher = {
    "ISAP-A-128A",
    ISAP_KEY_SIZE,
    ISAP_NONCE_SIZE,
    ISAP_TAG_SIZE,
    AEAD_FLAG_SC_PROTECT_KEY | AEAD_FLAG_SLOW,
    isap_ascon_128a_aead_encrypt,
    isap_ascon_128a_aead_decrypt,
    0, 0
};

aead_cipher_t const isap_keccak_128_cipher = {
    "ISAP-K-128",
    ISAP_KEY_SIZE,
    ISAP_NONCE_SIZE,
    ISAP_TAG_SIZE,
    AEAD_FLAG_SC_PROTECT_KEY | AEAD_FLAG_SLOW,
    isap_keccak_128_aead_encrypt,
    isap_keccak_128_aead_decrypt,
    0, 0
};

aead_cipher_t const isap_ascon_128_cipher = {
    "ISAP-A-128",
    ISAP_KEY_SIZE,
    ISAP_NONCE_SIZE,
    ISAP_TAG_SIZE,
    AEAD_FLAG_SC_PROTECT_KEY | AEAD_FLAG_SLOW,
    isap_ascon_128_aead_encrypt,
    isap_ascon_128_aead_decrypt,
    0, 0
};

aead_cipher_t const isap_keccak_128a_pk_cipher = {
    "ISAP-K-128A-pk",
    ISAP_KEY_SIZE,
    ISAP_NONCE_SIZE,
    ISAP_TAG_SIZE,
    AEAD_FLAG_SC_PROTECT_KEY | AEAD_FLAG_SLOW,
    (aead_cipher_encrypt_t)isap_keccak_128a_aead_pk_encrypt,
    (aead_cipher_decrypt_t)isap_keccak_128a_aead_pk_decrypt,
    sizeof(isap_keccak_128a_key_t),
    (aead_cipher_pk_init_t)isap_keccak_128a_aead_pk_init
};

aead_cipher_t const isap_ascon_128a_pk_cipher = {
    "ISAP-A-128A-pk",
    ISAP_KEY_SIZE,
    ISAP_NONCE_SIZE,
    ISAP_TAG_SIZE,
    AEAD_FLAG_SC_PROTECT_KEY | AEAD_FLAG_SLOW,
    (aead_cipher_encrypt_t)isap_ascon_128a_aead_pk_encrypt,
    (aead_cipher_decrypt_t)isap_ascon_128a_aead_pk_decrypt,
    sizeof(isap_ascon_128a_key_t),
    (aead_cipher_pk_init_t)isap_ascon_128a_aead_pk_init
};

aead_cipher_t const isap_keccak_128_pk_cipher = {
    "ISAP-K-128-pk",
    ISAP_KEY_SIZE,
    ISAP_NONCE_SIZE,
    ISAP_TAG_SIZE,
    AEAD_FLAG_SC_PROTECT_KEY | AEAD_FLAG_SLOW,
    (aead_cipher_encrypt_t)isap_keccak_128_aead_pk_encrypt,
    (aead_cipher_decrypt_t)isap_keccak_128_aead_pk_decrypt,
    sizeof(isap_keccak_128_key_t),
    (aead_cipher_pk_init_t)isap_keccak_128_aead_pk_init
};

aead_cipher_t const isap_ascon_128_pk_cipher = {
    "ISAP-A-128-pk",
    ISAP_KEY_SIZE,
    ISAP_NONCE_SIZE,
    ISAP_TAG_SIZE,
    AEAD_FLAG_SC_PROTECT_KEY | AEAD_FLAG_SLOW,
    (aead_cipher_encrypt_t)isap_ascon_128_aead_pk_encrypt,
    (aead_cipher_decrypt_t)isap_ascon_128_aead_pk_decrypt,
    sizeof(isap_ascon_128_key_t),
    (aead_cipher_pk_init_t)isap_ascon_128_aead_pk_init
};

/*--------------------- PHOTON-Beetle ---------------------*/

aead_cipher_t const photon_beetle_128_cipher = {
    "PHOTON-Beetle-AEAD-ENC-128",
    PHOTON_BEETLE_KEY_SIZE,
    PHOTON_BEETLE_NONCE_SIZE,
    PHOTON_BEETLE_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    photon_beetle_128_aead_encrypt,
    photon_beetle_128_aead_decrypt,
    0, 0
};

aead_cipher_t const photon_beetle_32_cipher = {
    "PHOTON-Beetle-AEAD-ENC-32",
    PHOTON_BEETLE_KEY_SIZE,
    PHOTON_BEETLE_NONCE_SIZE,
    PHOTON_BEETLE_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    photon_beetle_32_aead_encrypt,
    photon_beetle_32_aead_decrypt,
    0, 0
};

aead_hash_algorithm_t const photon_beetle_hash_algorithm = {
    "PHOTON-Beetle-HASH",
    sizeof(photon_beetle_hash_state_t),
    PHOTON_BEETLE_HASH_SIZE,
    AEAD_FLAG_NONE,
    photon_beetle_hash,
    (aead_hash_init_t)photon_beetle_hash_init,
    (aead_hash_update_t)photon_beetle_hash_update,
    (aead_hash_finalize_t)photon_beetle_hash_finalize,
    (aead_xof_absorb_t)0,
    (aead_xof_squeeze_t)0
};

/*------------------------ Romulus ------------------------*/

aead_cipher_t const romulus_n_cipher = {
    "Romulus-N",
    ROMULUS_N_KEY_SIZE,
    ROMULUS_N_NONCE_SIZE,
    ROMULUS_N_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    romulus_n_aead_encrypt,
    romulus_n_aead_decrypt,
    0, 0
};

aead_cipher_t const romulus_m_cipher = {
    "Romulus-M",
    ROMULUS_M_KEY_SIZE,
    ROMULUS_M_NONCE_SIZE,
    ROMULUS_M_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    romulus_m_aead_encrypt,
    romulus_m_aead_decrypt,
    0, 0
};

aead_cipher_t const romulus_t_cipher = {
    "Romulus-T",
    ROMULUS_T_KEY_SIZE,
    ROMULUS_T_NONCE_SIZE,
    ROMULUS_T_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    romulus_t_aead_encrypt,
    romulus_t_aead_decrypt,
    0, 0
};

aead_hash_algorithm_t const romulus_hash_algorithm = {
    "Romulus-H",
    sizeof(romulus_hash_state_t),
    ROMULUS_HASH_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    romulus_hash,
    (aead_hash_init_t)romulus_hash_init,
    (aead_hash_update_t)romulus_hash_update,
    (aead_hash_finalize_t)romulus_hash_finalize,
    (aead_xof_absorb_t)0,
    (aead_xof_squeeze_t)0
};

aead_hash_algorithm_t const romulus_xof_algorithm = {
    "Romulus-H-XOF",
    sizeof(romulus_xof_state_t),
    ROMULUS_HASH_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    romulus_xof,
    (aead_hash_init_t)romulus_xof_init,
    (aead_hash_update_t)0,
    (aead_hash_finalize_t)0,
    (aead_xof_absorb_t)romulus_xof_absorb,
    (aead_xof_squeeze_t)romulus_xof_squeeze
};

/*------------------------ SPARKLE ------------------------*/

aead_cipher_t const schwaemm_256_128_cipher = {
    "Schwaemm256-128",
    SCHWAEMM_256_128_KEY_SIZE,
    SCHWAEMM_256_128_NONCE_SIZE,
    SCHWAEMM_256_128_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    schwaemm_256_128_aead_encrypt,
    schwaemm_256_128_aead_decrypt,
    0, 0
};

aead_cipher_t const schwaemm_192_192_cipher = {
    "Schwaemm192-192",
    SCHWAEMM_192_192_KEY_SIZE,
    SCHWAEMM_192_192_NONCE_SIZE,
    SCHWAEMM_192_192_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    schwaemm_192_192_aead_encrypt,
    schwaemm_192_192_aead_decrypt,
    0, 0
};

aead_cipher_t const schwaemm_128_128_cipher = {
    "Schwaemm128-128",
    SCHWAEMM_128_128_KEY_SIZE,
    SCHWAEMM_128_128_NONCE_SIZE,
    SCHWAEMM_128_128_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    schwaemm_128_128_aead_encrypt,
    schwaemm_128_128_aead_decrypt,
    0, 0
};

aead_cipher_t const schwaemm_256_256_cipher = {
    "Schwaemm256-256",
    SCHWAEMM_256_256_KEY_SIZE,
    SCHWAEMM_256_256_NONCE_SIZE,
    SCHWAEMM_256_256_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    schwaemm_256_256_aead_encrypt,
    schwaemm_256_256_aead_decrypt,
    0, 0
};

aead_hash_algorithm_t const esch_256_hash_algorithm = {
    "Esch256",
    sizeof(esch_256_hash_state_t),
    ESCH_256_HASH_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    esch_256_hash,
    (aead_hash_init_t)esch_256_hash_init,
    (aead_hash_update_t)esch_256_hash_update,
    (aead_hash_finalize_t)esch_256_hash_finalize,
    (aead_xof_absorb_t)0,
    (aead_xof_squeeze_t)0
};

aead_hash_algorithm_t const esch_384_hash_algorithm = {
    "Esch384",
    sizeof(esch_384_hash_state_t),
    ESCH_384_HASH_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    esch_384_hash,
    (aead_hash_init_t)esch_384_hash_init,
    (aead_hash_update_t)esch_384_hash_update,
    (aead_hash_finalize_t)esch_384_hash_finalize,
    (aead_xof_absorb_t)0,
    (aead_xof_squeeze_t)0
};

aead_hash_algorithm_t const esch_256_xof_algorithm = {
    "XOEsch256",
    sizeof(esch_256_hash_state_t),
    ESCH_256_HASH_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    esch_256_xof,
    (aead_hash_init_t)esch_256_hash_init,
    (aead_hash_update_t)0,
    (aead_hash_finalize_t)0,
    (aead_xof_absorb_t)esch_256_hash_update,
    (aead_xof_squeeze_t)esch_256_hash_squeeze
};

aead_hash_algorithm_t const esch_384_xof_algorithm = {
    "XOEsch384",
    sizeof(esch_384_hash_state_t),
    ESCH_384_HASH_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    esch_384_xof,
    (aead_hash_init_t)esch_384_hash_init,
    (aead_hash_update_t)0,
    (aead_hash_finalize_t)0,
    (aead_xof_absorb_t)esch_384_hash_update,
    (aead_xof_squeeze_t)esch_384_hash_squeeze
};

/*----------------------- TinyJAMBU -----------------------*/

aead_cipher_t const tiny_jambu_128_cipher = {
    "TinyJAMBU-128",
    TINY_JAMBU_128_KEY_SIZE,
    TINY_JAMBU_NONCE_SIZE,
    TINY_JAMBU_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    tiny_jambu_128_aead_encrypt,
    tiny_jambu_128_aead_decrypt,
    0, 0
};

aead_cipher_t const tiny_jambu_192_cipher = {
    "TinyJAMBU-192",
    TINY_JAMBU_192_KEY_SIZE,
    TINY_JAMBU_NONCE_SIZE,
    TINY_JAMBU_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    tiny_jambu_192_aead_encrypt,
    tiny_jambu_192_aead_decrypt,
    0, 0
};

aead_cipher_t const tiny_jambu_256_cipher = {
    "TinyJAMBU-256",
    TINY_JAMBU_256_KEY_SIZE,
    TINY_JAMBU_NONCE_SIZE,
    TINY_JAMBU_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    tiny_jambu_256_aead_encrypt,
    tiny_jambu_256_aead_decrypt,
    0, 0
};

aead_cipher_t const tiny_jambu_128_masked_cipher = {
    "TinyJAMBU-128-Masked",
    TINY_JAMBU_MASKED_128_KEY_SIZE,
    TINY_JAMBU_MASKED_NONCE_SIZE,
    TINY_JAMBU_MASKED_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN | AEAD_FLAG_SC_PROTECT_ALL | AEAD_FLAG_MASKED,
    tiny_jambu_128_masked_aead_encrypt,
    tiny_jambu_128_masked_aead_decrypt,
    0, 0
};

aead_cipher_t const tiny_jambu_192_masked_cipher = {
    "TinyJAMBU-192-Masked",
    TINY_JAMBU_MASKED_192_KEY_SIZE,
    TINY_JAMBU_MASKED_NONCE_SIZE,
    TINY_JAMBU_MASKED_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN | AEAD_FLAG_SC_PROTECT_ALL | AEAD_FLAG_MASKED,
    tiny_jambu_192_masked_aead_encrypt,
    tiny_jambu_192_masked_aead_decrypt,
    0, 0
};

aead_cipher_t const tiny_jambu_256_masked_cipher = {
    "TinyJAMBU-256-Masked",
    TINY_JAMBU_MASKED_256_KEY_SIZE,
    TINY_JAMBU_MASKED_NONCE_SIZE,
    TINY_JAMBU_MASKED_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN | AEAD_FLAG_SC_PROTECT_ALL | AEAD_FLAG_MASKED,
    tiny_jambu_256_masked_aead_encrypt,
    tiny_jambu_256_masked_aead_decrypt,
    0, 0
};

/*------------------------ Xoodyak ------------------------*/

aead_cipher_t const xoodyak_cipher = {
    "Xoodyak",
    XOODYAK_KEY_SIZE,
    XOODYAK_NONCE_SIZE,
    XOODYAK_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    xoodyak_aead_encrypt,
    xoodyak_aead_decrypt,
    0, 0
};

aead_hash_algorithm_t const xoodyak_hash_algorithm = {
    "Xoodyak-Hash",
    sizeof(xoodyak_hash_state_t),
    XOODYAK_HASH_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    xoodyak_hash,
    (aead_hash_init_t)xoodyak_hash_init,
    (aead_hash_update_t)xoodyak_hash_absorb,
    (aead_hash_finalize_t)xoodyak_hash_finalize,
    (aead_xof_absorb_t)xoodyak_hash_absorb,
    (aead_xof_squeeze_t)xoodyak_hash_squeeze
};

aead_cipher_t const xoodyak_masked_cipher = {
    "Xoodyak-Masked",
    XOODYAK_MASKED_KEY_SIZE,
    XOODYAK_MASKED_NONCE_SIZE,
    XOODYAK_MASKED_TAG_SIZE,
#if AEAD_MASKING_KEY_ONLY
    AEAD_FLAG_LITTLE_ENDIAN | AEAD_FLAG_SC_PROTECT_KEY | AEAD_FLAG_MASKED,
#else
    AEAD_FLAG_LITTLE_ENDIAN | AEAD_FLAG_SC_PROTECT_ALL | AEAD_FLAG_MASKED,
#endif
    xoodyak_masked_aead_encrypt,
    xoodyak_masked_aead_decrypt,
    0, 0
};
