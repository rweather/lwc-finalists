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

/*
 * The contents of this header file expand out to the full implementation of
 * HMAC for a specific underlying hash algorithm.  We expect a number of
 * macros to be defined before this file is included to configure the
 * underlying HMAC variant:
 *
 * HMAC_ALG_NAME        Name of the HMAC algorithm; e.g. ascon_hmac
 * HMAC_HASH_SIZE       Size of the hash output for the underlying algorithm.
 * HMAC_BLOCK_SIZE      Size of the formatted key block for HMAC.
 * HMAC_STATE           Type for the HMAC state; e.g. ascon_hmac_state_t
 * HMAC_HASH_INIT       Name of the hash initialization function.
 * HMAC_HASH_UPDATE     Name of the hash update function.
 * HMAC_HASH_FINALIZE   Name of the hash finalization function.
 */
#if defined(HMAC_ALG_NAME)

#define HMAC_CONCAT_INNER(name,suffix) name##suffix
#define HMAC_CONCAT(name,suffix) HMAC_CONCAT_INNER(name,suffix)

/** Inner padding value for HMAC */
#define HMAC_IPAD 0x36

/** Outer padding value for HMAC */
#define HMAC_OPAD 0x5C

/**
 * \brief XOR's a padding value with the contents of a buffer.
 *
 * \param out Points to the output buffer.
 * \param in Points to the input buffer.
 * \param size Size of the input and output buffe in bytes.
 * \param pad Padding value to XOR with the contents.
 */
static void HMAC_CONCAT(HMAC_ALG_NAME,_xor_pad)
    (unsigned char *out, const unsigned char *in,
     size_t size, unsigned char pad)
{
    while (size > 0) {
        *out++ = *in++ ^ pad;
        --size;
    }
}

/**
 * \brief Formats a key block for HMAC and absorbs it.
 *
 * \param state State for the underlying hash algorithm.
 * \param key Points to the key.
 * \param keylen Length of the key in bytes.
 * \param pad HMAC_IPAD or HMAC_OPAD.
 */
static void HMAC_CONCAT(HMAC_ALG_NAME,_absorb_key)
    (HMAC_STATE *state, const unsigned char *key, size_t keylen,
     unsigned char pad)
{
    unsigned char temp[HMAC_HASH_SIZE];
    size_t posn, len;

    /* Break the key up into smaller chunks and XOR it with "pad".
     * We do it this way to avoid having a large buffer on the
     * stack of size HMAC_BLOCK_SIZE. */
    if (keylen <= HMAC_BLOCK_SIZE) {
        HMAC_HASH_INIT(state);
        posn = 0;
        while (keylen > 0) {
            len = keylen - posn;
            if (len > HMAC_HASH_SIZE)
                len = HMAC_HASH_SIZE;
            HMAC_CONCAT(HMAC_ALG_NAME,_xor_pad)(temp, key, len, pad);
            HMAC_HASH_UPDATE(state, temp, len);
            posn += len;
            key += len;
            keylen -= len;
        }
    } else {
        /* Hash long keys down first and then absorb */
        HMAC_HASH_INIT(state);
        HMAC_HASH_UPDATE(state, key, keylen);
        HMAC_HASH_FINALIZE(state, temp);
        HMAC_CONCAT(HMAC_ALG_NAME,_xor_pad)(temp, temp, HMAC_HASH_SIZE, pad);
        HMAC_HASH_INIT(state);
        HMAC_HASH_UPDATE(state, temp, HMAC_HASH_SIZE);
        posn = HMAC_HASH_SIZE;
    }

    /* Pad the rest of the block with the padding value */
    memset(temp, pad, sizeof(temp));
    while (posn < HMAC_BLOCK_SIZE) {
        len = HMAC_BLOCK_SIZE - posn;
        if (len > HMAC_HASH_SIZE)
            len = HMAC_HASH_SIZE;
        HMAC_HASH_UPDATE(state, temp, len);
        posn += len;
    }
}

void HMAC_ALG_NAME
    (unsigned char *out,
     const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen)
{
    HMAC_STATE state;
    HMAC_CONCAT(HMAC_ALG_NAME,_absorb_key)(&state, key, keylen, HMAC_IPAD);
    HMAC_HASH_UPDATE(&state, in, inlen);
    HMAC_CONCAT(HMAC_ALG_NAME,_finalize)(&state, key, keylen, out);
    aead_clean(&state, sizeof(state));
}

void HMAC_CONCAT(HMAC_ALG_NAME,_init)
    (HMAC_STATE *state, const unsigned char *key, size_t keylen)
{
    HMAC_CONCAT(HMAC_ALG_NAME,_absorb_key)(state, key, keylen, HMAC_IPAD);
}

void HMAC_CONCAT(HMAC_ALG_NAME,_update)
    (HMAC_STATE *state, const unsigned char *in, size_t inlen)
{
    HMAC_HASH_UPDATE(state, in, inlen);
}

void HMAC_CONCAT(HMAC_ALG_NAME,_finalize)
    (HMAC_STATE *state, const unsigned char *key, size_t keylen,
     unsigned char *out)
{
    unsigned char temp[HMAC_HASH_SIZE];
    HMAC_HASH_FINALIZE(state, temp);
    HMAC_CONCAT(HMAC_ALG_NAME,_absorb_key)(state, key, keylen, HMAC_OPAD);
    HMAC_HASH_UPDATE(state, temp, HMAC_HASH_SIZE);
    HMAC_HASH_FINALIZE(state, out);
    aead_clean(temp, sizeof(temp));
}

#endif /* HMAC_ALG_NAME */

/* Now undefine everything so that we can include this file again for
 * another variant on the HMAC algorithm */
#undef HMAC_ALG_NAME
#undef HMAC_HASH_SIZE
#undef HMAC_BLOCK_SIZE
#undef HMAC_STATE
#undef HMAC_HASH_INIT
#undef HMAC_HASH_UPDATE
#undef HMAC_HASH_FINALIZE
#undef HMAC_CONCAT_INNER
#undef HMAC_CONCAT
#undef HMAC_IPAD
#undef HMAC_OPAD
