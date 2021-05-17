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
 * PBKDF2 for a specific underlying hash algorithm.  We expect a number of
 * macros to be defined before this file is included to configure the
 * underlying PBKDF2 variant:
 *
 * PBKDF2_ALG_NAME        Name of the PBKDF2 algorithm; e.g. ascon_pbkdf2
 * PBKDF2_HMAC_SIZE       Size of the output for the HMAC algorithm.
 * PBKDF2_HMAC_STATE      Type for the HMAC state; e.g. ascon_hmac_state_t
 * PBKDF2_HMAC_INIT       Name of the HMAC initialization function.
 * PBKDF2_HMAC_UPDATE     Name of the HMAC update function.
 * PBKDF2_HMAC_FINALIZE   Name of the HMAC finalization function.
 */
#if defined(PBKDF2_ALG_NAME)

#define PBKDF2_CONCAT_INNER(name,suffix) name##suffix
#define PBKDF2_CONCAT(name,suffix) PBKDF2_CONCAT_INNER(name,suffix)

/* Implementation of the "F" function from RFC 8018, section 5.2 */
static void PBKDF2_CONCAT(PBKDF2_ALG_NAME,_f)
    (PBKDF2_HMAC_STATE *state, unsigned char *T, unsigned char *U,
     const unsigned char *password, size_t passwordlen,
     const unsigned char *salt, size_t saltlen,
     unsigned long count, unsigned long blocknum)
{
    unsigned char b[4];
    be_store_word32(b, blocknum);
    PBKDF2_HMAC_INIT(state, password, passwordlen);
    PBKDF2_HMAC_UPDATE(state, salt, saltlen);
    PBKDF2_HMAC_UPDATE(state, b, sizeof(b));
    PBKDF2_HMAC_FINALIZE(state, password, passwordlen, T);
    if (count > 1) {
        PBKDF2_HMAC_INIT(state, password, passwordlen);
        PBKDF2_HMAC_UPDATE(state, T, PBKDF2_HMAC_SIZE);
        PBKDF2_HMAC_FINALIZE(state, password, passwordlen, U);
        lw_xor_block(T, U, PBKDF2_HMAC_SIZE);
        while (count > 2) {
            PBKDF2_HMAC_INIT(state, password, passwordlen);
            PBKDF2_HMAC_UPDATE(state, U, PBKDF2_HMAC_SIZE);
            PBKDF2_HMAC_FINALIZE(state, password, passwordlen, U);
            lw_xor_block(T, U, PBKDF2_HMAC_SIZE);
            --count;
        }
    }
}

void PBKDF2_ALG_NAME
    (unsigned char *out, size_t outlen,
     const unsigned char *password, size_t passwordlen,
     const unsigned char *salt, size_t saltlen, unsigned long count)
{
    PBKDF2_HMAC_STATE state;
    unsigned char U[PBKDF2_HMAC_SIZE];
    unsigned long blocknum = 1;
    while (outlen > 0) {
        if (outlen >= PBKDF2_HMAC_SIZE) {
            PBKDF2_CONCAT(PBKDF2_ALG_NAME,_f)
                (&state, out, U, password, passwordlen,
                 salt, saltlen, count, blocknum);
            out += PBKDF2_HMAC_SIZE;
            outlen -= PBKDF2_HMAC_SIZE;
        } else {
            unsigned char T[PBKDF2_HMAC_SIZE];
            PBKDF2_CONCAT(PBKDF2_ALG_NAME,_f)
                (&state, T, U, password, passwordlen,
                 salt, saltlen, count, blocknum);
            memcpy(out, T, outlen);
            aead_clean(T, sizeof(T));
            break;
        }
        ++blocknum;
    }
    aead_clean(&state, sizeof(state));
    aead_clean(U, sizeof(U));
}

#endif /* PBKDF2_ALG_NAME */

/* Now undefine everything so that we can include this file again for
 * another variant on the PBKDF2 algorithm */
#undef PBKDF2_ALG_NAME
#undef PBKDF2_HMAC_SIZE
#undef PBKDF2_HMAC_STATE
#undef PBKDF2_HMAC_INIT
#undef PBKDF2_HMAC_UPDATE
#undef PBKDF2_HMAC_FINALIZE
