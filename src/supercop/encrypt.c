
#include "HEADER"

int crypto_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    size_t len = 0;
    int result = AEAD_ENCRYPT
        (c, &len, m, mlen, a, adlen, nsec, npub, k);
    *clen = clen_size;
    return result;
}

int crypto_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    size_t len = 0;
    int result = AEAD_DECRYPT
        (m, &len, nsec, c, clen, ad, adlen, npub, k);
    *mlen = len;
    return result;
}
