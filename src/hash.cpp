#include "hash.h"

int HMAC_SHA512_Init(HMAC_SHA512_CTX *pctx, const void *pkey, size_t len)
{
    unsigned char key[128];
    if (len <= 128)
    {
        memcpy(key, pkey, len);
        memset(key + len, 0, 128-len);
    }
    else
    {
        unsigned int key_len = 0;
        EVP_MD_CTX *ctxKey = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctxKey, EVP_sha512(), NULL);
        EVP_DigestUpdate(ctxKey, pkey, len);
        EVP_DigestFinal_ex(ctxKey, key, &key_len);

        memset(key + 64, 0, 64);
    }

    for (int n=0; n<128; n++)
        key[n] ^= 0x5c;
    pctx->ctxOuter = EVP_MD_CTX_new();
    EVP_DigestInit_ex(pctx->ctxOuter, EVP_sha512(), NULL);
    EVP_DigestUpdate(pctx->ctxOuter, key, 128);

    for (int n=0; n<128; n++)
        key[n] ^= 0x5c ^ 0x36;
    pctx->ctxInner = EVP_MD_CTX_new();
    EVP_DigestInit_ex(pctx->ctxInner, EVP_sha512(), NULL);
    EVP_DigestUpdate(pctx->ctxInner, key, 128);

    return 0;
}

int HMAC_SHA512_Update(HMAC_SHA512_CTX *pctx, const void *pdata, size_t len)
{
    return EVP_DigestUpdate(pctx->ctxInner, pdata, len);
}

int HMAC_SHA512_Final(unsigned char *pmd, HMAC_SHA512_CTX *pctx)
{
    unsigned char buf[64];
    unsigned int key_len = 0;

    EVP_DigestFinal_ex(pctx->ctxInner, buf, &key_len);
    EVP_DigestUpdate(pctx->ctxOuter, buf, 64);
    EVP_DigestFinal_ex(pctx->ctxOuter, pmd, &key_len);

    EVP_MD_CTX_free(pctx->ctxInner);
    EVP_MD_CTX_free(pctx->ctxOuter);

    return 0;
}
