// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include <openssl/encoder.h>
#include <openssl/provider.h>
#include <openssl/param_build.h>

#include <openssl/err.h>

#include "key.h"

// anonymous namespace with local implementation code (OpenSSL interaction)
namespace {

int regenerate_key(EVP_PKEY** pkey, const BIGNUM *priv_key)
{
    int ok = 0;
    EVP_PKEY *tmp = NULL;
    OSSL_PARAM *params = NULL;
    unsigned char pub_key_buf[65]; // 1 header byte + 2*32 bytes for secp256k1
    OSSL_PARAM_BLD *param_bld = OSSL_PARAM_BLD_new();
    EC_POINT *pub_key_point = NULL;
    size_t pub_key_len = 0;

    if (!priv_key)
        return 0;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!ctx) {
        return 0;
    }

    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!group) {
        goto cleanup;
    }

    if (EVP_PKEY_fromdata_init(ctx) <= 0) {
        goto cleanup;
    }

    pub_key_point = EC_POINT_new(group);
    if (!pub_key_point) {
        goto cleanup;
    }

    if (EC_POINT_mul(group, pub_key_point, priv_key, NULL, NULL, NULL) != 1) {
        goto cleanup;
    }

    pub_key_len = EC_POINT_point2oct(group, pub_key_point, POINT_CONVERSION_UNCOMPRESSED,
                                           pub_key_buf, sizeof(pub_key_buf), NULL);
    if (pub_key_len == 0) {
        goto cleanup;
    }

    OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME, "secp256k1", 0);
    OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_PRIV_KEY, priv_key);
    OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY, pub_key_buf, pub_key_len);

    params = OSSL_PARAM_BLD_to_param(param_bld);

    if (EVP_PKEY_fromdata(ctx, &tmp, EVP_PKEY_KEYPAIR, params) <= 0) {
        goto cleanup;
    }

    if (*pkey != NULL) {
        EVP_PKEY_free(*pkey);
    }
    *pkey = tmp;

    ok = 1;
cleanup:
    EVP_PKEY_CTX_free(ctx);
    if (params != NULL)
        OSSL_PARAM_free(params);
    if (pub_key_point != NULL)
        EC_POINT_free(pub_key_point);
    OSSL_PARAM_BLD_free(param_bld);
    return ok;
}


// Perform ECDSA key recovery (see SEC1 4.1.6) for curves over (mod p)-fields
// recid selects which key is recovered
// if check is non-zero, additional checks are performed
int recover_pubkey_GFp(EVP_PKEY *eckey, ECDSA_SIG *ecsig, const unsigned char *msg, int msglen, int recid, int check)
{
    if (!eckey) return 0;

    int ret = 0;
    BN_CTX *ctx = NULL;
    unsigned char pubkey_buf[1000];
    size_t pubkey_len;

    BIGNUM *x = NULL;
    BIGNUM *e = NULL;
    BIGNUM *order = NULL;
    BIGNUM *sor = NULL;
    BIGNUM *eor = NULL;
    BIGNUM *field = NULL;
    EC_POINT *R = NULL;
    EC_POINT *O = NULL;
    EC_POINT *Q = NULL;
    BIGNUM *rr = NULL;
    BIGNUM *zero = NULL;
    int n = 0;
    int i = recid / 2;

    const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!group) goto err;
    if ((ctx = BN_CTX_new()) == NULL) { ret = -1; goto err; }
    BN_CTX_start(ctx);
    order = BN_CTX_get(ctx);
    if (!EC_GROUP_get_order(group, order, ctx)) { ret = -2; goto err; }
    x = BN_CTX_get(ctx);
    if (!BN_copy(x, order)) { ret=-1; goto err; }
    if (!BN_mul_word(x, i)) { ret=-1; goto err; }
    if (!BN_add(x, x, ECDSA_SIG_get0_r(ecsig))) { ret=-1; goto err; }
    field = BN_CTX_get(ctx);
    if (!EC_GROUP_get_curve(group, field, NULL, NULL, ctx)) { ret=-2; goto err; }
    if (BN_cmp(x, field) >= 0) { ret=0; goto err; }
    if ((R = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
    if (!EC_POINT_set_compressed_coordinates(group, R, x, recid % 2, ctx)) { ret=0; goto err; }
    if (check)
    {
        if ((O = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
        if (!EC_POINT_mul(group, O, NULL, R, order, ctx)) { ret=-2; goto err; }
        if (!EC_POINT_is_at_infinity(group, O)) { ret = 0; goto err; }
    }
    if ((Q = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
    n = EC_GROUP_get_degree(group);
    e = BN_CTX_get(ctx);
    if (!BN_bin2bn(msg, msglen, e)) { ret=-1; goto err; }
    if (8*msglen > n) BN_rshift(e, e, 8-(n & 7));
    zero = BN_CTX_get(ctx);
    BN_zero(zero);
    if (!BN_mod_sub(e, zero, e, order, ctx)) { ret=-1; goto err; }
    rr = BN_CTX_get(ctx);
    if (!BN_mod_inverse(rr, ECDSA_SIG_get0_r(ecsig), order, ctx)) { ret=-1; goto err; }
    sor = BN_CTX_get(ctx);
    if (!BN_mod_mul(sor, ECDSA_SIG_get0_s(ecsig), rr, order, ctx)) { ret=-1; goto err; }
    eor = BN_CTX_get(ctx);
    if (!BN_mod_mul(eor, e, rr, order, ctx)) { ret=-1; goto err; }
    if (!EC_POINT_mul(group, Q, eor, R, sor, ctx)) { ret=-2; goto err; }

    // Q is pubkey
    pubkey_len = EC_POINT_point2oct(group, Q, POINT_CONVERSION_UNCOMPRESSED,
                                   pubkey_buf, sizeof(pubkey_buf), NULL);
    if (pubkey_len == 0) {
       ret = -2;
       goto err;
    }

    if (EVP_PKEY_set1_encoded_public_key(eckey, pubkey_buf, pubkey_len) != 1) {
       ret = -2;
       goto err;
    }

    ret = 1;

err:
    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (R != NULL) EC_POINT_free(R);
    if (O != NULL) EC_POINT_free(O);
    if (Q != NULL) EC_POINT_free(Q);

    return ret;
}


// RAII Wrapper around OpenSSL's EC_KEY
class CECKey {
private:
    EVP_PKEY *pkey = NULL;

public:
    CECKey() {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);

        EVP_PKEY_keygen_init(ctx);
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp256k1);
        EVP_PKEY_keygen(ctx, &pkey);

        assert(pkey != NULL);
    }

    ~CECKey() {
        EVP_PKEY_free(pkey);
    }

    void GetSecretBytes(unsigned char vch[32]) const {
        BIGNUM *bn_priv = NULL;

        if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &bn_priv)) {
            assert(0);
        }

        int nBytes = BN_num_bytes(bn_priv);
        int n = BN_bn2bin(bn_priv, &vch[32 - nBytes]);
        assert(n == nBytes);
        memset(vch, 0, 32 - nBytes);

        BN_free(bn_priv);
    }

    void SetSecretBytes(const unsigned char vch[32]) {
        bool ret;
        BIGNUM *bn = BN_new();
        ret = BN_bin2bn(vch, 32, bn);
        assert(ret);
        ret = regenerate_key(&pkey, bn);
        assert(ret);
        BN_clear_free(bn);
    }

    void GetPrivKey(CPrivKey &privkey, bool fCompressed) {
        OSSL_ENCODER_CTX *ctx = NULL;
        unsigned char *data = NULL;
        size_t data_len = 0;

        ctx = OSSL_ENCODER_CTX_new_for_pkey(pkey, EVP_PKEY_KEYPAIR, "DER", NULL, NULL);
        assert(ctx != NULL);

        if (!OSSL_ENCODER_to_data(ctx, &data, &data_len)) {
            OSSL_ENCODER_CTX_free(ctx);
            assert(0);
            return;
        }

        OSSL_ENCODER_CTX_free(ctx);

        privkey.assign(data, data + data_len);

        OPENSSL_free(data);
    }

    bool SetPrivKey(const CPrivKey &privkey, bool fSkipCheck=false) {
        const unsigned char* pbegin = &privkey[0];

        EVP_PKEY *new_pkey = d2i_AutoPrivateKey(NULL, &pbegin, privkey.size());
        if (new_pkey == NULL)
            return false;

        if (!fSkipCheck) {
            EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
            if (!ctx) {
                return false;
            }
            int check = EVP_PKEY_private_check(ctx);
            if (check <= 0) {
                EVP_PKEY_free(new_pkey);
                EVP_PKEY_CTX_free(ctx);
                return false;
            }
            EVP_PKEY_CTX_free(ctx);
        }

        if (pkey)
            EVP_PKEY_free(pkey);

        pkey = new_pkey;
        return true;
    }

    int convert_pubkey(const unsigned char *uncomp, size_t uncomp_len, unsigned char **comp, size_t *comp_len, point_conversion_form_t conversion) {
        int ret = 0;
        EC_GROUP *group = NULL;
        EC_POINT *point = NULL;
        BN_CTX *ctx = NULL;

        group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        if (!group) goto err;

        point = EC_POINT_new(group);
        if (!point) goto err;

        ctx = BN_CTX_new();
        if (!ctx) goto err;

        if (!EC_POINT_oct2point(group, point, uncomp, uncomp_len, ctx)) {
            fprintf(stderr, "EC_POINT_oct2point failed\n");
            ERR_print_errors_fp(stderr);
            goto err;
        }

        *comp_len = EC_POINT_point2oct(group, point, conversion, NULL, 0, ctx);
        if (*comp_len == 0) {
            fprintf(stderr, "Failed to get compressed key size\n");
            goto err;
        }

        *comp = (unsigned char*)OPENSSL_malloc(*comp_len);
        if (!*comp) goto err;

        if (!EC_POINT_point2oct(group, point, conversion, *comp, *comp_len, ctx)) {
            fprintf(stderr, "EC_POINT_point2oct failed\n");
            ERR_print_errors_fp(stderr);
            OPENSSL_free(*comp);
            *comp = NULL;
            goto err;
        }

        ret = 1;

    err:
        if (ctx) BN_CTX_free(ctx);
        if (point) EC_POINT_free(point);
        if (group) EC_GROUP_free(group);
        return ret;
    }


    void GetPubKey(CPubKey &pubkey, bool fCompressed) {
        point_conversion_form_t format = fCompressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED;
        unsigned char *ret_pubkey = NULL;
        size_t ret_len = 0;
        size_t pub_len = 0;

        EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &pub_len);
        assert(pub_len);
        assert(pub_len <= 65);

        unsigned char *pub_buf = (unsigned char*)OPENSSL_malloc(pub_len);
        size_t outlen = 0;
        EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pub_buf, pub_len, &outlen);

        assert(outlen);
        assert(outlen <= 65);

        assert(convert_pubkey(pub_buf, outlen, &ret_pubkey, &ret_len, format));
        pubkey.Set(&ret_pubkey[0], &ret_pubkey[ret_len]);

        OPENSSL_free(pub_buf);
        OPENSSL_free(ret_pubkey);
    }

    bool SetPubKey(const CPubKey &pubkey) {
        const unsigned char* pbegin = pubkey.begin();
        return EVP_PKEY_set1_encoded_public_key(pkey, pbegin, pubkey.size()) == 1;
    }

    int do_sign(const unsigned char *msg, size_t msglen, ECDSA_SIG **sigout) {
        EVP_MD_CTX *mdctx = NULL;
        unsigned char *sig = NULL;
        size_t siglen = 0;
        const unsigned char *p = NULL;
        int ret = 0;

        if (!msg)
            return 0;

        mdctx = EVP_MD_CTX_new();
        if (!mdctx)
            return 0;

        if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0)
            goto err;

        if (EVP_DigestSignUpdate(mdctx, msg, msglen) <= 0)
            goto err;

        if (EVP_DigestSignFinal(mdctx, NULL, &siglen) <= 0)
            goto err;

        sig = (unsigned char*)OPENSSL_malloc(siglen);
        if (!*sig)
            goto err;
        if (EVP_DigestSignFinal(mdctx, sig, &siglen) <= 0)
            goto err;

        p = sig;
        *sigout = d2i_ECDSA_SIG(NULL, &p, siglen);
        if (*sigout == NULL)
            goto err;

        ret = 1;

     err:
        if (sig) {
            OPENSSL_free(sig);
        }
        EVP_MD_CTX_free(mdctx);

        return ret;
    }

    bool Sign(const uint256 &hash, std::vector<unsigned char>& vchSig) {
        vchSig.clear();
#if OPENSSL_IS_SANE
        ECDSA_SIG *sig = NULL;

        int x = do_sign((unsigned char*)&hash, sizeof(hash), &sig);
        if (x != 1)
            return false;
        if (!sig)
            return false;
#else
        const EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
        if (!ec)
            return false;
        ECDSA_SIG *sig = ECDSA_do_sign((unsigned char*)&hash, sizeof(hash), (EC_KEY*)ec);
        if (sig == NULL)
            return false;
#endif

        BN_CTX *ctx = BN_CTX_new();
        BN_CTX_start(ctx);
        //const EC_GROUP *group = EC_KEY_get0_group(pkey);
        const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);

        BIGNUM *order = BN_CTX_get(ctx);
        BIGNUM *halforder = BN_CTX_get(ctx);
        EC_GROUP_get_order(group, order, ctx);
        BN_rshift1(halforder, order);

        if (BN_cmp(ECDSA_SIG_get0_s(sig), halforder) > 0) {
            // enforce low S values, by negating the value (modulo the order) if above order/2.
            BIGNUM *s = BN_dup(ECDSA_SIG_get0_s(sig));
            BIGNUM *r = BN_dup(ECDSA_SIG_get0_r(sig));

            BN_sub(s, order, s);
            ECDSA_SIG_set0(sig, r, s);
        }
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);

        unsigned int nSize = EVP_PKEY_size(pkey);
        vchSig.resize(nSize); // Make sure it is big enough
        unsigned char *pos = &vchSig[0];
        nSize = i2d_ECDSA_SIG(sig, &pos);
        ECDSA_SIG_free(sig);
        vchSig.resize(nSize); // Shrink to fit actual size

        return true;
    }

    int do_verify(const unsigned char *hash, size_t hash_len, const unsigned char *sig, size_t sig_len) {
        EVP_PKEY_CTX *ctx = NULL;
        int ret = 0;

        ctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!ctx)
            return 0;

        if (EVP_PKEY_verify_init(ctx) <= 0)
            goto done;

        if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_md_null()) <= 0)
        //if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
            goto done;

        ret = EVP_PKEY_verify(ctx, sig, sig_len, hash, hash_len);
    done:
        EVP_PKEY_CTX_free(ctx);
        return ret == 1; // returns 1 if verified, 0 otherwise
    }

    bool Verify(const uint256 &hash, const std::vector<unsigned char>& vchSig) {
#if OPENSSL_IS_SANE
        return do_verify((unsigned char*)&hash, sizeof(hash), &vchSig[0], vchSig.size());
#else
        // -1 = error, 0 = bad sig, 1 = good
        const EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
        if (!ec)
           return false;
        
        if (ECDSA_verify(0, (unsigned char*)&hash, sizeof(hash), &vchSig[0], vchSig.size(), (EC_KEY*)ec) != 1)
           return false;

        return true;
#endif
    }

    bool SignCompact(const uint256 &hash, unsigned char *p64, int &rec) {
        bool fOk = false;

#if OPENSSL_IS_SANE
        ECDSA_SIG *sig = NULL;

        int x = do_sign((unsigned char*)&hash, sizeof(hash), &sig);
        if (x != 1)
            return false;

        if (!sig)
            return false;
#else
        const EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
        if (!ec)
            return false;
        ECDSA_SIG *sig = ECDSA_do_sign((unsigned char*)&hash, sizeof(hash), (EC_KEY*)ec);
        if (sig == NULL)
            return false;
#endif

        memset(p64, 0, 64);
        int nBitsR = BN_num_bits(ECDSA_SIG_get0_r(sig));
        int nBitsS = BN_num_bits(ECDSA_SIG_get0_s(sig));
        if (nBitsR <= 256 && nBitsS <= 256) {
            CPubKey pubkey;
            GetPubKey(pubkey, true);
            for (int i=0; i<4; i++) {
                CECKey keyRec;
                if (recover_pubkey_GFp(keyRec.pkey, sig, (unsigned char*)&hash, sizeof(hash), i, 1) == 1) {
                    CPubKey pubkeyRec;
                    keyRec.GetPubKey(pubkeyRec, true);
                    if (pubkeyRec == pubkey) {
                        rec = i;
                        fOk = true;
                        break;
                    }
                }
            }
            assert(fOk);
            BN_bn2bin(const_cast<BIGNUM*>(ECDSA_SIG_get0_r(sig)),&p64[32-(nBitsR+7)/8]);
            BN_bn2bin(const_cast<BIGNUM*>(ECDSA_SIG_get0_s(sig)),&p64[64-(nBitsS+7)/8]);
        }
        ECDSA_SIG_free(sig);
        return fOk;
    }

    // reconstruct public key from a compact signature
    // This is only slightly more CPU intensive than just verifying it.
    // If this function succeeds, the recovered public key is guaranteed to be valid
    // (the signature is a valid signature of the given data for that key)
    bool Recover(const uint256 &hash, const unsigned char *p64, int rec)
    {
        if (rec<0 || rec>=3)
            return false;
        ECDSA_SIG *sig = ECDSA_SIG_new();
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        BN_bin2bn(&p64[0],  32, sig->r);
        BN_bin2bn(&p64[32], 32, sig->s);
#else
        BIGNUM *r = BN_new();
        BIGNUM *s = BN_new();
        BN_bin2bn(&p64[0],  32, r);
        BN_bin2bn(&p64[32], 32, s);
        ECDSA_SIG_set0(sig, r, s);
#endif
        bool ret = recover_pubkey_GFp(pkey, sig, (unsigned char*)&hash, sizeof(hash), rec, 0) == 1;
        ECDSA_SIG_free(sig);
        return ret;
    }

    static bool TweakSecret(unsigned char vchSecretOut[32], const unsigned char vchSecretIn[32], const unsigned char vchTweak[32])
    {
        bool ret = true;
        BN_CTX *ctx = BN_CTX_new();
        BN_CTX_start(ctx);
        BIGNUM *bnSecret = BN_CTX_get(ctx);
        BIGNUM *bnTweak = BN_CTX_get(ctx);
        BIGNUM *bnOrder = BN_CTX_get(ctx);
        EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        EC_GROUP_get_order(group, bnOrder, ctx); // what a grossly inefficient way to get the (constant) group order...
        BN_bin2bn(vchTweak, 32, bnTweak);
        if (BN_cmp(bnTweak, bnOrder) >= 0)
            ret = false; // extremely unlikely
        BN_bin2bn(vchSecretIn, 32, bnSecret);
        BN_add(bnSecret, bnSecret, bnTweak);
        BN_nnmod(bnSecret, bnSecret, bnOrder, ctx);
        if (BN_is_zero(bnSecret))
            ret = false; // ridiculously unlikely
        int nBits = BN_num_bits(bnSecret);
        memset(vchSecretOut, 0, 32);
        BN_bn2bin(bnSecret, &vchSecretOut[32-(nBits+7)/8]);
        EC_GROUP_free(group);
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        return ret;
    }

    bool TweakPublic(const unsigned char vchTweak[32]) {
        bool ret = true;
        size_t pubkey_len = 0;
        unsigned char pubkey_buf[256];
        BN_CTX *ctx = BN_CTX_new();
        BN_CTX_start(ctx);
        BIGNUM *bnTweak = BN_CTX_get(ctx);
        BIGNUM *bnOrder = BN_CTX_get(ctx);
        BIGNUM *bnOne = BN_CTX_get(ctx);
        const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        //const EC_GROUP *group = EC_KEY_get0_group(pkey);
        EC_GROUP_get_order(group, bnOrder, ctx); // what a grossly inefficient way to get the (constant) group order...
        BN_bin2bn(vchTweak, 32, bnTweak);
        if (BN_cmp(bnTweak, bnOrder) >= 0)
            ret = false; // extremely unlikely

        //EC_POINT *point = EC_POINT_dup(EC_KEY_get0_public_key(pkey), group);

        OSSL_PARAM params_pubkey[] = {
            OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pubkey_buf, pubkey_len),
            OSSL_PARAM_construct_end()
        };

        if (!EVP_PKEY_get_params((EVP_PKEY *)pkey, params_pubkey)) {
            return false;
        }

        // params_pubkey[0].return_size has actual length of pubkey
        pubkey_len = params_pubkey[0].return_size;

        EC_POINT *point = EC_POINT_new(group);
        if (!point) {
            return false;
        }

        if (!EC_POINT_oct2point(group, point, pubkey_buf, pubkey_len, NULL)) {
            EC_POINT_free(point);
            return false;
        }

        BN_one(bnOne);
        EC_POINT_mul(group, point, bnTweak, point, bnOne, ctx);
        if (EC_POINT_is_at_infinity(group, point))
            ret = false; // ridiculously unlikely

        //EC_KEY_set_public_key(pkey, point);

        pubkey_len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                                       pubkey_buf, sizeof(pubkey_buf), NULL);
        if (pubkey_len == 0) {
           ret = -2;
           goto err;
        }

        if (EVP_PKEY_set1_encoded_public_key(pkey, pubkey_buf, pubkey_len) != 1) {
           ret = -2;
           goto err;
        }
err:
        EC_POINT_free(point);
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        return ret;
    }
};

int CompareBigEndian(const unsigned char *c1, size_t c1len, const unsigned char *c2, size_t c2len) {
    while (c1len > c2len) {
        if (*c1)
            return 1;
        c1++;
        c1len--;
    }
    while (c2len > c1len) {
        if (*c2)
            return -1;
        c2++;
        c2len--;
    }
    while (c1len > 0) {
        if (*c1 > *c2)
            return 1;
        if (*c2 > *c1)
            return -1;
        c1++;
        c2++;
        c1len--;
    }
    return 0;
}

// Order of secp256k1's generator minus 1.
const unsigned char vchMaxModOrder[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
    0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x40
};

// Half of the order of secp256k1's generator minus 1.
const unsigned char vchMaxModHalfOrder[32] = {
    0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,
    0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0
};

const unsigned char vchZero[0] = {};

}; // end of anonymous namespace

bool CKey::Check(const unsigned char *vch) {
    // Do not convert to OpenSSL's data structures for range-checking keys,
    // it's easy enough to do directly.
    static const unsigned char vchMax[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
        0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
        0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x40
    };
    bool fIsZero = true;
    for (int i=0; i<32 && fIsZero; i++)
        if (vch[i] != 0)
            fIsZero = false;
    if (fIsZero)
        return false;
    for (int i=0; i<32; i++) {
        if (vch[i] < vchMax[i])
            return true;
        if (vch[i] > vchMax[i])
            return false;
    }
    return true;
}

bool CKey::CheckSignatureElement(const unsigned char *vch, int len, bool half) {
    return CompareBigEndian(vch, len, vchZero, 0) > 0 &&
           CompareBigEndian(vch, len, half ? vchMaxModHalfOrder : vchMaxModOrder, 32) <= 0;
}

const unsigned char vchOrder[32] = {
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41
};

const unsigned char vchHalfOrder[32] = {
    0x7f,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x5d,0x57,0x6e,0x73,0x57,0xa4,0x50,0x1d,0xdf,0xe9,0x2f,0x46,0x68,0x1b,0x20,0xa0
};

bool EnsureLowS(std::vector<unsigned char>& vchSig) {
    unsigned char *pos;

    if (vchSig.empty())
        return false;

    pos = &vchSig[0];
    ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, (const unsigned char **)&pos, vchSig.size());
    if (sig == NULL)
        return false;

    BIGNUM *order = BN_bin2bn(vchOrder, sizeof(vchOrder), NULL);
    BIGNUM *halforder = BN_bin2bn(vchHalfOrder, sizeof(vchHalfOrder), NULL);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
     if (BN_cmp(sig->s, halforder) > 0) {
           // enforce low S values, by negating the value (modulo the order) if above order/2.
           BN_sub(sig->s, order, sig->s);
     }
#else
    if (BN_cmp(ECDSA_SIG_get0_s(sig), halforder) > 0) {
        // enforce low S values, by negating the value (modulo the order) if above order/2.
        BIGNUM *s = BN_dup(ECDSA_SIG_get0_s(sig));
        BIGNUM *r = BN_dup(ECDSA_SIG_get0_r(sig));
        BN_sub(s, order, s);
        ECDSA_SIG_set0(sig, r, s);
    }
#endif

    BN_free(halforder);
    BN_free(order);

    pos = &vchSig[0];
    unsigned int nSize = i2d_ECDSA_SIG(sig, &pos);
    ECDSA_SIG_free(sig);
    vchSig.resize(nSize); // Shrink to fit actual size
    return true;
}

void CKey::MakeNewKey(bool fCompressedIn) {
    do {
        RAND_bytes(vch, sizeof(vch));
    } while (!Check(vch));
    fValid = true;
    fCompressed = fCompressedIn;
}

bool CKey::SetPrivKey(const CPrivKey &privkey, bool fCompressedIn) {
    CECKey key;
    if (!key.SetPrivKey(privkey))
        return false;
    key.GetSecretBytes(vch);
    fCompressed = fCompressedIn;
    fValid = true;
    return true;
}

CPrivKey CKey::GetPrivKey() const {
    assert(fValid);
    CECKey key;
    key.SetSecretBytes(vch);
    CPrivKey privkey;
    key.GetPrivKey(privkey, fCompressed);
    return privkey;
}

CPubKey CKey::GetPubKey() const {
    assert(fValid);
    CECKey key;
    key.SetSecretBytes(vch);
    CPubKey pubkey;
    key.GetPubKey(pubkey, fCompressed);
    return pubkey;
}

bool CKey::Sign(const uint256 &hash, std::vector<unsigned char>& vchSig) const {
    if (!fValid)
        return false;
    CECKey key;
    key.SetSecretBytes(vch);
    return key.Sign(hash, vchSig);
}

bool CKey::SignCompact(const uint256 &hash, std::vector<unsigned char>& vchSig) const {
    if (!fValid)
        return false;
    CECKey key;
    key.SetSecretBytes(vch);
    vchSig.resize(65);
    int rec = -1;
    if (!key.SignCompact(hash, &vchSig[1], rec))
        return false;
    assert(rec != -1);
    vchSig[0] = 27 + rec + (fCompressed ? 4 : 0);
    return true;
}

bool CKey::Load(CPrivKey &privkey, CPubKey &vchPubKey, bool fSkipCheck=false) {
    CECKey key;
    if (!key.SetPrivKey(privkey, fSkipCheck))
        return false;

    key.GetSecretBytes(vch);
    fCompressed = vchPubKey.IsCompressed();
    fValid = true;

    if (fSkipCheck)
        return true;

    if (GetPubKey() != vchPubKey)
        return false;

    return true;
}

bool CPubKey::Verify(const uint256 &hash, const std::vector<unsigned char>& vchSig) const {
    if (!IsValid())
        return false;
    CECKey key;
    if (!key.SetPubKey(*this))
        return false;
    if (!key.Verify(hash, vchSig))
        return false;
    return true;
}

bool CPubKey::RecoverCompact(const uint256 &hash, const std::vector<unsigned char>& vchSig) {
    if (vchSig.size() != 65)
        return false;
    CECKey key;
    if (!key.Recover(hash, &vchSig[1], (vchSig[0] - 27) & ~4))
        return false;
    key.GetPubKey(*this, (vchSig[0] - 27) & 4);
    return true;
}

bool CPubKey::VerifyCompact(const uint256 &hash, const std::vector<unsigned char>& vchSig) const {
    if (!IsValid())
        return false;
    if (vchSig.size() != 65)
        return false;
    CECKey key;
    if (!key.Recover(hash, &vchSig[1], (vchSig[0] - 27) & ~4))
        return false;
    CPubKey pubkeyRec;
    key.GetPubKey(pubkeyRec, IsCompressed());
    if (*this != pubkeyRec)
        return false;
    return true;
}

bool CPubKey::IsFullyValid() const {
    if (!IsValid())
        return false;
    CECKey key;
    if (!key.SetPubKey(*this))
        return false;
    return true;
}

bool CPubKey::Decompress() {
    if (!IsValid())
        return false;
    CECKey key;
    if (!key.SetPubKey(*this))
        return false;
    key.GetPubKey(*this, false);
    return true;
}

void static BIP32Hash(const unsigned char chainCode[32], unsigned int nChild, unsigned char header, const unsigned char data[32], unsigned char output[64]) {
    unsigned char num[4];
    num[0] = (nChild >> 24) & 0xFF;
    num[1] = (nChild >> 16) & 0xFF;
    num[2] = (nChild >>  8) & 0xFF;
    num[3] = (nChild >>  0) & 0xFF;
    HMAC_SHA512_CTX ctx;
    HMAC_SHA512_Init(&ctx, chainCode, 32);
    HMAC_SHA512_Update(&ctx, &header, 1);
    HMAC_SHA512_Update(&ctx, data, 32);
    HMAC_SHA512_Update(&ctx, num, 4);
    HMAC_SHA512_Final(output, &ctx);
}

bool CKey::Derive(CKey& keyChild, unsigned char ccChild[32], unsigned int nChild, const unsigned char cc[32]) const {
    assert(IsValid());
    assert(IsCompressed());
    unsigned char out[64];
    LockObject(out);
    if ((nChild >> 31) == 0) {
        CPubKey pubkey = GetPubKey();
        assert(pubkey.begin() + 33 == pubkey.end());
        BIP32Hash(cc, nChild, *pubkey.begin(), pubkey.begin()+1, out);
    } else {
        assert(begin() + 32 == end());
        BIP32Hash(cc, nChild, 0, begin(), out);
    }
    memcpy(ccChild, out+32, 32);
    bool ret = CECKey::TweakSecret((unsigned char*)keyChild.begin(), begin(), out);
    UnlockObject(out);
    keyChild.fCompressed = true;
    keyChild.fValid = ret;
    return ret;
}

bool CPubKey::Derive(CPubKey& pubkeyChild, unsigned char ccChild[32], unsigned int nChild, const unsigned char cc[32]) const {
    assert(IsValid());
    assert((nChild >> 31) == 0);
    assert(begin() + 33 == end());
    unsigned char out[64];
    BIP32Hash(cc, nChild, *begin(), begin()+1, out);
    memcpy(ccChild, out+32, 32);
    CECKey key;
    bool ret = key.SetPubKey(*this);
    ret &= key.TweakPublic(out);
    key.GetPubKey(pubkeyChild, true);
    return ret;
}

bool CExtKey::Derive(CExtKey &out, unsigned int nChild) const {
    out.nDepth = nDepth + 1;
    CKeyID id = key.GetPubKey().GetID();
    memcpy(&out.vchFingerprint[0], &id, 4);
    out.nChild = nChild;
    return key.Derive(out.key, out.vchChainCode, nChild, vchChainCode);
}

void CExtKey::SetMaster(const unsigned char *seed, unsigned int nSeedLen) {
    static const char hashkey[] = {'B','i','t','c','o','i','n',' ','s','e','e','d'};
    HMAC_SHA512_CTX ctx;
    HMAC_SHA512_Init(&ctx, hashkey, sizeof(hashkey));
    HMAC_SHA512_Update(&ctx, seed, nSeedLen);
    unsigned char out[64];
    LockObject(out);
    HMAC_SHA512_Final(out, &ctx);
    key.Set(&out[0], &out[32], true);
    memcpy(vchChainCode, &out[32], 32);
    UnlockObject(out);
    nDepth = 0;
    nChild = 0;
    memset(vchFingerprint, 0, sizeof(vchFingerprint));
}

CExtPubKey CExtKey::Neuter() const {
    CExtPubKey ret;
    ret.nDepth = nDepth;
    memcpy(&ret.vchFingerprint[0], &vchFingerprint[0], 4);
    ret.nChild = nChild;
    ret.pubkey = key.GetPubKey();
    memcpy(&ret.vchChainCode[0], &vchChainCode[0], 32);
    return ret;
}

void CExtKey::Encode(unsigned char code[74]) const {
    code[0] = nDepth;
    memcpy(code+1, vchFingerprint, 4);
    code[5] = (nChild >> 24) & 0xFF; code[6] = (nChild >> 16) & 0xFF;
    code[7] = (nChild >>  8) & 0xFF; code[8] = (nChild >>  0) & 0xFF;
    memcpy(code+9, vchChainCode, 32);
    code[41] = 0;
    assert(key.size() == 32);
    memcpy(code+42, key.begin(), 32);
}

void CExtKey::Decode(const unsigned char code[74]) {
    nDepth = code[0];
    memcpy(vchFingerprint, code+1, 4);
    nChild = (code[5] << 24) | (code[6] << 16) | (code[7] << 8) | code[8];
    memcpy(vchChainCode, code+9, 32);
    key.Set(code+42, code+74, true);
}

void CExtPubKey::Encode(unsigned char code[74]) const {
    code[0] = nDepth;
    memcpy(code+1, vchFingerprint, 4);
    code[5] = (nChild >> 24) & 0xFF; code[6] = (nChild >> 16) & 0xFF;
    code[7] = (nChild >>  8) & 0xFF; code[8] = (nChild >>  0) & 0xFF;
    memcpy(code+9, vchChainCode, 32);
    assert(pubkey.size() == 33);
    memcpy(code+41, pubkey.begin(), 33);
}

void CExtPubKey::Decode(const unsigned char code[74]) {
    nDepth = code[0];
    memcpy(vchFingerprint, code+1, 4);
    nChild = (code[5] << 24) | (code[6] << 16) | (code[7] << 8) | code[8];
    memcpy(vchChainCode, code+9, 32);
    pubkey.Set(code+41, code+74);
}

bool CExtPubKey::Derive(CExtPubKey &out, unsigned int nChild) const {
    out.nDepth = nDepth + 1;
    CKeyID id = pubkey.GetID();
    memcpy(&out.vchFingerprint[0], &id, 4);
    out.nChild = nChild;
    return pubkey.Derive(out.pubkey, out.vchChainCode, nChild, vchChainCode);
}

bool ECC_InitSanityCheck() {
    OSSL_LIB_CTX *libctx;
    OSSL_PROVIDER *defprov;

    libctx = OSSL_LIB_CTX_new();
    assert(libctx);

    defprov = OSSL_PROVIDER_load(NULL, "default");
    assert(defprov);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", NULL);
    EVP_PKEY *key = NULL;
    if (!ctx ||
       EVP_PKEY_paramgen_init(ctx) <= 0 ||
       EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp256k1) <= 0 ||
       EVP_PKEY_paramgen(ctx, &key) <= 0) {
           return false;
    }
    EVP_PKEY_CTX_free(ctx);

    // TODO Is there more EC functionality that could be missing?
    return true;
}
