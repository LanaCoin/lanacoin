// Copyright (c) 2026 The LanaCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pqkey.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <stdexcept>

extern "C" {
#include "mldsa44/api.h"
}

namespace {

// FIPS 204 context strings, one per signature purpose, so that a signature
// made for one purpose can never be valid for another
const char *PQDomainContext(PQSigDomain domain)
{
    switch (domain)
    {
    case PQ_DOMAIN_TX:      return "LanaCoin/tx";
    case PQ_DOMAIN_BLOCK:   return "LanaCoin/block";
    case PQ_DOMAIN_MESSAGE: return "LanaCoin/message";
    }
    return NULL;
}

// Secret key expanded from the seed, wiped when it goes out of scope
class CExpandedSecretKey
{
public:
    unsigned char sk[MLDSA44_SECRETKEY_SIZE];
    unsigned char pk[MLDSA44_PUBLICKEY_SIZE];

    explicit CExpandedSecretKey(const unsigned char *seed) {
        LockObject(sk);
        PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair_seed(pk, sk, seed);
    }
    ~CExpandedSecretKey() {
        UnlockObject(sk);
    }
};

bool SignImpl(const unsigned char *seed, const uint256 &hash, std::vector<unsigned char> &vchSig,
              PQSigDomain domain, const unsigned char *rnd)
{
    const char *ctx = PQDomainContext(domain);
    if (!ctx)
        return false;

    CExpandedSecretKey key(seed);
    vchSig.resize(MLDSA44_SIGNATURE_SIZE);
    size_t nSigLen = 0;
    int ret;
    if (rnd)
        ret = PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature_ctx_rnd(&vchSig[0], &nSigLen,
                  (const uint8_t*)&hash, 32, (const uint8_t*)ctx, strlen(ctx), rnd, key.sk);
    else
        ret = PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature_ctx(&vchSig[0], &nSigLen,
                  (const uint8_t*)&hash, 32, (const uint8_t*)ctx, strlen(ctx), key.sk);
    if (ret != 0 || nSigLen != MLDSA44_SIGNATURE_SIZE) {
        vchSig.clear();
        return false;
    }
    return true;
}

} // anonymous namespace

bool CPQPubKey::Verify(const uint256 &hash, const std::vector<unsigned char> &vchSig, PQSigDomain domain) const
{
    if (!IsValid())
        return false;
    if (vchSig.size() != MLDSA44_SIGNATURE_SIZE)
        return false;
    const char *ctx = PQDomainContext(domain);
    if (!ctx)
        return false;
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify_ctx(&vchSig[0], vchSig.size(), (const uint8_t*)&hash, 32,
               (const uint8_t*)ctx, strlen(ctx), &vch[1]) == 0;
}

bool CPQKey::Set(const unsigned char *pbegin, const unsigned char *pend)
{
    fValid = false;
    pubkey = CPQPubKey();
    if (pend - pbegin != (ptrdiff_t)PQ_SEED_SIZE)
        return false;
    memcpy(seed, pbegin, PQ_SEED_SIZE);

    CExpandedSecretKey key(seed);
    std::vector<unsigned char> vchPubKey(PQ_PUBKEY_SIZE);
    vchPubKey[0] = PQ_ALGO_MLDSA44;
    memcpy(&vchPubKey[1], key.pk, MLDSA44_PUBLICKEY_SIZE);
    pubkey = CPQPubKey(vchPubKey);
    fValid = true;
    return true;
}

void CPQKey::MakeNewKey()
{
    unsigned char vchSeed[PQ_SEED_SIZE];
    LockObject(vchSeed);
    bool fOk = RAND_bytes(vchSeed, sizeof(vchSeed)) == 1;
    if (fOk)
        Set(vchSeed, vchSeed + sizeof(vchSeed));
    UnlockObject(vchSeed);
    if (!fOk)
        throw std::runtime_error("CPQKey::MakeNewKey() : RAND_bytes failed");
}

bool CPQKey::Sign(const uint256 &hash, std::vector<unsigned char> &vchSig, PQSigDomain domain) const
{
    if (!fValid)
        return false;
    return SignImpl(seed, hash, vchSig, domain, NULL);
}

bool CPQKey::SignWithRandomness(const uint256 &hash, std::vector<unsigned char> &vchSig, PQSigDomain domain,
                                const unsigned char rnd[32]) const
{
    if (!fValid)
        return false;
    return SignImpl(seed, hash, vchSig, domain, rnd);
}
