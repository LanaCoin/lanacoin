// Copyright (c) 2026 The LanaCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef LANACOIN_PQKEY_H
#define LANACOIN_PQKEY_H

#include <string.h>
#include <vector>

#include "allocators.h"
#include "serialize.h"
#include "uint256.h"
#include "hash.h"

// Post-quantum signatures, used after the post-quantum hard fork
// (see doc/pq-hardfork.md).
//
// Every serialized public key starts with an algorithm byte, so that further
// schemes can be added later without new script opcodes or address types.

/** Post-quantum signature algorithms */
enum PQAlgorithm
{
    PQ_ALGO_MLDSA44 = 0x01, // ML-DSA-44, NIST FIPS 204, security category 2
};

/** Domain separation: what a signature is for (the FIPS 204 context string) */
enum PQSigDomain
{
    PQ_DOMAIN_TX = 0,      // transaction input (signature hash)
    PQ_DOMAIN_BLOCK = 1,   // proof-of-stake block signature
    PQ_DOMAIN_MESSAGE = 2, // signmessage / verifymessage
};

static const unsigned int MLDSA44_PUBLICKEY_SIZE = 1312;
static const unsigned int MLDSA44_SECRETKEY_SIZE = 2560;
static const unsigned int MLDSA44_SIGNATURE_SIZE = 2420;

/** Size of the seed a post-quantum private key is derived from */
static const unsigned int PQ_SEED_SIZE = 32;
/** Size of a serialized ML-DSA-44 public key (algorithm byte + key) */
static const unsigned int PQ_PUBKEY_SIZE = 1 + MLDSA44_PUBLICKEY_SIZE;
/** Size of an ML-DSA-44 signature (without the script hash type byte) */
static const unsigned int PQ_SIGNATURE_SIZE = MLDSA44_SIGNATURE_SIZE;

/** A reference to a CPQPubKey: the double SHA-256 of its serialization.
 *  256 bits keep 128 bit security against quantum (Grover) preimage search. */
class CPQKeyID : public uint256
{
public:
    CPQKeyID() : uint256(0) { }
    CPQKeyID(const uint256 &in) : uint256(in) { }
};

/** A reference to a script: the double SHA-256 of its serialization (P2SH256) */
class CScriptID256 : public uint256
{
public:
    CScriptID256() : uint256(0) { }
    CScriptID256(const uint256 &in) : uint256(in) { }
};

/** An encapsulated post-quantum public key */
class CPQPubKey
{
private:
    std::vector<unsigned char> vch;

public:
    CPQPubKey() { }

    template<typename T>
    CPQPubKey(const T pbegin, const T pend) : vch(pbegin, pend) { }

    explicit CPQPubKey(const std::vector<unsigned char> &vchIn) : vch(vchIn) { }

    unsigned int size() const { return vch.size(); }
    const unsigned char *begin() const { return vch.empty() ? NULL : &vch[0]; }
    const unsigned char *end() const { return begin() + vch.size(); }
    const std::vector<unsigned char> &Raw() const { return vch; }

    // Known algorithm and the exact size for it
    bool IsValid() const {
        return vch.size() == PQ_PUBKEY_SIZE && vch[0] == PQ_ALGO_MLDSA44;
    }

    CPQKeyID GetID() const {
        return CPQKeyID(Hash(vch.begin(), vch.end()));
    }

    // Verify a signature of a 32 byte hash for the given purpose
    bool Verify(const uint256 &hash, const std::vector<unsigned char> &vchSig, PQSigDomain domain) const;

    friend bool operator==(const CPQPubKey &a, const CPQPubKey &b) { return a.vch == b.vch; }
    friend bool operator!=(const CPQPubKey &a, const CPQPubKey &b) { return a.vch != b.vch; }
    friend bool operator<(const CPQPubKey &a, const CPQPubKey &b) { return a.vch < b.vch; }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vch);
    )
};

/** A post-quantum private key, stored as the 32 byte seed it is derived from */
class CPQKey
{
private:
    bool fValid;
    unsigned char seed[PQ_SEED_SIZE];
    CPQPubKey pubkey; // derived from the seed

public:
    CPQKey() : fValid(false) {
        LockObject(seed);
    }

    CPQKey(const CPQKey &other) : fValid(other.fValid), pubkey(other.pubkey) {
        LockObject(seed);
        memcpy(seed, other.seed, sizeof(seed));
    }

    CPQKey& operator=(const CPQKey &other) {
        fValid = other.fValid;
        pubkey = other.pubkey;
        memcpy(seed, other.seed, sizeof(seed));
        return *this;
    }

    // UnlockObject also wipes the seed
    ~CPQKey() {
        UnlockObject(seed);
    }

    friend bool operator==(const CPQKey &a, const CPQKey &b) {
        return a.fValid == b.fValid && memcmp(a.seed, b.seed, sizeof(a.seed)) == 0;
    }

    // Set from a 32 byte seed
    bool Set(const unsigned char *pbegin, const unsigned char *pend);

    // Generate a new key from the system CSPRNG
    void MakeNewKey();

    bool IsValid() const { return fValid; }

    // The seed (the private key material)
    unsigned int size() const { return fValid ? PQ_SEED_SIZE : 0; }
    const unsigned char *begin() const { return seed; }
    const unsigned char *end() const { return seed + size(); }

    const CPQPubKey &GetPubKey() const { return pubkey; }

    // Sign a 32 byte hash for the given purpose
    bool Sign(const uint256 &hash, std::vector<unsigned char> &vchSig, PQSigDomain domain) const;

    // Sign with caller supplied signing randomness (known answer tests only)
    bool SignWithRandomness(const uint256 &hash, std::vector<unsigned char> &vchSig, PQSigDomain domain,
                            const unsigned char rnd[32]) const;
};

#endif
