// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_KEYSTORE_H
#define BITCOIN_KEYSTORE_H

#include "key.h"
#include "pqkey.h"
#include "sync.h"
#include <boost/signals2/signal.hpp>

class CScript;

/** A virtual base class for key stores */
class CKeyStore
{
protected:
    mutable CCriticalSection cs_KeyStore;

public:
    virtual ~CKeyStore() {}

    // Add a key to the store.
    virtual bool AddKeyPubKey(const CKey &key, const CPubKey &pubkey) =0;
    virtual bool AddKey(const CKey &key);

    // Check whether a key corresponding to a given address is present in the store.
    virtual bool HaveKey(const CKeyID &address) const =0;
    virtual bool GetKey(const CKeyID &address, CKey& keyOut) const =0;
    virtual void GetKeys(std::set<CKeyID> &setAddress) const =0;
    virtual bool GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const;

    // Support for BIP 0013 : see https://en.bitcoin.it/wiki/BIP_0013
    virtual bool AddCScript(const CScript& redeemScript) =0;
    virtual bool HaveCScript(const CScriptID &hash) const =0;
    virtual bool GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const =0;

    // Post-quantum keys
    virtual bool AddPQKey(const CPQKey &key) =0;
    virtual bool HavePQKey(const CPQKeyID &address) const =0;
    virtual bool GetPQKey(const CPQKeyID &address, CPQKey &keyOut) const =0;
    virtual bool GetPQPubKey(const CPQKeyID &address, CPQPubKey &pubKeyOut) const =0;
    virtual void GetPQKeys(std::set<CPQKeyID> &setAddress) const =0;

    // Redeem scripts referenced by a 256 bit hash (P2SH256)
    virtual bool AddCScript256(const CScript& redeemScript) =0;
    virtual bool HaveCScript256(const CScriptID256 &hash) const =0;
    virtual bool GetCScript256(const CScriptID256 &hash, CScript& redeemScriptOut) const =0;
};

typedef std::map<CKeyID, CKey> KeyMap;
typedef std::map<CScriptID, CScript > ScriptMap;
typedef std::map<CPQKeyID, CPQKey> PQKeyMap;
typedef std::map<CScriptID256, CScript> Script256Map;

/** Basic key store, that keeps keys in an address->secret map */
class CBasicKeyStore : public CKeyStore
{
protected:
    KeyMap mapKeys;
    ScriptMap mapScripts;
    PQKeyMap mapPQKeys;
    Script256Map mapScripts256;

public:
    bool AddPQKey(const CPQKey &key);
    bool HavePQKey(const CPQKeyID &address) const;
    bool GetPQKey(const CPQKeyID &address, CPQKey &keyOut) const;
    bool GetPQPubKey(const CPQKeyID &address, CPQPubKey &pubKeyOut) const;
    void GetPQKeys(std::set<CPQKeyID> &setAddress) const;
    virtual bool AddCScript256(const CScript& redeemScript);
    virtual bool HaveCScript256(const CScriptID256 &hash) const;
    virtual bool GetCScript256(const CScriptID256 &hash, CScript& redeemScriptOut) const;

    bool AddKeyPubKey(const CKey& key, const CPubKey &pubkey);
    bool HaveKey(const CKeyID &address) const
    {
        bool result;
        {
            LOCK(cs_KeyStore);
            result = (mapKeys.count(address) > 0);
        }
        return result;
    }
    void GetKeys(std::set<CKeyID> &setAddress) const
    {
        setAddress.clear();
        {
            LOCK(cs_KeyStore);
            KeyMap::const_iterator mi = mapKeys.begin();
            while (mi != mapKeys.end())
            {
                setAddress.insert((*mi).first);
                mi++;
            }
        }
    }
    bool GetKey(const CKeyID &address, CKey &keyOut) const
    {
        {
            LOCK(cs_KeyStore);
            KeyMap::const_iterator mi = mapKeys.find(address);
            if (mi != mapKeys.end())
            {
                keyOut = mi->second;
                return true;
            }
        }
        return false;
    }
    virtual bool AddCScript(const CScript& redeemScript);
    virtual bool HaveCScript(const CScriptID &hash) const;
    virtual bool GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const;
};

typedef std::map<CKeyID, std::pair<CPubKey, std::vector<unsigned char> > > CryptedKeyMap;
typedef std::map<CPQKeyID, std::pair<CPQPubKey, std::vector<unsigned char> > > CryptedPQKeyMap;

#endif
