// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "keystore.h"
#include "script.h"

bool CKeyStore::GetPubKey(const CKeyID &address, CPubKey &vchPubKeyOut) const
{
    CKey key;
    if (!GetKey(address, key))
        return false;
    vchPubKeyOut = key.GetPubKey();
    return true;
}

bool CKeyStore::AddKey(const CKey &key) {
    return AddKeyPubKey(key, key.GetPubKey());
}

bool CBasicKeyStore::AddKeyPubKey(const CKey& key, const CPubKey &pubkey)
{
    LOCK(cs_KeyStore);
    mapKeys[pubkey.GetID()] = key;
    return true;
}

bool CBasicKeyStore::AddCScript(const CScript& redeemScript)
{
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE)
        return error("CBasicKeyStore::AddCScript() : redeemScripts > %i bytes are invalid", MAX_SCRIPT_ELEMENT_SIZE);

    LOCK(cs_KeyStore);
    mapScripts[redeemScript.GetID()] = redeemScript;
    return true;
}

bool CBasicKeyStore::HaveCScript(const CScriptID& hash) const
{
    LOCK(cs_KeyStore);
    return mapScripts.count(hash) > 0;
}

bool CBasicKeyStore::GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const
{
    LOCK(cs_KeyStore);
    ScriptMap::const_iterator mi = mapScripts.find(hash);
    if (mi != mapScripts.end())
    {
        redeemScriptOut = (*mi).second;
        return true;
    }
    return false;
}

bool CBasicKeyStore::AddPQKey(const CPQKey &key)
{
    if (!key.IsValid())
        return false;
    LOCK(cs_KeyStore);
    mapPQKeys[key.GetPubKey().GetID()] = key;
    return true;
}

bool CBasicKeyStore::HavePQKey(const CPQKeyID &address) const
{
    LOCK(cs_KeyStore);
    return mapPQKeys.count(address) > 0;
}

bool CBasicKeyStore::GetPQKey(const CPQKeyID &address, CPQKey &keyOut) const
{
    LOCK(cs_KeyStore);
    PQKeyMap::const_iterator mi = mapPQKeys.find(address);
    if (mi == mapPQKeys.end())
        return false;
    keyOut = mi->second;
    return true;
}

bool CBasicKeyStore::GetPQPubKey(const CPQKeyID &address, CPQPubKey &pubKeyOut) const
{
    LOCK(cs_KeyStore);
    PQKeyMap::const_iterator mi = mapPQKeys.find(address);
    if (mi == mapPQKeys.end())
        return false;
    pubKeyOut = mi->second.GetPubKey();
    return true;
}

void CBasicKeyStore::GetPQKeys(std::set<CPQKeyID> &setAddress) const
{
    setAddress.clear();
    LOCK(cs_KeyStore);
    for (PQKeyMap::const_iterator mi = mapPQKeys.begin(); mi != mapPQKeys.end(); ++mi)
        setAddress.insert(mi->first);
}

bool CBasicKeyStore::AddCScript256(const CScript& redeemScript)
{
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE_PQ)
        return error("CBasicKeyStore::AddCScript256() : redeemScripts > %i bytes are invalid", MAX_SCRIPT_ELEMENT_SIZE_PQ);

    LOCK(cs_KeyStore);
    mapScripts256[redeemScript.GetID256()] = redeemScript;
    return true;
}

bool CBasicKeyStore::HaveCScript256(const CScriptID256 &hash) const
{
    LOCK(cs_KeyStore);
    return mapScripts256.count(hash) > 0;
}

bool CBasicKeyStore::GetCScript256(const CScriptID256 &hash, CScript& redeemScriptOut) const
{
    LOCK(cs_KeyStore);
    Script256Map::const_iterator mi = mapScripts256.find(hash);
    if (mi == mapScripts256.end())
        return false;
    redeemScriptOut = mi->second;
    return true;
}
