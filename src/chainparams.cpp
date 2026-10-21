// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assert.h"

#include "chainparams.h"
#include "main.h"
#include "util.h"

#include <boost/assign/list_of.hpp>

using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

//
// Main network
//

// Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress> &vSeedsOut, const SeedSpec6 *data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7*24*60*60;
    for (unsigned int i = 0; i < count; i++)
    {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

class CMainParams : public CChainParams {
public:
    CMainParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xa5;
        pchMessageStart[1] = 0xf7;
        pchMessageStart[2] = 0x90;
        pchMessageStart[3] = 0xfd;
        vAlertPubKey = ParseHex("047f56d2d20f12f16f323e83233f94057723f5833e7f214818603d4833540319f79e19852fcec13943f7ff532483d2d331ec2ee2012fe2c4c4");
        nDefaultPort = 7506;
        nRPCPort = 5706;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 20);

        const char* pszTimestamp = "Happy 10th birthday Lana - Genesis block 7. March 2016 at 6:39 AM (GMT+2)";
        std::vector<CTxIn> vin;
        vin.resize(1);
        vin[0].scriptSig = CScript() << 0 << CBigNum(42) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        std::vector<CTxOut> vout;
        vout.resize(1);
        vout[0].SetEmpty();
        CTransaction txNew(1, 1462595940, vin, vout, 0);
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1462595940;
        genesis.nBits    = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce   = 30362;

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x0000095667f3c1fdbf0b9b4937be57c6401162fcfe72be373df27393f0c69d93"));
        assert(genesis.hashMerkleRoot == uint256("0xdcff6dc527aa9264066c514019630d56652973f3728deeaa597851941e14703e"));

        vSeeds.push_back(CDNSSeedData("lanacoin.com", "seed1.lanacoin.com"));
        vSeeds.push_back(CDNSSeedData("lanacoin.com", "seed2.lanacoin.com"));
        vSeeds.push_back(CDNSSeedData("lanacoin.com", "seed3.lanacoin.com"));
        vSeeds.push_back(CDNSSeedData("lanacoin.com", "seed4.lanacoin.com"));
        vSeeds.push_back(CDNSSeedData("lanacoin.com", "seed5.lanacoin.com"));
        vSeeds.push_back(CDNSSeedData("lanacoin.com", "seed6.lanacoin.com"));
        vSeeds.push_back(CDNSSeedData("lanacoin.com", "seed7.lanacoin.com"));
        vSeeds.push_back(CDNSSeedData("lanacoin.com", "seed8.lanacoin.com"));
        vSeeds.push_back(CDNSSeedData("lanacoin.com", "seed9.lanacoin.com"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,48);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,176);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        nLastPOWBlock = 750000;

        // Post-quantum hard fork: 7 May 2028 06:39 GMT+2, Lana's birthday.
        // From then on new outputs must be post-quantum (ML-DSA-44); ECDSA
        // signatures stop being valid one year later, 7 May 2029 06:39 GMT+2.
        nPQForkTime = 1841287140;       // 2028-05-07 04:39:00 UTC
        nECDSASunsetTime = 1872823140;  // 2029-05-07 04:39:00 UTC

        base58Prefixes[PQ_PUBKEY_ADDRESS] = boost::assign::list_of(131)(46).convert_to_container<std::vector<unsigned char> >();  // "LQ..."
        base58Prefixes[PQ_SCRIPT_ADDRESS] = boost::assign::list_of(131)(105).convert_to_container<std::vector<unsigned char> >(); // "LS..."
        base58Prefixes[PQ_SECRET_KEY] =     boost::assign::list_of(130)(152).convert_to_container<std::vector<unsigned char> >(); // "LK..."
    }

    virtual const CBlock& GenesisBlock() const { return genesis; }
    virtual Network NetworkID() const { return CChainParams::MAIN; }

    virtual const vector<CAddress>& FixedSeeds() const {
        return vFixedSeeds;
    }
protected:
    CBlock genesis;
    vector<CAddress> vFixedSeeds;
};
static CMainParams mainParams;


//
// Testnet
//

class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xcc;
        pchMessageStart[1] = 0xcb;
        pchMessageStart[2] = 0xd2;
        pchMessageStart[3] = 0x7f;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 16);
        vAlertPubKey = ParseHex("047fd61d8df73107614672d908cc51774dd7382cf4e71e1241160df9c8df1c37774d6c940c542728f11723757de6c3cedecd801097e762d");
        nDefaultPort = 17506;
        nRPCPort = 15706;
        strDataDir = "testnet";

        // Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nBits  = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce = 18887;
        genesis.nTime = 1462595940;

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x00005f78276904fdf0cbd61b10b5330e915362c2457173d443ad46e08fa621ef"));

        vSeeds.push_back(CDNSSeedData("lanacoin.com", "test1.lanacoin.com"));
        vSeeds.push_back(CDNSSeedData("lanacoin.com", "test2.lanacoin.com"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        nLastPOWBlock = 0x7fffffff;

        // Testnet goes through the whole post-quantum transition before mainnet
        nPQForkTime = 1833514740;       // 2028-02-07 05:39:00 UTC
        nECDSASunsetTime = 1838695140;  // 2028-04-07 04:39:00 UTC

        base58Prefixes[PQ_PUBKEY_ADDRESS] = boost::assign::list_of(178)(128).convert_to_container<std::vector<unsigned char> >(); // "TQ..."
        base58Prefixes[PQ_SCRIPT_ADDRESS] = boost::assign::list_of(178)(187).convert_to_container<std::vector<unsigned char> >(); // "TS..."
        base58Prefixes[PQ_SECRET_KEY] =     boost::assign::list_of(177)(234).convert_to_container<std::vector<unsigned char> >(); // "TK..."
    }
    virtual Network NetworkID() const { return CChainParams::TESTNET; }
};
static CTestNetParams testNetParams;


//
// Regression test
//
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        pchMessageStart[0] = 0xdd;
        pchMessageStart[1] = 0x13;
        pchMessageStart[2] = 0x9f;
        pchMessageStart[3] = 0x27;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 1);
        genesis.nTime = 1462595940;
        genesis.nBits  = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce = 1;

        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 27506;
        strDataDir = "regtest";


        assert(hashGenesisBlock == uint256("0x0eede8c987624337822f251729bfb79f8b5b0c069eedb72d0eb9fdb35780450b"));

        vSeeds.clear();  // Regtest mode doesn't have any DNS seeds.
    }

    virtual bool RequireRPCPassword() const { return false; }
    virtual Network NetworkID() const { return CChainParams::REGTEST; }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = &mainParams;

const CChainParams &Params() {
    return *pCurrentParams;
}

CChainParams &ModifiableParams() {
    return *pCurrentParams;
}

void SelectParams(CChainParams::Network network) {
    switch (network) {
        case CChainParams::MAIN:
            pCurrentParams = &mainParams;
            break;
        case CChainParams::TESTNET:
            pCurrentParams = &testNetParams;
            break;
        case CChainParams::REGTEST:
            pCurrentParams = &regTestParams;
            break;
        default:
            assert(false && "Unimplemented network");
            return;
    }
}

bool SelectParamsFromCommandLine() {
    bool fRegTest = GetBoolArg("-regtest", false);
    bool fTestNet = GetBoolArg("-testnet", false);

    if (fTestNet && fRegTest) {
        return false;
    }

    if (fRegTest) {
        SelectParams(CChainParams::REGTEST);
    } else if (fTestNet) {
        SelectParams(CChainParams::TESTNET);
    } else {
        SelectParams(CChainParams::MAIN);
    }

    // The post-quantum fork times can only be changed for test networks
    if (fRegTest || fTestNet) {
        int64_t nForkTime = GetArg("-pqforktime", Params().PQForkTime());
        int64_t nSunsetTime = GetArg("-ecdsasunsettime", std::max(nForkTime, Params().ECDSASunsetTime()));
        if (nSunsetTime < nForkTime)
            return false;
        ModifiableParams().SetPQForkTimes(nForkTime, nSunsetTime);
    } else if (mapArgs.count("-pqforktime") || mapArgs.count("-ecdsasunsettime")) {
        return false;
    }
    return true;
}
