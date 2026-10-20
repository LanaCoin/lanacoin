#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

#include "base58.h"
#include "chainparams.h"
#include "main.h"
#include "timedata.h"
#include "wallet.h"
#include "walletdb.h"

using namespace std;

extern CWallet* pwalletMain;

// Moves the post-quantum fork for one test and restores the mainnet times
struct PQForkTimes
{
    PQForkTimes(int64_t nFork, int64_t nSunset) { ModifiableParams().SetPQForkTimes(nFork, nSunset); }
    ~PQForkTimes() { ModifiableParams().SetPQForkTimes(1809664740, 1841287140); }
};

static CScript ScriptFor(const CTxDestination& dest)
{
    CScript script;
    script.SetDestination(dest);
    return script;
}

BOOST_AUTO_TEST_SUITE(pqwallet_tests)

BOOST_AUTO_TEST_CASE(pqwallet_keys)
{
    LOCK(pwalletMain->cs_wallet);

    CPQPubKey pubkey = pwalletMain->GenerateNewPQKey();
    BOOST_CHECK(pubkey.IsValid());
    BOOST_CHECK(pwalletMain->HavePQKey(pubkey.GetID()));
    BOOST_CHECK(IsMine(*pwalletMain, ScriptFor(pubkey.GetID())));
    BOOST_CHECK(pwalletMain->mapPQKeyMetadata.count(pubkey.GetID()));

    CPQKey key;
    BOOST_CHECK(pwalletMain->GetPQKey(pubkey.GetID(), key));
    BOOST_CHECK(key.GetPubKey() == pubkey);

    // The key pool hands out keys the wallet has
    BOOST_CHECK(pwalletMain->TopUpPQKeyPool(5));
    BOOST_CHECK(pwalletMain->GetPQKeyPoolSize() >= 5);
    CPQPubKey pooled;
    BOOST_CHECK(pwalletMain->GetPQKeyFromPool(pooled));
    BOOST_CHECK(pwalletMain->HavePQKey(pooled.GetID()));
    BOOST_CHECK(pooled != pubkey);

    // Reserved keys go back to the pool unless kept
    unsigned int nPoolSize = pwalletMain->GetPQKeyPoolSize();
    {
        CReserveKey reservekey(pwalletMain);
        CPQPubKey reserved;
        BOOST_CHECK(reservekey.GetReservedPQKey(reserved));
        BOOST_CHECK(reserved.IsValid());
    }
    BOOST_CHECK(pwalletMain->GetPQKeyPoolSize() >= nPoolSize);
}

BOOST_AUTO_TEST_CASE(pqwallet_new_destination_follows_fork)
{
    LOCK(pwalletMain->cs_wallet);
    int64_t nNow = GetAdjustedTime();
    CTxDestination dest;

    {
        PQForkTimes times(nNow + 3600, nNow + 7200); // fork in the future
        BOOST_CHECK(!pwalletMain->UsePostQuantum());
        BOOST_CHECK(pwalletMain->GetNewDestination(dest, false));
        BOOST_CHECK(boost::get<CKeyID>(&dest));
        BOOST_CHECK(pwalletMain->GetNewDestination(dest, true));
        BOOST_CHECK(boost::get<CPQKeyID>(&dest));

        CScript script;
        CReserveKey reservekey(pwalletMain);
        BOOST_CHECK(reservekey.GetReservedScript(script));
        txnouttype whichType;
        vector<vector<unsigned char> > vSolutions;
        BOOST_CHECK(Solver(script, whichType, vSolutions) && whichType == TX_PUBKEYHASH);
    }
    {
        PQForkTimes times(nNow - 3600, nNow + 3600); // fork active
        BOOST_CHECK(pwalletMain->UsePostQuantum());
        BOOST_CHECK(pwalletMain->GetNewDestination(dest, false));
        BOOST_CHECK(boost::get<CPQKeyID>(&dest));
        BOOST_CHECK(IsMine(*pwalletMain, dest));
        BOOST_CHECK_EQUAL(CBitcoinAddress(dest).ToString().substr(0, 2), "LQ");

        // Change goes to a post-quantum address
        CScript script;
        CReserveKey reservekey(pwalletMain);
        BOOST_CHECK(reservekey.GetReservedScript(script));
        txnouttype whichType;
        vector<vector<unsigned char> > vSolutions;
        BOOST_CHECK(Solver(script, whichType, vSolutions) && whichType == TX_PQKEYHASH);
        BOOST_CHECK(IsMine(*pwalletMain, script));
    }
}

BOOST_AUTO_TEST_CASE(pqwallet_send_destinations)
{
    LOCK(pwalletMain->cs_wallet);
    int64_t nNow = GetAdjustedTime();
    CTxDestination pqDest, legacyDest;
    BOOST_REQUIRE(pwalletMain->GetNewDestination(pqDest, true));
    CPubKey legacyKey = pwalletMain->GenerateNewKey();
    legacyDest = legacyKey.GetID();

    vector<pair<CScript, int64_t> > toPQ(1, make_pair(ScriptFor(pqDest), COIN));
    vector<pair<CScript, int64_t> > toLegacy(1, make_pair(ScriptFor(legacyDest), COIN));
    vector<pair<CScript, int64_t> > toScript256(1, make_pair(ScriptFor(CScriptID256(uint256(5))), COIN));
    string strError;

    {
        // Before the fork: post-quantum outputs could not be spent yet
        PQForkTimes times(nNow + 3600, nNow + 7200);
        BOOST_CHECK(pwalletMain->CheckSendDestinations(toLegacy, strError));
        BOOST_CHECK(!pwalletMain->CheckSendDestinations(toPQ, strError));
        BOOST_CHECK(!pwalletMain->CheckSendDestinations(toScript256, strError));
        BOOST_CHECK(!strError.empty());
    }
    {
        // After it: legacy outputs are invalid
        PQForkTimes times(nNow - 3600, nNow + 3600);
        BOOST_CHECK(pwalletMain->CheckSendDestinations(toPQ, strError));
        BOOST_CHECK(pwalletMain->CheckSendDestinations(toScript256, strError));
        BOOST_CHECK(!pwalletMain->CheckSendDestinations(toLegacy, strError));
        vector<pair<CScript, int64_t> > mixed = toPQ;
        mixed.push_back(toLegacy[0]);
        BOOST_CHECK(!pwalletMain->CheckSendDestinations(mixed, strError));
    }
}

BOOST_AUTO_TEST_CASE(pqwallet_database_roundtrip)
{
    CPQPubKey pubkey, staking;
    unsigned int nPoolSize;
    bool fFirstRun;
    {
        // A wallet file of its own, so only this test's records are in it
        CWallet wallet("pqwallet_test.dat");
        BOOST_REQUIRE_EQUAL(wallet.LoadWallet(fFirstRun), DB_LOAD_OK);
        LOCK(wallet.cs_wallet);
        pubkey = wallet.GenerateNewPQKey();
        wallet.SetAddressBookName(pubkey.GetID(), "pq label");
        CPQKey stakingKey;
        BOOST_REQUIRE(wallet.GetPQStakingKey(stakingKey));
        staking = stakingKey.GetPubKey();
        CScript redeem = CScript() << pubkey << OP_CHECKSIGPQ;
        BOOST_REQUIRE(wallet.AddCScript256(redeem));
        nPoolSize = wallet.GetPQKeyPoolSize();
        BOOST_CHECK(nPoolSize > 0);
    }
    bitdb.Flush(false);

    // A second wallet object loads the same file
    CWallet wallet("pqwallet_test.dat");
    BOOST_REQUIRE_EQUAL(wallet.LoadWallet(fFirstRun), DB_LOAD_OK);
    LOCK(wallet.cs_wallet);
    CPQKey key;
    BOOST_CHECK(wallet.GetPQKey(pubkey.GetID(), key));
    BOOST_CHECK(key.GetPubKey() == pubkey);
    BOOST_CHECK(wallet.mapPQKeyMetadata.count(pubkey.GetID()));
    BOOST_CHECK(wallet.mapAddressBook.count(pubkey.GetID()) && wallet.mapAddressBook[pubkey.GetID()] == "pq label");
    BOOST_CHECK(wallet.pqStakingKeyID == staking.GetID());
    BOOST_CHECK(wallet.HavePQKey(staking.GetID()));
    BOOST_CHECK(wallet.HaveCScript256((CScript() << pubkey << OP_CHECKSIGPQ).GetID256()));
    BOOST_CHECK_EQUAL(wallet.GetPQKeyPoolSize(), nPoolSize);
}

BOOST_AUTO_TEST_SUITE_END()
