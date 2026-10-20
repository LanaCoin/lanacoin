#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

#include "base58.h"
#include "chainparams.h"
#include "crypter.h"
#include "key.h"
#include "keystore.h"
#include "main.h"
#include "pqkey.h"
#include "script.h"

using namespace std;

typedef vector<unsigned char> valtype;

extern uint256 SignatureHash(CScript scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType);
extern bool CastToBool(const valtype& vch);

// Transaction spending output 0 of txFrom
static CTransaction SpendingTx(const CTransaction& txFrom, const CScript& scriptPubKeyTo)
{
    CTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = txFrom.GetHash();
    tx.vin[0].prevout.n = 0;
    tx.vout.resize(1);
    tx.vout[0].nValue = txFrom.vout[0].nValue;
    tx.vout[0].scriptPubKey = scriptPubKeyTo;
    return tx;
}

static CTransaction CreditingTx(const CScript& scriptPubKey)
{
    CTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout.SetNull();
    tx.vin[0].scriptSig = CScript() << OP_0 << OP_0;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000 * COIN;
    tx.vout[0].scriptPubKey = scriptPubKey;
    return tx;
}

static CScript PQKeyHashScript(const CPQKey& key)
{
    CScript script;
    script.SetDestination(key.GetPubKey().GetID());
    return script;
}

static valtype SignPQ(const CPQKey& key, const CScript& scriptCode, const CTransaction& tx, unsigned int nIn, int nHashType = SIGHASH_ALL)
{
    uint256 hash = SignatureHash(scriptCode, tx, nIn, nHashType);
    valtype vchSig;
    BOOST_REQUIRE(key.Sign(hash, vchSig, PQ_DOMAIN_TX));
    vchSig.push_back((unsigned char)nHashType);
    return vchSig;
}

static const unsigned int flagsBeforeFork = MANDATORY_SCRIPT_VERIFY_FLAGS;
static const unsigned int flagsAfterFork = MANDATORY_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_PQ;
static const unsigned int flagsAfterSunset = MANDATORY_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_PQ | SCRIPT_VERIFY_NO_ECDSA;

BOOST_AUTO_TEST_SUITE(pqfork_tests)

BOOST_AUTO_TEST_CASE(pqfork_activation_times)
{
    // Mainnet: 7 May 2027 06:39 GMT+2, ECDSA sunset one year later
    SelectParams(CChainParams::MAIN);
    BOOST_CHECK_EQUAL(Params().PQForkTime(), 1809664740);
    BOOST_CHECK_EQUAL(Params().ECDSASunsetTime(), 1841287140);
    BOOST_CHECK(!IsPQForkActive(1809664739));
    BOOST_CHECK(IsPQForkActive(1809664740));
    BOOST_CHECK(!IsECDSASunset(1841287139));
    BOOST_CHECK(IsECDSASunset(1841287140));

    BOOST_CHECK_EQUAL(GetPQScriptFlags(1809664739), 0U);
    BOOST_CHECK_EQUAL(GetPQScriptFlags(1809664740), (unsigned int)SCRIPT_VERIFY_PQ);
    BOOST_CHECK_EQUAL(GetPQScriptFlags(1841287140), (unsigned int)(SCRIPT_VERIFY_PQ | SCRIPT_VERIFY_NO_ECDSA));

    // Testnet goes through the transition before mainnet
    SelectParams(CChainParams::TESTNET);
    BOOST_CHECK(Params().PQForkTime() < Params().ECDSASunsetTime());
    BOOST_CHECK(Params().ECDSASunsetTime() < 1809664740);
    SelectParams(CChainParams::MAIN);
}

BOOST_AUTO_TEST_CASE(pqfork_pqkeyhash_spend)
{
    CBasicKeyStore keystore;
    CPQKey key, key2;
    key.MakeNewKey();
    key2.MakeNewKey();
    BOOST_REQUIRE(keystore.AddPQKey(key));

    CScript scriptPubKey = PQKeyHashScript(key);
    txnouttype whichType;
    vector<valtype> vSolutions;
    BOOST_CHECK(Solver(scriptPubKey, whichType, vSolutions));
    BOOST_CHECK_EQUAL(whichType, TX_PQKEYHASH);
    BOOST_CHECK(IsMine(keystore, scriptPubKey));
    BOOST_CHECK(!IsMine(keystore, PQKeyHashScript(key2)));
    CTxDestination dest;
    BOOST_CHECK(ExtractDestination(scriptPubKey, dest));
    BOOST_CHECK(boost::get<CPQKeyID>(&dest) && *boost::get<CPQKeyID>(&dest) == key.GetPubKey().GetID());

    CTransaction txFrom = CreditingTx(scriptPubKey);
    CTransaction txTo = SpendingTx(txFrom, PQKeyHashScript(key2));

    // The wallet signs it
    BOOST_CHECK(SignSignature(keystore, txFrom, txTo, 0));
    const CScript& scriptSig = txTo.vin[0].scriptSig;

    // Valid after the fork (also after the ECDSA sunset), invalid before
    BOOST_CHECK(VerifyScript(scriptSig, scriptPubKey, txTo, 0, flagsAfterFork, 0));
    BOOST_CHECK(VerifyScript(scriptSig, scriptPubKey, txTo, 0, flagsAfterSunset, 0));
    BOOST_CHECK(!VerifyScript(scriptSig, scriptPubKey, txTo, 0, flagsBeforeFork, 0));

    // The signature commits to the transaction
    CTransaction txOther = txTo;
    txOther.vout[0].nValue -= 1;
    BOOST_CHECK(!VerifyScript(scriptSig, scriptPubKey, txOther, 0, flagsAfterFork, 0));

    // A modified signature fails
    valtype vchSig = SignPQ(key, scriptPubKey, txTo, 0);
    vchSig[100] ^= 1;
    BOOST_CHECK(!VerifyScript(CScript() << vchSig << key.GetPubKey(), scriptPubKey, txTo, 0, flagsAfterFork, 0));

    // Somebody else's key and signature fail the key hash
    valtype vchSig2 = SignPQ(key2, scriptPubKey, txTo, 0);
    BOOST_CHECK(!VerifyScript(CScript() << vchSig2 << key2.GetPubKey(), scriptPubKey, txTo, 0, flagsAfterFork, 0));

    // Strict encoding: wrong size, undefined hash type, empty signature
    valtype vchGood = SignPQ(key, scriptPubKey, txTo, 0);
    BOOST_CHECK(VerifyScript(CScript() << vchGood << key.GetPubKey(), scriptPubKey, txTo, 0, flagsAfterFork, 0));
    valtype vchShort(vchGood.begin() + 1, vchGood.end());
    BOOST_CHECK(!VerifyScript(CScript() << vchShort << key.GetPubKey(), scriptPubKey, txTo, 0, flagsAfterFork, 0));
    valtype vchBadType = vchGood;
    vchBadType.back() = 0x42;
    BOOST_CHECK(!VerifyScript(CScript() << vchBadType << key.GetPubKey(), scriptPubKey, txTo, 0, flagsAfterFork, 0));
    BOOST_CHECK(!VerifyScript(CScript() << valtype() << key.GetPubKey(), scriptPubKey, txTo, 0, flagsAfterFork, 0));

    // Other hash types work and are committed to
    valtype vchNone = SignPQ(key, scriptPubKey, txTo, 0, SIGHASH_NONE);
    BOOST_CHECK(VerifyScript(CScript() << vchNone << key.GetPubKey(), scriptPubKey, txTo, 0, flagsAfterFork, 0));
    vchNone.back() = SIGHASH_ALL;
    BOOST_CHECK(!VerifyScript(CScript() << vchNone << key.GetPubKey(), scriptPubKey, txTo, 0, flagsAfterFork, 0));

    // SIGHASH_SINGLE without a matching output ("SIGHASH_SINGLE bug": the
    // signature hash would be the constant 1) is rejected
    CTransaction txTwoIn = txTo;
    txTwoIn.vin.push_back(txTo.vin[0]);
    txTwoIn.vin[1].prevout.n = 1;
    valtype vchSingle;
    BOOST_REQUIRE(key.Sign(uint256(1), vchSingle, PQ_DOMAIN_TX));
    vchSingle.push_back(SIGHASH_SINGLE);
    BOOST_CHECK(!VerifyScript(CScript() << vchSingle << key.GetPubKey(), scriptPubKey, txTwoIn, 1, flagsAfterFork, 0));
    valtype vchSingle0 = SignPQ(key, scriptPubKey, txTwoIn, 0, SIGHASH_SINGLE);
    BOOST_CHECK(VerifyScript(CScript() << vchSingle0 << key.GetPubKey(), scriptPubKey, txTwoIn, 0, flagsAfterFork, 0));

    // A transaction signature is not valid as a block signature and vice versa
    uint256 sighash = SignatureHash(scriptPubKey, txTo, 0, SIGHASH_ALL);
    valtype vchBlockSig;
    BOOST_REQUIRE(key.Sign(sighash, vchBlockSig, PQ_DOMAIN_BLOCK));
    vchBlockSig.push_back(SIGHASH_ALL);
    BOOST_CHECK(!VerifyScript(CScript() << vchBlockSig << key.GetPubKey(), scriptPubKey, txTo, 0, flagsAfterFork, 0));
}

BOOST_AUTO_TEST_CASE(pqfork_ecdsa_sunset)
{
    CBasicKeyStore keystore;
    CKey key;
    key.MakeNewKey(true);
    keystore.AddKey(key);

    CScript scriptPubKey;
    scriptPubKey.SetDestination(key.GetPubKey().GetID());
    CTransaction txFrom = CreditingTx(scriptPubKey);
    CPQKey pqkey;
    pqkey.MakeNewKey();
    CTransaction txTo = SpendingTx(txFrom, PQKeyHashScript(pqkey));
    BOOST_REQUIRE(SignSignature(keystore, txFrom, txTo, 0));

    // Moving ECDSA coins to a post-quantum address works until the sunset
    BOOST_CHECK(VerifyScript(txTo.vin[0].scriptSig, scriptPubKey, txTo, 0, flagsBeforeFork, 0));
    BOOST_CHECK(VerifyScript(txTo.vin[0].scriptSig, scriptPubKey, txTo, 0, flagsAfterFork, 0));
    BOOST_CHECK(!VerifyScript(txTo.vin[0].scriptSig, scriptPubKey, txTo, 0, flagsAfterSunset, 0));

    // Pay-to-pubkey (staking outputs) and multisig too
    CScript p2pk = CScript() << key.GetPubKey() << OP_CHECKSIG;
    CTransaction txFrom2 = CreditingTx(p2pk);
    CTransaction txTo2 = SpendingTx(txFrom2, PQKeyHashScript(pqkey));
    BOOST_REQUIRE(SignSignature(keystore, txFrom2, txTo2, 0));
    BOOST_CHECK(VerifyScript(txTo2.vin[0].scriptSig, p2pk, txTo2, 0, flagsAfterFork, 0));
    BOOST_CHECK(!VerifyScript(txTo2.vin[0].scriptSig, p2pk, txTo2, 0, flagsAfterSunset, 0));

    CScript multisig;
    vector<CPubKey> keys(1, key.GetPubKey());
    multisig.SetMultisig(1, keys);
    CTransaction txFrom3 = CreditingTx(multisig);
    CTransaction txTo3 = SpendingTx(txFrom3, PQKeyHashScript(pqkey));
    BOOST_REQUIRE(SignSignature(keystore, txFrom3, txTo3, 0));
    BOOST_CHECK(VerifyScript(txTo3.vin[0].scriptSig, multisig, txTo3, 0, flagsAfterFork, 0));
    BOOST_CHECK(!VerifyScript(txTo3.vin[0].scriptSig, multisig, txTo3, 0, flagsAfterSunset, 0));
}

BOOST_AUTO_TEST_CASE(pqfork_p2sh256_multisig)
{
    // 2-of-2 post-quantum multisig in a P2SH256 output
    CPQKey key1, key2;
    key1.MakeNewKey();
    key2.MakeNewKey();
    CScript redeemScript = CScript() << key1.GetPubKey() << OP_CHECKSIGPQVERIFY << key2.GetPubKey() << OP_CHECKSIGPQ;
    BOOST_CHECK(redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE);
    BOOST_CHECK_EQUAL(redeemScript.GetPQSigOpCount(), 2U);

    CScript scriptPubKey;
    scriptPubKey.SetDestination(redeemScript.GetID256());
    BOOST_CHECK(scriptPubKey.IsPayToScriptHash256());
    txnouttype whichType;
    vector<valtype> vSolutions;
    BOOST_CHECK(Solver(scriptPubKey, whichType, vSolutions));
    BOOST_CHECK_EQUAL(whichType, TX_SCRIPTHASH256);

    CTransaction txFrom = CreditingTx(scriptPubKey);
    CTransaction txTo = SpendingTx(txFrom, PQKeyHashScript(key1));
    valtype sig1 = SignPQ(key1, redeemScript, txTo, 0);
    valtype sig2 = SignPQ(key2, redeemScript, txTo, 0);
    valtype vchRedeem(redeemScript.begin(), redeemScript.end());

    CScript scriptSig = CScript() << sig2 << sig1 << vchRedeem;
    BOOST_CHECK(VerifyScript(scriptSig, scriptPubKey, txTo, 0, flagsAfterFork, 0));
    BOOST_CHECK_EQUAL(scriptPubKey.GetPQSigOpCount(scriptSig), 2U);

    // Both signatures are needed, in the right order
    BOOST_CHECK(!VerifyScript(CScript() << sig1 << sig2 << vchRedeem, scriptPubKey, txTo, 0, flagsAfterFork, 0));
    BOOST_CHECK(!VerifyScript(CScript() << valtype() << sig1 << vchRedeem, scriptPubKey, txTo, 0, flagsAfterFork, 0));
    BOOST_CHECK(!VerifyScript(CScript() << sig2 << valtype() << vchRedeem, scriptPubKey, txTo, 0, flagsAfterFork, 0));

    // A different redeem script does not match the hash
    CScript other = CScript() << key1.GetPubKey() << OP_CHECKSIGPQ;
    valtype vchOther(other.begin(), other.end());
    BOOST_CHECK(!VerifyScript(CScript() << SignPQ(key1, other, txTo, 0) << vchOther, scriptPubKey, txTo, 0, flagsAfterFork, 0));

    // scriptSig must be push only
    CScript scriptSigNotPush = CScript() << sig2 << sig1 << OP_NOP << vchRedeem;
    BOOST_CHECK(!VerifyScript(scriptSigNotPush, scriptPubKey, txTo, 0, flagsAfterFork, 0));

    // The keystore knows the script and the keys
    CBasicKeyStore keystore;
    BOOST_CHECK(keystore.AddCScript256(redeemScript));
    keystore.AddPQKey(key1);
    keystore.AddPQKey(key2);
    BOOST_CHECK(keystore.HaveCScript256(redeemScript.GetID256()));
}

BOOST_AUTO_TEST_CASE(pqfork_script_limits)
{
    // Pushes larger than 520 bytes only after the fork
    CScript script = CScript() << valtype(600, 1) << OP_DROP << OP_1;
    vector<valtype> stack;
    CTransaction tx;
    BOOST_CHECK(!EvalScript(stack, script, tx, 0, flagsBeforeFork, 0));
    stack.clear();
    BOOST_CHECK(EvalScript(stack, script, tx, 0, flagsAfterFork, 0));

    CScript huge = CScript() << valtype(MAX_SCRIPT_ELEMENT_SIZE_PQ + 1, 1) << OP_DROP << OP_1;
    stack.clear();
    BOOST_CHECK(!EvalScript(stack, huge, tx, 0, flagsAfterFork, 0));

    // OP_CHECKSIGPQ is an invalid opcode before the fork
    CPQKey key;
    key.MakeNewKey();
    CScript checksig = CScript() << valtype() << key.GetPubKey() << OP_CHECKSIGPQ << OP_NOT;
    stack.clear();
    BOOST_CHECK(!EvalScript(stack, checksig, tx, 0, flagsBeforeFork, 0));
    stack.clear();
    BOOST_CHECK(EvalScript(stack, checksig, tx, 0, flagsAfterFork, 0));
    BOOST_CHECK(!stack.empty() && CastToBool(stack.back()));

    // An invalid post-quantum public key fails the script
    CScript badkey = CScript() << valtype() << valtype(PQ_PUBKEY_SIZE, 2) << OP_CHECKSIGPQ << OP_NOT;
    stack.clear();
    BOOST_CHECK(!EvalScript(stack, badkey, tx, 0, flagsAfterFork, 0));

    // Post-quantum signature operations are counted separately
    CScript pqkeyhash = PQKeyHashScript(key);
    BOOST_CHECK_EQUAL(pqkeyhash.GetPQSigOpCount(), 1U);
    BOOST_CHECK_EQUAL(pqkeyhash.GetSigOpCount(false), 0U);
}

BOOST_AUTO_TEST_CASE(pqfork_quantum_safe_outputs)
{
    CPQKey pqkey;
    pqkey.MakeNewKey();
    CKey key;
    key.MakeNewKey(true);
    string reason;

    CTransaction tx;
    tx.vin.resize(1);
    tx.vout.resize(1);
    tx.vout[0].nValue = COIN;

    tx.vout[0].scriptPubKey = PQKeyHashScript(pqkey);
    BOOST_CHECK(CheckPQOutputs(tx, reason));
    tx.vout[0].scriptPubKey.SetDestination(CScriptID256(uint256(7)));
    BOOST_CHECK(CheckPQOutputs(tx, reason));
    tx.vout[0].scriptPubKey = CScript() << OP_RETURN << valtype(20, 1);
    BOOST_CHECK(CheckPQOutputs(tx, reason));
    tx.vout[0].SetEmpty();
    BOOST_CHECK(CheckPQOutputs(tx, reason));

    // An empty script with a value could be spent by anyone
    tx.vout[0].scriptPubKey = CScript();
    tx.vout[0].nValue = COIN;
    BOOST_CHECK(!CheckPQOutputs(tx, reason));

    // ECDSA and other legacy outputs
    tx.vout[0].scriptPubKey.SetDestination(key.GetPubKey().GetID());
    BOOST_CHECK(!CheckPQOutputs(tx, reason));
    BOOST_CHECK_EQUAL(reason, "output-not-quantum-safe");
    tx.vout[0].scriptPubKey = CScript() << key.GetPubKey() << OP_CHECKSIG;
    BOOST_CHECK(!CheckPQOutputs(tx, reason));
    tx.vout[0].scriptPubKey.SetDestination(CScriptID(uint160(7)));
    BOOST_CHECK(!CheckPQOutputs(tx, reason));
    tx.vout[0].scriptPubKey = CScript() << OP_1;
    BOOST_CHECK(!CheckPQOutputs(tx, reason));

    // One bad output makes the transaction invalid
    tx.vout.resize(2);
    tx.vout[0].scriptPubKey = PQKeyHashScript(pqkey);
    tx.vout[1].nValue = COIN;
    tx.vout[1].scriptPubKey.SetDestination(key.GetPubKey().GetID());
    BOOST_CHECK(!CheckPQOutputs(tx, reason));
}

// Proof-of-stake block skeleton whose coinstake pays to scriptStake
static CBlock StakeBlock(const CScript& scriptStake, unsigned int nTime)
{
    CBlock block;
    block.nTime = nTime;
    CTransaction coinbase;
    coinbase.nTime = nTime;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vout.resize(1);
    coinbase.vout[0].SetEmpty();
    CTransaction coinstake;
    coinstake.nTime = nTime;
    coinstake.vin.resize(1);
    coinstake.vin[0].prevout.hash = uint256(1);
    coinstake.vin[0].prevout.n = 0;
    coinstake.vout.resize(2);
    coinstake.vout[0].SetEmpty();
    coinstake.vout[1].nValue = 1000 * COIN;
    coinstake.vout[1].scriptPubKey = scriptStake;
    block.vtx.push_back(coinbase);
    block.vtx.push_back(coinstake);
    block.hashMerkleRoot = block.BuildMerkleTree();
    return block;
}

static valtype PQBlockSig(const CPQKey& key, const CBlock& block)
{
    valtype vchSig;
    BOOST_REQUIRE(key.Sign(block.GetHash(), vchSig, PQ_DOMAIN_BLOCK));
    valtype ret = key.GetPubKey().Raw();
    ret.insert(ret.end(), vchSig.begin(), vchSig.end());
    return ret;
}

BOOST_AUTO_TEST_CASE(pqfork_block_signature)
{
    SelectParams(CChainParams::MAIN);
    const unsigned int nForkTime = Params().PQForkTime();
    CPQKey key, key2;
    key.MakeNewKey();
    key2.MakeNewKey();

    CBlock block = StakeBlock(PQKeyHashScript(key), nForkTime);
    BOOST_REQUIRE(block.IsProofOfStake());
    block.vchBlockSig = PQBlockSig(key, block);
    BOOST_CHECK_EQUAL(block.vchBlockSig.size(), PQ_BLOCK_SIGNATURE_SIZE);
    BOOST_CHECK(block.CheckBlockSignature());

    // Signed by a different key than the coinstake pays to
    CBlock block2 = block;
    block2.vchBlockSig = PQBlockSig(key2, block2);
    BOOST_CHECK(!block2.CheckBlockSignature());

    // Signature with the transaction domain
    valtype vchSig;
    BOOST_REQUIRE(key.Sign(block.GetHash(), vchSig, PQ_DOMAIN_TX));
    CBlock block3 = block;
    block3.vchBlockSig = key.GetPubKey().Raw();
    block3.vchBlockSig.insert(block3.vchBlockSig.end(), vchSig.begin(), vchSig.end());
    BOOST_CHECK(!block3.CheckBlockSignature());

    // Modified signature, wrong size, empty
    CBlock block4 = block;
    block4.vchBlockSig.back() ^= 1;
    BOOST_CHECK(!block4.CheckBlockSignature());
    block4.vchBlockSig = block.vchBlockSig;
    block4.vchBlockSig.push_back(0);
    BOOST_CHECK(!block4.CheckBlockSignature());
    block4.vchBlockSig.clear();
    BOOST_CHECK(!block4.CheckBlockSignature());

    // The signature covers the block
    CBlock block5 = block;
    block5.nNonce++;
    BOOST_CHECK(!block5.CheckBlockSignature());

    // Block signing key hash in a nonspendable output (multisig staking)
    CBlock block6 = StakeBlock(CScript() << OP_RETURN << key.GetPubKey().GetID(), nForkTime);
    block6.vchBlockSig = PQBlockSig(key, block6);
    BOOST_CHECK(block6.CheckBlockSignature());
    CBlock block7 = StakeBlock(CScript() << OP_RETURN << key2.GetPubKey().GetID(), nForkTime);
    block7.vchBlockSig = PQBlockSig(key, block7);
    BOOST_CHECK(!block7.CheckBlockSignature());

    // After the fork an ECDSA staker can not sign blocks
    CKey ecdsa;
    ecdsa.MakeNewKey(true);
    CBlock block8 = StakeBlock(CScript() << ecdsa.GetPubKey() << OP_CHECKSIG, nForkTime);
    BOOST_REQUIRE(ecdsa.Sign(block8.GetHash(), block8.vchBlockSig));
    BOOST_CHECK(!block8.CheckBlockSignature());

    // ... while before the fork that is how blocks are signed
    CBlock block9 = StakeBlock(CScript() << ecdsa.GetPubKey() << OP_CHECKSIG, nForkTime - 16);
    BOOST_REQUIRE(ecdsa.Sign(block9.GetHash(), block9.vchBlockSig));
    BOOST_CHECK(block9.CheckBlockSignature());
}

BOOST_AUTO_TEST_CASE(pqfork_addresses)
{
    SelectParams(CChainParams::MAIN);
    CPQKey key;
    key.MakeNewKey();
    CPQKeyID keyID = key.GetPubKey().GetID();

    CBitcoinAddress addr(keyID);
    string str = addr.ToString();
    BOOST_CHECK_EQUAL(str.size(), 52U);
    BOOST_CHECK_EQUAL(str.substr(0, 2), "LQ");
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsPostQuantum());
    BOOST_CHECK(!addr.IsScript());

    CBitcoinAddress parsed(str);
    BOOST_CHECK(parsed.IsValid());
    BOOST_CHECK(parsed.Get() == CTxDestination(keyID));
    CPQKeyID keyID2;
    BOOST_CHECK(parsed.GetPQKeyID(keyID2) && keyID2 == keyID);
    CKeyID legacyID;
    BOOST_CHECK(!parsed.GetKeyID(legacyID));

    // A typo is detected
    string bad = str;
    bad[10] = (bad[10] == 'a') ? 'b' : 'a';
    BOOST_CHECK(!CBitcoinAddress(bad).IsValid());

    CBitcoinAddress script(CScriptID256(uint256(12345)));
    BOOST_CHECK_EQUAL(script.ToString().substr(0, 2), "LS");
    BOOST_CHECK(CBitcoinAddress(script.ToString()).IsScript());
    BOOST_CHECK(CBitcoinAddress(script.ToString()).IsPostQuantum());

    // Legacy addresses still work
    CKey ecdsa;
    ecdsa.MakeNewKey(true);
    CBitcoinAddress legacy(ecdsa.GetPubKey().GetID());
    BOOST_CHECK_EQUAL(legacy.ToString()[0], 'L');
    BOOST_CHECK(CBitcoinAddress(legacy.ToString()).IsValid());
    BOOST_CHECK(!CBitcoinAddress(legacy.ToString()).IsPostQuantum());

    // Post-quantum secrets
    CPQSecret secret(key);
    BOOST_CHECK_EQUAL(secret.ToString().substr(0, 2), "LK");
    CPQSecret secret2;
    BOOST_CHECK(secret2.SetString(secret.ToString()));
    CPQKey key2;
    BOOST_CHECK(secret2.GetKey(key2));
    BOOST_CHECK(key2.GetPubKey() == key.GetPubKey());
    BOOST_CHECK(!CPQSecret().SetString(str));

    // Testnet prefixes
    SelectParams(CChainParams::TESTNET);
    BOOST_CHECK_EQUAL(CBitcoinAddress(keyID).ToString().substr(0, 2), "TQ");
    BOOST_CHECK_EQUAL(CBitcoinAddress(CScriptID256(uint256(1))).ToString().substr(0, 2), "TS");
    BOOST_CHECK_EQUAL(CPQSecret(key).ToString().substr(0, 2), "TK");
    BOOST_CHECK(!CBitcoinAddress(str).IsValid()); // mainnet address on testnet
    SelectParams(CChainParams::MAIN);
}

// Exposes the protected encryption functions of CCryptoKeyStore
class CTestCryptoKeyStore : public CCryptoKeyStore
{
public:
    bool Encrypt(CKeyingMaterial& vMasterKey) { return EncryptKeys(vMasterKey); }
    bool UnlockWith(const CKeyingMaterial& vMasterKey) { return Unlock(vMasterKey); }
};

BOOST_AUTO_TEST_CASE(pqfork_encrypted_keystore)
{
    CTestCryptoKeyStore keystore;
    CPQKey key;
    key.MakeNewKey();
    CPQKeyID keyID = key.GetPubKey().GetID();
    BOOST_REQUIRE(keystore.AddPQKey(key));

    CKeyingMaterial vMasterKey(32, 0x5a);
    BOOST_REQUIRE(keystore.Encrypt(vMasterKey));
    BOOST_REQUIRE(keystore.Lock());

    // Locked: the public key is known, the private key is not
    CPQKey keyOut;
    CPQPubKey pubkeyOut;
    BOOST_CHECK(keystore.HavePQKey(keyID));
    BOOST_CHECK(keystore.GetPQPubKey(keyID, pubkeyOut) && pubkeyOut == key.GetPubKey());
    BOOST_CHECK(!keystore.GetPQKey(keyID, keyOut));
    CPQKey key2;
    key2.MakeNewKey();
    BOOST_CHECK(!keystore.AddPQKey(key2));

    // The wrong master key does not unlock
    CKeyingMaterial vWrongKey(32, 0x5b);
    BOOST_CHECK(!keystore.UnlockWith(vWrongKey));

    // Unlocked: the key decrypts to the original and new keys are encrypted
    BOOST_REQUIRE(keystore.UnlockWith(vMasterKey));
    BOOST_CHECK(keystore.GetPQKey(keyID, keyOut) && keyOut == key);
    BOOST_CHECK(keystore.AddPQKey(key2));
    BOOST_CHECK(keystore.GetPQKey(key2.GetPubKey().GetID(), keyOut) && keyOut == key2);
    set<CPQKeyID> setKeys;
    keystore.GetPQKeys(setKeys);
    BOOST_CHECK_EQUAL(setKeys.size(), 2U);
}

BOOST_AUTO_TEST_SUITE_END()
