#include <boost/test/unit_test.hpp>

#include <string.h>
#include <vector>

#include "crypter.h"
#include "key.h"
#include "script.h"
#include "util.h"

using namespace std;

// Exposes the protected encryption functions of CCryptoKeyStore
class CCryptoKeyStoreForTest : public CCryptoKeyStore
{
public:
    bool Encrypt(CKeyingMaterial& vMasterKey) { return EncryptKeys(vMasterKey); }
    bool UnlockWith(const CKeyingMaterial& vMasterKey) { return Unlock(vMasterKey); }
};

BOOST_AUTO_TEST_SUITE(crypter_tests)

BOOST_AUTO_TEST_CASE(crypter_encrypt_decrypt)
{
    // Wallet master key derivation from a passphrase, as in encryptwallet
    SecureString strPassphrase("correct horse battery staple");
    vector<unsigned char> vchSalt(WALLET_CRYPTO_SALT_SIZE, 0x11);
    CCrypter crypter;
    BOOST_REQUIRE(crypter.SetKeyFromPassphrase(strPassphrase, vchSalt, 25000, 0));

    for (unsigned int nSize = 0; nSize < 70; nSize++)
    {
        CKeyingMaterial vchPlaintext(nSize);
        for (unsigned int i = 0; i < nSize; i++)
            vchPlaintext[i] = (unsigned char)(i * 7 + nSize);

        vector<unsigned char> vchCiphertext;
        BOOST_REQUIRE(crypter.Encrypt(vchPlaintext, vchCiphertext));
        BOOST_CHECK_EQUAL(vchCiphertext.size(), (nSize / 16 + 1) * 16U);
        if (nSize > 0)
            BOOST_CHECK(memcmp(&vchCiphertext[0], &vchPlaintext[0], min((size_t)nSize, vchCiphertext.size())) != 0);

        CKeyingMaterial vchDecrypted;
        BOOST_REQUIRE(crypter.Decrypt(vchCiphertext, vchDecrypted));
        BOOST_CHECK(vchDecrypted == vchPlaintext);
    }

    // A different passphrase does not decrypt
    CCrypter crypter2;
    BOOST_REQUIRE(crypter2.SetKeyFromPassphrase(SecureString("wrong"), vchSalt, 25000, 0));
    CKeyingMaterial vchSecret(32, 0x42);
    vector<unsigned char> vchCiphertext;
    BOOST_REQUIRE(crypter.Encrypt(vchSecret, vchCiphertext));
    CKeyingMaterial vchDecrypted;
    BOOST_CHECK(!crypter2.Decrypt(vchCiphertext, vchDecrypted) || vchDecrypted != vchSecret);
}

BOOST_AUTO_TEST_CASE(crypter_keystore)
{
    CCryptoKeyStoreForTest keystore;
    CKey key;
    key.MakeNewKey(true);
    CKeyID keyID = key.GetPubKey().GetID();
    BOOST_REQUIRE(keystore.AddKey(key));

    // encryptwallet: encrypt the keys with the master key and lock
    CKeyingMaterial vMasterKey(32, 0x5a);
    BOOST_REQUIRE(keystore.Encrypt(vMasterKey));
    BOOST_REQUIRE(keystore.Lock());
    BOOST_CHECK(keystore.IsCrypted());
    BOOST_CHECK(keystore.IsLocked());

    CKey keyOut;
    CPubKey pubkeyOut;
    BOOST_CHECK(keystore.HaveKey(keyID));
    BOOST_CHECK(keystore.GetPubKey(keyID, pubkeyOut) && pubkeyOut == key.GetPubKey());
    BOOST_CHECK(!keystore.GetKey(keyID, keyOut));

    // walletpassphrase: only the right master key unlocks
    CKeyingMaterial vWrongKey(32, 0x5b);
    BOOST_CHECK(!keystore.UnlockWith(vWrongKey));
    BOOST_CHECK(keystore.IsLocked());
    BOOST_REQUIRE(keystore.UnlockWith(vMasterKey));
    BOOST_CHECK(!keystore.IsLocked());
    BOOST_CHECK(keystore.GetKey(keyID, keyOut));
    BOOST_CHECK(keyOut.GetPubKey() == key.GetPubKey());

    // New keys are stored encrypted
    CKey key2;
    key2.MakeNewKey(true);
    BOOST_CHECK(keystore.AddKey(key2));
    BOOST_CHECK(keystore.GetKey(key2.GetPubKey().GetID(), keyOut));
    BOOST_CHECK(keyOut.GetPubKey() == key2.GetPubKey());
}

BOOST_AUTO_TEST_SUITE_END()
