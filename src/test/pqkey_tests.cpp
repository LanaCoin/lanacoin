#include <boost/test/unit_test.hpp>

#include <string.h>
#include <string>
#include <vector>

#include <openssl/sha.h>

#include "pqkey.h"
#include "util.h"

extern "C" {
#include "mldsa44/api.h"
}

using namespace std;

static string SHA256Hex(const unsigned char *data, size_t len)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data, len, hash);
    return HexStr(hash, hash + sizeof(hash));
}

static uint256 Uint256FromBytes(const vector<unsigned char> &v)
{
    uint256 ret;
    BOOST_REQUIRE(v.size() == 32);
    memcpy(&ret, &v[0], 32);
    return ret;
}

// NIST ACVP ML-DSA-44 keyGen vectors (seed, SHA-256 of pk, SHA-256 of sk)
static const char *vKeyGen[][3] = {
    {"93ef2e6ef1fb08999d142abe0295482370d3f43bdb254a78e2b0d5168eca065f", "6995b20ecd5cde41719035028a712ccf35b1adf53b913030423d9d6fa188d673", "16a35d4b59f932aeada987dc689b075add0df57b4815bb103be7443ee3c1c561"},
    {"d6a5d2325b94ca1b993a0151e24ab95b396f415831dc14a08404820ae58a2ad1", "51bced8954e17da402e93fc5275f723aed1b9101bdf4fac5afc2b5c227d9e674", "7b1145d3514f394295a88cc96f90a3125602b51b18cd118478194ac1e97d34f0"},
    {"8a5e79b82dc81553bbe821ee367f0adfa54f59a3e8a71ca626f873f638636dd7", "190ba0b968c4fc62435a5269c72a81bfdcfa1531f95abed1c03be42733c9620d", "7235a6c9e4c2a8b33838dbf352059b957e66413093b4ffeb77a1ec0ad9bd93bd"},
    {"6137cab1dbf57a5cfcd0079ba87faf2c7141ebb92dabbd45fd8b478d24ab8946", "820f4546691b68c62f09f496d1613dd37dce3348bda09a36add4865c6da9e683", "bfcbe064066b07139237ff0de68a661c4ccb1db6c34c7e006e63a922fb54ccd1"},
};

// Signatures with the LanaCoin domain contexts, from an independent ML-DSA
// implementation: seed, message hash, domain, signing randomness,
// SHA-256 of the public key, SHA-256 of the signature
struct PQSignVector {
    const char *seed, *msg;
    int domain;
    const char *rnd, *pkhash, *sighash;
};
static const PQSignVector vSign[] = {
    {"df3a4d897ec32aaa924214f1069f94be4903b3bfe91282d60cea2b45029e8b0c", "904664d5e87ed5c206fee27e08a47f6c91aa9dc0df515d5bbaf45119dc573944", 0, "0000000000000000000000000000000000000000000000000000000000000000", "60bfc4ca6430a9240a85b7c5b81b0791823d86dec1f8cdb5388e6877be226503", "c441b15e7e4d451f2b8ccd7a012b39f3203388bfbc32b96530cd91ff8558b370"},
    {"505f0031690e39e06f1bb44b8befeccf95151543ed917004f7369c068e240f61", "550a99c59b97e9f01a09ad0cdcb529b3040fb8bbeab437240c365f5adbe1cb25", 1, "e2f350ed44f87ff2512aa7029e678a9a2cfe40b694e98857f663969a473ffdcd", "32f790230a71c995de0ca09eba7558d5ee5fe0175c61951eb0168aed827499b1", "1cd1e72916677f93d46427106e6fca8ee2544d46350a424d1243d2ea0aa18992"},
    {"34756fa38bacac8a6dd096580d2a70f6fd8cc77c5ba44eae7179f940ead78532", "1a957e7817aab907e1ffa8191317f4141da6164a42f7fe8df0001726d61da2c9", 2, "d598bd55e3ba56e90c536c139fce050216a709622c213cf59198088d3a162e69", "4c28943b5305d93663522c79646cd61dc31434542683a94f223b438db9bf7faf", "58bfefe3e71b2b14c1c0304b53d4c8a8d7115bcdca3e1c4b98266face1654ede"},
};

BOOST_AUTO_TEST_SUITE(pqkey_tests)

BOOST_AUTO_TEST_CASE(mldsa44_acvp_keygen)
{
    for (unsigned int i = 0; i < sizeof(vKeyGen) / sizeof(vKeyGen[0]); i++)
    {
        vector<unsigned char> seed = ParseHex(vKeyGen[i][0]);
        unsigned char pk[MLDSA44_PUBLICKEY_SIZE], sk[MLDSA44_SECRETKEY_SIZE];
        BOOST_CHECK(PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair_seed(pk, sk, &seed[0]) == 0);
        BOOST_CHECK_EQUAL(SHA256Hex(pk, sizeof(pk)), vKeyGen[i][1]);
        BOOST_CHECK_EQUAL(SHA256Hex(sk, sizeof(sk)), vKeyGen[i][2]);

        // CPQKey derives the same public key from the seed
        CPQKey key;
        BOOST_CHECK(key.Set(&seed[0], &seed[0] + seed.size()));
        BOOST_CHECK(key.GetPubKey().IsValid());
        BOOST_CHECK(key.GetPubKey().Raw()[0] == PQ_ALGO_MLDSA44);
        BOOST_CHECK(memcmp(key.GetPubKey().begin() + 1, pk, sizeof(pk)) == 0);
    }
}

BOOST_AUTO_TEST_CASE(mldsa44_known_signatures)
{
    for (unsigned int i = 0; i < sizeof(vSign) / sizeof(vSign[0]); i++)
    {
        const PQSignVector &v = vSign[i];
        vector<unsigned char> seed = ParseHex(v.seed);
        vector<unsigned char> rnd = ParseHex(v.rnd);
        uint256 hash = Uint256FromBytes(ParseHex(v.msg));
        PQSigDomain domain = (PQSigDomain)v.domain;

        CPQKey key;
        BOOST_REQUIRE(key.Set(&seed[0], &seed[0] + seed.size()));
        const CPQPubKey &pubkey = key.GetPubKey();
        BOOST_CHECK_EQUAL(SHA256Hex(pubkey.begin() + 1, pubkey.size() - 1), v.pkhash);

        vector<unsigned char> sig;
        BOOST_REQUIRE(key.SignWithRandomness(hash, sig, domain, &rnd[0]));
        BOOST_CHECK_EQUAL(sig.size(), PQ_SIGNATURE_SIZE);
        BOOST_CHECK_EQUAL(SHA256Hex(&sig[0], sig.size()), v.sighash);
        BOOST_CHECK(pubkey.Verify(hash, sig, domain));

        // A signature is only valid for the domain it was made for
        for (int d = PQ_DOMAIN_TX; d <= PQ_DOMAIN_MESSAGE; d++)
            if (d != v.domain)
                BOOST_CHECK(!pubkey.Verify(hash, sig, (PQSigDomain)d));
    }
}

BOOST_AUTO_TEST_CASE(pqkey_sign_verify)
{
    CPQKey key, key2;
    key.MakeNewKey();
    key2.MakeNewKey();
    BOOST_CHECK(key.IsValid() && key2.IsValid());
    BOOST_CHECK(!(key == key2));
    const CPQPubKey &pubkey = key.GetPubKey();
    BOOST_CHECK(pubkey.IsValid());
    BOOST_CHECK_EQUAL(pubkey.size(), PQ_PUBKEY_SIZE);
    BOOST_CHECK(pubkey.GetID() == Hash(pubkey.Raw().begin(), pubkey.Raw().end()));

    for (int n = 0; n < 8; n++)
    {
        uint256 hash = GetRandHash();
        vector<unsigned char> sig, sig2;
        BOOST_REQUIRE(key.Sign(hash, sig, PQ_DOMAIN_TX));
        BOOST_CHECK(pubkey.Verify(hash, sig, PQ_DOMAIN_TX));

        // Hedged signing: signing twice gives different, valid signatures
        BOOST_REQUIRE(key.Sign(hash, sig2, PQ_DOMAIN_TX));
        BOOST_CHECK(sig != sig2);
        BOOST_CHECK(pubkey.Verify(hash, sig2, PQ_DOMAIN_TX));

        // Wrong key, hash, domain or a modified signature must fail
        BOOST_CHECK(!key2.GetPubKey().Verify(hash, sig, PQ_DOMAIN_TX));
        uint256 hash2 = hash;
        hash2 ^= uint256(1);
        BOOST_CHECK(!pubkey.Verify(hash2, sig, PQ_DOMAIN_TX));
        BOOST_CHECK(!pubkey.Verify(hash, sig, PQ_DOMAIN_BLOCK));
        vector<unsigned char> bad = sig;
        bad[GetRand(bad.size())] ^= 1 << GetRand(8);
        BOOST_CHECK(!pubkey.Verify(hash, bad, PQ_DOMAIN_TX));
        bad = sig;
        bad.pop_back();
        BOOST_CHECK(!pubkey.Verify(hash, bad, PQ_DOMAIN_TX));
        bad = sig;
        bad.push_back(0);
        BOOST_CHECK(!pubkey.Verify(hash, bad, PQ_DOMAIN_TX));
        BOOST_CHECK(!pubkey.Verify(hash, vector<unsigned char>(), PQ_DOMAIN_TX));
    }
}

BOOST_AUTO_TEST_CASE(pqkey_invalid)
{
    // Wrong seed size
    unsigned char seed[33] = {0};
    CPQKey key;
    BOOST_CHECK(!key.Set(seed, seed + 31));
    BOOST_CHECK(!key.Set(seed, seed + 33));
    BOOST_CHECK(!key.IsValid());
    vector<unsigned char> sig;
    BOOST_CHECK(!key.Sign(uint256(1), sig, PQ_DOMAIN_TX));

    // Public keys with an unknown algorithm or the wrong size are invalid
    CPQKey good;
    good.MakeNewKey();
    BOOST_REQUIRE(good.Sign(uint256(1), sig, PQ_DOMAIN_TX));
    vector<unsigned char> raw = good.GetPubKey().Raw();
    raw[0] = 0x02;
    BOOST_CHECK(!CPQPubKey(raw).IsValid());
    BOOST_CHECK(!CPQPubKey(raw).Verify(uint256(1), sig, PQ_DOMAIN_TX));
    raw = good.GetPubKey().Raw();
    raw.pop_back();
    BOOST_CHECK(!CPQPubKey(raw).IsValid());
    BOOST_CHECK(!CPQPubKey().IsValid());
}

BOOST_AUTO_TEST_SUITE_END()
