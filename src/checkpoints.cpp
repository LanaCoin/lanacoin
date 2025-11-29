// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/foreach.hpp>

#include "checkpoints.h"

#include "txdb.h"
#include "main.h"
#include "uint256.h"


static const int nCheckpointSpan = 500;

namespace Checkpoints
{
    typedef std::map<int, uint256> MapCheckpoints;

    //
    // What makes a good checkpoint block?
    // + Is surrounded by blocks with reasonable timestamps
    //   (no blocks before with a timestamp after, none after with
    //    timestamp before)
    // + Contains no strange transactions
    //
    static MapCheckpoints mapCheckpoints =
        boost::assign::map_list_of
        ( 0,   uint256("0x0000095667f3c1fdbf0b9b4937be57c6401162fcfe72be373df27393f0c69d93") ) // genesis
        ( 50000,   uint256("0x38de11fd0ac1ef41a3fab6d5faac3e597c509244ad028dba20a12832f9b38e92") )
        ( 100000,   uint256("0x4d32d90e958c1060a8346dbcd72b96459bcc9ded1241d51f7b09be3eaf405901") )
        ( 150000,   uint256("0x3efea69afbdfaab1a9e2d1240a014aa7c88c66cf246107febbe0d2db147e7350") )
        ( 200000,   uint256("0xf0bb302a774b841e03d3818f980ecb0c1354f7ff048ff2dc004c3003178c3d56") )
        ( 250000,   uint256("0xa7325d458200a636d20f3be182d2121acb725de486adf1f855cb72ea9203f56d") )
        ( 300000,   uint256("0x3c536e6c98d1eb54610a7133d671f560627d731aaef8a46db35335255217d2eb") )
        ( 330000,   uint256("0xbc45b022e71c2c83765009426a5a54db7e6fa4f94d3ee53e1418a54388529b95") )
        ( 360000,   uint256("0x103c1ee3cf53529a1bee0bfdff21a32bec361c668df6f7bfc3665d84cbad394d") )
        ( 423000,   uint256("0x00000000000000940d7a26bfaf12ac74bcefb22ff231560b805deac6728917fc") )
        ( 451000,   uint256("0x66e23ed10acad88fe2b81c3e31d510dd37ee351c217c5c1a2146bcab754e89cc") )
        ( 472737,   uint256("0x2b306a5c48b16fd7fd84017ef6a9df4da86bb9871bf8a015a74044d41ec84aaa") )
        ( 482666,   uint256("0x9291b42d4b06da001a471a306888c0a58329b812ed26509129e0231545d7a93a") )
        ( 499888,   uint256("0xe9c977ab38ce0d47dc222e078ad71a548c67425d563d79d8f25247eaf6457e1c") )
        ( 511111,   uint256("0xf2e9623e0efe8fe23687126cb5cb7588584407e89121fa238d7729af38366de7") )
        ( 523000,   uint256("0x0000000000000114b08260c1c94752710bdfd6bb415f6e4ff7d071e0a8c1797b") )
        ( 525600,   uint256("0xdba6cc2f5ab9621386dbef5f9343096923f50e47536eda4cc18418a48bb5ac67") )
        ( 543395,   uint256("0x2ef14111409247ab85c8c3ace85333eefcb0590fadeb28a7e79217a4df43e749") )
        ( 560377,   uint256("0x484e5af078c27931f29ddc6a905619fffce13c65ef59a1d37d5c81dcd2dbbb76") )
        ( 605960,   uint256("0x00000000000001b66d1b283d9da527e603a456bd3645ae35f0f4101c84c0de20") )
        ( 644980,   uint256("0x00000000000000263fd4d52a9ad9fdcec5a047933595177781cdf7af937e3227") )
        ( 701668,   uint256("0x559f48d675a6b8c044fe0d97c9accd28e65244f5af660b5d0739abac9d98d70a") )
        ( 753126,   uint256("0xb0e94bd3bdc75d54281a1ab3e505ad389883014eac1fe0325a62f120a5795e26") )
        ( 761509,   uint256("0x8473cde785fa630903e449dfe942c6d0ccc288da0275a223f3916b0d9ab3cd29") )
        ( 772666,   uint256("0x9552fa63985dd40ad3b53279b4148a216df4da1132dc841e065ffe11df0fa00a") )
        ( 794843,   uint256("0x8ec218b0cb65242084ea136e46363d7aa5807136ebaac9db7273f72eaae9da95") )
        ( 813320,   uint256("0x27a3ab50a2f3c690474c3d13f38ce0da7adbd5572b986884840f9c3fe83201dd") )
        ( 876046,   uint256("0x937e01133e1ad0ac7152fc209004bc65ca2c81c48ca89611e92d715f111a91d3") )
        ( 919651,   uint256("0xda3f65e03f0e0df1fa61060afd3bd15a9e0b36e3dfee09096e0277392fa1ee9b") )
        ( 948330,   uint256("0x680909e4dba3a41fb99479bf09dba407faa718d369f225d7a62960b8bf58dced") )
        ( 1000000,   uint256("0x070f9a6921a7bfe8b07bef892755107742293bf5ae3c793292212b4db165a1f3") )
    ;

    // TestNet has no checkpoints
    static MapCheckpoints mapCheckpointsTestnet;

    bool CheckHardened(int nHeight, const uint256& hash)
    {
        MapCheckpoints& checkpoints = (TestNet() ? mapCheckpointsTestnet : mapCheckpoints);

        MapCheckpoints::const_iterator i = checkpoints.find(nHeight);
        if (i == checkpoints.end()) return true;
        return hash == i->second;
    }

    int GetTotalBlocksEstimate()
    {
        MapCheckpoints& checkpoints = (TestNet() ? mapCheckpointsTestnet : mapCheckpoints);

        if (checkpoints.empty())
            return 0;
        return checkpoints.rbegin()->first;
    }

    CBlockIndex* GetLastCheckpoint(const std::map<uint256, CBlockIndex*>& mapBlockIndex)
    {
        MapCheckpoints& checkpoints = (TestNet() ? mapCheckpointsTestnet : mapCheckpoints);

        BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type& i, checkpoints)
        {
            const uint256& hash = i.second;
            std::map<uint256, CBlockIndex*>::const_iterator t = mapBlockIndex.find(hash);
            if (t != mapBlockIndex.end())
                return t->second;
        }
        return NULL;
    }

    // Automatically select a suitable sync-checkpoint
    const CBlockIndex* AutoSelectSyncCheckpoint()
    {
        const CBlockIndex *pindex = pindexBest;
        // Search backward for a block within max span and maturity window
        while (pindex->pprev && pindex->nHeight + nCheckpointSpan > pindexBest->nHeight)
            pindex = pindex->pprev;
        return pindex;
    }

    // Check against synchronized checkpoint
    bool CheckSync(int nHeight)
    {
        const CBlockIndex* pindexSync = AutoSelectSyncCheckpoint();

        if (nHeight <= pindexSync->nHeight)
            return false;
        return true;
    }
}
