#include <boost/test/unit_test.hpp>

#include "main.h"

BOOST_AUTO_TEST_SUITE(reward_tests)

static int64_t FixedStakeReward(int nPrevHeight)
{
    CBlockIndex index;
    index.nHeight = nPrevHeight;
    return GetProofOfStakeReward(&index, 0, 0);
}

BOOST_AUTO_TEST_CASE(stake_reward_halving)
{
    // The fixed part of the stake reward halves every 525600 blocks,
    // based on the height of the block's parent: block 525601 is the
    // first one with the halved reward
    BOOST_CHECK_EQUAL(FixedStakeReward(750000), 1000 * COIN / 2);
    BOOST_CHECK_EQUAL(FixedStakeReward(525600), 1000 * COIN / 2);
    BOOST_CHECK_EQUAL(FixedStakeReward(525599), 1000 * COIN);
    BOOST_CHECK_EQUAL(FixedStakeReward(1051200), 1000 * COIN / 4);
    BOOST_CHECK_EQUAL(FixedStakeReward(1051199), 1000 * COIN / 2);
    BOOST_CHECK_EQUAL(FixedStakeReward(525600 * 64), 0);

    // Must not depend on the current tip
    CBlockIndex* pindexBestSaved = pindexBest;
    CBlockIndex tip;
    tip.nHeight = 2000000;
    pindexBest = &tip;
    BOOST_CHECK_EQUAL(FixedStakeReward(750000), 1000 * COIN / 2);
    pindexBest = pindexBestSaved;
}

BOOST_AUTO_TEST_SUITE_END()
