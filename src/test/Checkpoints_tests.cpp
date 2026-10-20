//
// Unit tests for block-chain checkpoints
//
#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/test/unit_test.hpp>
#include <boost/foreach.hpp>

#include "../checkpoints.h"
#include "../util.h"

using namespace std;

BOOST_AUTO_TEST_SUITE(Checkpoints_tests)

BOOST_AUTO_TEST_CASE(sanity)
{
    uint256 p50000 = uint256("0x38de11fd0ac1ef41a3fab6d5faac3e597c509244ad028dba20a12832f9b38e92");
    uint256 p100000 = uint256("0x4d32d90e958c1060a8346dbcd72b96459bcc9ded1241d51f7b09be3eaf405901");
    BOOST_CHECK(Checkpoints::CheckHardened(50000, p50000));
    BOOST_CHECK(Checkpoints::CheckHardened(100000, p100000));

    
    // Wrong hashes at checkpoints should fail:
    BOOST_CHECK(!Checkpoints::CheckHardened(50000, p100000));
    BOOST_CHECK(!Checkpoints::CheckHardened(100000, p50000));

    // ... but any hash not at a checkpoint should succeed:
    BOOST_CHECK(Checkpoints::CheckHardened(50000+1, p100000));
    BOOST_CHECK(Checkpoints::CheckHardened(100000+1, p50000));

    BOOST_CHECK(Checkpoints::GetTotalBlocksEstimate() >= 100000);
}    

BOOST_AUTO_TEST_SUITE_END()
