#define BOOST_TEST_MODULE Lanacoin Test Suite
#include <boost/test/unit_test.hpp>
#include <boost/filesystem.hpp>
#include <boost/preprocessor/stringize.hpp>

#include <fstream>

#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_utils.h"

#include "db.h"
#include "main.h"
#include "wallet.h"
#include "util.h"
#include "ui_interface.h"

#include "init.h"

extern void noui_connect();

struct TestingSetup {
    boost::filesystem::path pathTemp;

    TestingSetup() {
        fPrintToDebugLog = false; // don't want to write to debug.log file
        noui_connect();
        bitdb.MakeMock();
        pathTemp = boost::filesystem::temp_directory_path() / strprintf("test_lanacoin_%lu_%i", (unsigned long)GetTime(), (int)(GetRand(100000)));
        boost::filesystem::create_directories(pathTemp);
        mapArgs["-datadir"] = pathTemp.string();
        bool fFirstRun;
        pwalletMain = new CWallet("wallet.dat");
        pwalletMain->LoadWallet(fFirstRun);
        RegisterWallet(pwalletMain);
    }
    ~TestingSetup()
    {
        delete pwalletMain;
        pwalletMain = NULL;
        bitdb.Flush(true);
        boost::filesystem::remove_all(pathTemp);
    }
};

BOOST_GLOBAL_FIXTURE(TestingSetup);

// Read a JSON test vector file from test/data
json_spirit::Array read_json(const std::string& filename)
{
    namespace fs = boost::filesystem;
    fs::path testFile = fs::current_path() / "test" / "data" / filename;
#ifdef TEST_DATA_DIR
    if (!fs::exists(testFile))
        testFile = fs::path(BOOST_PP_STRINGIZE(TEST_DATA_DIR)) / filename;
#endif
    std::ifstream ifs(testFile.string().c_str(), std::ifstream::in);
    json_spirit::Value v;
    if (!json_spirit::read_stream(ifs, v))
    {
        if (ifs.fail())
            BOOST_ERROR("Cound not find/open " << filename);
        else
            BOOST_ERROR("JSON syntax error in " << filename);
        return json_spirit::Array();
    }
    if (v.type() != json_spirit::array_type)
    {
        BOOST_ERROR(filename << " does not contain a json array");
        return json_spirit::Array();
    }
    return v.get_array();
}
