/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.08.15   Soo Han, Kim        elapsed time
 */

#ifndef __HOTPLACE_SDK_TEST_UNITEST_TESTCASE__
#define __HOTPLACE_SDK_TEST_UNITEST_TESTCASE__

#include <hotplace/sdk/base.hpp>
#include <list>
#include <map>
#include <string>
#include <time.h>

namespace hotplace {
namespace test {

class test_case
{
public:
    test_case ();
    void begin (const char* case_name, const char* file_path = nullptr);
    void start ();
    void assert (bool expect, const char* test_function, const char* message = nullptr);
    void test (return_t result, const char* test_function, const char* message = nullptr);
    void report ();
    return_t result ();

private:
    typedef struct _unittest_item_t {
        uint32 _result;
        std::string _test_function;
        std::string _message;
        struct timespec _time;

        _unittest_item_t ()
            : _result (0)
        {
        }
    } unittest_item_t;
    typedef std::list<unittest_item_t> unittest_list_t;
    typedef struct _test_status_t {
        uint32 _count_success;
        uint32 _count_fail;
        uint32 _count_not_supported;
        uint32 _count_low_security;
        unittest_list_t _test_list;

        _test_status_t ()
            : _count_success (0),
            _count_fail (0),
            _count_not_supported (0),
            _count_low_security (0)
        {
        }
    } test_status_t;
    typedef std::map<std::string, test_status_t> unittest_map_t;    /* test case to test_status_t */
    typedef std::map<std::string, std::string> unittest_file_t;     /* test case to file path */

    critical_section _lock;
    unittest_map_t _test_map;
    unittest_file_t _test_file;
    uint32 _count_success;
    uint32 _count_fail;
    uint32 _count_not_supported;
    uint32 _count_low_security;
    std::string _current_case_name;
    std::string _current_file_path;

    struct timespec _timestamp;
};

}
}  // namespace

#endif
