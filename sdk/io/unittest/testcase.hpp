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

#ifndef __HOTPLACE_SDK_IO_UNITEST_TESTCASE__
#define __HOTPLACE_SDK_IO_UNITEST_TESTCASE__

#include <hotplace/sdk/base.hpp>
#include <list>
#include <map>
#include <string>
#include <time.h>

namespace hotplace {
namespace io {

class test_case
{
public:
    test_case ();
    void begin (const char* case_name, ...);
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
    typedef std::list<unittest_item_t> unittest_result_t;
    typedef struct _test_status_t {
        uint32 _count_success;
        uint32 _count_fail;
        uint32 _count_not_supported;
        uint32 _count_low_security;
        unittest_result_t _test_results;

        _test_status_t ()
            : _count_success (0),
            _count_fail (0),
            _count_not_supported (0),
            _count_low_security (0)
        {
        }
    } test_status_t;
    typedef std::list<std::string> unittest_index_t;                /* ordered test cases */
    typedef std::map<std::string, test_status_t> unittest_map_t;    /* pair (test case, test_status_t) */

    critical_section _lock;
    unittest_index_t _test_list;
    unittest_map_t _test_map;

    uint32 _count_success;
    uint32 _count_fail;
    uint32 _count_not_supported;
    uint32 _count_low_security;

    std::string _current_case_name;

    struct timespec _timestamp;
};

}
}  // namespace

#endif
