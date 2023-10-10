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

#include <time.h>

#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/base/basic/console_color.hpp>
#include <list>
#include <map>
#include <string>

namespace hotplace {
namespace io {

/**
 * @brief   unit test
 * @desc
 *  report example
 *    part of pseudo code
 *      int main (void)
 *      {
 *          test_case _test_case;
 *          _test_case.begin ("test case 1");
 *          _test_case.test (return_code, __FUNCTION__, "case 1 desc1");
 *          _test_case.test (return_code, __FUNCTION__, "case 1 desc2");
 *          _test_case.begin ("test case 2");
 *          _test_case.test (return_code, __FUNCTION__, "case 2 desc1");
 *          _test_case.test (return_code, __FUNCTION__, "case 2 desc2");
 *          _test_case.report ();
 *          return _test_case.result ();
 *      }
 *    part of report
 *      test case 1 | passfail
 *      passfail | errorcode | function | time | case 1 desc1
 *      passfail | errorcode | function | time | case 1 desc2
 *      test case 2 | passfail
 *      passfail | errorcode | function | time | case 2 desc1
 *      passfail | errorcode | function | time | case 2 desc2
 *      success / fail
 *
 *  time check
 *    case1
 *      test_case _test_case;   // reset
 *      _test_case.test (..);   // check time
 *    case2
 *      test_case _test_case;   // reset
 *      _test_case.begin (...); // reset, same in start method
 *      _test_case.test (..);   // check time, same in assert method
 *    case3
 *      test_case _test_case;   // reset
 *      _test_case.begin (...); // reset, same in start method
 *      _test_case.assert (..); // check time, same in assert method
 */
class test_case {
   public:
    test_case();
    /**
     * @brief   test group
     * @param   const char* case_name [in]
     * @desc    reset stopwatch
     */
    void begin(const char* case_name, ...);
    /**
     * @brief   reset timer
     * @desc    to capture first unittest-time in thread, call reset_time at each thread startup code
     */
    void reset_time();
    /**
     * @brief   pause timer
     */
    void pause_time();
    /**
     * @brief   resume timer
     */
    void resume_time();
    /**
     * @brief   test
     * @param   bool expect [in]
     * @param   const char* test_function [in]
     * @param   const char* message [inopt]
     * @desc    check result and time
     */
    void assert(bool expect, const char* test_function, const char* message, ...);
    /**
     * @brief   test
     * @param   return_t result [in]
     * @param   const char* test_function [in]
     * @param   const char* message [inopt]
     * @desc    check result and time
     */
    void test(return_t result, const char* test_function, const char* message, ...);
    /**
     * @brief   report
     * @param   uint32 top_count [inopt] oder by test-time, and list top
     */
    void report(uint32 top_count = -1);
    /**
     * @brief   result indicator
     * @return
     *          errorcode_t::internal_error
     *          errorcode_t::success
     */
    return_t result();

    typedef struct _unittest_item_t {
        uint32 _result;
        std::string _test_function;
        std::string _message;
        struct timespec _time;

        _unittest_item_t() : _result(0) {
            // do nothing
        }
    } unittest_item_t;
    typedef std::list<unittest_item_t> unittest_list_t;
    typedef struct _test_stat_t {
        uint32 _count_success;
        uint32 _count_fail;
        uint32 _count_not_supported;
        uint32 _count_low_security;
        _test_stat_t() : _count_success(0), _count_fail(0), _count_not_supported(0), _count_low_security(0) {
            // do nothing
        }
    } test_stat_t;
    typedef struct _test_status_t {
        unittest_list_t _test_list;
        test_stat_t _test_stat;

        _test_status_t() {
            // do nothing
        }
    } test_status_t;

    typedef std::list<std::string> unittest_index_t;             /* ordered test cases */
    typedef std::map<std::string, test_status_t> unittest_map_t; /* pair (test case, test_status_t) */
    typedef std::pair<unittest_map_t::iterator, bool> unittest_map_pib_t;

    typedef std::list<struct timespec> time_slice_t;
    typedef std::map<arch_t, std::string> testcase_per_thread_t;
    typedef std::map<arch_t, bool> time_flag_per_thread_t;
    typedef std::map<arch_t, struct timespec> timestamp_per_thread_t;
    typedef std::map<arch_t, time_slice_t> time_slice_per_thread_t;

    typedef std::pair<time_slice_t::iterator, bool> time_slice_pib_t;
    typedef std::pair<testcase_per_thread_t::iterator, bool> testcase_per_thread_pib_t;
    typedef std::pair<time_flag_per_thread_t::iterator, bool> time_flag_per_thread_pib_t;
    typedef std::pair<timestamp_per_thread_t::iterator, bool> timestamp_per_thread_pib_t;
    typedef std::pair<time_slice_per_thread_t::iterator, bool> time_slice_per_thread_pib_t;

   protected:
    void report_unittest(ansi_string& stream);
    void report_testtime(ansi_string& stream, uint32 top_count = -1);

    void dump_list_into_stream(unittest_list_t& array, ansi_string& stream);

    void check_time(struct timespec& time);

   private:
    critical_section _lock;
    console_color _concolor;
    unittest_index_t _test_list;
    unittest_map_t _test_map;
    test_stat_t _total;

    testcase_per_thread_t _testcase_per_threads;
    time_flag_per_thread_t _time_flag_per_threads;
    timestamp_per_thread_t _timestamp_per_threads;
    time_slice_per_thread_t _time_slice_per_threads;
};

/**
 * @example
 *  // as-is
 *      _test_case.pause_time ();
 *      // do not count time this code block
 *      _test_case.resume_time ();
 *  // replace
 *      {
 *          test_case_notimecheck block (_test_case);
 *          // do not count time this code block
 *      }
 */
class test_case_notimecheck {
   public:
    test_case_notimecheck(test_case& tc) {
        tc.pause_time();
        _tc = &tc;
    }
    ~test_case_notimecheck() { _tc->resume_time(); }
    test_case* _tc;
};

}  // namespace io
}  // namespace hotplace

#endif
