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

#include <hotplace/sdk/io/basic/console_color.hpp>
#include <hotplace/sdk/io/stream/string.hpp>
#include <hotplace/sdk/io/string/string.hpp>
#include <hotplace/sdk/io/system/datetime.hpp>
#include <hotplace/sdk/io/unittest/testcase.hpp>
#include <fstream>
#include <iostream>

namespace hotplace {
namespace io {

test_case::test_case ()
{
    reset_time ();
}

void test_case::begin (const char* case_name, ...)
{
    if (nullptr != case_name) {
        console_color col;
        ansi_string stream;

        va_list ap;
        va_start (ap, case_name);
        stream.vprintf (case_name, ap);
        va_end (ap);

        _current_case_name = stream.c_str ();

        /* "test case" */
        stream.flush ();
        char STRING_TEST_CASE[] = { '[', ' ', 't', 'e', 's', 't', ' ', 'c', 'a', 's', 'e', ' ', ']', 0, };
        stream  << col.turnon ().set_style (console_style_t::bold).set_fgcolor (console_color_t::magenta)
                << STRING_TEST_CASE
                << _current_case_name.c_str ()
                << col.turnoff ();
        std::cout << stream.c_str () << std::endl;
    } else {
        _current_case_name.clear ();
    }

    reset_time ();
}

void test_case::reset_time ()
{
    struct timespec now = { 0, };

    time_monotonic (now);

    _lock.enter ();

    arch_t tid = get_thread_id ();

    // turn on flag
    time_flag_per_thread_pib_t flag_pib;
    flag_pib = _time_flag_per_threads.insert (std::make_pair (tid, true));
    if (false == flag_pib.second) {
        bool& flag = flag_pib.first->second;
        flag = true;
    }

    // update timestamp
    timestamp_per_thread_pib_t timestamp_pib;
    timestamp_pib = _timestamp_per_threads.insert (std::make_pair (tid, now));
    if (false == timestamp_pib.second) {
        struct timespec* stamp = &(timestamp_pib.first->second);
        memcpy (stamp, &now, sizeof (struct timespec));
    }

    // clear time slices
    time_slice_per_thread_pib_t slice_pib;
    time_slice_t clean_time_slice;
    slice_pib = _time_slice_per_threads.insert (std::make_pair (tid, clean_time_slice));
    if (false == slice_pib.second) {
        slice_pib.first->second.clear ();
    }

    _lock.leave ();
}

void test_case::pause_time ()
{
    _lock.enter ();

    arch_t tid = get_thread_id ();

    time_flag_per_thread_pib_t flag_pib;
    flag_pib = _time_flag_per_threads.insert (std::make_pair (tid, false));
    if (false == flag_pib.second) {
        bool& flag = flag_pib.first->second;
        if (true == flag) {
            // push_back time difference slice necessary
            struct timespec now = { 0, };
            time_monotonic (now);

            timestamp_per_thread_pib_t timestamp_pib;
            timestamp_pib = _timestamp_per_threads.insert (std::make_pair (tid, now));
            if (false == timestamp_pib.second) {
                // read a last timestamp and calcurate a time difference
                struct timespec& stamp = timestamp_pib.first->second;

                struct timespec diff = { 0, };
                time_diff (diff, stamp, now);

                time_slice_per_thread_pib_t slice_pib;
                time_slice_t clean_time_slice;

                // push back into a list
                slice_pib = _time_slice_per_threads.insert (std::make_pair (tid, clean_time_slice));
                time_slice_t& slices = slice_pib.first->second;
                slices.push_back (diff);
            }
        }
        flag = false; // turn off thread flag
    }

    _lock.leave ();
}

void test_case::resume_time ()
{
    _lock.enter ();

    arch_t tid = get_thread_id ();

    time_flag_per_thread_pib_t flag_pib;
    flag_pib = _time_flag_per_threads.insert (std::make_pair (tid, false));
    if (false == flag_pib.second) {
        bool& flag = flag_pib.first->second;
        if (false == flag) {
            // update timestamp
            struct timespec now = { 0, };
            time_monotonic (now);

            timestamp_per_thread_pib_t timestamp_pib;
            timestamp_pib = _timestamp_per_threads.insert (std::make_pair (tid, now));
            if (false == timestamp_pib.second) {
                struct timespec* stamp = &(timestamp_pib.first->second);
                memcpy (stamp, &now, sizeof (struct timespec));
            }
        }
        flag = true; // turn on thread flag
    }

    _lock.leave ();
}

void test_case::check_time (struct timespec& ts)
{
    memset (&ts, 0, sizeof (ts));

    time_slice_t clean_time_slice;

    _lock.enter ();

    arch_t tid = get_thread_id ();

    time_flag_per_thread_pib_t flag_pib;
    flag_pib = _time_flag_per_threads.insert (std::make_pair (tid, false));
    if (false == flag_pib.second) {
        bool& flag = flag_pib.first->second;
        if (true == flag) {
            // push_back time difference slice necessary
            struct timespec now = { 0, };
            time_monotonic (now);

            timestamp_per_thread_pib_t timestamp_pib;
            timestamp_pib = _timestamp_per_threads.insert (std::make_pair (tid, now));
            if (false == timestamp_pib.second) {
                // read a last timestamp and calcurate a time difference
                struct timespec& stamp = timestamp_pib.first->second;

                struct timespec diff = { 0, };
                time_diff (diff, stamp, now);

                // push back into a list
                time_slice_per_thread_pib_t slice_pib;
                slice_pib = _time_slice_per_threads.insert (std::make_pair (tid, clean_time_slice));
                time_slice_t& slices = slice_pib.first->second;
                slices.push_back (diff);
            }
        }
    }

    time_slice_per_thread_pib_t slice_pib;
    slice_pib = _time_slice_per_threads.insert (std::make_pair (tid, clean_time_slice));
    time_slice_t& slices = slice_pib.first->second;

    time_sum (ts, slices);

    _lock.leave ();
}

void test_case::assert (bool expect, const char* test_function, const char* message, ...)
{
    return_t ret = errorcode_t::success;

    if (false == expect) {
        ret = errorcode_t::unexpected;
    }

    ansi_string tltle;
    if (nullptr != message) {
        va_list ap;
        va_start (ap, message);
        tltle.vprintf (message, ap);
        va_end (ap);
    }
    test (ret, test_function, tltle.c_str ());
}

void test_case::test (return_t result, const char* test_function, const char* message, ...)
{
    struct timespec elapsed;

    __try2
    {
        check_time (elapsed);

        ansi_string tltle;
        if (nullptr != message) {
            va_list ap;
            va_start (ap, message);
            tltle.vprintf (message, ap);
            va_end (ap);
        }

        _lock.enter ();

        console_color_t color = console_color_t::yellow;
        if (errorcode_t::success == result) {
            _total._count_success++;
        } else if (errorcode_t::not_supported == result) {
            color = console_color_t::cyan;
            _total._count_not_supported++;
        } else if (errorcode_t::low_security == result) {
            color = console_color_t::yellow;
            _total._count_low_security++;
        } else {
            _total._count_fail++;
        }

        unittest_item_t item;
        memcpy (&item._time, &elapsed, sizeof (elapsed));
        item._result = result;
        if (nullptr != test_function) {
            item._test_function = test_function;
        }
        item._message = tltle.c_str ();

        test_status_t clean_status;
        unittest_map_pib_t pib = _test_map.insert (std::make_pair (_current_case_name, clean_status));
        unittest_map_t::iterator it = pib.first;
        test_status_t& status = it->second;

        if (errorcode_t::success == result) {
            status._test_stat._count_success++;
        } else if (errorcode_t::not_supported == result) {
            status._test_stat._count_not_supported++;
        } else if (errorcode_t::low_security == result) {
            status._test_stat._count_low_security++;
        } else {
            status._test_stat._count_fail++;
        }

        status._test_list.push_back (item); /* append a unittest_item_t */

        if (true == pib.second) {
            _test_list.push_back (_current_case_name); /* ordered test cases */
        }

        console_color col;
        ansi_string stream;

        stream  << col.turnon ()
                << col.set_style (console_style_t::bold)
                << col.set_fgcolor (color)
                << format ("[%08x]", result).c_str ()
                << col.set_fgcolor (console_color_t::yellow)
                << format ("[%s] ", test_function ? test_function : "").c_str ()
                << tltle.c_str ()
                << col.turnoff ();

        std::cout << stream.c_str ()  << std::endl;
    }
    __finally2
    {
        _lock.leave ();

        reset_time ();
    }
}

#define PRINT_STRING_SUCCESS col.set_fgcolor (console_color_t::green) << STRING_SUCCESS << col.set_fgcolor (fgcolor)
#define PRINT_STRING_FAIL col.set_fgcolor (console_color_t::red) << STRING_FAIL << col.set_fgcolor (fgcolor)
#define PRINT_STRING_NOT_SUPPORTED col.set_fgcolor (console_color_t::cyan) << STRING_NOT_SUPPORTED << col.set_fgcolor (fgcolor)
#define PRINT_STRING_LOW_SECURITY col.set_fgcolor (console_color_t::yellow) << STRING_LOW_SECURITY  << col.set_fgcolor (fgcolor)

void test_case::dump_list_into_stream (unittest_list_t& array, ansi_string& stream)
{
    /* "success" */
    char STRING_SUCCESS[] = { 's', 'u', 'c', 'c', 'e', 's', 's', 0, };
    /* "pass" */
    char STRING_PASS[] = { 'p', 'a', 's', 's', 0, };
    /* "fail" */
    char STRING_FAIL[] = { 'f', 'a', 'i', 'l', 0, };
    /* "skip" */
    char STRING_NOT_SUPPORTED[] = { 's', 'k', 'i', 'p', 0, };
    /* "low" */
    char STRING_LOW_SECURITY[] = { 'l', 'o', 'w', ' ', 0, };
    /* "test case" */
    char STRING_TEST_CASE[] = { 't', 'e', 's', 't', ' ', 'c', 'a', 's', 'e', 0, };
    /* "result" */
    char STRING_RESULT[] = { 'r', 'e', 's', 'u', 'l', 't', 0, };
    /* "errorcode" */
    char STRING_ERRORCODE[] = { 'e', 'r', 'r', 'o', 'r', 'c', 'o', 'd', 'e', 0, };
    /* "test function" */
    char STRING_TEST_FUNCTION[] = { 't', 'e', 's', 't', ' ', 'f', 'u', 'n', 'c', 't', 'i', 'o', 'n', 0, };
    /* "time" */
    char STRING_TIME[] = { 't', 'i', 'm', 'e', 0, };
    /* "message" */
    char STRING_MESSAGE[] = { 'm', 'e', 's', 's', 'a', 'g', 'e', 0, };

    console_color col;
    console_color_t fgcolor = console_color_t::white;

    stream.printf ("%-5s|%-10s|%-20s|%-11s|%s\n", STRING_RESULT, STRING_ERRORCODE, STRING_TEST_FUNCTION, STRING_TIME, STRING_MESSAGE);

    for (unittest_list_t::iterator list_iterator = array.begin (); list_iterator != array.end (); list_iterator++) {
        unittest_item_t item = *list_iterator;

        ansi_string error_message;
        switch (item._result) {
            case errorcode_t::success:       error_message << STRING_PASS; break;
            case errorcode_t::not_supported: error_message << PRINT_STRING_NOT_SUPPORTED; break;
            case errorcode_t::low_security:  error_message << PRINT_STRING_LOW_SECURITY; break;
            default:                         error_message << PRINT_STRING_FAIL; break;
        }

        std::string funcname;
        if (item._test_function.size () > 20) {
            funcname = item._test_function.substr (0, 18);
            funcname += "..";
        } else {
            funcname = item._test_function;
        }
        stream.printf (" %-4s |0x%08x|%-20s|%-11s|%s\n",
                       error_message.c_str (), item._result, funcname.c_str (),
                       format ("%lld.%09ld", item._time.tv_sec, item._time.tv_nsec / 100).c_str (),
                       item._message.c_str ());
    }
}

void test_case::report (uint32 top_count)
{
    ansi_string stream;

    _lock.enter ();

    report_unittest (stream);
    report_testtime (stream, top_count);

    _lock.leave ();

    //
    // print
    //

    std::cout << stream.c_str ();

    //
    // file
    //

    char STRING_REPORT[] = { 'r', 'e', 'p', 'o', 'r', 't', 0, };

    std::ofstream file (STRING_REPORT, std::ios::trunc);
    file << stream.c_str ();
    file.close ();
}

void test_case::report_unittest (ansi_string& stream)
{
    console_color col;
    console_color_t fgcolor = console_color_t::white;

    /* test */
    char STRING_REPORT[] = { 'r', 'e', 'p', 'o', 'r', 't', 0, };
    /* "success" */
    char STRING_SUCCESS[] = { 's', 'u', 'c', 'c', 'e', 's', 's', 0, };
    /* "pass" */
    char STRING_PASS[] = { 'p', 'a', 's', 's', 0, };
    /* "fail" */
    char STRING_FAIL[] = { 'f', 'a', 'i', 'l', 0, };
    /* "skip" */
    char STRING_NOT_SUPPORTED[] = { 's', 'k', 'i', 'p', 0, };
    /* "low" */
    char STRING_LOW_SECURITY[] = { 'l', 'o', 'w', ' ', 0, };
    /* "test case" */
    char STRING_TEST_CASE[] = { 't', 'e', 's', 't', ' ', 'c', 'a', 's', 'e', 0, };
    /* "result" */
    char STRING_RESULT[] = { 'r', 'e', 's', 'u', 'l', 't', 0, };
    /* "errorcode" */
    char STRING_ERRORCODE[] = { 'e', 'r', 'r', 'o', 'r', 'c', 'o', 'd', 'e', 0, };
    /* "test function" */
    char STRING_TEST_FUNCTION[] = { 't', 'e', 's', 't', ' ', 'f', 'u', 'n', 'c', 't', 'i', 'o', 'n', 0, };
    /* "time" */
    char STRING_TIME[] = { 't', 'i', 'm', 'e', 0, };
    /* "message" */
    char STRING_MESSAGE[] = { 'm', 'e', 's', 's', 'a', 'g', 'e', 0, };
    char STRING_UPPERCASE_TEST_FAILED[] = { 'T', 'E', 'S', 'T', ' ', 'F', 'A', 'I', 'L', 'E', 'D', 0, };

    //
    // compose
    //

    _lock.enter ();

    stream << col.turnon ().set_style (console_style_t::bold);
    stream.fill (80, '=');
    stream.endl ();
    stream << col.set_fgcolor (fgcolor) << STRING_REPORT;
    stream.endl ();

    for (unittest_index_t::iterator iter = _test_list.begin (); iter != _test_list.end (); iter++) {
        std::string testcase = *iter;
        unittest_map_t::iterator map_iter = _test_map.find (testcase);
        test_status_t status = map_iter->second;

        stream  << "@ "
                << STRING_TEST_CASE << " \"" << testcase.c_str () << "\" "
                << PRINT_STRING_SUCCESS << " " << status._test_stat._count_success;
        if (status._test_stat._count_fail) {
            stream << " " << PRINT_STRING_FAIL << " " << status._test_stat._count_fail;
        }
        if (status._test_stat._count_not_supported) {
            stream << " " << PRINT_STRING_NOT_SUPPORTED << " " << status._test_stat._count_not_supported;
        }
        if (status._test_stat._count_low_security) {
            stream << " " << PRINT_STRING_LOW_SECURITY << " " << status._test_stat._count_low_security;
        }
        stream.endl ();

        stream.fill (80, '-');
        stream.endl ();

        dump_list_into_stream (status._test_list, stream);

        stream.fill (80, '-');
        stream.endl ();
    }

    stream << "# " << PRINT_STRING_SUCCESS << " " << _total._count_success;
    if (_total._count_fail) {
        stream << " " << PRINT_STRING_FAIL << " " << _total._count_fail;
    }
    if (_total._count_not_supported) {
        stream << " " << PRINT_STRING_NOT_SUPPORTED << " " << _total._count_not_supported;
    }
    if (_total._count_low_security) {
        stream << " " << PRINT_STRING_LOW_SECURITY << " " << _total._count_low_security;
    }
    stream.endl ();
    stream.fill (80, '=');
    stream.endl ();
    if (_total._count_fail) {
        stream << col.set_fgcolor (console_color_t::red) << STRING_UPPERCASE_TEST_FAILED;
        stream.endl ();
    }

    stream << col.turnoff ();

    _lock.leave ();
}

#if 0
bool compare_timespec (const unittest_item_t& lhs, const unittest_item_t& rhs)
{
    bool ret = false;

    if ((lhs._time.tv_sec >= rhs._time.tv_sec) && (lhs._time.tv_nsec > rhs._time.tv_nsec)) {
        ret = true;
    }
    return ret;
}
#endif

void test_case::report_testtime (ansi_string& stream, uint32 top_count)
{
    _lock.enter ();

    console_color col;
    unittest_list_t array;
    typedef std::map <uint128, unittest_item_t*> temp_map_t;
    temp_map_t temp_map;
    unittest_map_t::iterator it;

    unsigned int field_nsec = (RTL_FIELD_SIZE (struct timespec, tv_nsec) << 3);
    stream << col.turnon ().set_style (console_style_t::bold);

    for (it = _test_map.begin (); it != _test_map.end (); it++) {
        // not efficient nor unsatisfied results
        //     test_status_t& status = it->second;
        //     unittest_list_t copied = it->second._test_list;
        //     array.sort (compare_timespec);
        //     copied.sort (compare_timespec);
        //     array.merge (copied, compare_timespec);
        // so... using map
        unittest_list_t::iterator unittest_it;
        for (unittest_it = it->second._test_list.begin (); unittest_it != it->second._test_list.end (); unittest_it++) {
            struct timespec* t = &((*unittest_it)._time);
            uint128 timekey = ((uint128) t->tv_sec << field_nsec) | (t->tv_nsec);
            temp_map.insert (std::make_pair (timekey, &(*unittest_it))); // build pair(timekey, pointer)
        }
    }
    temp_map_t::reverse_iterator rit;
    for (rit = temp_map.rbegin (); rit != temp_map.rend (); rit++) {
        array.push_back (*rit->second); // copy unittest_item_t here
    }

    // top N
    if (array.size () > top_count) {
        array.resize (top_count);
    }

    // dump and cout
    if (array.size ()) {
        stream.printf ("sort by time (top %zi)\n", array.size ());

        stream.fill (80, '-');
        stream.endl ();

        dump_list_into_stream (array, stream);

        stream.fill (80, '-');
        stream.endl ();
    }

    stream << col.turnoff ();

    _lock.leave ();
}

return_t test_case::result ()
{
    return _total._count_fail > 0 ? errorcode_t::internal_error : errorcode_t::success;
}

}
}  // namespace
