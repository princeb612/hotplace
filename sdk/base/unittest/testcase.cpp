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

#include <fstream>
#include <iostream>
#include <sdk/base/stl.hpp>
#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/datetime.hpp>
#include <sdk/base/system/thread.hpp>
#include <sdk/base/unittest/testcase.hpp>

namespace hotplace {

test_case::test_case() { reset_time(); }

void test_case::begin(const char* case_name, ...) {
    arch_t tid = get_thread_id();
    testcase_per_thread_pib_t pib;
    basic_stream topic;
    basic_stream stream;
    t_stream_binder<basic_stream, console_color> console_colored_stream(stream);

    critical_section_guard guard(_lock);

    if (nullptr != case_name) {
        va_list ap;
        va_start(ap, case_name);
        topic.vprintf(case_name, ap);
        va_end(ap);

        pib = _testcase_per_threads.insert(std::make_pair(tid, topic.c_str()));
        if (false == pib.second) {
            pib.first->second = topic.c_str();
        }
    } else {
        pib = _testcase_per_threads.insert(std::make_pair(tid, topic.c_str()));
        if (false == pib.second) {
            pib.first->second.clear();
        }
    }

    constexpr char constexpr_testcase[] = "[test case] ";

    console_colored_stream << _concolor.turnon().set_style(console_style_t::bold).set_fgcolor(console_color_t::magenta) << constexpr_testcase << topic.c_str();
    console_colored_stream << _concolor.turnoff();
    std::cout << stream.c_str() << std::endl;

    reset_time();
}

void test_case::reset_time() {
    struct timespec now = {
        0,
    };

    time_monotonic(now);

    critical_section_guard guard(_lock);

    arch_t tid = get_thread_id();

    // turn on flag
    time_flag_per_thread_pib_t flag_pib;
    flag_pib = _time_flag_per_threads.insert(std::make_pair(tid, true));
    if (false == flag_pib.second) {
        bool& flag = flag_pib.first->second;
        flag = true;
    }

    // update timestamp
    timestamp_per_thread_pib_t timestamp_pib;
    timestamp_pib = _timestamp_per_threads.insert(std::make_pair(tid, now));
    if (false == timestamp_pib.second) {
        struct timespec* stamp = &(timestamp_pib.first->second);
        memcpy(stamp, &now, sizeof(struct timespec));
    }

    // clear time slices
    time_slice_per_thread_pib_t slice_pib;
    time_slice_t clean_time_slice;
    slice_pib = _time_slice_per_threads.insert(std::make_pair(tid, clean_time_slice));
    if (false == slice_pib.second) {
        slice_pib.first->second.clear();
    }
}

void test_case::pause_time() {
    critical_section_guard guard(_lock);

    arch_t tid = get_thread_id();

    time_flag_per_thread_pib_t flag_pib;
    flag_pib = _time_flag_per_threads.insert(std::make_pair(tid, false));
    if (false == flag_pib.second) {
        bool& flag = flag_pib.first->second;
        if (true == flag) {
            // push_back time difference slice necessary
            struct timespec now = {
                0,
            };
            time_monotonic(now);

            timestamp_per_thread_pib_t timestamp_pib;
            timestamp_pib = _timestamp_per_threads.insert(std::make_pair(tid, now));
            if (false == timestamp_pib.second) {
                // read a last timestamp and calcurate a time difference
                struct timespec& stamp = timestamp_pib.first->second;

                struct timespec diff = {
                    0,
                };
                time_diff(diff, stamp, now);

                time_slice_per_thread_pib_t slice_pib;
                time_slice_t clean_time_slice;

                // push back into a list
                slice_pib = _time_slice_per_threads.insert(std::make_pair(tid, clean_time_slice));
                time_slice_t& slices = slice_pib.first->second;
                slices.push_back(diff);
            }
        }
        flag = false;  // turn off thread flag
    }
}

void test_case::resume_time() {
    critical_section_guard guard(_lock);

    arch_t tid = get_thread_id();

    time_flag_per_thread_pib_t flag_pib;
    flag_pib = _time_flag_per_threads.insert(std::make_pair(tid, false));
    if (false == flag_pib.second) {
        bool& flag = flag_pib.first->second;
        if (false == flag) {
            // update timestamp
            struct timespec now = {
                0,
            };
            time_monotonic(now);

            timestamp_per_thread_pib_t timestamp_pib;
            timestamp_pib = _timestamp_per_threads.insert(std::make_pair(tid, now));
            if (false == timestamp_pib.second) {
                struct timespec* stamp = &(timestamp_pib.first->second);
                memcpy(stamp, &now, sizeof(struct timespec));
            }
        }
        flag = true;  // turn on thread flag
    }
}

void test_case::check_time(struct timespec& ts) {
    memset(&ts, 0, sizeof(ts));

    time_slice_t clean_time_slice;

    critical_section_guard guard(_lock);

    arch_t tid = get_thread_id();

    time_flag_per_thread_pib_t flag_pib;
    flag_pib = _time_flag_per_threads.insert(std::make_pair(tid, false));
    if (false == flag_pib.second) {
        bool& flag = flag_pib.first->second;
        if (true == flag) {
            // push_back time difference slice necessary
            struct timespec now = {
                0,
            };
            time_monotonic(now);

            timestamp_per_thread_pib_t timestamp_pib;
            timestamp_pib = _timestamp_per_threads.insert(std::make_pair(tid, now));
            if (false == timestamp_pib.second) {
                // read a last timestamp and calcurate a time difference
                struct timespec& stamp = timestamp_pib.first->second;

                struct timespec diff = {
                    0,
                };
                time_diff(diff, stamp, now);

                // push back into a list
                time_slice_per_thread_pib_t slice_pib;
                slice_pib = _time_slice_per_threads.insert(std::make_pair(tid, clean_time_slice));
                time_slice_t& slices = slice_pib.first->second;
                slices.push_back(diff);
            }
        }
    }

    time_slice_per_thread_pib_t slice_pib;
    slice_pib = _time_slice_per_threads.insert(std::make_pair(tid, clean_time_slice));
    time_slice_t& slices = slice_pib.first->second;

    time_sum(ts, slices);
}

void test_case::assert(bool expect, const char* test_function, const char* message, ...) {
    return_t ret = errorcode_t::success;

    if (false == expect) {
        ret = errorcode_t::unexpected;
    }

    basic_stream tltle;
    if (nullptr != message) {
        va_list ap;
        va_start(ap, message);
        tltle.vprintf(message, ap);
        va_end(ap);
    }
    test(ret, test_function, tltle.c_str());
}

void test_case::test(return_t result, const char* test_function, const char* message, ...) {
    struct timespec elapsed;
    arch_t tid = get_thread_id();
    testcase_per_thread_pib_t pib;
    std::string topic;

    __try2 {
        check_time(elapsed);

        basic_stream tltle;
        if (nullptr != message) {
            va_list ap;
            va_start(ap, message);
            tltle.vprintf(message, ap);
            va_end(ap);
        }

        _lock.enter();

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
            color = console_color_t::red;
            _total._count_fail++;
        }

        unittest_item_t item;
        memcpy(&item._time, &elapsed, sizeof(elapsed));
        item._result = result;
        if (nullptr != test_function) {
            item._test_function = test_function;
        }
        item._message = tltle.c_str();

        pib = _testcase_per_threads.insert(std::make_pair(tid, topic));
        if (false == pib.second) {
            topic = pib.first->second;
        }

        test_status_t clean_status;
        unittest_map_pib_t pib = _test_map.insert(std::make_pair(topic, clean_status));
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

        status._test_list.push_back(item); /* append a unittest_item_t */

        if (true == pib.second) {
            _test_list.push_back(topic); /* ordered test cases */
        }

        basic_stream stream;
        t_stream_binder<basic_stream, console_color> console_colored_stream(stream);

        console_colored_stream << _concolor.turnon() << _concolor.set_style(console_style_t::bold) << _concolor.set_fgcolor(color)
                               << format("[%08x]", result).c_str() << _concolor.set_fgcolor(console_color_t::yellow)
                               << format("[%s] ", test_function ? test_function : "").c_str() << tltle.c_str();
        console_colored_stream << _concolor.turnoff();

        std::cout << stream.c_str() << std::endl;
    }
    __finally2 {
        _lock.leave();

        reset_time();
    }
}

constexpr char constexpr_success[] = "success";
constexpr char constexpr_pass[] = "pass";
constexpr char constexpr_fail[] = "fail";
constexpr char constexpr_skip[] = "skip";
constexpr char constexpr_low[] = "low ";

constexpr char constexpr_report[] = "report";
constexpr char constexpr_testcase[] = "test case";
constexpr char constexpr_result[] = "result";
constexpr char constexpr_errorcode[] = "errorcode";
constexpr char constexpr_function[] = "test function";
constexpr char constexpr_time[] = "time";
constexpr char constexpr_message[] = "message";

#define cprint(stream, concolor, color1, color2, msg) \
    stream << concolor.set_fgcolor(color1) << msg;    \
    stream << concolor.set_fgcolor(color2);

void test_case::dump_list_into_stream(unittest_list_t& array, basic_stream& stream, uint32 flags) {
    error_advisor* advisor = error_advisor::get_instance();

    console_color_t fgcolor = console_color_t::white;

    _concolor.set_style(console_style_t::bold);

    constexpr char constexpr_header[] = "%-5s|%-10s|%-20s|%-11s|%s\n";
    constexpr char constexpr_header_err[] = "%-5s|%-10s|%-32s|%-20s|%-11s|%s\n";
    constexpr char constexpr_line[] = " %-4s |0x%08x|%-20s|%-11s|%s\n";
    constexpr char constexpr_line_err[] = " %-4s |0x%08x|%-32s|%-20s|%-11s|%s\n";
    constexpr char constexpr_timefmt[] = "%lld.%09ld";
    if (testcase_dump_t::testcase_dump_error & flags) {
        stream.printf(constexpr_header_err, "result", "errorcode", "desc", "test function", "time", "message");
    } else {
        stream.printf(constexpr_header, "result", "errorcode", "test function", "time", "message");
    }

    for (unittest_list_t::iterator list_iterator = array.begin(); list_iterator != array.end(); list_iterator++) {
        unittest_item_t item = *list_iterator;

        basic_stream error_message;
        t_stream_binder<basic_stream, console_color> console_colored_stream(error_message);

        std::string funcname;
        if (item._test_function.size() > 20) {
            funcname = item._test_function.substr(0, 18);
            funcname += "..";
        } else {
            funcname = item._test_function;
        }

        switch (item._result) {
            case errorcode_t::success:
                cprint(console_colored_stream, _concolor, console_color_t::white, fgcolor, constexpr_pass);
                break;
            case errorcode_t::not_supported:
                cprint(console_colored_stream, _concolor, console_color_t::cyan, fgcolor, constexpr_skip);
                break;
            case errorcode_t::low_security:
                cprint(console_colored_stream, _concolor, console_color_t::yellow, fgcolor, constexpr_low);
                break;
            default:
                cprint(console_colored_stream, _concolor, console_color_t::red, fgcolor, constexpr_fail);
                break;
        }

        std::string error_message_string;
        std::string errormsg;
        if (testcase_dump_t::testcase_dump_error & flags) {
            advisor->error_message(item._result, error_message_string);
            if (error_message_string.size() > 32) {
                errormsg = error_message_string.substr(0, 30);
                errormsg += "..";
            } else {
                errormsg = error_message_string;
            }
            stream.printf(constexpr_line_err, error_message.c_str(), item._result, errormsg.c_str(), funcname.c_str(),
                          format(constexpr_timefmt, item._time.tv_sec, item._time.tv_nsec / 100).c_str(), item._message.c_str());
        } else {
            stream.printf(constexpr_line, error_message.c_str(), item._result, funcname.c_str(),
                          format(constexpr_timefmt, item._time.tv_sec, item._time.tv_nsec / 100).c_str(), item._message.c_str());
        }
    }
}

void test_case::report(uint32 top_count) {
    basic_stream stream;

    _lock.enter();

    report_unittest(stream);
    report_failed(stream);
    report_testtime(stream, top_count);

    _lock.leave();

    //
    // print
    //

    std::cout << stream.c_str();

    //
    // file
    //

    std::ofstream file(constexpr_report, std::ios::trunc);
    file << stream.c_str();
    file.close();
}

void test_case::report_unittest(basic_stream& stream) {
    t_stream_binder<basic_stream, console_color> console_colored_stream(stream);
    console_color_t fgcolor = console_color_t::white;

    //
    // compose
    //

    _lock.enter();

    console_colored_stream << _concolor.turnon().set_style(console_style_t::bold);
    stream.fill(80, '=');
    stream << "\n";
    console_colored_stream << _concolor.set_fgcolor(fgcolor) << constexpr_report;
    stream << "\n";

    for (unittest_index_t::iterator iter = _test_list.begin(); iter != _test_list.end(); iter++) {
        std::string testcase = *iter;
        unittest_map_t::iterator map_iter = _test_map.find(testcase);
        test_status_t status = map_iter->second;

        stream << "@ " << constexpr_testcase << " \"" << testcase.c_str() << "\" " << constexpr_success << " " << status._test_stat._count_success;
        if (status._test_stat._count_fail) {
            stream << " ";
            cprint(console_colored_stream, _concolor, console_color_t::red, fgcolor, constexpr_fail);
            stream << " " << status._test_stat._count_fail;
        }
        if (status._test_stat._count_not_supported) {
            stream << " ";
            cprint(console_colored_stream, _concolor, console_color_t::cyan, fgcolor, constexpr_skip);
            stream << " " << status._test_stat._count_not_supported;
        }
        if (status._test_stat._count_low_security) {
            stream << " ";
            cprint(console_colored_stream, _concolor, console_color_t::yellow, fgcolor, constexpr_low);
            stream << " " << status._test_stat._count_low_security;
        }
        stream << "\n";

        stream.fill(80, '-');
        stream << "\n";

        dump_list_into_stream(status._test_list, stream);

        stream.fill(80, '-');
        stream << "\n";
    }

    stream << "# ";
    cprint(console_colored_stream, _concolor, console_color_t::white, fgcolor, constexpr_pass);
    stream << " " << _total._count_success;
    if (_total._count_fail) {
        stream << " ";
        cprint(console_colored_stream, _concolor, console_color_t::red, fgcolor, constexpr_fail);
        stream << " " << _total._count_fail;
    }
    if (_total._count_not_supported) {
        stream << " ";
        cprint(console_colored_stream, _concolor, console_color_t::cyan, fgcolor, constexpr_skip);
        stream << " " << _total._count_not_supported;
    }
    if (_total._count_low_security) {
        stream << " ";
        cprint(console_colored_stream, _concolor, console_color_t::yellow, fgcolor, constexpr_low);
        stream << " " << _total._count_low_security;
    }
    stream << "\n";
    stream.fill(80, '=');
    stream << "\n";
    if (_total._count_fail) {
        constexpr char constexpr_testfail[] = "TEST FAILED";
        cprint(console_colored_stream, _concolor, console_color_t::red, fgcolor, constexpr_testfail);
        stream << "\n";
    }

    console_colored_stream << _concolor.turnoff();

    _lock.leave();
}

void test_case::report_failed(basic_stream& stream) {
    t_stream_binder<basic_stream, console_color> console_colored_stream(stream);

    _lock.enter();

    unittest_list_t array;
    unittest_map_t::iterator it;

    unsigned int field_nsec = (RTL_FIELD_SIZE(struct timespec, tv_nsec) << 3);
    console_colored_stream << _concolor.turnon().set_style(console_style_t::bold);

    for (it = _test_map.begin(); it != _test_map.end(); it++) {
        unittest_list_t::iterator unittest_it;
        for (unittest_it = it->second._test_list.begin(); unittest_it != it->second._test_list.end(); unittest_it++) {
            unittest_item_t& item = *unittest_it;
            switch (item._result) {
                case errorcode_t::not_supported:
                case errorcode_t::low_security:
                case errorcode_t::success:
                    break;
                default:
                    array.push_back(item);
                    break;
            }
        }
    }

    // dump
    if (array.size()) {
        constexpr char constexpr_failed[] = "failed case(s)\n";
        stream.printf(constexpr_failed, array.size());

        stream.fill(80, '-');
        stream << "\n";

        dump_list_into_stream(array, stream, testcase_dump_t::testcase_dump_error);

        stream.fill(80, '-');
        stream << "\n";
    }

    console_colored_stream << _concolor.turnoff();

    _lock.leave();
}

void test_case::report_testtime(basic_stream& stream, uint32 top_count) {
    t_stream_binder<basic_stream, console_color> console_colored_stream(stream);

    _lock.enter();

    unittest_list_t array;
    typedef std::map<uint128, unittest_item_t*> temp_map_t;
    temp_map_t temp_map;
    unittest_map_t::iterator it;

    unsigned int field_nsec = (RTL_FIELD_SIZE(struct timespec, tv_nsec) << 3);
    console_colored_stream << _concolor.turnon().set_style(console_style_t::bold);

    for (it = _test_map.begin(); it != _test_map.end(); it++) {
        // neither efficient nor satisfactory results
        //     test_status_t& status = it->second;
        //     unittest_list_t copied = it->second._test_list;
        //     array.sort (compare_timespec);
        //     copied.sort (compare_timespec);
        //     array.merge (copied, compare_timespec);
        // so... use map
        //      pair <time, pointer>
        //      list of object don't needed right now
        unittest_list_t::iterator unittest_it;
        for (unittest_it = it->second._test_list.begin(); unittest_it != it->second._test_list.end(); unittest_it++) {
            struct timespec* t = &((*unittest_it)._time);
            uint128 timekey = ((uint128)t->tv_sec << field_nsec) | (t->tv_nsec);
            temp_map.insert(std::make_pair(timekey, &(*unittest_it)));  // build pair(timekey, pointer)
        }
    }

    // build list
    temp_map_t::reverse_iterator rit;
    for (rit = temp_map.rbegin(); rit != temp_map.rend(); rit++) {
        array.push_back(*rit->second);  // copy unittest_item_t here
    }

    // top N
    if (array.size() > top_count) {
        array.resize(top_count);
    }

    // dump and cout
    if (array.size()) {
        constexpr char constexpr_timesort[] = "sort by time (top %zi)\n";
        stream.printf(constexpr_timesort, array.size());

        stream.fill(80, '-');
        stream << "\n";

        dump_list_into_stream(array, stream);

        stream.fill(80, '-');
        stream << "\n";
    }

    console_colored_stream << _concolor.turnoff();

    _lock.leave();
}

return_t test_case::result() { return _total._count_fail > 0 ? errorcode_t::internal_error : errorcode_t::success; }

}  // namespace hotplace
