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

#include <algorithm>
#include <fstream>
#include <hotplace/sdk/base/string/string.hpp>
#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/base/system/datetime.hpp>
#include <hotplace/sdk/base/system/error.hpp>
#include <hotplace/sdk/base/system/thread.hpp>
#include <hotplace/sdk/base/unittest/testcase.hpp>
#include <iostream>
#include <vector>

namespace hotplace {

/**
 * @brief   stream util
 * @desc    work around pure virtual operator overloading
 *
 *          // concept sketch - binder must provide printf (STREAM_T*) method
 *          basic_stream bs;
 *          console_color concolor;
 *          t_stream_binder <basic_stream, console_color> console_colored_stream(bs);
 *          console_colored_stream << concolor.turnon ().set_fgcolor(console_color_t::yellow)
 *                                 << "hello"
 *                                 << concolor.turnoff ();
 *          std::cout << bs << std::endl;
 */
template <typename STREAM_T, typename BINDER>
class t_stream_binder {
   public:
    t_stream_binder(STREAM_T& stream) : _stream(stream) {}
    t_stream_binder<STREAM_T, BINDER>& operator<<(const char* rvalue) {
        if (rvalue) {
            _stream.printf("%s", rvalue);
        }
        return *this;
    }
    t_stream_binder<STREAM_T, BINDER>& operator<<(int rvalue) {
        if (rvalue) {
            _stream.printf("%i", rvalue);
        }
        return *this;
    }
    t_stream_binder<STREAM_T, BINDER>& operator<<(BINDER& rvalue) {
        rvalue.printf(&_stream);
        return *this;
    }
    t_stream_binder<STREAM_T, BINDER>& operator+=(const char* rvalue) {
        if (rvalue) {
            _stream.printf("%s", rvalue);
        }
        return *this;
    }
    t_stream_binder<STREAM_T, BINDER>& operator+=(int rvalue) {
        if (rvalue) {
            _stream.printf("%i", rvalue);
        }
        return *this;
    }
    t_stream_binder<STREAM_T, BINDER>& operator+=(BINDER& rvalue) {
        // binder MUST provide printf (STREAM_T*) method
        rvalue.printf(&_stream);
        return *this;
    }

    STREAM_T& get_stream() { return _stream; }

   private:
    STREAM_T& _stream;
};

test_case::test_case() : _logger(nullptr) { reset_time(); }

void test_case::begin(const char* case_name, ...) {
    arch_t tid = get_thread_id();
    basic_stream topic;
    basic_stream stream;
    t_stream_binder<basic_stream, console_color> console_colored_stream(stream);

    critical_section_guard guard(_lock);

    if (nullptr != case_name) {
        va_list ap;
        va_start(ap, case_name);
        topic.vprintf(case_name, ap);
        va_end(ap);
        _testcase_per_threads[tid] = topic.c_str();
    } else {
        _testcase_per_threads[tid].clear();
    }

    constexpr char constexpr_testcase[] = "[test case] ";

    console_colored_stream << _concolor.turnon().set_style(console_style_t::bold).set_fgcolor(console_color_t::magenta) << constexpr_testcase << topic.c_str();
    console_colored_stream << _concolor.turnoff();
    if (_logger) {
        _logger->writeln(stream);
    } else {
        std::cout << stream << std::endl;
    }

    reset_time();
}

void test_case::begin(const std::string& case_name) { begin(case_name.c_str()); }

void test_case::reset_time() {
    struct timespec now = {0};

    time_monotonic(now);

    critical_section_guard guard(_lock);

    arch_t tid = get_thread_id();

    // turn on per-thread stopwatch flag.
    _time_flag_per_threads[tid] = true;

    // update per-thread timestamp.
    _timestamp_per_threads[tid] = now;

    // clear per-thread accumulated time slices.
    _time_slice_per_threads[tid].clear();
}

void test_case::pause_time() {
    critical_section_guard guard(_lock);

    arch_t tid = get_thread_id();

    bool& flag = _time_flag_per_threads[tid];
    if (true == flag) {
        // push a time slice for the elapsed interval since last timestamp.
        struct timespec now = {0};
        time_monotonic(now);

        struct timespec& stamp = _timestamp_per_threads[tid];

        struct timespec diff = {0};
        time_diff(diff, stamp, now);
        _time_slice_per_threads[tid].push_back(diff);
    }
    flag = false;  // turn off per-thread stopwatch flag.
}

void test_case::resume_time() {
    critical_section_guard guard(_lock);

    arch_t tid = get_thread_id();

    bool& flag = _time_flag_per_threads[tid];
    if (false == flag) {
        // update timestamp on resume.
        struct timespec now = {0};
        time_monotonic(now);
        _timestamp_per_threads[tid] = now;
    }
    flag = true;  // turn on per-thread stopwatch flag.
}

void test_case::check_time(struct timespec& ts) {
    memset(&ts, 0, sizeof(ts));

    critical_section_guard guard(_lock);

    arch_t tid = get_thread_id();

    bool& flag = _time_flag_per_threads[tid];
    if (true == flag) {
        // Push a time slice for the elapsed interval since last timestamp.
        struct timespec now = {0};
        time_monotonic(now);

        struct timespec& stamp = _timestamp_per_threads[tid];

        struct timespec diff = {0};
        time_diff(diff, stamp, now);
        _time_slice_per_threads[tid].push_back(diff);
    }

    time_slice_t& slices = _time_slice_per_threads[tid];

    time_sum(ts, slices);
}

void test_case::assert(bool expect, const char* test_function, const char* message, ...) {
    return_t ret = errorcode_t::success;
    va_list ap;
    va_start(ap, message);
    assert(expect, test_function, message, ap);
    va_end(ap);
}

void test_case::assert(bool expect, const char* test_function, const char* message, va_list ap) {
    return_t ret = errorcode_t::success;

    if (false == expect) {
        ret = errorcode_t::assert_failed;
    }

    basic_stream tltle;
    if (message) {
        tltle.vprintf(message, ap);
    }
    test(ret, test_function, tltle.c_str());
}

void test_case::nassert(bool expect, const char* test_function, const char* message, ...) {
    va_list ap;
    va_start(ap, message);
    nassert(expect, test_function, message, ap);
    va_end(ap);
}

void test_case::nassert(bool expect, const char* test_function, const char* message, va_list ap) {
    return_t ret = (false == expect) ? expect_failure : unexpected;
    basic_stream tltle;
    if (message) {
        tltle.vprintf(message, ap);
    }
    test(ret, test_function, tltle.c_str());
}

void test_case::test(return_t result, const char* test_function, const char* message, ...) {
    va_list ap;
    va_start(ap, message);
    test(result, test_function, message, ap);
    va_end(ap);
}

void test_case::test(return_t result, const char* test_function, const char* message, va_list ap) {
    struct timespec elapsed;
    arch_t tid = get_thread_id();
    std::string topic;
    error_advisor* advisor = error_advisor::get_instance();

    __try2 {
        check_time(elapsed);

        basic_stream tltle;
        if (message) {
            tltle.vprintf(message, ap);
        }

        critical_section_guard guard(_lock);

        console_color_t color = console_color_t::yellow;
        auto category = advisor->categoryof(result);

        unittest_item_t item;
        memcpy(&item._time, &elapsed, sizeof(elapsed));
        item._result = result;
        if (test_function) {
            item._test_function = test_function;
        }
        item._message = tltle.c_str();

        topic = _testcase_per_threads[tid];

        test_status_t clean_status;
        unittest_map_pib_t pib = _test_map.insert(std::make_pair(topic, clean_status));
        unittest_map_t::iterator it = pib.first;
        test_status_t& status = it->second;

        switch (category) {
            case error_category_success:  // pass
                _total._count_success++;
                status._test_stat._count_success++;
                break;
            case error_category_expect_failure:  // pass
                color = console_color_t::magenta;
                _total._count_success++;
                status._test_stat._count_success++;
                break;
            case error_category_severe:  // fail
                color = console_color_t::red;
                _total._count_fail++;
                status._test_stat._count_fail++;
                break;
            case error_category_not_supported:  // skip
                color = console_color_t::cyan;
                _total._count_not_supported++;
                status._test_stat._count_not_supported++;
                break;
            case error_category_low_security:  // triv
            case error_category_trivial:
            case error_category_warn:
                color = console_color_t::yellow;
                _total._count_trivial++;
                status._test_stat._count_trivial++;
                break;
            default:
                // do not reach here
                color = console_color_t::white;
                break;
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

        if (_logger) {
            _logger->writeln(stream);
        } else {
            std::cout << stream << std::endl;
        }
    }
    __finally2 { reset_time(); }
}

void test_case::ntest(return_t result, const char* test_function, const char* message, ...) {
    va_list ap;
    va_start(ap, message);
    ntest(result, test_function, message, ap);
    va_end(ap);
}

void test_case::ntest(return_t result, const char* test_function, const char* message, va_list ap) {
    return_t ret = (errorcode_t::success != result) ? expect_failure : unexpected;
    test(ret, test_function, message, ap);
}

constexpr char constexpr_success[] = "success";
constexpr char constexpr_pass[] = "pass";
constexpr char constexpr_fail[] = "fail";
constexpr char constexpr_skip[] = "skip";
constexpr char constexpr_trivial[] = "triv";
constexpr char constexpr_warn[] = "warn";
constexpr char constexpr_blah[] = "    ";
constexpr char constexpr_expect_failure[] = "expt";

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

void test_case::dump_list_into_stream(const unittest_list_t& array, basic_stream& stream, uint32 flags) {
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

    for (const auto& item : array) {
        basic_stream error_message;
        t_stream_binder<basic_stream, console_color> console_colored_stream(error_message);

        std::string funcname;
        if (item._test_function.size() > 20) {
            funcname = item._test_function.substr(0, 18);
            funcname += "..";
        } else {
            funcname = item._test_function;
        }

        auto category = advisor->categoryof(item._result);
        switch (category) {
            case error_category_success:
                cprint(console_colored_stream, _concolor, console_color_t::white, fgcolor, constexpr_pass);
                break;
            case error_category_expect_failure:
                cprint(console_colored_stream, _concolor, console_color_t::magenta, fgcolor, constexpr_expect_failure);
                break;
            case error_category_severe:
                cprint(console_colored_stream, _concolor, console_color_t::red, fgcolor, constexpr_fail);
                break;
            case error_category_not_supported:
                cprint(console_colored_stream, _concolor, console_color_t::cyan, fgcolor, constexpr_skip);
                break;
            case error_category_low_security:
            case error_category_trivial:
                cprint(console_colored_stream, _concolor, console_color_t::yellow, fgcolor, constexpr_trivial);
                break;
            case error_category_warn:
                cprint(console_colored_stream, _concolor, console_color_t::green, fgcolor, constexpr_warn);
                break;
            default:
                cprint(console_colored_stream, _concolor, console_color_t::green, fgcolor, constexpr_blah);
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

    // @ test case "" success 1 fail 1 skip 1 low  1
    // --------------------------------------------------------------------------------
    // result|errorcode |test function       |time       |message
    //  pass |0x00000000|function1           |0.000000049|case desc 1
    //  fail |0xef010003|function2           |0.000000032|case desc 2 - intentional fail
    //  skip |0xef010100|function3           |0.000000115|case desc 4
    //  low  |0xef010101|function4           |0.000000020|case desc 5
    // --------------------------------------------------------------------------------
    // @ test case "test case 1" success 1 fail 1
    // --------------------------------------------------------------------------------
    // result|errorcode |test function       |time       |message
    //  pass |0x00000000|function5           |0.000000100|case 1 desc 1
    //  fail |0xef01001b|function6           |0.000000029|case 1 desc 2 - intentional fail
    // --------------------------------------------------------------------------------
    // @ test case "test case 2" success 3 fail 1
    // --------------------------------------------------------------------------------
    // result|errorcode |test function       |time       |message
    //  pass |0x00000000|function7           |0.000000042|case 2 desc 1
    //  pass |0x00000000|function8           |0.000000074|case 2 desc 2
    //  fail |0xef010036|function9           |0.000000049|case 2 desc 3 - intentional fail
    //  pass |0x00000000|test_unittest       |0.000000103|result
    // --------------------------------------------------------------------------------
    // @ test case "try finally" success 3
    // --------------------------------------------------------------------------------
    // result|errorcode |test function       |time       |message
    //  pass |0x00000000|test_fail           |0.000000053|__leave2_if_fail
    //  pass |0x00000000|test_trace          |0.000721476|__leave2_trace
    //  pass |0x00000000|test_try_leave      |0.000656350|__leave2_tracef
    // --------------------------------------------------------------------------------
    // # pass 8 fail 3 skip 1 low  1
    // ================================================================================
    // TEST FAILED
    report_unittest(stream);
    // 3 cases failed
    // --------------------------------------------------------------------------------
    // result|errorcode |desc                            |test function       |time       |message
    //  fail |0xef010003|invalid parameter               |function2           |0.000000032|case desc 2 - intentional fail
    //  fail |0xef01001b|failed                          |function6           |0.000000029|case 1 desc 2 - intentional fail
    //  fail |0xef010036|assert_failed                   |function9           |0.000000049|case 2 desc 3 - intentional fail
    // --------------------------------------------------------------------------------
    report_failed(stream);

    report_cases(stream);

    // sort by time (top 5)
    // --------------------------------------------------------------------------------
    // result|errorcode |test function       |time       |message
    //  pass |0x00000000|test_trace          |0.000721476|__leave2_trace
    //  pass |0x00000000|test_try_leave      |0.000656350|__leave2_tracef
    //  skip |0xef010100|function3           |0.000000115|case desc 4
    //  pass |0x00000000|test_unittest       |0.000000103|result
    //  pass |0x00000000|function5           |0.000000100|case 1 desc 1
    // --------------------------------------------------------------------------------
    report_testtime(stream, top_count);

    critical_section_guard guard(_lock);

    //
    // print
    //

    if (_logger) {
        _logger->write(stream);
    } else {
        std::cout << stream;
    }

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

    critical_section_guard guard(_lock);

    console_colored_stream << _concolor.turnon().set_style(console_style_t::bold);
    stream.fill(80, '=');
    stream << "\n";
    console_colored_stream << _concolor.set_fgcolor(fgcolor) << constexpr_report;
    stream << "\n";

    for (const auto& testcase : _test_list) {
        unittest_map_t::iterator map_iter = _test_map.find(testcase);
        const test_status_t& status = map_iter->second;

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
        if (status._test_stat._count_trivial) {
            stream << " ";
            cprint(console_colored_stream, _concolor, console_color_t::yellow, fgcolor, constexpr_trivial);
            stream << " " << status._test_stat._count_trivial;
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
    if (_total._count_trivial) {
        stream << " ";
        cprint(console_colored_stream, _concolor, console_color_t::yellow, fgcolor, constexpr_trivial);
        stream << " " << _total._count_trivial;
    }
    stream << "\n";
    stream.fill(80, '-');
    stream << "\n";
    if (_total._count_fail) {
        constexpr char constexpr_testfail[] = "TEST FAILED";
        cprint(console_colored_stream, _concolor, console_color_t::red, fgcolor, constexpr_testfail);
        stream << "\n";
    }

    console_colored_stream << _concolor.turnoff();
}

void test_case::report_cases(basic_stream& stream) {
    t_stream_binder<basic_stream, console_color> console_colored_stream(stream);
    console_color_t fgcolor = console_color_t::white;

    //
    // compose
    //

    constexpr char constexpr_brief[] = "brief";
    constexpr char constexpr_case[] = "case";

    critical_section_guard guard(_lock);

    console_colored_stream << _concolor.turnon().set_style(console_style_t::bold);

    stream << constexpr_brief << "\n";
    stream << constexpr_pass << " " << constexpr_fail << " " << constexpr_skip << " " << constexpr_trivial << " " << constexpr_case << "\n";

    for (const auto& testcase : _test_list) {
        unittest_map_t::iterator map_iter = _test_map.find(testcase);
        const test_status_t& status = map_iter->second;

        console_colored_stream << _concolor.turnon();
        if (status._test_stat._count_fail) {
            console_colored_stream << _concolor.set_fgcolor(console_color_t::red);
        } else if (status._test_stat._count_not_supported) {
            console_colored_stream << _concolor.set_fgcolor(console_color_t::cyan);
        } else if (status._test_stat._count_trivial) {
            console_colored_stream << _concolor.set_fgcolor(console_color_t::yellow);
        } else {
            console_colored_stream << _concolor.set_fgcolor(console_color_t::white);
        }

        stream.printf("%4i %4i %4i %4i %s\n", status._test_stat._count_success, status._test_stat._count_fail, status._test_stat._count_not_supported,
                      status._test_stat._count_trivial, testcase.c_str());

        console_colored_stream << _concolor.set_fgcolor(console_color_t::white);
    }

    stream.fill(80, '-');
    stream << "\n";

    console_colored_stream << _concolor.turnoff();
}

void test_case::report_failed(basic_stream& stream) {
    t_stream_binder<basic_stream, console_color> console_colored_stream(stream);

    error_advisor* advisor = error_advisor::get_instance();
    critical_section_guard guard(_lock);

    unittest_list_t array;

    unsigned int field_nsec = (RTL_FIELD_SIZE(struct timespec, tv_nsec) << 3);
    console_colored_stream << _concolor.turnon().set_style(console_style_t::bold);

    for (const auto& pair : _test_map) {
        for (const auto& item : pair.second._test_list) {
            auto category = advisor->categoryof(item._result);
            if (error_category_severe == category) {
                array.push_back(item);
            }
        }
    }

    // dump
    if (array.size()) {
        constexpr char constexpr_failed[] = " case";
        stream << array.size() << constexpr_failed;
        if (array.size() > 1) {
            stream << "s";
        }
        stream << " failed\n";

        // stream.fill(80, '-');
        // stream << "\n";

        dump_list_into_stream(array, stream, testcase_dump_t::testcase_dump_error);

        stream.fill(80, '-');
        stream << "\n";
    }

    console_colored_stream << _concolor.turnoff();
}

void test_case::report_testtime(basic_stream& stream, uint32 top_count) {
    t_stream_binder<basic_stream, console_color> console_colored_stream(stream);

    critical_section_guard guard(_lock);

    // collect pointers to avoid copying unittest_item_t (can be large due to strings).
    std::vector<const unittest_item_t*> items;
    console_colored_stream << _concolor.turnon().set_style(console_style_t::bold);

    for (const auto& pair : _test_map) {
        for (const auto& testitem : pair.second._test_list) {
            items.push_back(&testitem);
        }
    }

    auto by_time_desc = [](const unittest_item_t* a, const unittest_item_t* b) {
        if (a->_time.tv_sec != b->_time.tv_sec) {
            return a->_time.tv_sec > b->_time.tv_sec;
        }
        return a->_time.tv_nsec > b->_time.tv_nsec;
    };

    // top N
    // Note: default is (uint32)-1 meaning "all".
    if ((static_cast<uint32>(-1) != top_count) && (items.size() > top_count)) {
        std::nth_element(items.begin(), items.begin() + top_count, items.end(), by_time_desc);
        items.resize(top_count);
    }
    std::sort(items.begin(), items.end(), by_time_desc);

    // dump and cout
    if (items.size()) {
        constexpr char constexpr_timesort[] = "sort by time (top %zi)\n";
        stream.printf(constexpr_timesort, items.size());

        stream.fill(80, '-');
        stream << "\n";

        unittest_list_t array;
        for (const auto* p : items) {
            array.push_back(*p);  // dump_list_into_stream expects a list of values
        }
        dump_list_into_stream(array, stream);

        stream.fill(80, '-');
        stream << "\n";
    }

    console_colored_stream << _concolor.turnoff();
}

return_t test_case::result() { return _total._count_fail > 0 ? errorcode_t::internal_error : errorcode_t::success; }

void test_case::lock() { _lock.enter(); }

void test_case::unlock() { _lock.leave(); }

void test_case::attach(logger* log) { _logger = log; }

}  // namespace hotplace
