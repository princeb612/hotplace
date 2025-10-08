/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * Comments
 *  logger_stdout       test
 *  logger_file         test
 *  logger_interval     test
 *  logger_flush_time   test
 *  logger_flush_size   test
 *  logger_rotate_size  not_yet
 *  logger_max_file     not_yet
 *  datefmt             test
 */

#include <fstream>
#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/system/datetime.hpp>
#include <hotplace/sdk/base/unittest/logger.hpp>
#include <hotplace/sdk/base/unittest/testcase.hpp>
#include <iostream>

namespace hotplace {

// after dump_memory(..., &bs);
//      p bs.c_str()
//      "00000000 : FF 40 88 25 A8 49 E9 5B A9 7D 7F 89 25 A8 49 E9 | .@.%.I.[.}..%.I."
// but, after vprintf, output is as follows
//      "00000000 : FF 40 88 25 A8 49 E9 5B A9 7D 7F 89 25 A8 49 E9 | .@.6290232.[.}..6290128."
// for std::string and basic_stream, use write, not printf nor vprintf

logger& logger::consoleln(const char* fmt, ...) {
    if (test_loglevel()) {
        va_list ap;
        va_start(ap, fmt);
        do_console_vprintf(fmt, ap, true);
        va_end(ap);
    }
    return *this;
}

logger& logger::consoleln(const std::string& msg) {
    if (test_loglevel()) {
        do_console_raw(msg.c_str(), msg.size(), true);
    }
    return *this;
}

logger& logger::consoleln(const basic_stream& msg) {
    if (test_loglevel()) {
        do_console_raw(msg.c_str(), msg.size(), true);
    }
    return *this;
}

logger& logger::consoleln(stream_t* s) {
    if (test_loglevel()) {
        do_console_stream(s, true);
    }
    return *this;
}

logger& logger::consoleln(std::function<void(basic_stream& bs)> f) {
    if (f) {
        basic_stream bs;
        f(bs);
        colorln(bs);
    }
    return *this;
}

logger& logger::consoleln(loglevel_t level, const char* fmt, ...) {
    if (test_loglevel(level)) {
        va_list ap;
        va_start(ap, fmt);
        do_console_vprintf(fmt, ap, true);
        va_end(ap);
    }
    return *this;
}

logger& logger::consoleln(loglevel_t level, const std::string& msg) {
    if (test_loglevel(level)) {
        do_console_raw(msg.c_str(), msg.size(), true);
    }
    return *this;
}

logger& logger::consoleln(loglevel_t level, const basic_stream& msg) {
    if (test_loglevel(level)) {
        do_console_raw(msg.c_str(), msg.size(), true);
    }
    return *this;
}

logger& logger::consoleln(loglevel_t level, stream_t* s) {
    if (test_loglevel(level)) {
        do_console_stream(s, true);
    }
    return *this;
}

logger& logger::consoleln(loglevel_t level, std::function<void(basic_stream& bs)> f) {
    if (f) {
        basic_stream bs;
        f(bs);
        colorln(bs);
    }
    return *this;
}

logger& logger::write(const char* fmt, ...) {
    if (test_loglevel()) {
        va_list ap;
        va_start(ap, fmt);
        do_write_vprintf(fmt, ap);
        va_end(ap);
    }
    return *this;
}

logger& logger::write(const std::string& msg) {
    if (test_loglevel()) {
        do_write_raw(msg.c_str(), msg.size(), false);
    }
    return *this;
}

logger& logger::write(const basic_stream& msg) {
    if (test_loglevel()) {
        do_write_raw(msg.c_str(), msg.size(), false);
    }
    return *this;
}

logger& logger::write(stream_t* s) {
    if (test_loglevel()) {
        do_write_stream(s, false);
    }
    return *this;
}

logger& logger::write(loglevel_t level, const char* fmt, ...) {
    if (test_loglevel(level)) {
        va_list ap;
        va_start(ap, fmt);
        do_write_vprintf(fmt, ap);
        va_end(ap);
    }
    return *this;
}

logger& logger::write(loglevel_t level, const std::string& msg) {
    if (test_loglevel(level)) {
        do_write_raw(msg.c_str(), msg.size(), false);
    }
    return *this;
}

logger& logger::write(loglevel_t level, const basic_stream& msg) {
    if (test_loglevel(level)) {
        do_write_raw(msg.c_str(), msg.size(), false);
    }
    return *this;
}

logger& logger::write(loglevel_t level, stream_t* s) {
    if (test_loglevel(level)) {
        do_write_stream(s, false);
    }
    return *this;
}

logger& logger::write(std::function<void(basic_stream& bs)> f) {
    if (f) {
        basic_stream bs;
        f(bs);
        write(bs);
    }
    return *this;
}

logger& logger::write(loglevel_t level, std::function<void(basic_stream& bs)> f) {
    if (f) {
        basic_stream bs;
        f(bs);
        write(level, bs);
    }
    return *this;
}

logger& logger::writeln(const char* fmt, ...) {
    if (test_loglevel()) {
        va_list ap;
        va_start(ap, fmt);
        do_write_vprintf(fmt, ap, true);
        va_end(ap);
    }
    return *this;
}

logger& logger::writeln(const std::string& msg) {
    if (test_loglevel()) {
        do_write_raw(msg.c_str(), msg.size(), true);
    }
    return *this;
}

logger& logger::writeln(const basic_stream& msg) {
    if (test_loglevel()) {
        do_write_raw(msg.c_str(), msg.size(), true);
    }
    return *this;
}

logger& logger::writeln(stream_t* s) {
    if (test_loglevel()) {
        do_write_stream(s, true);
    }
    return *this;
}

logger& logger::writeln(loglevel_t level, const char* fmt, ...) {
    if (test_loglevel(level)) {
        va_list ap;
        va_start(ap, fmt);
        do_write_vprintf(fmt, ap, true);
        va_end(ap);
    }
    return *this;
}

logger& logger::writeln(loglevel_t level, const std::string& msg) {
    if (test_loglevel(level)) {
        do_write_raw(msg.c_str(), msg.size(), true);
    }
    return *this;
}

logger& logger::writeln(loglevel_t level, const basic_stream& msg) {
    if (test_loglevel(level)) {
        do_write_raw(msg.c_str(), msg.size(), true);
    }
    return *this;
}

logger& logger::writeln(loglevel_t level, stream_t* s) {
    if (test_loglevel(level)) {
        do_write_stream(s, true);
    }
    return *this;
}

logger& logger::writeln(std::function<void(basic_stream& bs)> f) {
    if (f) {
        basic_stream bs;
        f(bs);
        writeln(bs);
    }
    return *this;
}

logger& logger::writeln(loglevel_t level, std::function<void(basic_stream& bs)> f) {
    if (f) {
        basic_stream bs;
        f(bs);
        writeln(level, bs);
    }
    return *this;
}

logger& logger::colorln(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    do_color_write_vprintf(fmt, ap, true);
    va_end(ap);
    return *this;
}

logger& logger::colorln(const std::string& msg) { return do_color_write_raw(msg.c_str(), msg.size(), true); }

logger& logger::colorln(const basic_stream& msg) { return do_color_write_raw(msg.c_str(), msg.size(), true); }

logger& logger::colorln(stream_t* s) { return do_color_write_stream(s, true); }

logger& logger::colorln(std::function<void(basic_stream& bs)> f) {
    if (f) {
        basic_stream bs;
        f(bs);
        colorln(bs);
    }
    return *this;
}

}  // namespace hotplace
