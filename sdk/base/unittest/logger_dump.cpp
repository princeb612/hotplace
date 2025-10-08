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

logger& logger::dump(const byte_t* addr, size_t size, unsigned hexpart, unsigned indent) {
    if (test_loglevel()) {
        do_dump(addr, size, hexpart, indent);
    }
    return *this;
}

logger& logger::dump(const char* addr, size_t size, unsigned hexpart, unsigned indent) {
    if (test_loglevel()) {
        do_dump((byte_t*)addr, size, hexpart, indent);
    }
    return *this;
}

logger& logger::dump(const binary_t& msg, unsigned hexpart, unsigned indent) {
    if (test_loglevel()) {
        do_dump(msg.empty() ? nullptr : &msg[0], msg.size(), hexpart, indent);
    }
    return *this;
}

logger& logger::dump(const binary& msg, unsigned hexpart, unsigned indent) {
    if (test_loglevel()) {
        const auto& m = msg.get();
        do_dump(m.empty() ? nullptr : &m[0], m.size(), hexpart, indent);
    }
    return *this;
}

logger& logger::dump(const std::string& msg, unsigned hexpart, unsigned indent) {
    if (test_loglevel()) {
        do_dump((byte_t*)msg.c_str(), msg.size(), hexpart, indent);
    }
    return *this;
}

logger& logger::dump(const basic_stream& msg, unsigned hexpart, unsigned indent) {
    if (test_loglevel()) {
        do_dump(msg.data(), msg.size(), hexpart, indent);
    }
    return *this;
}

logger& logger::dump(loglevel_t level, const byte_t* addr, size_t size, unsigned hexpart, unsigned indent) {
    if (test_loglevel(level)) {
        do_dump(addr, size, hexpart, indent);
    }
    return *this;
}

logger& logger::dump(loglevel_t level, const char* addr, size_t size, unsigned hexpart, unsigned indent) {
    if (test_loglevel(level)) {
        do_dump((byte_t*)addr, size, hexpart, indent);
    }
    return *this;
}

logger& logger::dump(loglevel_t level, const binary_t& msg, unsigned hexpart, unsigned indent) {
    if (test_loglevel(level)) {
        do_dump(msg.empty() ? nullptr : &msg[0], msg.size(), hexpart, indent);
    }
    return *this;
}

logger& logger::dump(loglevel_t level, const binary& msg, unsigned hexpart, unsigned indent) {
    if (test_loglevel(level)) {
        const auto& m = msg.get();
        do_dump(m.empty() ? nullptr : &m[0], m.size(), hexpart, indent);
    }
    return *this;
}

logger& logger::dump(loglevel_t level, const std::string& msg, unsigned hexpart, unsigned indent) {
    if (test_loglevel(level)) {
        do_dump((byte_t*)msg.c_str(), msg.size(), hexpart, indent);
    }
    return *this;
}

logger& logger::dump(loglevel_t level, const basic_stream& msg, unsigned hexpart, unsigned indent) {
    if (test_loglevel(level)) {
        do_dump(msg.data(), msg.size(), hexpart, indent);
    }
    return *this;
}

logger& logger::hdump(const std::string& header, const byte_t* addr, size_t size, unsigned hexpart, unsigned indent) {
    if (test_loglevel()) {
        do_hdump(header, addr, size, hexpart, indent);
    }
    return *this;
}

logger& logger::hdump(const std::string& header, const char* addr, size_t size, unsigned hexpart, unsigned indent) {
    if (test_loglevel()) {
        do_hdump(header, (byte_t*)addr, size, hexpart, indent);
    }
    return *this;
}

logger& logger::hdump(const std::string& header, const binary_t& msg, unsigned hexpart, unsigned indent) {
    if (test_loglevel()) {
        do_hdump(header, msg.empty() ? nullptr : &msg[0], msg.size(), hexpart, indent);
    }
    return *this;
}

logger& logger::hdump(const std::string& header, const binary& msg, unsigned hexpart, unsigned indent) {
    if (test_loglevel()) {
        const auto& m = msg.get();
        do_hdump(header, m.empty() ? nullptr : &m[0], m.size(), hexpart, indent);
    }
    return *this;
}

logger& logger::hdump(const std::string& header, const std::string& msg, unsigned hexpart, unsigned indent) {
    if (test_loglevel()) {
        do_hdump(header, (byte_t*)msg.c_str(), msg.size(), hexpart, indent);
    }
    return *this;
}

logger& logger::hdump(const std::string& header, const basic_stream& msg, unsigned hexpart, unsigned indent) {
    if (test_loglevel()) {
        do_hdump(header, msg.data(), msg.size(), hexpart, indent);
    }
    return *this;
}

logger& logger::hdump(loglevel_t level, const std::string& header, const byte_t* addr, size_t size, unsigned hexpart, unsigned indent) {
    if (test_loglevel(level)) {
        do_hdump(header, addr, size, hexpart, indent);
    }
    return *this;
}

logger& logger::hdump(loglevel_t level, const std::string& header, const char* addr, size_t size, unsigned hexpart, unsigned indent) {
    if (test_loglevel(level)) {
        do_hdump(header, (byte_t*)addr, size, hexpart, indent);
    }
    return *this;
}

logger& logger::hdump(loglevel_t level, const std::string& header, const binary_t& msg, unsigned hexpart, unsigned indent) {
    if (test_loglevel(level)) {
        do_hdump(header, msg.empty() ? nullptr : &msg[0], msg.size(), hexpart, indent);
    }
    return *this;
}

logger& logger::hdump(loglevel_t level, const std::string& header, const binary& msg, unsigned hexpart, unsigned indent) {
    if (test_loglevel(level)) {
        const auto& m = msg.get();
        do_hdump(header, m.empty() ? nullptr : &m[0], m.size(), hexpart, indent);
    }
    return *this;
}

logger& logger::hdump(loglevel_t level, const std::string& header, const std::string& msg, unsigned hexpart, unsigned indent) {
    if (test_loglevel(level)) {
        do_hdump(header, (byte_t*)msg.c_str(), msg.size(), hexpart, indent);
    }
    return *this;
}

logger& logger::hdump(loglevel_t level, const std::string& header, const basic_stream& msg, unsigned hexpart, unsigned indent) {
    if (test_loglevel(level)) {
        do_hdump(header, msg.data(), msg.size(), hexpart, indent);
    }
    return *this;
}

}  // namespace hotplace
