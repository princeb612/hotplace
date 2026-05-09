/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   logger_builder.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <hotplace/sdk/base/nostd/template.hpp>
#include <hotplace/sdk/base/unittest/logger.hpp>

namespace hotplace {

logger_builder::logger_builder() : _testcase(nullptr) {
    _keyvalue.set(logger_t::logger_stdout, 1)
        .set(logger_t::logger_file, 0)
        .set(logger_t::logger_interval, 100)
        .set(logger_t::logger_flush_time, 0)
        .set(logger_t::logger_flush_size, 0);
}

logger_builder& logger_builder::set(logger_t key, uint16 value) {
    _keyvalue.set(key, value);
    return *this;
}

logger_builder& logger_builder::set_timeformat(const std::string& fmt) {
    _skeyvalue.set("datefmt", fmt);
    return *this;
}

logger_builder& logger_builder::set_logfile(const std::string& filename) {
    _keyvalue.set(logger_t::logger_file, 1);
    _skeyvalue.set("logfile", filename);
    return *this;
}

logger_builder& logger_builder::attach(test_case* testcase) {
    _testcase = testcase;
    return *this;
}

logger* logger_builder::build() {
    auto p = new logger();
    p->_keyvalue = _keyvalue;
    p->_skeyvalue = _skeyvalue;
    p->start_consumer();
    if (_testcase) {
        p->attach(_testcase);
    }

    // https://doodlenerd.com/web-tool/figlet-generator
    basic_stream stream;
    stream << ANSI_ESCAPE << "1;" << fgmagenta << "m" << R"( _   _           _             _                       )" << ANSI_ESCAPE << "0m\n";
    stream << ANSI_ESCAPE << "1;" << fgmagenta << "m" << R"(| | | |   ___   | |_   _ __   | |   __ _    ___    ___ )" << ANSI_ESCAPE << "0m\n";
    stream << ANSI_ESCAPE << "1;" << fgmagenta << "m" << R"(| |_| |  / _ \  | __| | '_ \  | |  / _` |  / __|  / _ \)" << ANSI_ESCAPE << "0m\n";
    stream << ANSI_ESCAPE << "1;" << fgmagenta << "m" << R"(|  _  | | (_) | | |_  | |_) | | | | (_| | | (__  |  __/)" << ANSI_ESCAPE << "0m\n";
    stream << ANSI_ESCAPE << "1;" << fgmagenta << "m" << R"(|_| |_|  \___/   \__| | .__/  |_|  \__,_|  \___|  \___|)" << ANSI_ESCAPE << "0m\n";
    stream << ANSI_ESCAPE << "1;" << fgmagenta << "m" << R"(                      |_|                              )" << ANSI_ESCAPE << "0m\n";
    p->consoleln(stream);

    return p;
}

}  // namespace hotplace
