/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <sdk/base/unittest/logger.hpp>

namespace hotplace {

logger_builder::logger_builder() {
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

logger* logger_builder::build() {
    logger* p = nullptr;
    __try_new_catch_only(p, new logger);
    if (p) {
        p->_keyvalue = _keyvalue;
        p->_skeyvalue = _skeyvalue;
        p->start_consumer();
    }
    return p;
}

}  // namespace hotplace
