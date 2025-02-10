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
#include <iostream>
#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/system/datetime.hpp>
#include <sdk/base/unittest/logger.hpp>
#include <sdk/base/unittest/testcase.hpp>

namespace hotplace {

logger::logger()
    : _thread(nullptr),
      _run(true),
      _style(normal),
      _fgcolor(white),
      _bgcolor(black),
      _log_level(loglevel_t::loglevel_trace),
      _implicit_level(loglevel_t::loglevel_trace),
      _test_case(nullptr) {}

logger::~logger() { clear(); }

logger& logger::set_loglevel(loglevel_t level) {
    _log_level = level;
    return *this;
}

logger& logger::set_implicit_loglevel(loglevel_t level) {
    _implicit_level = level;
    return *this;
}

void logger::clear() {
    stop_consumer();

    critical_section_guard guard(_lock);

    flush();

    for (auto item : _logger_stream_map) {
        item.second->release();
    }
    _logger_stream_map.clear();
}

void logger::start_consumer() {
    if (test_logging_file()) {
        _thread = new thread(consumer, this);
        _thread->start();
    }
}

void logger::stop_consumer() {
    if (_thread) {
        {
            critical_section_guard guard(_lock);
            _run = false;
        }
        _thread->join();
        delete _thread;
        _thread = nullptr;
    }
}

return_t logger::consumer(void* param) {
    return_t ret = errorcode_t::success;
    logger* inst = (logger*)param;
    uint16 interval = 100;
    {
        critical_section_guard guard(inst->_lock);
        interval = inst->_keyvalue.get(logger_t::logger_interval);
    }
    while (1) {
        {
            critical_section_guard guard(inst->_lock);
            if (false == inst->_run) {
                break;
            }
        }
        inst->flush(true);
        msleep(interval);
    }
    return ret;
}

logger::logger_item* logger::get_context(bool upref) {
    arch_t tid = get_thread_id();
    logger_item* item = nullptr;

    critical_section_guard guard(_lock);

    // stream per thread
    logger_stream_map_t::iterator iter = _logger_stream_map.find(tid);
    if (_logger_stream_map.end() == iter) {
        _logger_stream_map.insert(std::make_pair(tid, item = new logger_item));
    } else {
        item = iter->second;
    }

    if (upref) {
        item->addref();
    }

    return item;
}

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

logger& logger::writeln(const char* fmt, ...) {
    if (test_loglevel()) {
        va_list ap;
        va_start(ap, fmt);
        do_write_vprintf(fmt, ap, true);
        va_end(ap);
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
        do_dump(&msg[0], msg.size(), hexpart, indent);
    }
    return *this;
}

logger& logger::dump(const binary& msg, unsigned hexpart, unsigned indent) {
    if (test_loglevel()) {
        do_dump(&msg.get()[0], msg.get().size(), hexpart, indent);
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
        do_dump(&msg[0], msg.size(), hexpart, indent);
    }
    return *this;
}

logger& logger::dump(loglevel_t level, const binary& msg, unsigned hexpart, unsigned indent) {
    if (test_loglevel(level)) {
        do_dump(&msg.get()[0], msg.get().size(), hexpart, indent);
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
        do_hdump(header, &msg[0], msg.size(), hexpart, indent);
    }
    return *this;
}

logger& logger::hdump(const std::string& header, const binary& msg, unsigned hexpart, unsigned indent) {
    if (test_loglevel()) {
        do_hdump(header, &msg.get()[0], msg.get().size(), hexpart, indent);
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
        do_hdump(header, &msg[0], msg.size(), hexpart, indent);
    }
    return *this;
}

logger& logger::hdump(loglevel_t level, const std::string& header, const binary& msg, unsigned hexpart, unsigned indent) {
    if (test_loglevel(level)) {
        do_hdump(header, &msg.get()[0], msg.get().size(), hexpart, indent);
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

logger& logger::operator<<(const char* msg) {
    if (test_loglevel()) {
        do_write_raw(msg, msg ? strlen(msg) : 0, false);
    }
    return *this;
}

logger& logger::operator<<(const std::string& msg) {
    if (test_loglevel()) {
        do_write_raw(msg.c_str(), msg.size(), false);
    }
    return *this;
}

logger& logger::operator<<(const basic_stream& msg) {
    if (test_loglevel()) {
        do_write_raw(msg.c_str(), msg.size(), false);
    }
    return *this;
}

bool logger::test_logging_stdout() {
    critical_section_guard guard(_lock);
    return _keyvalue.get(logger_t::logger_stdout) ? true : false;
}

bool logger::test_logging_file() {
    critical_section_guard guard(_lock);
    uint16 do_file = _keyvalue.get(logger_t::logger_file);
    std::string logfile = _skeyvalue.get("logfile");
    if (do_file && logfile.empty()) {
        do_file = 0;
    }
    return do_file ? true : false;
}

logger& logger::do_console(std::function<void(logger_item*)> f) {
    std::string datefmt;
    {
        critical_section_guard guard(_lock);
        datefmt = _skeyvalue.get("datefmt");
    }

    logger_item* item = get_context();
    if (item) {
        if (false == datefmt.empty()) {
            datetime dt;
            dt.format(1, item->bs, datefmt);
        }

        f(item);

        stdout_handler(item->bs);
        item->bs.clear();

        item->release();
    }

    return *this;
}

logger& logger::do_console_vprintf(const char* fmt, va_list ap, bool lf) {
    auto lambda = [&](logger_item* item) -> void {
        item->bs.vprintf(fmt, ap);
        if (lf) {
            item->bs.printf("\n");
        }
    };
    return do_console(lambda);
}

logger& logger::do_console_raw(const char* buf, size_t bufsize, bool lf) {
    auto lambda = [&](logger_item* item) -> void {
        item->bs.write(buf, bufsize);
        if (lf) {
            item->bs.printf("\n");
        }
    };
    return do_console(lambda);
}

logger& logger::do_console_stream(stream_t* s, bool lf) {
    auto lambda = [&](logger_item* item) -> void {
        if (s) {
            item->bs.write(s->data(), s->size());
            if (lf) {
                item->bs.printf("\n");
            }
        }
    };
    return do_console(lambda);
}

logger& logger::do_write(std::function<void(logger_item*)> f) {
    std::string datefmt;
    {
        critical_section_guard guard(_lock);
        datefmt = _skeyvalue.get("datefmt");
    }
    if (test_logging_stdout() || test_logging_file()) {
        logger_item* item = get_context();
        if (item) {
            if (false == datefmt.empty()) {
                datetime dt;
                dt.format(1, item->bs, datefmt);
            }

            f(item);

            touch(item);
            item->release();
        }
    }
    return *this;
}

logger& logger::do_write_vprintf(const char* fmt, va_list ap, bool lf) {
    auto lambda = [&](logger_item* item) -> void {
        item->bs.vprintf(fmt, ap);
        if (lf) {
            item->bs.printf("\n");
        }
    };
    return do_write(lambda);
}

logger& logger::do_write_raw(const char* buf, size_t bufsize, bool lf) {
    auto lambda = [&](logger_item* item) -> void {
        item->bs.write(buf, bufsize);
        if (lf) {
            item->bs.printf("\n");
        }
    };
    return do_write(lambda);
}

logger& logger::do_write_stream(stream_t* s, bool lf) {
    auto lambda = [&](logger_item* item) -> void {
        if (s) {
            item->bs.write(s->data(), s->size());
            if (lf) {
                item->bs.printf("\n");
            }
        }
    };
    return do_write(lambda);
}

logger& logger::do_dump(const byte_t* addr, size_t size, unsigned hexpart, unsigned indent) {
    if (addr) {
        auto lambda = [&](logger_item* item) -> void { dump_memory(addr, size, &item->bs, hexpart, indent, 0, dump_memory_flag_t::dump_notrunc); };
        do_write(lambda);
    }
    return *this;
}

logger& logger::do_hdump(const std::string& header, const byte_t* addr, size_t size, unsigned hexpart, unsigned indent) {
    if (addr) {
        auto lambda = [&](logger_item* item) -> void {
            item->bs.printf("%s\n", header.c_str());
            dump_memory(addr, size, &item->bs, hexpart, indent, 0, dump_memory_flag_t::dump_notrunc);
        };
        do_write(lambda);
    }
    return *this;
}

void logger::stdout_handler(const basic_stream& bs) {
    critical_section_guard guard(_lock);  // lock

    std::cout << bs;
    fflush(stdout);
}

logger& logger::touch(logger_item* item) {
    time_t now = time(nullptr);
    uint16 flush_time = 0;
    uint16 flush_size = 0;

    basic_stream& bs = item->bs;

    if (bs.size()) {
        if (test_logging_stdout()) {
            stdout_handler(bs);
        }
        if (test_logging_file()) {
            item->delayed << bs;  // concurrency - using basic_stream lock (bufferio specific)
        }
        bs.clear();
    }

    return *this;
}

logger& logger::flush(bool check) {
    time_t now = time(nullptr);
    logger_stream_map_t::iterator iter;

    critical_section_guard guard(_lock);  // lock

    uint16 flush_time = _keyvalue.get(logger_t::logger_flush_time);
    uint16 flush_size = _keyvalue.get(logger_t::logger_flush_size);
    std::string logfile = _skeyvalue.get("logfile");

    for (auto& pair : _logger_stream_map) {
        logger_item* item = pair.second;
        basic_stream& bs = item->delayed;
        bool cond = true;
        if (bs.size()) {
            if (check) {
                auto size = bs.size();
                auto cond1 = (now - item->timestamp >= flush_time) && size;
                auto cond2 = (size >= flush_size);
                cond = cond1 || cond2;
            }
            if (cond) {
                std::ofstream file(logfile.c_str(), std::ios::out | std::ios::app);
                file << bs.c_str();
                file.close();

                bs.clear();
                item->timestamp = now;
            }
        }
    }
    return *this;
}

logger& logger::setcolor(console_style_t style, console_color_t fgcolor, console_color_t bgcolor) {
    _style = style;
    _fgcolor = fgcolor;
    _bgcolor = bgcolor;
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

logger& logger::do_color_write_vprintf(const char* fmt, va_list ap, bool lf) {
    auto lambda = [&](logger_item* item) -> void {
        console_color color;
        color.set_style(_style).set_fgcolor(_fgcolor).set_bgcolor(_bgcolor);
        color.printf(&item->bs);
        item->bs.vprintf(fmt, ap);
        color.turnoff();
        color.printf(&item->bs);
        if (lf) {
            item->bs.printf("\n");
        }
    };
    return do_write(lambda);
}

logger& logger::do_color_write_raw(const char* buf, size_t bufsize, bool lf) {
    auto lambda = [&](logger_item* item) -> void {
        console_color color;
        color.set_style(_style).set_fgcolor(_fgcolor).set_bgcolor(_bgcolor);
        color.printf(&item->bs);
        item->bs.write(buf, bufsize);
        color.turnoff();
        color.printf(&item->bs);
        if (lf) {
            item->bs.printf("\n");
        }
    };
    return do_write(lambda);
}

logger& logger::do_color_write_stream(stream_t* s, bool lf) {
    auto lambda = [&](logger_item* item) -> void {
        if (s) {
            console_color color;
            color.set_style(_style).set_fgcolor(_fgcolor).set_bgcolor(_bgcolor);
            color.printf(&item->bs);
            item->bs.write(s->data(), s->size());
            color.turnoff();
            color.printf(&item->bs);
            if (lf) {
                item->bs.printf("\n");
            }
        }
    };
    return do_write(lambda);
}

bool logger::test_loglevel(loglevel_t level) { return level >= _log_level; }

bool logger::test_loglevel() { return _implicit_level >= _log_level; }

logger& logger::attach(test_case* testcase) {
    if (testcase) {
        testcase->attach(this);
    }
    return *this;
}

}  // namespace hotplace
