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

logger_builder& logger_builder::set_format(const std::string& fmt) {
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

logger::logger() : _thread(nullptr), _run(true) {}

logger::~logger() { clear(); }

void logger::clear() {
    critical_section_guard guard(_lock);

    stop_consumer();

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
        _run = false;
        _thread->wait(-1);
        _thread->join(_thread->gettid());
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
    while (inst->_run) {
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
    va_list ap;
    va_start(ap, fmt);
    do_console_vprintf(fmt, ap, true);
    va_end(ap);
    return *this;
}

logger& logger::consoleln(const std::string& msg) { return do_console_raw(msg.c_str(), msg.size(), true); }

logger& logger::consoleln(const basic_stream& msg) { return do_console_raw(msg.c_str(), msg.size(), true); }

logger& logger::writeln(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    do_write_vprintf(fmt, ap, true);
    va_end(ap);
    return *this;
}

logger& logger::writeln(const std::string& msg) { return do_write_raw(msg.c_str(), msg.size(), true); }

logger& logger::writeln(const basic_stream& msg) { return do_write_raw(msg.c_str(), msg.size(), true); }

logger& logger::write(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    do_write_vprintf(fmt, ap);
    va_end(ap);
    return *this;
}

logger& logger::write(const std::string& msg) { return do_write_raw(msg.c_str(), msg.size(), false); }

logger& logger::write(const basic_stream& msg) { return do_write_raw(msg.c_str(), msg.size(), false); }

logger& logger::dump(const byte_t* addr, size_t size, unsigned hexpart, unsigned indent) { return do_dump(addr, size, hexpart, indent, true); }

logger& logger::dump(const char* addr, size_t size, unsigned hexpart, unsigned indent) { return do_dump((byte_t*)addr, size, hexpart, indent, true); }

logger& logger::dump(const binary_t& msg, unsigned hexpart, unsigned indent) { return do_dump(&msg[0], msg.size(), hexpart, indent, true); }

logger& logger::hdump(const std::string& header, const byte_t* addr, size_t size, unsigned hexpart, unsigned indent) {
    return do_hdump(header, addr, size, hexpart, indent, true);
}

logger& logger::hdump(const std::string& header, const char* addr, size_t size, unsigned hexpart, unsigned indent) {
    return do_hdump(header, (byte_t*)addr, size, hexpart, indent, true);
}

logger& logger::hdump(const std::string& header, const binary_t& msg, unsigned hexpart, unsigned indent) {
    return do_hdump(header, &msg[0], msg.size(), hexpart, indent, true);
}

logger& logger::operator<<(const std::string& msg) { return do_write_raw(msg.c_str(), msg.size(), false); }

logger& logger::operator<<(const basic_stream& msg) { return do_write_raw(msg.c_str(), msg.size(), false); }

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
    return do_console([&](logger_item* item) -> void {
        item->bs.vprintf(fmt, ap);
        if (lf) {
            item->bs.printf("\n");
        }
    });
}

logger& logger::do_console_raw(const char* buf, size_t bufsize, bool lf) {
    return do_console([&](logger_item* item) -> void {
        item->bs.write(buf, bufsize);
        if (lf) {
            item->bs.printf("\n");
        }
    });
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
    return do_write([&](logger_item* item) -> void {
        item->bs.vprintf(fmt, ap);
        if (lf) {
            item->bs.printf("\n");
        }
    });
}

logger& logger::do_write_raw(const char* buf, size_t bufsize, bool lf) {
    return do_write([&](logger_item* item) -> void {
        item->bs.write(buf, bufsize);
        if (lf) {
            item->bs.printf("\n");
        }
    });
}

logger& logger::do_dump(const byte_t* addr, size_t size, unsigned hexpart, unsigned indent, bool lf) {
    if (addr) {
        do_write([&](logger_item* item) -> void {
            dump_memory(addr, size, &item->bs, hexpart, indent, 0, dump_memory_flag_t::dump_notrunc);
            if (lf) {
                item->bs.printf("\n");
            }
        });
    }
    return *this;
}

logger& logger::do_hdump(const std::string& header, const byte_t* addr, size_t size, unsigned hexpart, unsigned indent, bool lf) {
    if (addr) {
        do_write([&](logger_item* item) -> void {
            item->bs.printf("%s\n", header.c_str());
            dump_memory(addr, size, &item->bs, hexpart, indent, 0, dump_memory_flag_t::dump_notrunc);
            if (lf) {
                item->bs.printf("\n");
            }
        });
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

    for (iter = _logger_stream_map.begin(); iter != _logger_stream_map.end(); iter++) {
        logger_item* item = iter->second;
        basic_stream& bs = item->delayed;
        bool cond = true;
        if (bs.size()) {
            if (check) {
                cond = (bs.size() >= flush_size) && (now - item->timestamp >= flush_time);
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

}  // namespace hotplace
