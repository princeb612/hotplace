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

#ifndef __HOTPLACE_SDK_BASE_LOGGER__
#define __HOTPLACE_SDK_BASE_LOGGER__

#include <sdk/base/basic/binary.hpp>
#include <sdk/base/basic/console_color.hpp>
#include <sdk/base/basic/keyvalue.hpp>
#include <sdk/base/charset.hpp>
#include <sdk/base/error.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/shared_instance.hpp>
#include <sdk/base/system/thread.hpp>
#include <sdk/base/types.hpp>

namespace hotplace {

/**
 * @brief   logger
 * @remarks
 *          // sketch
 *
 *          t_shared_instance<logger> _logger;
 *
 *          logger_builder builder;
 *          builder.set(logger_t::logger_stdout, 1)
 *                 .set(logger_t::logger_flush_time, 0)
 *                 .set(logger_t::logger_flush_size, 0)
 *                 .set_timeformat("Y-M-D h:m:s.f ");
 *          _logger.make_share(builder.build());
 *
 *          _logger->writeln("logging message ...");
 *
 *          _logger->flush();
 */
enum logger_t {
    logger_stdout = 0,       // stdout
    logger_file = 1,         // outfile
    logger_interval = 2,     // consumer-thread cooltime
    logger_flush_time = 3,   // logger_file
    logger_flush_size = 4,   // logger_file
    logger_rotate_size = 5,  // log-rotate
    logger_max_file = 6,     // keep log files
};

class test_case;
class logger;
class logger_builder {
   public:
    logger_builder();
    logger_builder& set(logger_t key, uint16 value);
    logger_builder& set_timeformat(const std::string& fmt);
    logger_builder& set_logfile(const std::string& filename);
    logger_builder& attach(test_case* testcase);

    logger* build();

   private:
    t_key_value<logger_t, uint16> _keyvalue;
    skey_value _skeyvalue;
    test_case* _testcase;
};

/**
 * @brief   logger
 */
class logger {
    friend class logger_builder;

   private:
    typedef struct _logger_item {
        basic_stream bs;
        basic_stream delayed;
        time_t timestamp;
        t_shared_reference<_logger_item> _ref;

        _logger_item() : timestamp(time(nullptr)) { _ref.make_share(this); }
        void addref() { _ref.addref(); }
        void release() { _ref.delref(); }
    } logger_item;

    typedef std::map<arch_t, logger_item*> logger_stream_map_t;
    typedef std::pair<logger_stream_map_t::iterator, bool> logger_stream_map_pib_t;

    critical_section _lock;
    logger_stream_map_t _logger_stream_map;
    t_key_value<logger_t, uint16> _keyvalue;
    skey_value _skeyvalue;

    thread* _thread;
    bool _run;

    console_style_t _style;
    console_color_t _fgcolor;
    console_color_t _bgcolor;

    loglevel_t _log_level;
    loglevel_t _implicit_level;

    test_case* _test_case;

   public:
    ~logger();

    /**
     * @brief   log level
     * @remarks
     *          default level is loglevel_trace
     * @sample
     *      // implicit log level is loglevel_trace
     *
     *      // implicit log level to loglevel_debug
     *      logger->set_implicit_loglevel(loglevel_debug);
     *      logger->writeln("test");                // loglevel_debug
     *
     *      logger->set_loglevel(loglevel_debug);
     *      logger->writeln("test");                // loglevel_debug == loglevel_debug, log
     *      logger->writeln(loglevel_info, "test"); // loglevel_info  >  loglevel_debug, log
     *
     *      logger->set_loglevel(loglevel_info);
     *      logger->writeln("test");                // loglevel_debug <  loglevel_info, do not log
     *      logger->writeln(loglevel_info, "test"); // loglevel_info  == loglevel_info, log
     */
    logger& set_loglevel(loglevel_t level);
    logger& set_implicit_loglevel(loglevel_t level);

    logger& consoleln(const char* fmt, ...);
    logger& consoleln(const std::string& msg);
    logger& consoleln(const basic_stream& msg);
    logger& consoleln(stream_t* s);

    logger& consoleln(loglevel_t level, const char* fmt, ...);
    logger& consoleln(loglevel_t level, const std::string& msg);
    logger& consoleln(loglevel_t level, const basic_stream& msg);
    logger& consoleln(loglevel_t level, stream_t* s);

    logger& writeln(const char* fmt, ...);
    logger& writeln(const std::string& msg);
    logger& writeln(const basic_stream& msg);
    logger& writeln(stream_t* s);

    logger& writeln(loglevel_t level, const char* fmt, ...);
    logger& writeln(loglevel_t level, const std::string& msg);
    logger& writeln(loglevel_t level, const basic_stream& msg);
    logger& writeln(loglevel_t level, stream_t* s);

    logger& write(const char* fmt, ...);
    logger& write(const std::string& msg);
    logger& write(const basic_stream& msg);
    logger& write(stream_t* s);

    logger& write(loglevel_t level, const char* fmt, ...);
    logger& write(loglevel_t level, const std::string& msg);
    logger& write(loglevel_t level, const basic_stream& msg);
    logger& write(loglevel_t level, stream_t* s);

    logger& dump(const byte_t* addr, size_t size, unsigned hexpart = 16, unsigned indent = 0);
    logger& dump(const char* addr, size_t size, unsigned hexpart = 16, unsigned indent = 0);
    logger& dump(const binary_t& msg, unsigned hexpart = 16, unsigned indent = 0);
    logger& dump(const binary& msg, unsigned hexpart = 16, unsigned indent = 0);
    logger& dump(const std::string& msg, unsigned hexpart = 16, unsigned indent = 0);
    logger& dump(const basic_stream& msg, unsigned hexpart = 16, unsigned indent = 0);

    logger& dump(loglevel_t level, const byte_t* addr, size_t size, unsigned hexpart = 16, unsigned indent = 0);
    logger& dump(loglevel_t level, const char* addr, size_t size, unsigned hexpart = 16, unsigned indent = 0);
    logger& dump(loglevel_t level, const binary_t& msg, unsigned hexpart = 16, unsigned indent = 0);
    logger& dump(loglevel_t level, const binary& msg, unsigned hexpart = 16, unsigned indent = 0);
    logger& dump(loglevel_t level, const std::string& msg, unsigned hexpart = 16, unsigned indent = 0);
    logger& dump(loglevel_t level, const basic_stream& msg, unsigned hexpart = 16, unsigned indent = 0);

    logger& hdump(const std::string& header, const byte_t* addr, size_t size, unsigned hexpart = 16, unsigned indent = 0);
    logger& hdump(const std::string& header, const char* addr, size_t size, unsigned hexpart = 16, unsigned indent = 0);
    logger& hdump(const std::string& header, const binary_t& msg, unsigned hexpart = 16, unsigned indent = 0);
    logger& hdump(const std::string& header, const binary& msg, unsigned hexpart = 16, unsigned indent = 0);
    logger& hdump(const std::string& header, const std::string& msg, unsigned hexpart = 16, unsigned indent = 0);
    logger& hdump(const std::string& header, const basic_stream& msg, unsigned hexpart = 16, unsigned indent = 0);

    logger& hdump(loglevel_t level, const std::string& header, const byte_t* addr, size_t size, unsigned hexpart = 16, unsigned indent = 0);
    logger& hdump(loglevel_t level, const std::string& header, const char* addr, size_t size, unsigned hexpart = 16, unsigned indent = 0);
    logger& hdump(loglevel_t level, const std::string& header, const binary_t& msg, unsigned hexpart = 16, unsigned indent = 0);
    logger& hdump(loglevel_t level, const std::string& header, const binary& msg, unsigned hexpart = 16, unsigned indent = 0);
    logger& hdump(loglevel_t level, const std::string& header, const std::string& msg, unsigned hexpart = 16, unsigned indent = 0);
    logger& hdump(loglevel_t level, const std::string& header, const basic_stream& msg, unsigned hexpart = 16, unsigned indent = 0);

    logger& operator<<(const char* msg);
    logger& operator<<(const std::string& msg);
    logger& operator<<(const basic_stream& msg);

    logger& flush(bool check = false);

    logger& setcolor(console_style_t style = normal, console_color_t fgcolor = white, console_color_t bgcolor = black);
    logger& colorln(const char* fmt, ...);
    logger& colorln(const std::string& msg);
    logger& colorln(const basic_stream& msg);
    logger& colorln(stream_t* s);

    logger& attach(test_case* testcase);

   private:
    logger();
    void clear();

    logger& do_console(std::function<void(logger_item*)> f);
    logger& do_console_vprintf(const char* fmt, va_list ap, bool lf = false);
    logger& do_console_raw(const char* buf, size_t bufsize, bool lf = false);
    logger& do_console_stream(stream_t* s, bool lf = false);

    logger& do_write(std::function<void(logger_item*)> f);
    logger& do_write_vprintf(const char* fmt, va_list ap, bool lf = false);
    logger& do_write_raw(const char* buf, size_t bufsize, bool lf = false);
    logger& do_write_stream(stream_t* s, bool lf = false);

    logger& do_color_write_vprintf(const char* fmt, va_list ap, bool lf = false);
    logger& do_color_write_raw(const char* buf, size_t bufsize, bool lf = false);
    logger& do_color_write_stream(stream_t* s, bool lf = false);

    logger& do_dump(const byte_t* addr, size_t size, unsigned hexpart = 16, unsigned indent = 0);
    logger& do_hdump(const std::string& header, const byte_t* addr, size_t size, unsigned hexpart = 16, unsigned indent = 0);

    void start_consumer();
    void stop_consumer();
    static return_t consumer(void* param);
    logger_item* get_context(bool upref = true);

    void stdout_handler(const basic_stream& bs);
    logger& touch(logger_item* item);

    bool test_logging_stdout();
    bool test_logging_file();
    bool test_loglevel(loglevel_t level);
    bool test_loglevel();
};

}  // namespace hotplace

#endif
