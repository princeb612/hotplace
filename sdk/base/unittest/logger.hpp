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

#include <sdk/base/basic/keyvalue.hpp>
#include <sdk/base/binary.hpp>
#include <sdk/base/error.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/shared_instance.hpp>
#include <sdk/base/system/thread.hpp>

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
 *                 .set_format("Y-M-D h:m:s.f ");
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

class logger;
class logger_builder {
   public:
    logger_builder();
    logger_builder& set(logger_t key, uint16 value);
    logger_builder& set_format(const std::string& fmt);
    logger_builder& set_logfile(const std::string& filename);

    logger* build();

   private:
    t_key_value<logger_t, uint16> _keyvalue;
    t_skey_value<std::string> _skeyvalue;
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
    t_skey_value<std::string> _skeyvalue;

    thread* _thread;
    bool _run;

   public:
    ~logger();

    logger& consoleln(const char* fmt, ...);
    logger& consoleln(const std::string& msg);
    logger& consoleln(const basic_stream& msg);

    logger& writeln(const char* fmt, ...);
    logger& writeln(const std::string& msg);
    logger& writeln(const basic_stream& msg);

    logger& write(const char* fmt, ...);
    logger& write(const std::string& msg);
    logger& write(const basic_stream& msg);

    logger& dump(const byte_t* addr, size_t size, unsigned hexpart = 16, unsigned indent = 0);
    logger& dump(const char* addr, size_t size, unsigned hexpart = 16, unsigned indent = 0);
    logger& dump(const binary_t& msg, unsigned hexpart = 16, unsigned indent = 0);
    logger& dump(const binary& msg, unsigned hexpart = 16, unsigned indent = 0);
    logger& dump(const std::string& msg, unsigned hexpart = 16, unsigned indent = 0);
    logger& dump(const basic_stream& msg, unsigned hexpart = 16, unsigned indent = 0);

    logger& hdump(const std::string& header, const byte_t* addr, size_t size, unsigned hexpart = 16, unsigned indent = 0);
    logger& hdump(const std::string& header, const char* addr, size_t size, unsigned hexpart = 16, unsigned indent = 0);
    logger& hdump(const std::string& header, const binary_t& msg, unsigned hexpart = 16, unsigned indent = 0);
    logger& hdump(const std::string& header, const binary& msg, unsigned hexpart = 16, unsigned indent = 0);
    logger& hdump(const std::string& header, const std::string& msg, unsigned hexpart = 16, unsigned indent = 0);
    logger& hdump(const std::string& header, const basic_stream& msg, unsigned hexpart = 16, unsigned indent = 0);

    logger& operator<<(const char* msg);
    logger& operator<<(const std::string& msg);
    logger& operator<<(const basic_stream& msg);

    logger& flush(bool check = false);

   private:
    logger();
    void clear();

    logger& do_console(std::function<void(logger_item*)> f);
    logger& do_console_vprintf(const char* fmt, va_list ap, bool lf = false);
    logger& do_console_raw(const char* buf, size_t bufsize, bool lf = false);

    logger& do_write(std::function<void(logger_item*)> f);
    logger& do_write_vprintf(const char* fmt, va_list ap, bool lf = false);
    logger& do_write_raw(const char* buf, size_t bufsize, bool lf = false);

    logger& do_dump(const byte_t* addr, size_t size, unsigned hexpart = 16, unsigned indent = 0, bool lf = false);
    logger& do_hdump(const std::string& header, const byte_t* addr, size_t size, unsigned hexpart = 16, unsigned indent = 0, bool lf = false);

    void start_consumer();
    void stop_consumer();
    static return_t consumer(void* param);
    logger_item* get_context(bool upref = true);

    void stdout_handler(const basic_stream& bs);
    logger& touch(logger_item* item);

    bool test_logging_stdout();
    bool test_logging_file();
};

}  // namespace hotplace

#endif
