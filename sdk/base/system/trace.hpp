/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   trace.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_TRACE__
#define __HOTPLACE_SDK_BASE_SYSTEM_TRACE__

#include <functional>
#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/stream/types.hpp>
#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/base/trace.hpp>
#include <list>

namespace hotplace {

/**
 * @brief   leave
 *      // leave a trace
 *      ret = do_something ();
 *      if (errorcode_t::success != ret) {
 *          __leave2_trace(x);
 *      }
 *
 *      // leave if faild
 *      ret = do_something ();
 *      __leave2_if_fail (ret);
 */

/**
 *  DEBUG only
 *  leave_trace_dbg_print(__FILE__, __LINE__, false, ret);
 */
void leave_trace_dbg_print(const char* file, unsigned int line, bool bt, return_t ret);
/**
 *  DEBUG only
 *  leave_trace_dbg_printf(__FILE__, __LINE__, false, ret, "%s", message);
 */
void leave_trace_dbg_printf(const char* file, unsigned int line, bool bt, return_t ret, const char* msg, ...);

#if defined DEBUG

#define __trace(x) leave_trace_dbg_print(__FILE__, __LINE__, false, x)
#define __trace_return(x)                                    \
    {                                                        \
        leave_trace_dbg_print(__FILE__, __LINE__, false, x); \
        return x;                                            \
    }
#define __leave2_trace(x)                                    \
    {                                                        \
        leave_trace_dbg_print(__FILE__, __LINE__, false, x); \
        break;                                               \
    }
#define __leave2_tracef(x, ...)                                           \
    {                                                                     \
        leave_trace_dbg_printf(__FILE__, __LINE__, true, x, __VA_ARGS__); \
        break;                                                            \
    }
#define __leave2_if_fail(x)                                 \
    if (errorcode_t::success != x) {                        \
        leave_trace_dbg_print(__FILE__, __LINE__, true, x); \
        break;                                              \
    }

#else

#define __trace(x)
#define __trace_return(x) return x
#define __leave2_trace(x) break
#define __leave2_tracef(x, ...) break
#define __leave2_if_fail(x)          \
    if (errorcode_t::success != x) { \
        break;                       \
    }

#endif

/**
 * @brief trace/debug
 * @sample
 *          void debug_handler(trace_category_t category, trace_event_t event, stream_t* s) {
 *              std::string ct;
 *              std::string ev;
 *              basic_stream bs;
 *              auto advisor = trace_advisor::get_instance();
 *              advisor->get_names(category, event, ct, ev);
 *              bs.printf("[%s][%s]%.*s", ct.c_str(), ev.c_str(), (unsigned int)s->size(), s->data());
 *              _logger->writeln(bs);
 *          };
 *
 *          void myfunction() {
 *              // do something
 *              basic_stream bs;
 *              bs = "blah blah\n";
 *              trace_debug_event(trace_category_t::trace_category_internal, 0, &bs);
 *          }
 *
 *          set_trace_option(trace_debug);
 *          set_trace_debug(handler);
 */
void set_trace_debug(std::function<void(trace_category_t category, trace_event_t event, stream_t* s)> f);
void trace_debug_event_stream(trace_category_t category, trace_event_t event, stream_t* s);
void trace_debug_event_printf(trace_category_t category, trace_event_t event, const char* fmt, ...);
void trace_debug_event(trace_category_t category, trace_event_t event, std::function<void(basic_stream& bs)> f);
void trace_debug_filter(trace_category_t category, bool filter);
bool trace_debug_filtered(trace_category_t category);
/**
 * @brief trace (only debug build)
 */
bool istraceable();
bool istraceable(trace_category_t category);
bool istraceable(trace_category_t category, loglevel_t level);
/**
 * @remarks the higher level, the more informations
 * @param int8 level [in] see loglevel_t
 *                        loglevel_trace(0)
 *                        loglevel_debug(2)
 * @sample
 *          if (check_trace_level(loglevel_t::loglevel_debug) && istraceable()) { do_something(); }
 */
bool check_trace_level(loglevel_t level);
void set_trace_level(loglevel_t level);

/**
 * @sample
 *          std::string ct;
 *          std::string ev;
 *          basic_stream bs;
 *          auto advisor = trace_advisor::get_instance();
 *          advisor->get_names(category, event, ct, ev);
 */
class trace_advisor {
   public:
    static trace_advisor* get_instance();
    void load();

    std::string nameof_category(trace_category_t category);
    void get_names(trace_category_t category, trace_event_t event, std::string& cvalue, std::string& evalue);

   protected:
    trace_advisor();

   private:
    critical_section _lock;
    static trace_advisor _instance;

    typedef std::map<trace_event_t, std::string> event_map_t;
    struct events {
        std::string cname;
        event_map_t event_map;
    };
    typedef std::map<trace_category_t, events> resource_map_t;
    resource_map_t _resource_map;
};

}  // namespace hotplace

#endif
