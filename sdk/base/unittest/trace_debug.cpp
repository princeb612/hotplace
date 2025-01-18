/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>

namespace hotplace {

static std::function<void(trace_category_t category, uint32 event, stream_t* s)> _internal_debug;
static std::map<trace_category_t, bool> _debug_category_filter;

void set_trace_debug(std::function<void(trace_category_t category, uint32 event, stream_t* s)> f) { _internal_debug = f; }

void trace_debug_event(trace_category_t category, uint32 event, stream_t* s) {
    if (s && (trace_debug & get_trace_option()) && (false == trace_debug_filtered(category)) && _internal_debug) {
        _internal_debug(category, event, s);
    }
}

void trace_debug_event(trace_category_t category, uint32 event, const char* fmt, ...) {
    if (fmt && (false == trace_debug_filtered(category))) {
        basic_stream bs;
        va_list ap;

        va_start(ap, fmt);
        bs.vprintf(fmt, ap);
        va_end(ap);

        trace_debug_event(category, event, &bs);
    }
}

void trace_debug_filter(trace_category_t category, bool filter) { _debug_category_filter[category] = filter; }

bool trace_debug_filtered(trace_category_t category) { return _debug_category_filter[category]; }

bool istraceable() {
    bool ret = true;
    // std::function
    // operator bool : checks if a target is contained
    // operator==    : compares a std::function with nullptr
    // operator!=    : (removed in C++20)
    if ((trace_debug & get_trace_option()) && _internal_debug) {
    } else {
        ret = false;
    }
    return ret;
}

bool istraceable(trace_category_t category) { return (istraceable() && (false == trace_debug_filtered(category))); }

}  // namespace hotplace
