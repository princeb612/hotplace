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
#include <sdk/base/unittest/traceable.hpp>

namespace hotplace {

traceable::traceable() {}

traceable::traceable(const traceable& rhs) : _df(rhs._df) {}

bool traceable::istraceable() {
    bool ret = true;
    // operator bool : checks if a target is contained
    // operator==    : compares a std::function with nullptr
    // operator!=    : (removed in C++20)
    if (nullptr == _df) {
        ret = false;
    }
    return ret;
}

void traceable::settrace(std::function<void(trace_category_t, uint32, stream_t*)> f) {
    _df = f;
    for (auto item : children) {
        item->settrace(f);
    }
}

void traceable::settrace(traceable* diag) {
    if (diag) {
        _df = diag->_df;
        for (auto item : children) {
            item->settrace(diag);
        }
    }
}

void traceable::traceevent(trace_category_t category, uint32 event, stream_t* s) {
    if (_df) {
        _df(category, event, s);
    }
}

void traceable::traceevent(trace_category_t category, uint32 event, const char* fmt, ...) {
    if (_df) {
        basic_stream bs;
        va_list ap;

        va_start(ap, fmt);
        bs.vprintf(fmt, ap);
        va_end(ap);

        _df(category, event, &bs);
    }
}

void traceable::addchain(traceable* tr) {
    if (tr) {
        children.push_back(tr);
    }
}

}  // namespace hotplace
