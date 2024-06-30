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

#ifndef __HOTPLACE_SDK_BASE_NOSTD_CONTAINER__
#define __HOTPLACE_SDK_BASE_NOSTD_CONTAINER__

#include <sdk/base/error.hpp>
//#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>

namespace hotplace {

enum seek_t {
    seek_begin = 0,
    seek_move = 1,
    seek_end = 2,
};

/**
 * @remarks
 *          where  0 seek_begin, 1 seek_set, 2 seek_end
 */

template <typename container_t>
void for_each_const(const container_t& c, typename std::function<void(typename container_t::const_iterator, int)> f) {
    if (c.size()) {
        auto iter = c.begin();
        f(iter++, seek_t::seek_begin);
        while (c.end() != iter) {
            f(iter++, seek_t::seek_move);
        }
        f(c.end(), seek_t::seek_end);
    }
}

template <typename container_t>
void for_each(container_t& c, typename std::function<void(typename container_t::iterator, int)> f) {
    if (c.size()) {
        auto iter = c.begin();
        f(iter++, seek_t::seek_begin);
        while (c.end() != iter) {
            f(iter++, seek_t::seek_move);
        }
        f(c.end(), seek_t::seek_end);
    }
}

template <typename container_t, typename stream_type>
void print(const container_t& c, stream_type& s, const std::string& mark_prologue = "[", const std::string& mark_delimiter = ", ",
           const std::string& mark_epilogue = "]") {
    auto func = [&](typename container_t::const_iterator iter, int where) -> void {
        switch (where) {
            case seek_t::seek_begin:
                s << mark_prologue << *iter;
                break;
            case seek_t::seek_move:
                s << mark_delimiter << *iter;
                break;
            case seek_t::seek_end:
                s << mark_epilogue;
                break;
        }
    };
    for_each_const<container_t>(c, func);
}

template <typename container_t, typename stream_type>
void print_pair(const container_t& c, stream_type& s, const std::string& mark_prologue = "[", const std::string& mark_delimiter = ", ",
                const std::string& mark_epilogue = "]") {
    auto func = [&](typename container_t::const_iterator iter, int where) -> void {
        switch (where) {
            case seek_t::seek_begin:
                s << mark_prologue << "{" << iter->first << "," << iter->second << "}";
                break;
            case seek_t::seek_move:
                s << mark_delimiter << "{" << iter->first << "," << iter->second << "}";
                break;
            case seek_t::seek_end:
                s << mark_epilogue;
                break;
        }
    };
    for_each_const<container_t>(c, func);
}

}  // namespace hotplace

#endif
