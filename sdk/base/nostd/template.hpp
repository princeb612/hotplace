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

#ifndef __HOTPLACE_SDK_BASE_NOSTD_TEMPLATE__
#define __HOTPLACE_SDK_BASE_NOSTD_TEMPLATE__

#include <algorithm>
#include <functional>
#include <sdk/base/basic/types.hpp>
#include <set>

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

/**
 * @brief   util
 * @sample
 *          std::list<int> result = {1, 2, 3};
 *          basic_stream bs;
 *          print<std::list<int>, basic_stream>(result, bs);
 *          std::cout << bs << std::endl; // [1, 2, 3]
 *
 *          std::set<int> result = {2, 3, 4};
 *          basic_stream bs;
 *          print<std::set<int>, basic_stream>(result, bs);
 *          std::cout << bs << std::endl; // [2, 3, 4]
 */
template <typename container_t, typename stream_type>
void print(const container_t& c, stream_type& s, const std::string& mark_prologue = "[", const std::string& mark_delimiter = ", ",
           const std::string& mark_epilogue = "]") {
    auto lambda = [&](typename container_t::const_iterator iter, int where) -> void {
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
    for_each_const<container_t>(c, lambda);
}

template <typename container_t, typename stream_type>
void print_pair(const container_t& c, stream_type& s, const std::string& mark_prologue = "[", const std::string& mark_delimiter = ", ",
                const std::string& mark_epilogue = "]") {
    auto lambda = [&](typename container_t::const_iterator iter, int where) -> void {
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
    for_each_const<container_t>(c, lambda);
}

/**
 * @brief   util
 * @sample
 *          typedef std::unordered_map<BT, trienode*> children_t;
 *          auto handler = [&](typename children_t::const_iterator iter, basic_stream& bs) -> void {
 *              bs.printf("%c, %p", iter->first, iter->second);
 *          };
 *          print_pair<children_t, basic_stream>(node->children, bs, handler);
 *          _logger->writeln("children : %s", bs.c_str());
 */
template <typename container_t, typename stream_type>
void print_pair(const container_t& c, stream_type& s, std::function<void(typename container_t::const_iterator, stream_type&)> f,
                const std::string& mark_prologue = "[", const std::string& mark_delimiter = ", ", const std::string& mark_epilogue = "]") {
    auto lambda = [&](typename container_t::const_iterator iter, int where) -> void {
        switch (where) {
            case seek_t::seek_begin:
                s << mark_prologue << "{";
                f(iter, s);
                s << "}";
                break;
            case seek_t::seek_move:
                s << mark_delimiter << "{";
                f(iter, s);
                s << "}";
                break;
            case seek_t::seek_end:
                s << mark_epilogue;
                break;
        }
    };
    for_each_const<container_t>(c, lambda);
}

/**
 * @brief   find_lessthan_or_equal
 */
template <typename T>
void find_lessthan_or_equal(std::set<T>& container, const T& point, T& value) {
    auto iter = std::lower_bound(container.begin(), container.end(), point);
    if ((container.begin() == iter) && (*iter > point)) {
        value = T();
    } else if ((container.end() == iter) || (*iter > point)) {
        value = *(--iter);
    } else {
        value = *iter;
    }
}

}  // namespace hotplace

#endif
