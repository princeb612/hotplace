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

#ifndef __HOTPLACE_SDK_BASE_BASIC_NOSTD_CONTAINER__
#define __HOTPLACE_SDK_BASE_BASIC_NOSTD_CONTAINER__

#include <deque>
#include <functional>
#include <map>
#include <sdk/base/error.hpp>
#include <sdk/base/stl.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>

namespace hotplace {

template <typename container_t>
void for_each(const container_t& c, typename std::function<void(typename container_t::const_iterator, int)> f) {
    if (c.size()) {
        auto iter = c.begin();
        f(iter++, 0);
        while (c.end() != iter) {
            f(iter++, 1);
        }
        f(c.end(), 2);
    }
}

template <typename container_t, typename stream_type>
void print(const container_t& c, stream_type& s) {
    for_each<container_t>(c, [&](typename container_t::const_iterator iter, int where) -> void {
        switch (where) {
            case 0:
                s << "[" << *iter;
                break;
            case 1:
                s << ", " << *iter;
                break;
            case 2:
                s << "]";
                break;
        }
    });
}

}  // namespace hotplace

#endif
