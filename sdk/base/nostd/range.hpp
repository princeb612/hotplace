/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   range.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_NOSTD_RANGE__
#define __HOTPLACE_SDK_BASE_NOSTD_RANGE__

#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/system/error.hpp>
#include <type_traits>  // use decay_t to remove const, volatile, reference(&)

namespace hotplace {

template <typename T = size_t>
struct t_range_t {
    T begin;
    T end;
    t_range_t() : begin(0), end(0) {}
    t_range_t(T b, T e) : begin(std::min(b, e)), end(std::max(b, e)) {}
    bool operator<(const t_range_t& other) const {
        bool ret = false;
        if (begin < other.begin) {
            ret = true;
        } else if (begin == other.begin) {
            ret = (end < other.end);
        }
        return ret;
    }
    bool operator==(const t_range_t& other) const { return (begin == other.begin) && (end == other.end); }
    size_t width() {
        size_t ret_value = 0;
        if (begin <= end) {
            ret_value = end - begin;
        } else {
            ret_value = begin - end;
        }
        return ret_value;
    }
};

typedef t_range_t<size_t> range_t;

// @refer   Gemini
struct universal_pairhash {
    template <typename T1, typename T2>
    std::size_t operator()(const std::pair<T1, T2>& p) const {
#if __cplusplus >= 201402L  // c++14
        using P1 = std::decay_t<T1>;
        using P2 = std::decay_t<T2>;
#else
        using P1 = typename std::decay<T1>::type;
        using P2 = typename std::decay<T2>::type;
#endif

        auto h1 = std::hash<P1>{}(p.first);
        auto h2 = std::hash<P2>{}(p.second);

        return h1 ^ (h2 + 0x9e3779b9 + (h1 << 6) + (h1 >> 2));
    }
};

}  // namespace hotplace

namespace std {

// @refer   Gemini
template <>
struct hash<hotplace::range_t> {
    std::size_t operator()(const hotplace::range_t& other) const {
        std::size_t h1 = std::hash<size_t>{}(other.begin);
        std::size_t h2 = std::hash<size_t>{}(other.end);
        return h1 ^ (h2 + 0x9e3779b9);
    }
};

}  // namespace std

#endif
