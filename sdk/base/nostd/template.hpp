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
 * @brief   merge overlapping intervals
 * @refer   https://www.geeksforgeeks.org/merging-intervals/
 *          merge all overlapping intervals into one and output the result which should have only mutually exclusive intervals
 *
 *          moi.clear().add(6, 8).add(1, 9).add(2, 4).add(4, 7);
 *          res = moi.merge(); // {1, 9}
 *
 *          moi.clear().add(9, 10, 3).add(6, 8, 2).add(1, 3, 0).add(2, 4, 1).add(1, 8, 4);
 *          res = moi.merge(); // {1, 8, 4}, {9, 10, 3}
 */
template <typename T>
class t_merge_ovl_intervals {
   public:
    struct interval {
        int s;
        int e;
        T t;  // tag

        interval() : s(0), e(0), t(T()) {}
        interval(int s, int e) : s(s), e(e), t(T()) {}
        interval(int s, int e, const T& t) : s(s), e(e), t(t) {}
        interval(int s, int e, T&& t) : s(s), e(e), t(std::move(t)) {}
        interval(const interval& rhs) : s(rhs.s), e(rhs.e), t(rhs.t) {}
        interval(interval&& rhs) : s(rhs.s), e(rhs.e), t(std::move(rhs.t)) {}
        interval& operator=(const interval& rhs) {
            s = rhs.s;
            e = rhs.e;
            t = rhs.t;
            return *this;
        }
        interval& operator=(interval&& rhs) {
            s = rhs.s;
            e = rhs.e;
            t = std::move(rhs.t);
            return *this;
        }
        bool operator==(const interval& rhs) const { return (s == rhs.s) && (e == rhs.e) && (t == rhs.t); }
    };

    static bool compare(const interval& lhs, const interval& rhs) { return lhs.s < rhs.s; }

    t_merge_ovl_intervals() {}

    t_merge_ovl_intervals& add(const interval& t) {
        _arr.push_back(t);
        return *this;
    }
    t_merge_ovl_intervals& add(interval&& t) {
        _arr.push_back(std::move(t));
        return *this;
    }
    t_merge_ovl_intervals& add(int start, int end) {
        _arr.push_back(interval(start, end));
        return *this;
    }
    t_merge_ovl_intervals& add(int start, int end, const T& t) {
        _arr.push_back(interval(start, end, t));
        return *this;
    }
    t_merge_ovl_intervals& add(const range_t& range, const T& t) {
        _arr.push_back(interval(range.begin, range.end, t));
        return *this;
    }

    t_merge_ovl_intervals& clear() {
        _arr.clear();
        return *this;
    }

    std::vector<interval> merge() {
        int index = 0;                                 // stores index of last element in output array (modified _arr[])
        std::sort(_arr.begin(), _arr.end(), compare);  // sort intervals in increasing order of start time

        // traverse all input intervals
        for (int i = 1; i < _arr.size(); i++) {
            // if this is not first interval and overlaps with the previous one
            if (_arr[index].e >= _arr[i].s) {
                // merge previous and current intervals
                if (_arr[index].e < _arr[i].e) {
                    _arr[index].e = _arr[i].e;
                    _arr[index].t = _arr[i].t;
                }

            } else {
                index++;
                _arr[index] = _arr[i];
            }
        }
        if (_arr.size()) {
            _arr.resize(index + 1);
        }
        return _arr;
    }

   private:
    std::vector<interval> _arr;
};

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
