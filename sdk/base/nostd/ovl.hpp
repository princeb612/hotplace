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

#ifndef __HOTPLACE_SDK_BASE_NOSTD_OVL__
#define __HOTPLACE_SDK_BASE_NOSTD_OVL__

#include <algorithm>
#include <functional>
#include <sdk/base/basic/types.hpp>
#include <sdk/base/nostd/range.hpp>
#include <set>

namespace hotplace {

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
 *
 * @sa      t_fragmented_binaries, parser
 */
template <typename T, typename TAGTYPE = char>
class t_merge_ovl_intervals {
   public:
    struct interval {
        T s;
        T e;
        TAGTYPE t;  // tag

        interval() : s(0), e(0), t(TAGTYPE()) {}
        interval(T start, T end) : s(start), e(end), t(TAGTYPE()) {}
        interval(T start, T end, const TAGTYPE& tag) : s(start), e(end), t(tag) {}
        interval(T start, T end, TAGTYPE&& tag) : s(start), e(end), t(std::move(tag)) {}
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
    t_merge_ovl_intervals& add(T start, T end) {
        _arr.push_back(interval(start, end));
        return *this;
    }
    t_merge_ovl_intervals& add(T start, T end, const TAGTYPE& t) {
        _arr.push_back(interval(start, end, t));
        return *this;
    }
    t_merge_ovl_intervals& add(const range_t& range, const TAGTYPE& t) {
        _arr.push_back(interval(range.begin, range.end, t));
        return *this;
    }

    t_merge_ovl_intervals& clear() {
        _arr.clear();
        return *this;
    }

    t_merge_ovl_intervals& subtract(T start, T end) {
        t_merge_ovl_intervals<T, TAGTYPE> temp;
        temp._arr = std::move(_arr);
        temp.merge();
        for (auto item : temp._arr) {
            if (item.e < start) {
                add(std::move(item));
            } else if (end < item.s) {
                add(std::move(item));
            } else {
                if ((item.s < start) && (start < item.e)) {
                    add(item.s, start - 1);
                }
                if ((item.s < end) && (end < item.e)) {
                    add(end + 1, item.e);
                }
            }
        }
        return *this;
    }

    std::vector<interval> merge() {
        size_t index = 0;                              // stores index of last element in output array (modified _arr[])
        std::sort(_arr.begin(), _arr.end(), compare);  // sort intervals in increasing order of start time

        // traverse all input intervals
        for (size_t i = 1; i < _arr.size(); i++) {
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
    size_t size() { return _arr.size(); }

   private:
    std::vector<interval> _arr;
};

/**
 * @sample
 *          t_ovl_points<uint64> part;
 *          part.add(7).add(8).add(9).add(10).add(11).add(12).add(14).add(15, 16).add(17, 18).add(21);
 *          auto res = part.merge();
 *
 *          // (gdb) p res
 *          // $1 = std::vector of length 3, capacity 3 = {{s = 7, e = 12}, {s = 14, e = 18}, {s = 21, e = 21}}
 *
 * @sa      quic_frame_ack, ack_t
 */
template <typename T>
class t_ovl_points {
   public:
    struct interval {
        T s;
        T e;

        interval() : s(0), e(0) {}
        interval(T p) : s(p), e(p) {}
        interval(T start, T end) : s(start), e(end) {}
        interval(const interval& rhs) : s(rhs.s), e(rhs.e) {}
        interval(interval&& rhs) : s(rhs.s), e(rhs.e) {}
        interval& operator=(const interval& rhs) {
            s = rhs.s;
            e = rhs.e;
            return *this;
        }
        interval& operator=(interval&& rhs) {
            s = rhs.s;
            e = rhs.e;
            return *this;
        }
        bool operator==(const interval& rhs) const { return (s == rhs.s) && (e == rhs.e); }
    };

    static bool compare(const interval& lhs, const interval& rhs) { return lhs.s < rhs.s; }

    t_ovl_points() {}

    t_ovl_points& add(T p) {
        _arr.push_back(interval(p, p));
        return *this;
    }
    t_ovl_points& add(T start, T end) {
        _arr.push_back(interval(start, end));
        return *this;
    }
    t_ovl_points& add(const range_t& range) {
        _arr.push_back(interval(range.begin, range.end));
        return *this;
    }

    t_ovl_points& clear() {
        _arr.clear();
        return *this;
    }

    std::vector<interval> merge() {
        size_t index = 0;                              // stores index of last element in output array (modified _arr[])
        std::sort(_arr.begin(), _arr.end(), compare);  // sort intervals in increasing order of start time

        // traverse all input intervals
        for (size_t i = 1; i < _arr.size(); i++) {
            // if this is not first interval and overlaps with the previous one
            if (_arr[index].e + 1 >= _arr[i].s) {
                // merge previous and current intervals
                if (_arr[index].e < _arr[i].e) {
                    _arr[index].e = _arr[i].e;
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
    size_t size() { return _arr.size(); }

    bool operator==(t_ovl_points<T>& rhs) {
        auto lres = merge();
        auto rres = rhs.merge();
        return lres == rres;
    }

   private:
    std::vector<interval> _arr;
};

}  // namespace hotplace

#endif
