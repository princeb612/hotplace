/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tagged_range_set.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_NOSTD_TAGGEDRANGESET__
#define __HOTPLACE_SDK_BASE_NOSTD_TAGGEDRANGESET__

#include <algorithm>
#include <functional>
#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/nostd/range.hpp>
#include <hotplace/sdk/base/nostd/traits.hpp>
#include <hotplace/sdk/base/system/critical_section.hpp>

namespace hotplace {

/**
 * @remarks
 *          parser search result {begin, to, AC-pattern-id}
 * @example
 *          rs.clear().add(9, 10, 3).add(6, 8, 2).add(1, 3, 0).add(2, 4, 1).add(1, 8, 4);
 *          res = rs.merge(); // {1, 8, 4}, {9, 10, 3}
 */
template <typename T, typename TAGTYPE = char, typename std::enable_if<custom::is_integral<typename std::decay<T>::type>::value, int>::type = 0>
class t_tagged_range_set {
   public:
    struct interval {
        T begin;
        T end;
        TAGTYPE t;  // tag

        interval() : begin(0), end(0), t(TAGTYPE()) {}
        interval(T from, T to) : begin(std::min(from, to)), end(std::max(from, to)), t(TAGTYPE()) {}
        interval(T from, T to, const TAGTYPE& tag) : begin(std::min(from, to)), end(std::max(from, to)), t(tag) {}
        interval(T from, T to, TAGTYPE&& tag) : begin(std::min(from, to)), end(std::max(from, to)), t(std::move(tag)) {}
        interval(const interval& other) : begin(other.begin), end(other.end), t(other.t) {}
        interval(interval&& other) : begin(other.begin), end(other.end), t(std::move(other.t)) {}
        interval& operator=(const interval& other) {
            begin = other.begin;
            end = other.end;
            t = other.t;
            return *this;
        }
        interval& operator=(interval&& other) {
            begin = std::move(other.begin);
            end = std::move(other.end);
            t = std::move(other.t);
            return *this;
        }
        bool operator==(const interval& other) const { return (begin == other.begin) && (end == other.end) && (t == other.t); }
    };

    static bool compare(const interval& lhs, const interval& rhs) { return lhs.begin < rhs.begin; }

    t_tagged_range_set() {}
    t_tagged_range_set(const t_tagged_range_set& other) { *this = other; }
    t_tagged_range_set(t_tagged_range_set&& other) { *this = std::move(other); }

    t_tagged_range_set& clear() {
        critical_section_guard guard(_lock);
        _arr.clear();
        return *this;
    }

    t_tagged_range_set& add(T from, T to, const TAGTYPE& t = {}) {
        critical_section_guard guard(_lock);
        _arr.push_back(interval(from, to, t));
        return *this;
    }
    t_tagged_range_set& add(const interval& value) {
        critical_section_guard guard(_lock);
        _arr.push_back(value);
        return *this;
    }
    t_tagged_range_set& add(interval&& value) {
        critical_section_guard guard(_lock);
        _arr.push_back(std::move(value));
        return *this;
    }
    t_tagged_range_set& add(const t_range_t<T>& range, const TAGTYPE& t = {}) {
        critical_section_guard guard(_lock);
        _arr.push_back(interval(range.begin, range.end, t));
        return *this;
    }

    t_tagged_range_set& subtract(T value) { return subtract(value, value); }
    t_tagged_range_set& subtract(T from, T to) {
        critical_section_guard guard(_lock);

        t_tagged_range_set<T, TAGTYPE> temp;
        temp._arr = std::move(_arr);
        temp.merge();
        for (const auto& item : temp._arr) {
            if ((item.end < from) || (to < item.begin)) {
                add(std::move(item));
            } else {
                if (item.begin < from) {
                    add(item.begin, from - 1);
                }
                if (to < item.end) {
                    add(to + 1, item.end);
                }
            }
        }
        return *this;
    }
    t_tagged_range_set& subtract(const interval& value) { return subtract(value.begin, value.end); }
    t_tagged_range_set& subtract(const t_range_t<T>& range) { return subtract(range.begin, range.to); }
    t_tagged_range_set& subtract(t_tagged_range_set& other) {
        // do not hold _lock while calling other.merge() to avoid deadlock if other == *this or cross-lock.
        auto temp = other.merge();
        for (const auto& item : temp) {
            subtract(item.begin, item.end);
        }
        return *this;
    }

    bool has(T value) {
        critical_section_guard guard(_lock);
        merge_internal();
        auto it = std::lower_bound(_arr.begin(), _arr.end(), interval(value, value), compare);
        if (it != _arr.end() && it->begin <= value && value <= it->end) {
            return true;
        }
        if (it != _arr.begin()) {
            auto prev = std::prev(it);
            if (prev->begin <= value && value <= prev->end) {
                return true;
            }
        }
        return false;
    }

    std::vector<interval> merge() {
        critical_section_guard guard(_lock);
        merge_internal();
        return _arr;
    }

    void intersect(t_tagged_range_set& other) {
        auto lhs = merge();
        auto rhs = other.merge();

        critical_section_guard guard(_lock);
        _arr.clear();

        size_t i = 0;
        size_t j = 0;
        while (i < lhs.size() && j < rhs.size()) {
            T from = std::max(lhs[i].begin, rhs[j].begin);
            T to = std::min(lhs[i].end, rhs[j].end);

            if (from <= to) {
                _arr.push_back(interval(from, to));
            }
            if (lhs[i].end < rhs[j].end) {
                i++;
            } else {
                j++;
            }
        }
    }

    size_t size() const { return _arr.size(); }

    t_tagged_range_set& operator=(const t_tagged_range_set& other) { _arr = other._arr; }
    t_tagged_range_set& operator=(t_tagged_range_set&& other) { _arr = std::move(other._arr); }

    bool operator==(t_tagged_range_set& other) {
        // avoid holding both locks; merge() acquires its own lock per object.
        auto l = merge();
        auto r = other.merge();
        return l == r;
    }

    template <typename F>  // void(const T&, const T&)
    void for_each(F func) {
        critical_section_guard guard(_lock);
        for (const auto& item : _arr) {
            func(item.begin, item.end);
        }
    }

   protected:
    void merge_internal() {
        if (false == _arr.empty()) {
            std::sort(_arr.begin(), _arr.end(), compare);  // sort intervals in increasing order of from time

            size_t index = 0;  // stores index of last element in output array (modified _arr[])
            // traverse all input intervals
            for (size_t i = 1; i < _arr.size(); i++) {
                // if this is not first interval and overlaps with the previous one
                if (_arr[index].end >= _arr[i].begin) {
                    // merge previous and current intervals
                    if (_arr[index].end < _arr[i].end) {
                        _arr[index].end = _arr[i].end;
                        _arr[index].t = _arr[i].t;
                    }
                } else {
                    index++;
                    _arr[index] = _arr[i];
                }
            }
            _arr.resize(index + 1);
        }
    }

   private:
    critical_section _lock;
    std::vector<interval> _arr;
};

}  // namespace hotplace

#endif
