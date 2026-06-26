/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   range_set.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_NOSTD_RANGESET__
#define __HOTPLACE_SDK_BASE_NOSTD_RANGESET__

#include <algorithm>
#include <functional>
#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/nostd/range.hpp>
#include <hotplace/sdk/base/nostd/types.hpp>
#include <hotplace/sdk/base/system/critical_section.hpp>

namespace hotplace {

/**
 * @brief   range set
 * @remarks
 *          parser search result {begin, end, AC-pattern-id}
 * @refer   https://www.geeksforgeeks.org/merging-intervals/
 *          merge all overlapping intervals into one and output the result which should have only mutually exclusive intervals
 *
 *          rs.clear().add(6, 8).add(1, 9).add(2, 4).add(4, 7);
 *          res = rs.merge(); // {1, 9}
 *
 *          rs.clear().add(9, 10, 3).add(6, 8, 2).add(1, 3, 0).add(2, 4, 1).add(1, 8, 4);
 *          res = rs.merge(); // {1, 8, 4}, {9, 10, 3}
 */
template <typename T>
class t_range_set : public t_set_t<T> {
   public:
    virtual void insert(T value) override { add(value, value); }
    virtual void insert_range(T start, T end) override { add(start, end); }
    virtual void erase(T value) override { subtract(value); }
    virtual void erase_range(T start, T end) override { subtract(start, end); }
    virtual bool contains(T value) override { return has(value); }
    virtual void reset() override { clear(); }

    struct interval {
        T s;
        T e;

        interval() : s(0), e(0) {}
        interval(T start, T end) : s(std::min(start, end)), e(std::max(start, end)) {}
        interval(const interval& other) : s(other.s), e(other.e) {}
        interval& operator=(const interval& other) {
            s = other.s;
            e = other.e;
            return *this;
        }
        bool operator==(const interval& other) const { return (s == other.s) && (e == other.e); }
    };

    static bool compare(const interval& lhs, const interval& rhs) { return lhs.s < rhs.s; }

    t_range_set() {}
    t_range_set(const t_range_set& other) { *this = other; }
    t_range_set(t_range_set&& other) { *this = std::move(other); }

    t_range_set& clear() {
        critical_section_guard guard(_lock);
        _arr.clear();
        return *this;
    }

    t_range_set& add(T start, T end) {
        critical_section_guard guard(_lock);
        _arr.push_back(interval(start, end));
        return *this;
    }
    t_range_set& add(const interval& value) {
        critical_section_guard guard(_lock);
        _arr.push_back(value);
        return *this;
    }
    t_range_set& add(const t_range_t<T>& range) {
        critical_section_guard guard(_lock);
        _arr.push_back(interval(range.begin, range.end));
        return *this;
    }

    t_range_set& subtract(T value) { return subtract(value, value); }
    t_range_set& subtract(T start, T end) {
        critical_section_guard guard(_lock);

        t_range_set<T> temp;
        temp._arr = std::move(_arr);
        temp.merge();
        for (const auto& item : temp._arr) {
            if ((item.e < start) || (end < item.s)) {
                add(std::move(item));
            } else {
                if (item.s < start) {
                    add(item.s, start - 1);
                }
                if (end < item.e) {
                    add(end + 1, item.e);
                }
            }
        }
        return *this;
    }
    t_range_set& subtract(const interval& value) { return subtract(value.s, value.e); }
    t_range_set& subtract(const t_range_t<T>& range) { return subtract(range.begin, range.end); }
    t_range_set& subtract(t_range_set& other) {
        // do not hold _lock while calling other.merge() to avoid deadlock if other == *this or cross-lock.
        auto temp = other.merge();
        for (const auto& item : temp) {
            subtract(item.s, item.e);
        }
        return *this;
    }

    bool has(T value) {
        critical_section_guard guard(_lock);
        merge_internal();
        auto it = std::lower_bound(_arr.begin(), _arr.end(), interval(value, value), compare);
        if (it != _arr.end() && it->s <= value && value <= it->e) {
            return true;
        }
        if (it != _arr.begin()) {
            auto prev = std::prev(it);
            if (prev->s <= value && value <= prev->e) {
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

    void intersect(t_range_set& other) {
        auto lhs = merge();
        auto rhs = other.merge();

        critical_section_guard guard(_lock);
        _arr.clear();

        size_t i = 0;
        size_t j = 0;
        while (i < lhs.size() && j < rhs.size()) {
            T start = std::max(lhs[i].s, rhs[j].s);
            T end = std::min(lhs[i].e, rhs[j].e);

            if (start <= end) {
                _arr.push_back(interval(start, end));
            }
            if (lhs[i].e < rhs[j].e) {
                i++;
            } else {
                j++;
            }
        }
    }

    size_t size() const { return _arr.size(); }

    t_range_set& operator=(const t_range_set& other) { _arr = other._arr; }
    t_range_set& operator=(t_range_set&& other) { _arr = std::move(other._arr); }

    bool operator==(t_range_set& other) {
        // avoid holding both locks; merge() acquires its own lock per object.
        auto l = merge();
        auto r = other.merge();
        return l == r;
    }

    template <typename F>  // void(const T&, const T&)
    void for_each(F func) {
        critical_section_guard guard(_lock);
        for (const auto& item : _arr) {
            func(item.s, item.e);
        }
    }

   protected:
    void merge_internal() {
        if (false == _arr.empty()) {
            std::sort(_arr.begin(), _arr.end(), compare);  // sort intervals in increasing order of start time

            size_t index = 0;  // stores index of last element in output array (modified _arr[])
            // traverse all input intervals
            for (size_t i = 1; i < _arr.size(); i++) {
                // if this is not first interval and overlaps with the previous one
                if (_arr[index].e >= _arr[i].s) {
                    // merge previous and current intervals
                    if (_arr[index].e < _arr[i].e) {
                        _arr[index].e = _arr[i].e;
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

template <typename T, typename TAGTYPE = char>
class t_tagged_range_set {
   public:
    struct interval {
        T s;
        T e;
        TAGTYPE t;  // tag

        interval() : s(0), e(0), t(TAGTYPE()) {}
        interval(T start, T end) : s(std::min(start, end)), e(std::max(start, end)), t(TAGTYPE()) {}
        interval(T start, T end, const TAGTYPE& tag) : s(std::min(start, end)), e(std::max(start, end)), t(tag) {}
        interval(T start, T end, TAGTYPE&& tag) : s(std::min(start, end)), e(std::max(start, end)), t(std::move(tag)) {}
        interval(const interval& other) : s(other.s), e(other.e), t(other.t) {}
        interval(interval&& other) : s(other.s), e(other.e), t(std::move(other.t)) {}
        interval& operator=(const interval& other) {
            s = other.s;
            e = other.e;
            t = other.t;
            return *this;
        }
        interval& operator=(interval&& other) {
            s = std::move(other.s);
            e = std::move(other.e);
            t = std::move(other.t);
            return *this;
        }
        bool operator==(const interval& other) const { return (s == other.s) && (e == other.e) && (t == other.t); }
    };

    static bool compare(const interval& lhs, const interval& rhs) { return lhs.s < rhs.s; }

    t_tagged_range_set() {}
    t_tagged_range_set(const t_tagged_range_set& other) { *this = other; }
    t_tagged_range_set(t_tagged_range_set&& other) { *this = std::move(other); }

    t_tagged_range_set& clear() {
        critical_section_guard guard(_lock);
        _arr.clear();
        return *this;
    }

    t_tagged_range_set& add(T start, T end, const TAGTYPE& t = {}) {
        critical_section_guard guard(_lock);
        _arr.push_back(interval(start, end, t));
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
    t_tagged_range_set& subtract(T start, T end) {
        critical_section_guard guard(_lock);

        t_tagged_range_set<T, TAGTYPE> temp;
        temp._arr = std::move(_arr);
        temp.merge();
        for (const auto& item : temp._arr) {
            if ((item.e < start) || (end < item.s)) {
                add(std::move(item));
            } else {
                if (item.s < start) {
                    add(item.s, start - 1);
                }
                if (end < item.e) {
                    add(end + 1, item.e);
                }
            }
        }
        return *this;
    }
    t_tagged_range_set& subtract(const interval& value) { return subtract(value.s, value.e); }
    t_tagged_range_set& subtract(const t_range_t<T>& range) { return subtract(range.begin, range.end); }
    t_tagged_range_set& subtract(t_tagged_range_set& other) {
        // do not hold _lock while calling other.merge() to avoid deadlock if other == *this or cross-lock.
        auto temp = other.merge();
        for (const auto& item : temp) {
            subtract(item.s, item.e);
        }
        return *this;
    }

    bool has(T value) {
        critical_section_guard guard(_lock);
        merge_internal();
        auto it = std::lower_bound(_arr.begin(), _arr.end(), interval(value, value), compare);
        if (it != _arr.end() && it->s <= value && value <= it->e) {
            return true;
        }
        if (it != _arr.begin()) {
            auto prev = std::prev(it);
            if (prev->s <= value && value <= prev->e) {
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
            T start = std::max(lhs[i].s, rhs[j].s);
            T end = std::min(lhs[i].e, rhs[j].e);

            if (start <= end) {
                _arr.push_back(interval(start, end));
            }
            if (lhs[i].e < rhs[j].e) {
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
            func(item.s, item.e);
        }
    }

   protected:
    void merge_internal() {
        if (false == _arr.empty()) {
            std::sort(_arr.begin(), _arr.end(), compare);  // sort intervals in increasing order of start time

            size_t index = 0;  // stores index of last element in output array (modified _arr[])
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
            _arr.resize(index + 1);
        }
    }

   private:
    critical_section _lock;
    std::vector<interval> _arr;
};

}  // namespace hotplace

#endif
