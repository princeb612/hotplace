/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   point_set.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_NOSTD_POINTSET__
#define __HOTPLACE_SDK_BASE_NOSTD_POINTSET__

#include <algorithm>
#include <functional>
#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/nostd/range.hpp>
#include <hotplace/sdk/base/nostd/types.hpp>
#include <hotplace/sdk/base/system/critical_section.hpp>

namespace hotplace {

/**
 * @brief   QUIC ACK Ranges
 * @sample
 *          t_point_set<uint64> part;
 *          part.add(7).add(8).add(9).add(10).add(11).add(12).add(14).add(15, 16).add(17, 18).add(21);
 *          auto res = part.merge();
 *
 *          // (gdb) p res
 *          // $1 = std::vector of length 3, capacity 3 = {{s = 7, e = 12}, {s = 14, e = 18}, {s = 21, e = 21}}
 *
 * @sa      quic_frame_ack, ack_t
 */
template <typename T>
class t_point_set : public t_set_t<T> {
   public:
    virtual void insert(T value) override { add(value); }
    virtual void insert_range(T start, T end) override { add(start, end); }
    virtual void erase(T value) override { subtract(value); }
    virtual void erase_range(T start, T end) override { subtract(start, end); }
    virtual bool contains(T value) override { return has(value); }
    virtual void reset() override { clear(); }

    struct interval {
        T s;
        T e;

        interval() : s(0), e(0) {}
        interval(T p) : s(p), e(p) {}
        interval(T start, T end) : s(std::min(start, end)), e(std::max(start, end)) {}
        interval(const interval& other) : s(other.s), e(other.e) {}
        interval(interval&& other) : s(std::move(other.s)), e(std::move(other.e)) {}
        interval& operator=(const interval& other) {
            s = other.s;
            e = other.e;
            return *this;
        }
        interval& operator=(interval&& other) {
            s = std::move(other.s);
            e = std::move(other.e);
            return *this;
        }
        bool operator==(const interval& other) const { return (s == other.s) && (e == other.e); }
    };

    static bool compare(const interval& lhs, const interval& rhs) { return lhs.s < rhs.s; }

    t_point_set() : _status(0) {}
    t_point_set(const t_point_set& other) : _arr(other._arr), _status(other._status) {}
    t_point_set(t_point_set&& other) : _arr(std::move(other._arr)), _status(other._status) {}

    t_point_set& clear() {
        critical_section_guard guard(_lock);
        _arr.clear();
        set_status(0);
        return *this;
    }

    t_point_set& add(const interval& t) {
        critical_section_guard guard(_lock);
        _arr.push_back(t);
        set_modified();
        return *this;
    }
    t_point_set& add(interval&& t) {
        critical_section_guard guard(_lock);
        _arr.push_back(std::move(t));
        set_modified();
        return *this;
    }
    t_point_set& add(T p) {
        critical_section_guard guard(_lock);
        _arr.push_back(interval(p, p));
        set_modified();
        return *this;
    }
    t_point_set& add(T start, T end) {
        critical_section_guard guard(_lock);
        _arr.push_back(interval(start, end));
        set_modified();
        return *this;
    }
    t_point_set& add(const range_t& range) {
        critical_section_guard guard(_lock);
        _arr.push_back(interval(range.begin, range.end));
        set_modified();
        return *this;
    }

    t_point_set& subtract(T t) { return subtract(t, t); }
    t_point_set& subtract(T start, T end) {
        critical_section_guard guard(_lock);

        t_point_set<T> temp;
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
    t_point_set& subtract(t_point_set& other) {
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

    void intersect(t_point_set& other) {
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

    t_point_set& operator=(const t_point_set& other) {
        _arr = other._arr;
        _status = other._status;
    }
    t_point_set& operator=(t_point_set&& other) {
        _arr = std::move(other._arr);
        _status = other._status;
    }

    bool operator==(t_point_set<T>& other) {
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

    /**
     *  // sketch
     *  critical_section_guard guard(ovl.get_lock());
     *  if (ovl.is_modified()) {
     *    // do something
     *    ovl.set_status(0);
     *  }
     */
    critical_section& get_lock() { return _lock; }

    enum flag_t {
        modified = (1 << 0),
    };
    void set_modified() { _status |= modified; }
    bool is_modified() { return _status & modified; }
    void set_status(uint8 status) { _status = status; }
    uint8 get_status() { return _status; }

   protected:
    void merge_internal() {
        if (false == _arr.empty()) {
            std::sort(_arr.begin(), _arr.end(), compare);  // sort intervals in increasing order of start time

            size_t index = 0;  // stores index of last element in output array (modified _arr[])
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
            _arr.resize(index + 1);
        }
    }

   private:
    critical_section _lock;
    std::vector<interval> _arr;
    uint8 _status;
};

}  // namespace hotplace

#endif
