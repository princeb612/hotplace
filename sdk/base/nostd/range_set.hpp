/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   range_set.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2026.06.29   Soo Han and Gemini  MIN, MAX applied
 *
 */

#ifndef __HOTPLACE_SDK_BASE_NOSTD_RANGESET__
#define __HOTPLACE_SDK_BASE_NOSTD_RANGESET__

#include <algorithm>
#include <functional>
#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/nostd/range.hpp>
#include <hotplace/sdk/base/nostd/traits.hpp>
#include <hotplace/sdk/base/nostd/types.hpp>
#include <hotplace/sdk/base/system/critical_section.hpp>

namespace hotplace {

enum class range_type_t : int8 {
    minvalue = -1,    // -inf
    ninf = minvalue,  // negative inf
    value = 0,        // value
    maxvalue = 1,     // +inf
    inf = maxvalue,   // positive inf
};
enum class range_flag_t : uint8 {
    excluded = 0,       // open
    open = excluded,    //
    included = 1,       // closed
    closed = included,  //
};

template <typename T>
struct t_interval {
    T begin;
    T end;
    range_flag_t begin_flag;
    range_flag_t end_flag;

    t_interval() : begin(T()), end(T()), begin_flag(range_flag_t::open), end_flag(range_flag_t::open) {}
    t_interval(T start, T end, range_flag_t sflag = range_flag_t::closed, range_flag_t eflag = range_flag_t::closed)
        : begin(start < end ? start : end), end(start < end ? end : start), begin_flag(sflag), end_flag(eflag) {}
    t_interval(const t_interval& other) : begin(other.begin), end(other.end), begin_flag(other.begin_flag), end_flag(other.end_flag) {}
    t_interval& operator=(const t_interval& other) {
        begin = other.begin;
        end = other.end;
        begin_flag = other.begin_flag;
        end_flag = other.end_flag;
        return *this;
    }
    bool operator==(const t_interval& other) const {
        return (begin == other.begin) && (end == other.end) && (begin_flag == other.begin_flag) && (end_flag == other.end_flag);
    }
    static bool compare(const t_interval& lhs, const t_interval& rhs) { return (lhs.begin < rhs.begin); }
};

template <typename T, typename enabled = void>
struct range_traits {
    static bool is_mergeable_with(const T& current_e, const T& next_s) { return (current_e + 1) >= next_s; }
    static bool is_mergeable_with(const t_interval<T>& current, const t_interval<T>& next) { return (current.end + 1) >= next.begin; }
    static T next(const T& v) { return v + 1; }
    static T prev(const T& v) { return v - 1; }
    static bool erased_type() { return false; }
};
template <typename T>
struct range_traits<T, typename std::enable_if<std::is_floating_point<T>::value>::type> {
    static bool is_mergeable_with(const T& current_e, const T& next_s) { return current_e >= next_s; }
    static bool is_mergeable_with(const t_interval<T>& current, const t_interval<T>& next) {
        if (current.end < next.begin) return false;
        if (current.end == next.begin) {
            return (current.end_flag == range_flag_t::closed) || (next.begin_flag == range_flag_t::closed);
        }
        return true;  // overlapped
    }
    static T next(const T& v) { return v; }
    static T prev(const T& v) { return v; }
    static bool erased_type() { return true; }
};
template <typename T>
struct t_range_value;
template <typename T>
struct range_traits<t_range_value<T>> {
    using V = t_range_value<T>;
    using I = t_interval<t_range_value<T>>;

    static bool is_mergeable_with(const V& current_e, const V& next_s) {
        if (current_e.type != range_type_t::value || next_s.type != range_type_t::value) {
            return current_e >= next_s;
        }
        return range_traits<T>::is_mergeable_with(current_e.value, next_s.value);
    }
    static bool is_mergeable_with(const I& current, const I& next) {
        if (current.end.type != range_type_t::value || next.begin.type != range_type_t::value) {
            return current.end >= next.begin;
        }

        if (current.end < next.begin) return false;
        if (current.end == next.begin) {
            return (current.end_flag == range_flag_t::closed) || (next.begin_flag == range_flag_t::closed);
        }
        return true;  // overlapped
    }
    static V next(const V& v) {
        if (v.type == range_type_t::value) {
            return V(range_traits<T>::next(v.value));
        }
        return v;
    }
    static V prev(const V& v) {
        if (v.type == range_type_t::value) {
            return V(range_traits<T>::prev(v.value));
        }
        return v;
    }
    static bool erased_type() { return range_traits<T>::erased_type(); }
};

template <typename T>
struct t_range_value {
    range_type_t type;
    T value;

    t_range_value() : type(range_type_t::value), value(T()) {}
    t_range_value(T v) : type(range_type_t::value), value(std::move(v)) {}
    template <typename U>
    t_range_value(const U& v) : type(range_type_t::value), value(v) {}
    t_range_value(range_type_t t) : type(t), value(T()) {}
    t_range_value(const t_range_value& other) : type(other.type), value(other.value) {}
    template <typename U>
    t_range_value(const t_range_value<U>& other) : type(other.type), value(other.value) {}

    t_range_value& operator=(const t_range_value& other) {
        if (this != &other) {
            type = other.type;
            value = other.value;
        }
        return *this;
    }
    template <typename U>
    t_range_value& operator=(const t_range_value<U>& other) {
        type = other.type;
        value = other.value;
        return *this;
    }
    template <typename U>
    t_range_value& operator=(const U& value) {
        type = range_type_t::value;
        value = value;
        return *this;
    }

    bool operator<(const t_range_value& other) const {
        if (type == other.type) {
            return (type == range_type_t::value) ? (value < other.value) : false;
        }
        return static_cast<int8>(type) < static_cast<int8>(other.type);
    }
    bool operator<=(const t_range_value& other) const {
        if (type == other.type) {
            return (type == range_type_t::value) ? (value <= other.value) : true;
        }
        return static_cast<int8>(type) <= static_cast<int8>(other.type);
    }

    bool operator>(const t_range_value& other) const {
        if (type == other.type) {
            return (type == range_type_t::value) ? (value > other.value) : false;
        }
        return static_cast<int8>(type) > static_cast<int8>(other.type);
    }
    bool operator>=(const t_range_value& other) const {
        if (type == other.type) {
            return (type == range_type_t::value) ? (value >= other.value) : true;
        }
        return static_cast<int8>(type) >= static_cast<int8>(other.type);
    }

    bool operator==(const t_range_value& other) const {
        if (type == other.type) {
            return (type == range_type_t::value) ? (value == other.value) : true;
        }
        return false;
    }
    bool operator!=(const t_range_value& other) const { return (*this == other) ? false : true; }
};

/**
 * @brief   range set (QUIC ACK Ranges)
 * @refer
 *          1. merge
 *          https://www.geeksforgeeks.org/merging-intervals/
 *          merge all overlapping intervals into one and output the result which should have only mutually exclusive intervals
 *
 *          2. subtract, intersect, [closed, open)
 *          collaboration Gemini
 *
 * @sample
 *          // merge - range
 *          rs.clear().add(6, 8).add(1, 9).add(2, 4).add(4, 7);
 *          res = rs.merge(); // {1, 9}
 *
 *          // merge - range, point
 *          t_point_set<uint64> part;
 *          part.add(7).add(8).add(9).add(10).add(11).add(12).add(14).add(15, 16).add(17, 18).add(21);
 *          auto res = part.merge();
 *
 *          // (gdb) p res
 *          // $1 = std::vector of length 3, capacity 3 = {{begin = 7, end = 12}, {begin = 14, end = 18}, {begin = 21, end = 21}}
 *
 *          // [1.0..1.5)(3.5..4.0]
 *          using range_set = t_range_set<float>;
 *          using interval = t_interval<float>;
 *          range_set rs;
 *          rs.clear().add(1.0, 2.0).add(3.0, 4.0).subtract(1.5, 3.5);
 *          t_range_set<float> expect;
 *          expect  //
 *              .clear()
 *              .add(interval(1.0, 1.5, range_flag_t::closed, range_flag_t::open))
 *              .add(interval(3.5, 4.0, range_flag_t::open, range_flag_t::closed));
 *          _test_case.assert(rs == expect, __FUNCTION__, "[1.0..1.5)(3.5..4.0]");
 *
 *          // [MIN, -1.0] [1.0, 1.5) (3.5, 4.0]
 *          using range_set = t_range_set<t_range_value<float>>;
 *          using interval = t_interval<t_range_value<float>>;
 *          range_set rs;
 *          rs.clear().add(range_type_t::minvalue, -1.0).add(1.0, 2.0).add(3.0, 4.0).subtract(1.5, 3.5);
 *          t_range_set<t_range_value<float>> expect;
 *          expect  //
 *              .clear()
 *              .add(range_type_t::minvalue, -1.0)
 *              .add(interval(1.0, 1.5, range_flag_t::closed, range_flag_t::open))
 *              .add(interval(3.5, 4.0, range_flag_t::open, range_flag_t::closed));
 *          _test_case.assert(rs == expect, __FUNCTION__, "[MIN..-1.0][1.0..1.5)(3.5..4.0]");
 *
 * @sa      quic_frame_ack, ack_t
 */
template <typename T>
class t_range_set {
   public:
    t_range_set() : _status(0), _invert(0) {}
    t_range_set(const t_range_set& other) : t_range_set() { *this = other; }
    t_range_set(t_range_set&& other) : t_range_set() { *this = std::move(other); }

    void reset() { clear(); }
    void insert(const T& value) { add(value, value); }
    void erase(const T& value) { subtract(value); }
    bool contains(const T& value) { return has(value); }
    void insert_range(const T& start, const T& end) { add(start, end); }
    void erase_range(const T& start, const T& end) { subtract(start, end); }

    /**
     * @brief   union
     * @remarks ALL EXCEPT
     *          S1  UNION S2  = S1.union_with(S2)       is_inverted=false
     *          S   UNION AE  = AE.erase_from(S)        is_inverted=true
     *          AE  UNION S   = AE.erase_from(S)        is_inverted=true
     *          AE1 UNION AE2 = AE1.intersect_with(AE2) is_inverted=true
     */
    void union_with(t_range_set& other) {
        uint8 lhs_inverted = is_inverted() ? 1 : 0;
        uint8 rhs_inverted = other.is_inverted() ? 1 : 0;
        if ((0 == lhs_inverted) && (0 == (lhs_inverted ^ rhs_inverted))) {
            add(other);
        } else if ((0 == lhs_inverted) && (1 == (lhs_inverted ^ rhs_inverted))) {
            t_range_set<T> temp(other);
            temp.subtract(*this);
            *this = std::move(temp);  // other.is_inverted=true
        } else if ((1 == lhs_inverted) && (1 == (lhs_inverted ^ rhs_inverted))) {
            subtract(other);  // is_inverted=true
        } else if ((1 == lhs_inverted) && (0 == (lhs_inverted ^ rhs_inverted))) {
            intersect(other);  // is_inverted=true
        }
    }
    /**
     * @brief   subtract
     * @remarks ALL EXCEPT
     *          S1  ERASE FROM S2  = S1.erase_from(S2)       is_inverted=false
     *          S   ERASE FROM AE  = S.intersect_with(AE)    is_inverted=false
     *          AE  ERASE FROM S   = AE.union_with(S)        is_inverted=true
     *          AE1 ERASE FROM AE2 = AE2.intersect_with(AE1) is_inverted=false
     */
    void erase_from(t_range_set& other) {
        uint8 lhs_inverted = is_inverted() ? 1 : 0;
        uint8 rhs_inverted = other.is_inverted() ? 1 : 0;
        if ((0 == lhs_inverted) && (0 == (lhs_inverted ^ rhs_inverted))) {
            subtract(other);  // is_inverted=false
        } else if ((0 == lhs_inverted) && (1 == (lhs_inverted ^ rhs_inverted))) {
            intersect(other);  // is_inverted=false
        } else if ((1 == lhs_inverted) && (1 == (lhs_inverted ^ rhs_inverted))) {
            add(other);  // is_inverted=true
        } else if ((1 == lhs_inverted) && (0 == (lhs_inverted ^ rhs_inverted))) {
            t_range_set<T> temp(other);
            temp.intersect(*this);
            *this = std::move(temp);  // other.is_inverted=false
        }
    }
    /**
     * @brief   intersection
     * @remarks ALL EXCEPT
     *          S1  INTERSECT S2  = S1.intersect_with(S2)   is_inverted=false
     *          S   INTERSECT AE  = S.erase_from(AE)        is_inverted=false
     *          AE  INTERSECT S   = S.erase_from(AE)        is_inverted=false
     *          AE1 INTERSECT AE2 = AE1.union_with(AE2)     is_inverted=true
     */
    void intersect_with(t_range_set& other) {
        uint8 lhs_inverted = is_inverted() ? 1 : 0;
        uint8 rhs_inverted = other.is_inverted() ? 1 : 0;
        if ((0 == lhs_inverted) && (0 == (lhs_inverted ^ rhs_inverted))) {
            intersect(other);  // is_inverted=false
        } else if ((0 == lhs_inverted) && (1 == (lhs_inverted ^ rhs_inverted))) {
            subtract(other);  // is_inverted=false
        } else if ((1 == lhs_inverted) && (1 == (lhs_inverted ^ rhs_inverted))) {
            t_range_set<T> temp(other);
            temp.subtract(*this);
            *this = std::move(temp);  // other.is_inverted=false
        } else if ((1 == lhs_inverted) && (0 == (lhs_inverted ^ rhs_inverted))) {
            add(other);  // is_inverted=true
        }
    }
    bool contains_all(const t_range_set& other) { return has(other); }

    t_range_set& clear() {
        critical_section_guard guard(_lock);
        _arr.clear();
        set_status(0);
        return *this;
    }

    t_range_set& add(T value) { return add(value, value); }
    t_range_set& add(T start, T end) {
        critical_section_guard guard(_lock);
        _arr.push_back(t_interval<T>(start, end));
        set_modified();
        return *this;
    }
    t_range_set& add(const t_interval<T>& value) {
        critical_section_guard guard(_lock);
        _arr.push_back(value);
        set_modified();
        return *this;
    }
    t_range_set& add(const t_range_t<T>& range) {
        critical_section_guard guard(_lock);
        _arr.push_back(t_interval<T>(range.begin, range.end));
        set_modified();
        return *this;
    }
    t_range_set& add(t_range_set& other) {
        critical_section_guard guard(_lock);
        auto temp = other.merge();
        for (auto& item : temp) {
            _arr.push_back(std::move(item));
        }
        set_modified();
        return *this;
    }

    t_range_set& subtract(T value) { return subtract(value, value); }
    t_range_set& subtract(T start, T end) {
        critical_section_guard guard(_lock);

        t_range_set<T> temp;
        temp._arr = std::move(_arr);
        temp.merge_internal();

        auto erased_type = range_traits<T>::erased_type();
        for (const auto& item : temp._arr) {
            if ((item.end < start) || (end < item.begin)) {
                _arr.push_back(item);
            } else {
                if (item.begin < start) {
                    range_flag_t updated_end_flag = erased_type ? range_flag_t::open : range_flag_t::closed;
                    _arr.push_back(t_interval<T>(item.begin, range_traits<T>::prev(start), item.begin_flag, updated_end_flag));
                }
                if (end < item.end) {
                    range_flag_t updated_begin_flag = erased_type ? range_flag_t::open : range_flag_t::closed;
                    _arr.push_back(t_interval<T>(range_traits<T>::next(end), item.end, updated_begin_flag, item.end_flag));
                }
            }
        }
        set_modified();
        return *this;
    }
    t_range_set& subtract(const t_interval<T>& value) { return subtract(value.begin, value.end); }
    t_range_set& subtract(const t_range_t<T>& range) { return subtract(range.begin, range.end); }
    t_range_set& subtract(t_range_set& other) {
        auto temp = other.merge();
        for (const auto& item : temp) {
            subtract(item.begin, item.end);
        }
        return *this;
    }

    t_range_set& intersect(t_range_set& other) {
        auto lhs = merge();
        auto rhs = other.merge();

        critical_section_guard guard(_lock);
        _arr.clear();

        size_t i = 0, j = 0;
        while (i < lhs.size() && j < rhs.size()) {
            T start = lhs[i].begin < rhs[j].begin ? rhs[j].begin : lhs[i].begin;
            T end = lhs[i].end < rhs[j].end ? lhs[i].end : rhs[j].end;

            if (start <= end) {
                range_flag_t start_flag = range_flag_t::closed;
                if (lhs[i].begin == rhs[j].begin) {
                    auto cond = ((lhs[i].begin_flag == range_flag_t::closed) && (rhs[j].begin_flag == range_flag_t::closed));
                    start_flag = cond ? range_flag_t::closed : range_flag_t::open;
                } else {
                    start_flag = (lhs[i].begin < rhs[j].begin) ? rhs[j].begin_flag : lhs[i].begin_flag;
                }

                range_flag_t end_flag = range_flag_t::closed;
                if (lhs[i].end == rhs[j].end) {
                    auto cond = ((lhs[i].end_flag == range_flag_t::closed) && (rhs[j].end_flag == range_flag_t::closed));
                    end_flag = cond ? range_flag_t::closed : range_flag_t::open;
                } else {
                    end_flag = (lhs[i].end < rhs[j].end) ? lhs[i].end_flag : rhs[j].end_flag;
                }

                if ((start == end) && ((start_flag == range_flag_t::open) || (end_flag == range_flag_t::open))) {
                    // invalid empty set
                } else {
                    _arr.push_back(t_interval<T>(start, end, start_flag, end_flag));
                }
            }
            if (lhs[i].end < rhs[j].end) {
                i++;
            } else {
                j++;
            }
        }
        set_modified();
        return *this;
    }

    bool has(T value) {
        critical_section_guard guard(_lock);
        merge_internal();

        for (const auto& item : _arr) {
            if (item.begin > value) {
                break;
            }

            bool lower_cond = (item.begin_flag == range_flag_t::closed) ? (item.begin <= value) : (item.begin < value);
            if (lower_cond) {
                bool upper_cond = (item.end_flag == range_flag_t::closed) ? (value <= item.end) : (value < item.end);
                if (upper_cond) {
                    return (false == _invert) ? true : false;
                }
            }
        }

        return (false == _invert) ? false : true;
    }
    bool has(const t_interval<T>& interval, bool merge_always = true) {
        critical_section_guard guard(_lock);
        if (merge_always) {
            merge_internal();
        }

        for (const auto& item : _arr) {
            if (item.begin > interval.end) {
                break;
            }

            bool lower_cond = false;
            if (item.begin < interval.begin) {
                lower_cond = true;
            } else if (item.begin == interval.begin) {
                if (item.begin_flag == range_flag_t::closed || interval.begin_flag == range_flag_t::open) {
                    lower_cond = true;
                }
            }

            if (lower_cond) {
                bool upper_cond = false;
                if (item.end > interval.end) {
                    upper_cond = true;
                } else if (item.end == interval.end) {
                    if (item.end_flag == range_flag_t::closed || interval.end_flag == range_flag_t::open) {
                        upper_cond = true;
                    }
                }

                if (upper_cond) {
                    return (false == _invert) ? true : false;
                }
            }
        }

        return (false == _invert) ? false : true;
    }
    bool has(const t_range_set& other) {
        if (this == &other) return true;

        auto temp = other.merge();
        if (temp.empty()) return true;

        critical_section_guard guard(_lock);
        merge_internal();

        for (const auto& item : temp) {
            auto expect = (false == _invert) ? false : true;
            if (expect == has(item, false)) {
                return false;
            }
        }

        return true;
    }

    std::vector<t_interval<T>> merge() {
        critical_section_guard guard(_lock);
        merge_internal();
        return _arr;
    }

    size_t size() const { return _arr.size(); }

    t_range_set& operator=(const t_range_set& other) {
        if (this != &other) {
            _arr = other._arr;
            _status = other._status;
            _invert = other._invert;
        }
        return *this;
    }
    t_range_set& operator=(t_range_set&& other) {
        if (this != &other) {
            _arr = std::move(other._arr);
            std::swap(_status, other._status);
            std::swap(_invert, other._invert);
        }
        return *this;
    }

    bool operator==(t_range_set& other) {
        auto l = merge();
        auto r = other.merge();
        return l == r;
    }

    template <typename F>
    void for_each(F func) {
        critical_section_guard guard(_lock);
        for (const auto& item : _arr) {
            func(item.begin, item.end);
        }
    }
    template <typename F>
    void for_each2(F func) {
        critical_section_guard guard(_lock);
        for (const auto& item : _arr) {
            func(item);
        }
    }

    critical_section& get_lock() { return _lock; }

    enum flag_t { modified = (1 << 0) };
    void set_modified() { _status |= modified; }
    bool is_modified() { return _status & modified; }
    void set_status(uint8 status) { _status = status; }
    uint8 get_status() { return _status; }

    bool is_inverted() const { return _invert; }
    t_range_set<T>& invert() {
        _invert = !_invert;
        return *this;
    }

   protected:
    void merge_internal() {
        if (false == _arr.empty()) {
            std::sort(_arr.begin(), _arr.end(), t_interval<T>::compare);

            size_t index = 0;
            for (size_t i = 1; i < _arr.size(); ++i) {
                if (range_traits<T>::is_mergeable_with(_arr[index], _arr[i])) {
                    if (_arr[index].end < _arr[i].end) {
                        _arr[index].end = _arr[i].end;
                        _arr[index].end_flag = _arr[i].end_flag;
                    } else if (_arr[index].end == _arr[i].end) {
                        if (_arr[i].end_flag == range_flag_t::closed) {
                            _arr[index].end_flag = range_flag_t::closed;
                        }
                    }
                } else {
                    ++index;
                    _arr[index] = _arr[i];
                }
            }
            _arr.resize(index + 1);
        }
    }

   private:
    critical_section _lock;
    std::vector<t_interval<T>> _arr;
    uint8 _status;
    bool _invert;
};

}  // namespace hotplace

#endif
