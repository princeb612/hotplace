/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   bit_set.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_NOSTD_BITSET__
#define __HOTPLACE_SDK_BASE_NOSTD_BITSET__

#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/nostd/types.hpp>

namespace hotplace {

/**
 * @brief   bitset
 * @remarks
 *          ASN.1 BIT STRING
 *          std::bitset is not enough
 */
template <typename T>
class t_bit_set : public t_set_t<T> {
   public:
    virtual void insert(T value) override { add(value); }
    virtual void insert_range(T start, T end) override { add(start, end); }
    virtual void erase(T value) override { subtract(value); }
    virtual void erase_range(T start, T end) override { subtract(start, end); }
    virtual bool contains(T value) override { return has(value); }
    virtual void reset() override { clear(); }

    t_bit_set(T low, T high) : _low(std::min(low, high)), _high(std::max(low, high)) {
        size_t allocsize = (_high - _low + 8) / 8;
        _bitset.resize(allocsize, 0);
    }
    t_bit_set(const t_bit_set& other) { *this = other; }
    t_bit_set(t_bit_set&& other) { *this = std::move(other); }
    ~t_bit_set() {}

    t_bit_set& operator=(const t_bit_set& other) {
        _low = other._low;
        _high = other._high;
        _bitset = other._bitset;
        return *this;
    }
    t_bit_set& operator=(t_bit_set&& other) {
        std::swap(_low, other._low);
        std::swap(_high, other._high);
        std::swap(_bitset, other._bitset);
        return *this;
    }

    return_t add(T value) {
        return_t ret = errorcode_t::success;
        if (value < _low || _high < value) {
            ret = errorcode_t::out_of_range;
        } else {
            T temp = value - _low;
            uint8 shift = unused_bit(temp);
            _bitset[temp >> 3] |= (uint8)(1 << shift);
        }
        return ret;
    }
    void add(T start, T end) {
        return_t ret = errorcode_t::success;
        auto lval = std::min(start, end);
        auto mval = std::max(start, end);
        for (T i = lval; i <= mval; ++i) {
            add(i);
        }
    }
    return_t subtract(T value) {
        return_t ret = errorcode_t::success;
        if (value < _low || _high < value) {
            ret = errorcode_t::out_of_range;
        } else {
            T temp = value - _low;
            uint8 shift = unused_bit(temp);
            _bitset[temp >> 3] &= ~(uint8)(1 << shift);
        }
        return ret;
    }
    void subtract(T start, T end) {
        return_t ret = errorcode_t::success;
        auto lval = std::min(start, end);
        auto mval = std::max(start, end);
        for (T i = lval; i <= mval; ++i) {
            subtract(i);
        }
    }
    bool has(T value) const {
        bool ret = false;
        if (value < _low || _high < value) {
            // errorcode_t::out_of_range;
        } else {
            T temp = value - _low;
            uint8 byte = _bitset[temp >> 3];
            uint8 shift = unused_bit(temp);
            if (byte & (uint8)(1 << shift)) {
                ret = true;
            }
        }
        return ret;
    }
    bool has(const std::list<T>& values) const {
        bool ret = false;
        std::list<T> items;
        for (const auto& item : values) {
            if (has(item)) {
                items.push_back(item);
            }
        }
        ret = (values == items);
        return ret;
    }

    void clear() { std::fill(_bitset.begin(), _bitset.end(), 0); }

    binary_t get() const {
        binary_t temp = _bitset;
        return temp;
    }

    uint8 unused_bit() const {
        T temp = _high - _low;
        return (7 - (temp & 7)) & 7;
    }

   protected:
    uint8 unused_bit(T value) const { return (7 - (value & 7)) & 7; }

   private:
    T _low;
    T _high;
    binary_t _bitset;
};

typedef t_bit_set<int> bit_set;

}  // namespace hotplace

#endif
