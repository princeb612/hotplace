/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   bitset.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/nostd/bitset.hpp>

namespace hotplace {

bitset::bitset(int low, int high) : _low(std::min(low, high)), _high(std::max(low, high)) {
    size_t allocsize = (_high - _low + 8) / 8;
    _bitset.resize(allocsize);
}

bitset::bitset(const bitset& other) { *this = other; }

bitset::bitset(bitset&& other) { *this = std::move(other); }

bitset::~bitset() {}

bitset& bitset::operator=(const bitset& other) {
    _low = other._low;
    _high = other._high;
    _bitset = other._bitset;
    return *this;
}

bitset& bitset::operator=(bitset&& other) {
    std::swap(_low, other._low);
    std::swap(_high, other._high);
    std::swap(_bitset, other._bitset);
    return *this;
}

return_t bitset::add(int value) {
    return_t ret = errorcode_t::success;
    if (value < _low || _high < value) {
        ret = errorcode_t::out_of_range;
    } else {
        int temp = value - _low;
        uint8 shift = unused_bit(temp);
        _bitset[temp >> 3] |= (uint8)(1 << shift);
    }
    return ret;
}

return_t bitset::subtract(int value) {
    return_t ret = errorcode_t::success;
    if (value < _low || _high < value) {
        ret = errorcode_t::out_of_range;
    } else {
        int temp = value - _low;
        uint8 shift = unused_bit(temp);
        _bitset[temp >> 3] |= (uint8)(1 << shift);
    }
    return ret;
}

bool bitset::has(int value) const {
    bool ret = false;
    if (value < _low || _high < value) {
        // errorcode_t::out_of_range;
    } else {
        int temp = value - _low;
        uint8 byte = _bitset[temp >> 3];
        uint8 shift = unused_bit(temp);
        if (byte & (uint8)(1 << shift)) {
            ret = true;
        }
    }
    return ret;
}

bool bitset::has(const std::list<int>& values) const {
    bool ret = false;
    std::list<int> items;
    for (const auto& item : values) {
        if (has(item)) {
            items.push_back(item);
        }
    }
    if (values.size() == items.size()) {
        auto temp = values;
        temp.sort();
        items.sort();
        ret = (temp == items);
    }
    return ret;
}

binary_t bitset::get() const {
    binary_t temp = _bitset;
    return temp;
}

uint8 bitset::unused_bit() const {
    int temp = _high - _low;
    return (7 - (temp & 7)) & 7;
}

uint8 bitset::unused_bit(int value) const { return (7 - (value & 7)) & 7; }

}  // namespace hotplace
