/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   bignumber_operator.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <cmath>
#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/base/encoding/base16.hpp>
#include <hotplace/sdk/base/nostd/binary.hpp>
#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/base/system/bignumber.hpp>

namespace hotplace {

bignumber& bignumber::operator=(const bignumber& other) {
    _v = other._v;
    _sign = other._sign;
    return *this;
}

bignumber& bignumber::operator=(bignumber&& other) {
    std::swap(_v, other._v);
    std::swap(_sign, other._sign);
    return *this;
}

bignumber& bignumber::operator=(const variant_t& vt) { return set(vt); }

bignumber& bignumber::operator=(const binary_t& base16hexstream) { return set(base16hexstream); }

bignumber& bignumber::operator=(const char* value) { return set(value); }

bignumber& bignumber::operator=(const std::string& value) { return set(value); }

bignumber bignumber::operator+(const bignumber& other) const { return add(*this, other); }

bignumber& bignumber::operator+=(const bignumber& other) { return *this = add(other); }

bignumber bignumber::operator-(const bignumber& other) const { return sub(*this, other); }

bignumber& bignumber::operator-=(const bignumber& other) { return *this = sub(other); }

bignumber bignumber::operator*(const bignumber& other) const { return mult(*this, other); }

bignumber& bignumber::operator*=(const bignumber& other) { return *this = mult(other); }

bignumber bignumber::operator/(const bignumber& other) const { return div(*this, other); }

bignumber& bignumber::operator/=(const bignumber& other) { return *this = div(other); }

bignumber bignumber::operator%(const bignumber& other) const { return mod(*this, other); }

bignumber& bignumber::operator%=(const bignumber& other) { return *this = mod(other); }

bignumber bignumber::operator&(const bignumber& other) const { return bitwise_and(*this, other); }

bignumber& bignumber::operator&=(const bignumber& other) { return *this = bitwise_and(*this, other); }

bignumber bignumber::operator|(const bignumber& other) const { return bitwise_or(*this, other); }

bignumber& bignumber::operator|=(const bignumber& other) { return *this = bitwise_or(*this, other); }

bignumber bignumber::operator^(const bignumber& other) const { return bitwise_xor(*this, other); }

bignumber& bignumber::operator^=(const bignumber& other) { return *this = bitwise_xor(*this, other); }

bignumber bignumber::operator~() const { return bitwise_not(*this); }

bool bignumber::operator<(const bignumber& other) const { return compare(*this, other) < 0; }

bool bignumber::operator<=(const bignumber& other) const { return compare(*this, other) <= 0; }

bool bignumber::operator>(const bignumber& other) const { return compare(*this, other) > 0; }

bool bignumber::operator>=(const bignumber& other) const { return compare(*this, other) >= 0; }

bool bignumber::operator==(const bignumber& other) const { return compare(*this, other) == 0; }

bool bignumber::operator!=(const bignumber& other) const { return compare(*this, other) != 0; }

bignumber bignumber::operator<<(const bignumber& shift) const { return leftshift(*this, shift); }

bignumber& bignumber::operator<<=(const bignumber& shift) { return *this = leftshift(*this, shift); }

bignumber bignumber::operator>>(const bignumber& shift) const { return rightshift(*this, shift); }

bignumber& bignumber::operator>>=(const bignumber& shift) { return *this = rightshift(*this, shift); }

bignumber& bignumber::operator-() { return neg(); }

bignumber& bignumber::operator++() { return *this += 1; }

bignumber& bignumber::operator--() { return *this -= 1; }

bignumber bignumber::operator++(int) {
    bignumber res(*this);
    res += 1;
    return res;
}

bignumber bignumber::operator--(int) {
    bignumber res(*this);
    res -= 1;
    return res;
}

bignumber::operator bool() const {
    for (const auto& item : _v) {
        if (item) return true;
    }
    return false;
}

bignumber::operator uint8() const {
    uint32 v = 0;
    if (false == _v.empty()) v = _v[0];
    return (uint8)v;
}

bignumber::operator uint16() const {
    uint32 v = 0;
    if (false == _v.empty()) v = _v[0];
    return (uint16)v;
}

bignumber::operator uint32() const {
    uint32 v = 0;
    if (false == _v.empty()) v = _v[0];
    return v;
}

binary_t& operator<<(binary_t& lhs, const bignumber& rhs) {
    rhs.get(lhs, false);
    return lhs;
}

std::string& operator<<(std::string& lhs, const bignumber& rhs) {
    binary_t bin;
    rhs.get(bin, true);
    lhs = base16_encode(bin);
    return lhs;
}

binary_t& operator>>(const bignumber& lhs, binary_t& rhs) {
    lhs.get(rhs, false);
    return rhs;
}

std::string& operator>>(const bignumber& lhs, std::string& rhs) {
    binary_t bin;
    lhs.get(bin, true);
    rhs = base16_encode(bin);
    return rhs;
}

}  // namespace hotplace
