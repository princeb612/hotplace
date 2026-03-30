/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/base16.hpp>
#include <hotplace/sdk/base/system/bignumber.hpp>

namespace hotplace {

#define bn_intuitive 1
#define base base2p32

// #define bn_intuitive 0
// #define base base1e9

bignumber::bignumber(largeint value) { set(value); }

bignumber::bignumber(const bignumber &other) {
    _units = other._units;
    _sign = other._sign;
}

bignumber::bignumber(bignumber &&other) {
    _units = std::move(other._units);
    _sign = other._sign;
    other._sign = 1;
}

bignumber::bignumber(const binary_t &base16hexstream) { *this = base16hexstream; }

bignumber::bignumber(const std::string &base16hexstream) { *this = base16hexstream; }

bignumber::~bignumber() {}

bignumber &bignumber::operator=(const bignumber &other) {
    _units = other._units;
    _sign = other._sign;
    return *this;
}

bignumber &bignumber::operator=(bignumber &&other) {
    _units = std::move(other._units);
    _sign = other._sign;
    return *this;
}

bignumber &bignumber::operator=(largeint value) {
    set(value);
    return *this;
}

bignumber &bignumber::operator=(const binary_t &base16hexstream) {
    if (base16hexstream.empty()) {
        *this = 0;
    } else {
        binary_t bin = base16hexstream;
        auto size = bin.size();
        auto pad = (4 - (size & 3)) & 3;  // (4 - (size % 4)) & 3
        if (pad) {
            bin.reserve(size + pad);
            while (pad--) {
                bin.insert(bin.begin(), 0);
            }
        }
        _units.clear();
        while (false == bin.empty()) {
            uint32 t = hton32(*(uint32 *)&bin[0]);
            _units.insert(_units.begin(), t);
            bin.erase(bin.begin(), bin.begin() + 4);
        }
        trim();
    }
    return *this;
}

bignumber &bignumber::operator=(const std::string &base16hexstream) {
#if (bn_intuitive == 1)
    if (base16hexstream.empty()) {
        *this = 0;
    } else {
        binary_t bin;
        base16_decode(base16hexstream, bin);
        *this = bin;
    }
#else
    // not supported
#endif
    return *this;
}

bignumber bignumber::operator+(const bignumber &other) const { return add(*this, other); }

bignumber &bignumber::operator+=(const bignumber &other) { return *this = add(other); }

bignumber bignumber::operator-(const bignumber &other) const { return sub(*this, other); }

bignumber &bignumber::operator-=(const bignumber &other) { return *this = sub(other); }

bignumber bignumber::operator*(const bignumber &other) const { return mult(*this, other); }

bignumber &bignumber::operator*=(const bignumber &other) { return *this = mult(other); }

bignumber bignumber::operator/(const bignumber &other) const { return div(*this, other); }

bignumber &bignumber::operator/=(const bignumber &other) { return *this = div(other); }

bignumber bignumber::operator%(const bignumber &other) const { return mod(*this, other); }

bignumber &bignumber::operator%=(const bignumber &other) { return *this = mod(other); }

bignumber bignumber::operator&(const bignumber &other) const { return bitwise_and(*this, other); }

bignumber &bignumber::operator&=(const bignumber &other) { return *this = bitwise_and(*this, other); }

bignumber bignumber::operator|(const bignumber &other) const { return bitwise_or(*this, other); }

bignumber &bignumber::operator|=(const bignumber &other) { return *this = bitwise_or(*this, other); }

bignumber bignumber::operator^(const bignumber &other) const { return bitwise_xor(*this, other); }

bignumber &bignumber::operator^=(const bignumber &other) { return *this = bitwise_xor(*this, other); }

bignumber bignumber::operator~() const { return bitwise_not(*this); }

bool bignumber::operator<(const bignumber &other) const { return compare(*this, other) < 0; }

bool bignumber::operator<=(const bignumber &other) const { return compare(*this, other) <= 0; }

bool bignumber::operator>(const bignumber &other) const { return compare(*this, other) > 0; }

bool bignumber::operator>=(const bignumber &other) const { return compare(*this, other) >= 0; }

bool bignumber::operator==(const bignumber &other) const { return compare(*this, other) == 0; }

bool bignumber::operator!=(const bignumber &other) const { return compare(*this, other) != 0; }

bignumber bignumber::operator<<(unsigned int k) const { return leftshift(*this, k); }

bignumber &bignumber::operator<<=(unsigned int k) { return *this = leftshift(*this, k); }

bignumber bignumber::operator>>(unsigned int shift) const { return rightshift(*this, shift); }

bignumber &bignumber::operator>>=(unsigned int shift) { return *this = rightshift(*this, shift); }

bignumber &bignumber::set(largeint value) {
    if (value >= 0) {
        _sign = 1;
    } else {
        _sign = -1;
        value = -value;
    }
    _units.clear();
    while (value) {
        _units.push_back(value % base);
        value /= base;
    }
    if (_units.empty()) {
        _sign = 1;
    }
    return *this;
}

bignumber bignumber::add(const bignumber &lhs, const bignumber &rhs) const {
    bignumber res;
    if (lhs._sign == rhs._sign) {
        res = absadd(lhs, rhs);
        res._sign = lhs._sign;
    } else {
        if (abscmp(lhs, rhs) >= 0) {
            res = abssub(lhs, rhs);
            res._sign = lhs._sign;
        } else {
            res = abssub(rhs, lhs);
            res._sign = rhs._sign;
        }
    }
    return res;
}

bignumber bignumber::sub(const bignumber &lhs, const bignumber &rhs) const {
    bignumber res;
    if (lhs._sign != rhs._sign) {
        res = absadd(lhs, rhs);
        res._sign = lhs._sign;
    } else {
        int cmp = abscmp(lhs, rhs);
        if (cmp == 0) {
            res = 0;
        } else {
            if (cmp > 0) {
                res = abssub(lhs, rhs);
                res._sign = lhs._sign;
            } else {
                res = abssub(rhs, lhs);
                res._sign = -lhs._sign;
            }
        }
    }
    return res;
}

bignumber bignumber::mult_simple(const bignumber &lhs, const bignumber &rhs) const {
    // schoolbook O(n^2)
    bignumber res;
    res._sign = lhs._sign * rhs._sign;
    res._units.assign(lhs._units.size() + rhs._units.size(), 0);

    for (size_t i = 0; i < lhs._units.size(); i++) {
        int64 carry = 0;
        for (size_t j = 0; j < rhs._units.size() || carry; j++) {
            int64 cur = res._units[i + j] + (int64)lhs._units[i] * (j < rhs._units.size() ? rhs._units[j] : 0) + carry;

            res._units[i + j] = cur % base;
            carry = cur / base;
        }
    }
    res.trim();
    return res;
}

bignumber bignumber::mult(const bignumber &lhs, const bignumber &rhs) const {
    // karatsuba O(n^1.58)
    bignumber res;
    auto n = lhs._units.size();
    if (n < 32) {
        res = mult_simple(lhs, rhs);
    } else {
        int k = n / 2;

        bignumber a1, a2, b1, b2;

        a1._units = std::vector<uint32>(lhs._units.begin(), lhs._units.begin() + k);
        a2._units = std::vector<uint32>(lhs._units.begin() + k, lhs._units.end());

        b1._units = std::vector<uint32>(rhs._units.begin(), rhs._units.begin() + std::min((int)rhs._units.size(), k));
        b2._units = std::vector<uint32>(rhs._units.begin() + std::min((int)rhs._units.size(), k), rhs._units.end());

        bignumber z0 = mult(a1, b1);
        bignumber z2 = mult(a2, b2);
        bignumber z1 = mult(a1 + a2, b1 + b2) - z0 - z2;

        res._units.resize(n * 2);

        for (size_t i = 0; i < z0._units.size(); i++) {
            res._units[i] += z0._units[i];
        }
        for (size_t i = 0; i < z1._units.size(); i++) {
            res._units[i + k] += z1._units[i];
        }
        for (size_t i = 0; i < z2._units.size(); i++) {
            res._units[i + 2 * k] += z2._units[i];
        }

        res.trim();
    }
    return res;
}

bignumber bignumber::div(const bignumber &lhs, const bignumber &rhs) const {
    // knuth algorithm O(n^2)
    bignumber res;
    if (rhs == 0) {
        // division by zero
        // throw exception
    } else if (abscmp(rhs, 1) == 0) {
        if (lhs._sign == 1) {
            res = lhs;
        } else {
            res._sign = -res._sign;
        }
    } else {
        bignumber a = lhs;
        bignumber b = rhs;
        bignumber r;

        res._sign = lhs._sign * rhs._sign;
        res._units.resize(a._units.size());

        a._sign = b._sign = 1;

        for (int i = (int)a._units.size() - 1; i >= 0; i--) {
            r._units.insert(r._units.begin(), a._units[i]);
            r.trim();

            uint32 x = 0;
            uint32 l = 0;
            uint32 h = base - 1;
            while (l <= h) {
                uint32 m = (l + h) >> 1;
                bignumber t = b * m;
                if (t <= r) {
                    x = m;
                    l = m + 1;
                } else {
                    h = m - 1;
                }
            }

            res._units[i] = x;
            r = r - b * x;
        }

        res.trim();
    }
    return res;
}

bignumber bignumber::bitwise_and(const bignumber &lhs, const bignumber &rhs) const {
    bignumber res;
    auto lsize = lhs._units.size();
    auto rsize = rhs._units.size();
    auto h = std::max(lsize, rsize);
    auto l = std::min(lsize, rsize);
    for (auto i = 0; i < h; i++) {
        uint32 lval = (i < lsize) ? lhs._units[i] : 0;
        uint32 rval = (i < rsize) ? rhs._units[i] : 0;
        res._units.push_back(lval & rval);
    }
    return res;
}

bignumber bignumber::bitwise_or(const bignumber &lhs, const bignumber &rhs) const {
    bignumber res;
    auto lsize = lhs._units.size();
    auto rsize = rhs._units.size();
    auto h = std::max(lsize, rsize);
    auto l = std::min(lsize, rsize);
    for (auto i = 0; i < h; i++) {
        uint32 lval = (i < lsize) ? lhs._units[i] : 0;
        uint32 rval = (i < rsize) ? rhs._units[i] : 0;
        res._units.push_back(lval | rval);
    }
    return res;
}

bignumber bignumber::bitwise_xor(const bignumber &lhs, const bignumber &rhs) const {
    bignumber res;
    auto lsize = lhs._units.size();
    auto rsize = rhs._units.size();
    auto h = std::max(lsize, rsize);
    auto l = std::min(lsize, rsize);
    for (auto i = 0; i < h; i++) {
        uint32 lval = (i < lsize) ? lhs._units[i] : 0;
        uint32 rval = (i < rsize) ? rhs._units[i] : 0;
        res._units.push_back(lval ^ rval);
    }
    return res;
}

bignumber bignumber::bitwise_not(const bignumber &other) const {
    bignumber res;
    for (uint32 item : other._units) {
        res._units.push_back(!item);
    }
    return res;
}

// c++ style remainder
// -7 % 3 = -1, 7 % -3 = 1
bignumber bignumber::mod(const bignumber &lhs, const bignumber &rhs) { return lhs - (lhs / rhs) * rhs; }

bignumber bignumber::gcd(const bignumber &lhs, const bignumber &rhs) {
    bignumber a = lhs;
    bignumber b = rhs;
    while (false == b._units.empty()) {
        a %= b;
        std::swap(a, b);
    }
    return a;
}

bignumber bignumber::modinv(bignumber a, bignumber m) {
    bignumber m0 = m;
    bignumber x0 = 0;
    bignumber x1 = 1;
    while (a > 1) {
        bignumber q = a / m;
        bignumber t = m;

        m = mod(a, m);
        a = t;

        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    if (x1 < 0) {
        x1 = x1 + m0;
    }
    return x1;
}

bignumber bignumber::modpow(bignumber b, bignumber exp, const bignumber &m) {
    bignumber res = 1;
    b = mod(b, m);

    while (!exp._units.empty()) {
        if (exp._units[0] & 1) res = mod(res * b, m);

        b = mod(b * b, m);

        // exp /= 2
        uint64 carry = 0;
        for (auto i = exp._units.size() - 1; i >= 0; i--) {
            uint64 cur = exp._units[i] + carry * base;
            exp._units[i] = cur / 2;
            carry = cur % 2;
        }
        exp.trim();
    }
    return res;
}

bignumber bignumber::sqrt(const bignumber &other) {
    bignumber x = other;
    bignumber y = (x + 1) / 2;
    while (y < x) {
        x = y;
        y = (x + other / x) / 2;
    }
    return x;
}

int bignumber::compare(const bignumber &lhs, const bignumber &rhs) const {
    if (lhs._sign != rhs._sign) {
        return lhs._sign < rhs._sign ? -1 : 1;
    }

    if (lhs._units.size() != rhs._units.size()) {
        if (lhs._sign == 1) {
            return lhs._units.size() < rhs._units.size() ? -1 : 1;
        } else {
            return lhs._units.size() < rhs._units.size() ? 1 : -1;
        }
    }

    for (int i = (int)lhs._units.size() - 1; i >= 0; i--) {
        if (lhs._units[i] != rhs._units[i]) {
            if (lhs._sign == 1) {
                return lhs._units[i] < rhs._units[i] ? -1 : 1;
            } else {
                return lhs._units[i] < rhs._units[i] ? 1 : -1;
            }
        }
    }
    return 0;
}

bignumber bignumber::leftshift(const bignumber &v, unsigned int shift) const {
#if (bn_intuitive == 0)
    // O(shift * n^2)
    bignumber res = v;
    bignumber two(2);
    while (shift--) {
        res = res * two;
    }
    return res;
#else
    // O(n)
    bignumber res = 0;
    if (v._units.empty()) {
    } else {
        int limb_shift = shift / 32;
        int bit_shift = shift % 32;

        res._sign = v._sign;
        res._units.assign(limb_shift, 0);

        uint64 carry = 0;
        for (uint32 x : v._units) {
            uint64 cur = ((uint64)x << bit_shift) | carry;
            res._units.push_back((uint32)cur);
            carry = cur >> 32;
        }

        if (carry) {
            res._units.push_back((uint32)carry);
        }
    }
    return res;
#endif
}

bignumber bignumber::rightshift(const bignumber &v, unsigned int shift) const {
#if (bn_intuitive == 0)
    // O(shift * n^2)
    bignumber res = v;
    bignumber two(2);
    while (shift--) {
        res = res / two;
    }
    return res;
#else
    // O(n);
    bignumber res = 0;
    if (v._units.empty()) {
    } else {
        int limb_shift = shift / 32;
        int bit_shift = shift % 32;

        if ((int)v._units.size() <= limb_shift) {
        } else {
            res._sign = v._sign;
            res._units.resize(v._units.size() - limb_shift);

            uint32 carry = 0;
            for (int i = (int)v._units.size() - 1; i >= limb_shift; --i) {
                uint32 cur = v._units[i];

                res._units[i - limb_shift] = (cur >> bit_shift) | ((uint64)carry << (32 - bit_shift));
                carry = cur & ((1u << bit_shift) - 1);
            }

            res.trim();
        }
    }
    return res;
#endif
}

void bignumber::trim() {
    while ((false == _units.empty()) && (0 == _units.back())) {
        _units.pop_back();
    }
    if (_units.empty()) {
        _sign = 1;
    }
}

int bignumber::abscmp(const bignumber &lhs, const bignumber &rhs) {
    int ret = 0;
    if (lhs._units.size() != rhs._units.size()) {
        ret = lhs._units.size() < rhs._units.size() ? -1 : 1;
    } else {
        for (int i = (int)lhs._units.size() - 1; i >= 0; --i) {
            if (lhs._units[i] != rhs._units[i]) {
                ret = lhs._units[i] < rhs._units[i] ? -1 : 1;
                break;
            }
        }
    }
    return ret;
}

bignumber bignumber::absadd(const bignumber &lhs, const bignumber &rhs) {
    // O(n)
    bignumber res;
    int64 carry = 0;
    size_t n = std::max(lhs._units.size(), rhs._units.size());
    res._units.resize(n);

    for (size_t i = 0; i < n; i++) {
        int64 sum = carry;
        if (i < lhs._units.size()) {
            sum += lhs._units[i];
        }
        if (i < rhs._units.size()) {
            sum += rhs._units[i];
        }
        res._units[i] = sum % base;
        carry = sum / base;
    }
    if (carry) {
        res._units.push_back(carry);
    }
    return res;
}

bignumber bignumber::abssub(const bignumber &lhs, const bignumber &rhs) {
    // |lhs| >= |rhs|
    // O(n)
    bignumber res;
    res._units.resize(lhs._units.size());
    int64 carry = 0;

    for (size_t i = 0; i < lhs._units.size(); i++) {
        int64 cur = (int64)lhs._units[i] - carry;
        if (i < rhs._units.size()) {
            cur -= rhs._units[i];
        }
        if (cur < 0) {
            cur += base;
            carry = 1;
        } else {
            carry = 0;
        }
        res._units[i] = (uint32)cur;
    }
    res.trim();
    return res;
}

bignumber &bignumber::add(const bignumber &other) { return *this = add(*this, other); }

bignumber &bignumber::sub(const bignumber &other) { return *this = sub(*this, other); }

bignumber &bignumber::mult(const bignumber &other) { return *this = mult(*this, other); }

bignumber &bignumber::div(const bignumber &other) { return *this = div(*this, other); }

bignumber &bignumber::mod(const bignumber &other) { return *this = mod(*this, other); }

bignumber &bignumber::neg() {
    if (false == _units.empty()) {
        _sign = -_sign;
    }
    return *this;
}

bignumber &bignumber::bitwise_and(const bignumber &other) { return *this = bitwise_and(*this, other); }

bignumber &bignumber::bitwise_or(const bignumber &other) { return *this = bitwise_or(*this, other); }

bignumber &bignumber::bitwise_xor(const bignumber &other) { return *this = bitwise_xor(*this, other); }

bignumber &bignumber::bitwise_not() { return *this = bitwise_not(*this); }

size_t bignumber::capacity() const { return _units.size(); }

std::string bignumber::str() const {
#if (bn_intuitive == 0)
    std::stringstream ss;
    // base
    if (_units.empty()) {
        ss << '0';
    } else {
        if (-1 == _sign) {
            ss << '-';
        }
        ss << _units.back();

        for (int i = (int)_units.size() - 2; i >= 0; i--) {
            ss << std::setw(9) << std::setfill('0') << _units[i];
        }
    }
    return ss.str();
#else
    std::string res;
    bignumber tmp = *this;
    if (tmp._units.empty()) {
        res = "0";
    } else {
        while (false == tmp._units.empty()) {
            uint64 carry = 0;
            for (int i = (int)tmp._units.size() - 1; i >= 0; i--) {
                uint64 cur = (carry << 32) | tmp._units[i];
                tmp._units[i] = (uint32)(cur / 10);
                carry = cur % 10;
            }
            res.push_back('0' + carry);
            while (false == tmp._units.empty() && 0 == tmp._units.back()) {
                tmp._units.pop_back();
            }
        }
        if (-1 == _sign) {
            res.push_back('-');
        }

        std::reverse(res.begin(), res.end());
    }
    return res;
#endif
}

void bignumber::dump(std::function<void(const binary_t &)> func) const {
    binary_t out;
    for (int i = (int)_units.size() - 1; i >= 0; i--) {
        auto x = _units[i];
        if (is_little_endian()) {
            x = hton32(x);
        }
        for (int i = 0; i < 4; i++) {
            out.push_back((x >> (8 * i)) & 0xFF);
        }
    }
    if (func) {
        func(out);
    }
}

int bignumber::get(binary_t &base16hexstream, bool trimzero) const {
    base16hexstream.clear();
    for (auto rit = _units.rbegin(); rit != _units.rend(); rit++) {
        binary_append(base16hexstream, *rit, ntoh32);
    }
    if (trimzero) {
        if (false == base16hexstream.empty()) {
            while (0 == base16hexstream.front()) {
                base16hexstream.erase(base16hexstream.begin());
            }
        }
    }
    return _sign;
}

binary_t &operator<<(binary_t &lhs, const bignumber &rhs) {
    rhs.get(lhs, false);
    return lhs;
}

std::string &operator<<(std::string &lhs, const bignumber &rhs) {
    binary_t bin;
    rhs.get(bin, false);
    lhs = base16_encode(bin);
    return lhs;
}

binary_t &operator>>(const bignumber &lhs, binary_t &rhs) {
    lhs.get(rhs, false);
    return rhs;
}
std::string &operator>>(const bignumber &lhs, std::string &rhs) {
    binary_t bin;
    lhs.get(bin, false);
    rhs = base16_encode(bin);
    return rhs;
}

}  // namespace hotplace
