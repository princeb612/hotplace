/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/system/bignumber.hpp>

namespace hotplace {

#if 1
#define bn_intuitive 1
#define base base2p32
#else
#define bn_intuitive 0
#define base base1e9
#endif

bignumber::bignumber(largeint value) { set(value); }

bignumber::bignumber(const bignumber &other) {
    _limbs = other._limbs;
    _sign = other._sign;
}

bignumber::bignumber(bignumber &&other) {
    _limbs = std::move(other._limbs);
    _sign = other._sign;
    other._sign = 1;
}

bignumber::~bignumber() {}

bignumber &bignumber::operator=(const bignumber &other) {
    _limbs = other._limbs;
    _sign = other._sign;
    return *this;
}

bignumber &bignumber::operator=(largeint value) {
    set(value);
    return *this;
}

bignumber bignumber::operator+(const bignumber &other) const { return add(*this, other); }

bignumber &bignumber::operator+=(const bignumber &other) { return *this = add(*this, other); }

bignumber bignumber::operator-(const bignumber &other) const { return sub(*this, other); }

bignumber &bignumber::operator-=(const bignumber &other) { return *this = sub(*this, other); }

bignumber bignumber::operator*(const bignumber &other) const { return mult(*this, other); }

bignumber &bignumber::operator*=(const bignumber &other) { return *this = mult(*this, other); }

bignumber bignumber::operator/(const bignumber &other) const { return div(*this, other); }

bignumber &bignumber::operator/=(const bignumber &other) { return *this = div(*this, other); }

bignumber bignumber::operator%(const bignumber &other) const { return mod(*this, other); }

bignumber &bignumber::operator%=(const bignumber &other) { return *this = mod(*this, other); }

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
    if (value > 0) {
        _sign = 1;
    } else {
        _sign = -1;
        value = -value;
    }
    _limbs.clear();
    while (value) {
        _limbs.push_back(value % base);
        value /= base;
    }
    if (_limbs.empty()) {
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
    res._limbs.assign(lhs._limbs.size() + rhs._limbs.size(), 0);

    for (size_t i = 0; i < lhs._limbs.size(); i++) {
        int64 carry = 0;
        for (size_t j = 0; j < rhs._limbs.size() || carry; j++) {
            int64 cur = res._limbs[i + j] + (int64)lhs._limbs[i] * (j < rhs._limbs.size() ? rhs._limbs[j] : 0) + carry;

            res._limbs[i + j] = cur % base;
            carry = cur / base;
        }
    }
    res.trim();
    return res;
}

bignumber bignumber::mult(const bignumber &lhs, const bignumber &rhs) const {
    // karatsuba O(n^1.58)
    bignumber res;
    auto n = lhs._limbs.size();
    if (n < 32) {
        res = mult_simple(lhs, rhs);
    } else {
        int k = n / 2;

        bignumber a1, a2, b1, b2;

        a1._limbs = std::vector<uint32>(lhs._limbs.begin(), lhs._limbs.begin() + k);
        a2._limbs = std::vector<uint32>(lhs._limbs.begin() + k, lhs._limbs.end());

        b1._limbs = std::vector<uint32>(rhs._limbs.begin(), rhs._limbs.begin() + std::min((int)rhs._limbs.size(), k));
        b2._limbs = std::vector<uint32>(rhs._limbs.begin() + std::min((int)rhs._limbs.size(), k), rhs._limbs.end());

        bignumber z0 = mult(a1, b1);
        bignumber z2 = mult(a2, b2);
        bignumber z1 = mult(a1 + a2, b1 + b2) - z0 - z2;

        res._limbs.resize(n * 2);

        for (size_t i = 0; i < z0._limbs.size(); i++) {
            res._limbs[i] += z0._limbs[i];
        }
        for (size_t i = 0; i < z1._limbs.size(); i++) {
            res._limbs[i + k] += z1._limbs[i];
        }
        for (size_t i = 0; i < z2._limbs.size(); i++) {
            res._limbs[i + 2 * k] += z2._limbs[i];
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
        res._limbs.resize(a._limbs.size());

        a._sign = b._sign = 1;

        for (int i = (int)a._limbs.size() - 1; i >= 0; i--) {
            r._limbs.insert(r._limbs.begin(), a._limbs[i]);
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

            res._limbs[i] = x;
            r = r - b * x;
        }

        res.trim();
    }
    return res;
}

// c++ style remainder
// -7 % 3 = -1, 7 % -3 = 1
bignumber bignumber::mod(const bignumber &lhs, const bignumber &rhs) { return lhs - (lhs / rhs) * rhs; }

bignumber bignumber::gcd(const bignumber &lhs, const bignumber &rhs) {
    bignumber a = lhs;
    bignumber b = rhs;
    while (false == b._limbs.empty()) {
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

    while (!exp._limbs.empty()) {
        if (exp._limbs[0] & 1) res = mod(res * b, m);

        b = mod(b * b, m);

        // exp /= 2
        uint64 carry = 0;
        for (auto i = exp._limbs.size() - 1; i >= 0; i--) {
            uint64 cur = exp._limbs[i] + carry * base;
            exp._limbs[i] = cur / 2;
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

    if (lhs._limbs.size() != rhs._limbs.size()) {
        if (lhs._sign == 1) {
            return lhs._limbs.size() < rhs._limbs.size() ? -1 : 1;
        } else {
            return lhs._limbs.size() < rhs._limbs.size() ? 1 : -1;
        }
    }

    for (int i = (int)lhs._limbs.size() - 1; i >= 0; i--) {
        if (lhs._limbs[i] != rhs._limbs[i]) {
            if (lhs._sign == 1) {
                return lhs._limbs[i] < rhs._limbs[i] ? -1 : 1;
            } else {
                return lhs._limbs[i] < rhs._limbs[i] ? 1 : -1;
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
    if (v._limbs.empty()) {
    } else {
        int limb_shift = shift / 32;
        int bit_shift = shift % 32;

        res._sign = v._sign;
        res._limbs.assign(limb_shift, 0);

        uint64 carry = 0;
        for (uint32 x : v._limbs) {
            uint64 cur = ((uint64)x << bit_shift) | carry;
            res._limbs.push_back((uint32)cur);
            carry = cur >> 32;
        }

        if (carry) {
            res._limbs.push_back((uint32)carry);
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
    if (v._limbs.empty()) {
    } else {
        int limb_shift = shift / 32;
        int bit_shift = shift % 32;

        if ((int)v._limbs.size() <= limb_shift) {
        } else {
            res._sign = v._sign;
            res._limbs.resize(v._limbs.size() - limb_shift);

            uint32 carry = 0;
            for (int i = (int)v._limbs.size() - 1; i >= limb_shift; --i) {
                uint32 cur = v._limbs[i];

                res._limbs[i - limb_shift] = (cur >> bit_shift) | ((uint64)carry << (32 - bit_shift));
                carry = cur & ((1u << bit_shift) - 1);
            }

            res.trim();
        }
    }
    return res;
#endif
}

void bignumber::trim() {
    while ((false == _limbs.empty()) && (0 == _limbs.back())) {
        _limbs.pop_back();
    }
    if (_limbs.empty()) {
        _sign = 1;
    }
}

int bignumber::abscmp(const bignumber &lhs, const bignumber &rhs) {
    int ret = 0;
    if (lhs._limbs.size() != rhs._limbs.size()) {
        ret = lhs._limbs.size() < rhs._limbs.size() ? -1 : 1;
    } else {
        for (int i = (int)lhs._limbs.size() - 1; i >= 0; --i) {
            if (lhs._limbs[i] != rhs._limbs[i]) {
                ret = lhs._limbs[i] < rhs._limbs[i] ? -1 : 1;
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
    size_t n = std::max(lhs._limbs.size(), rhs._limbs.size());
    res._limbs.resize(n);

    for (size_t i = 0; i < n; i++) {
        int64 sum = carry;
        if (i < lhs._limbs.size()) {
            sum += lhs._limbs[i];
        }
        if (i < rhs._limbs.size()) {
            sum += rhs._limbs[i];
        }
        res._limbs[i] = sum % base;
        carry = sum / base;
    }
    if (carry) {
        res._limbs.push_back(carry);
    }
    return res;
}

bignumber bignumber::abssub(const bignumber &lhs, const bignumber &rhs) {
    // |lhs| >= |rhs|
    // O(n)
    bignumber res;
    res._limbs.resize(lhs._limbs.size());
    int64 carry = 0;

    for (size_t i = 0; i < lhs._limbs.size(); i++) {
        int64 cur = (int64)lhs._limbs[i] - carry;
        if (i < rhs._limbs.size()) {
            cur -= rhs._limbs[i];
        }
        if (cur < 0) {
            cur += base;
            carry = 1;
        } else {
            carry = 0;
        }
        res._limbs[i] = (uint32)cur;
    }
    res.trim();
    return res;
}

void bignumber::normalize() {}

std::string bignumber::str() const {
#if (bn_intuitive == 0)
    std::stringstream ss;
    // base
    if (_limbs.empty()) {
        ss << '0';
    } else {
        if (-1 == _sign) {
            ss << '-';
        }
        ss << _limbs.back();

        for (int i = (int)_limbs.size() - 2; i >= 0; i--) {
            ss << std::setw(9) << std::setfill('0') << _limbs[i];
        }
    }
    return ss.str();
#else
    std::string res;
    bignumber tmp = *this;
    if (tmp._limbs.empty()) {
        res = "0";
    } else {
        while (false == tmp._limbs.empty()) {
            uint64 carry = 0;
            for (int i = (int)tmp._limbs.size() - 1; i >= 0; i--) {
                uint64 cur = (carry << 32) | tmp._limbs[i];
                tmp._limbs[i] = (uint32)(cur / 10);
                carry = cur % 10;
            }
            res.push_back('0' + carry);
            while (false == tmp._limbs.empty() && 0 == tmp._limbs.back()) {
                tmp._limbs.pop_back();
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

void bignumber::dump(std::function<void(binary_t &)> func) {
    bignumber res = 0;
    int debug = 1;
}

}  // namespace hotplace
