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

#include <hotplace/sdk/base/basic/base16.hpp>
#include <hotplace/sdk/base/basic/binary.hpp>
#include <hotplace/sdk/base/system/bignumber.hpp>
#include <hotplace/sdk/base/system/endian.hpp>

namespace hotplace {

#define bn_intuitive 1
#define base base2p32

// #define bn_intuitive 0
// #define base base1e9

static const uint64 base2p32 = 0x100000000;  // intuitive 2^32
static const uint32 base1e9 = 1000000000;    // printf-friendly (setw(9) << limb)

bignumber::bignumber() { set(0); }

bignumber::bignumber(int8 value) { set(value); }

bignumber::bignumber(uint8 value) { setu(value); }

bignumber::bignumber(int16 value) { set(value); }

bignumber::bignumber(uint16 value) { setu(value); }

bignumber::bignumber(int32 value) { set(value); }

bignumber::bignumber(uint32 value) { setu(value); }

bignumber::bignumber(int64 value) { set(value); }

bignumber::bignumber(uint64 value) { setu(value); }

#ifdef __SIZEOF_INT128__
bignumber::bignumber(int128 value) { set(value); }

bignumber::bignumber(uint128 value) { setu(value); }
#endif

bignumber::bignumber(const bignumber &other) {
    _v = other._v;
    _sign = other._sign;
}

bignumber::bignumber(bignumber &&other) {
    _v = std::move(other._v);
    _sign = other._sign;
    other._sign = 1;
}

bignumber::bignumber(const byte_t *p, size_t n) { set(p, n); }

bignumber::bignumber(const binary_t &base16hexstream) { sethex(base16hexstream); }

bignumber::bignumber(const std::string &value) { setstring(value); }

bignumber::~bignumber() {}

bignumber &bignumber::operator=(const bignumber &other) {
    _v = other._v;
    _sign = other._sign;
    return *this;
}

bignumber &bignumber::operator=(bignumber &&other) {
    _v = std::move(other._v);
    _sign = other._sign;
    return *this;
}

bignumber &bignumber::operator=(int8 value) { return set(value); }

bignumber &bignumber::operator=(uint8 value) { return setu(value); }

bignumber &bignumber::operator=(int16 value) { return set(value); }

bignumber &bignumber::operator=(uint16 value) { return setu(value); }

bignumber &bignumber::operator=(int32 value) { return set(value); }

bignumber &bignumber::operator=(uint32 value) { return setu(value); }

bignumber &bignumber::operator=(int64 value) { return set(value); }

bignumber &bignumber::operator=(uint64 value) { return setu(value); }

#ifdef __SIZEOF_INT128__
bignumber &bignumber::operator=(int128 value) { return set(value); }

bignumber &bignumber::operator=(uint128 value) { return setu(value); }
#endif

bignumber &bignumber::operator=(const binary_t &base16hexstream) { return sethex(base16hexstream); }

bignumber &bignumber::operator=(const char *value) { return setstring(value); }

bignumber &bignumber::operator=(const std::string &value) { return setstring(value); }

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

bignumber &bignumber::operator++() { return *this += 1; }

bignumber &bignumber::operator--() { return *this -= 1; }

bignumber &bignumber::operator-() { return neg(); }

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

#ifdef __SIZEOF_INT128__
bignumber &bignumber::set(int128 value)
#else
bignumber &bignumber::set(int64 value)
#endif
{
    if (value >= 0) {
        _sign = 1;
    } else {
        _sign = -1;
        value = -value;
    }
    _v.clear();
    while (value) {
        _v.push_back(value % base);
        value /= base;
    }
    if (_v.empty()) {
        _sign = 1;
    }
    return *this;
}

#ifdef __SIZEOF_INT128__
bignumber &bignumber::setu(uint128 value)
#else
bignumber &bignumber::setu(uint64 value)
#endif
{
    _sign = 1;
    _v.clear();
    while (value) {
        _v.push_back(value % base);
        value /= base;
    }
    return *this;
}

bignumber &bignumber::set(const byte_t *p, size_t n) {
    _sign = 1;
    _v.clear();
#if (bn_intuitive == 1)
    if (p) {
        binary_t bin;
        bin.insert(bin.end(), p, p + n);

        auto size = bin.size();
        auto pad = (4 - (size & 3)) & 3;  // (4 - (size % 4)) & 3
        if (pad) {
            bin.reserve(size + pad);
            while (pad--) {
                bin.insert(bin.begin(), 0);
            }
        }
        while (false == bin.empty()) {
            uint32 t = hton32(*(uint32 *)&bin[0]);
            _v.insert(_v.begin(), t);
            bin.erase(bin.begin(), bin.begin() + 4);
        }
        trim();
    }
#endif
    return *this;
}

bignumber &bignumber::sethex(const binary_t &base16hexstream) {
    _sign = 1;
    _v.clear();
#if (bn_intuitive == 1)
    if (false == base16hexstream.empty()) {
        binary_t bin = base16hexstream;
        auto size = bin.size();
        auto pad = (4 - (size & 3)) & 3;  // (4 - (size % 4)) & 3
        if (pad) {
            bin.reserve(size + pad);
            while (pad--) {
                bin.insert(bin.begin(), 0);
            }
        }
        while (false == bin.empty()) {
            uint32 t = hton32(*(uint32 *)&bin[0]);
            _v.insert(_v.begin(), t);
            bin.erase(bin.begin(), bin.begin() + 4);
        }
        trim();
    }
#endif
    return *this;
}

bignumber &bignumber::setstring(const char *value) {
    _sign = 1;
    _v.clear();
#if (bn_intuitive == 1)
    if (value) {
        auto len = strlen(value);
        // 0x prefixed hexadecimal
        if ((len >= 2) && (strncmp(value, "0x", 2) == 0)) {
            binary_t bin = base16_decode(value);
            if (false == bin.empty()) {
                auto size = bin.size();
                auto pad = (4 - (size & 3)) & 3;  // (4 - (size % 4)) & 3
                if (pad) {
                    bin.reserve(size + pad);
                    while (pad--) {
                        bin.insert(bin.begin(), 0);
                    }
                }
                while (false == bin.empty()) {
                    uint32 t = hton32(*(uint32 *)&bin[0]);
                    _v.insert(_v.begin(), t);
                    bin.erase(bin.begin(), bin.begin() + 4);
                }
                trim();
            }
        } else {
            // "numeric", "-numeric"

            const char *p = value;
            if (*p == '-') {
                _sign = -1;
                ++p;
            }
            _v.push_back(0);
            while (*p) {
                uint32 digit = *p - '0';
                uint64 carry = digit;
                for (auto i = 0; i < _v.size(); ++i) {
                    uint64 x = _v[i] * 10ULL + carry;
                    _v[i] = (x & 0xffffffff);
                    carry = x >> 32;
                }
                while (carry) {
                    _v.push_back(carry & 0xffffffff);
                    carry >>= 32;
                }
                ++p;
            };
        }
    }
#endif
    return *this;
}

bignumber &bignumber::setstring(const std::string &value) { return setstring(value.c_str()); }

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
            res.set(0);
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
    res._v.assign(lhs._v.size() + rhs._v.size(), 0);

    for (size_t i = 0; i < lhs._v.size(); i++) {
        int64 carry = 0;
        for (size_t j = 0; j < rhs._v.size() || carry; j++) {
            int64 cur = res._v[i + j] + (int64)lhs._v[i] * (j < rhs._v.size() ? rhs._v[j] : 0) + carry;

            res._v[i + j] = cur % base;
            carry = cur / base;
        }
    }
    res.trim();
    return res;
}

bignumber bignumber::mult(const bignumber &lhs, const bignumber &rhs) const {
    // karatsuba O(n^1.58)
    bignumber res;
    auto n = lhs._v.size();
    if (n < 32) {
        res = mult_simple(lhs, rhs);
    } else {
        int k = n / 2;

        bignumber a1;
        bignumber a2;
        bignumber b1;
        bignumber b2;

        a1._v = std::vector<uint32>(lhs._v.begin(), lhs._v.begin() + k);
        a2._v = std::vector<uint32>(lhs._v.begin() + k, lhs._v.end());

        b1._v = std::vector<uint32>(rhs._v.begin(), rhs._v.begin() + std::min((int)rhs._v.size(), k));
        b2._v = std::vector<uint32>(rhs._v.begin() + std::min((int)rhs._v.size(), k), rhs._v.end());

        bignumber z0 = mult(a1, b1);
        bignumber z2 = mult(a2, b2);
        bignumber z1 = mult(a1 + a2, b1 + b2) - z0 - z2;

        res._v.resize(n * 2);

        for (size_t i = 0; i < z0._v.size(); i++) {
            res._v[i] += z0._v[i];
        }
        for (size_t i = 0; i < z1._v.size(); i++) {
            res._v[i + k] += z1._v[i];
        }
        for (size_t i = 0; i < z2._v.size(); i++) {
            res._v[i + 2 * k] += z2._v[i];
        }

        res.trim();
    }
    return res;
}

bignumber bignumber::div(const bignumber &lhs, const bignumber &rhs) const {
    auto res = divide(lhs, rhs);
    return res.first;
}

// c++ style remainder
// -7 % 3 = -1, 7 % -3 = 1
bignumber bignumber::mod(const bignumber &lhs, const bignumber &rhs) const { return lhs - (lhs / rhs) * rhs; }

std::pair<bignumber, bignumber> bignumber::divide(const bignumber &lhs, const bignumber &rhs) const {
    std::pair<bignumber, bignumber> res = {{{0}}, {{0}}};
    bignumber quotient;
    bignumber remainder;

    if (rhs == 0) {
        // division by zero
        // throw exception
    } else if (abscmp(rhs, 1) == 0) {
        quotient = lhs;
        quotient._sign = lhs._sign * rhs._sign;
        res = {quotient, {{0}}};
    } else if (abscmp(lhs, rhs) < 0) {
        res = {{{0}}, lhs};
    } else {
        auto a = lhs;
        auto b = rhs;

        quotient._sign = a._sign * b._sign;
        quotient._v.resize(a._v.size());

        a._sign = b._sign = 1;

        for (int i = a._v.size() - 1; i >= 0; i--) {
            remainder._v.insert(remainder._v.begin(), a._v[i]);
            remainder.trim();

            uint32 limit = base - 1;
            uint32 x = 0;
            uint32 low = 0;
            uint32 high = limit;

            while (low <= high) {
                uint32 mid = ((uint64)low + high) >> 1;
                bignumber t = b * mid;

                if (t <= remainder) {
                    x = mid;
                    low = mid + 1;
                } else {
                    high = mid - 1;
                }
            }

            quotient._v[i] = x;
            remainder = remainder - (b * x);
        }

        quotient.trim();
        remainder.trim();

        res = {quotient, remainder};
    }
    return res;
}

bignumber bignumber::bitwise_and(const bignumber &lhs, const bignumber &rhs) const {
    bignumber res;
#if (bn_intuitive == 1)
    auto lsize = lhs._v.size();
    auto rsize = rhs._v.size();
    auto h = std::max(lsize, rsize);
    auto l = std::min(lsize, rsize);
    for (auto i = 0; i < h; i++) {
        uint32 lval = (i < lsize) ? lhs._v[i] : 0;
        uint32 rval = (i < rsize) ? rhs._v[i] : 0;
        res._v.push_back(lval & rval);
    }
#endif
    return res;
}

bignumber bignumber::bitwise_or(const bignumber &lhs, const bignumber &rhs) const {
    bignumber res;
#if (bn_intuitive == 1)
    auto lsize = lhs._v.size();
    auto rsize = rhs._v.size();
    auto h = std::max(lsize, rsize);
    auto l = std::min(lsize, rsize);
    for (auto i = 0; i < h; i++) {
        uint32 lval = (i < lsize) ? lhs._v[i] : 0;
        uint32 rval = (i < rsize) ? rhs._v[i] : 0;
        res._v.push_back(lval | rval);
    }
#endif
    return res;
}

bignumber bignumber::bitwise_xor(const bignumber &lhs, const bignumber &rhs) const {
    bignumber res;
#if (bn_intuitive == 1)
    auto lsize = lhs._v.size();
    auto rsize = rhs._v.size();
    auto h = std::max(lsize, rsize);
    auto l = std::min(lsize, rsize);
    for (auto i = 0; i < h; i++) {
        uint32 lval = (i < lsize) ? lhs._v[i] : 0;
        uint32 rval = (i < rsize) ? rhs._v[i] : 0;
        res._v.push_back(lval ^ rval);
    }
#endif
    return res;
}

bignumber bignumber::bitwise_not(const bignumber &other) const {
    bignumber res;
#if (bn_intuitive == 1)
    for (uint32 item : other._v) {
        res._v.push_back(!item);
    }
#endif
    return res;
}

bignumber bignumber::gcd(const bignumber &lhs, const bignumber &rhs) const {
    bignumber a = lhs;
    bignumber b = rhs;
    while (false == b._v.empty()) {
        a %= b;
        std::swap(a, b);
    }
    return a;
}

bignumber bignumber::modinv(bignumber a, bignumber m) const {
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

bignumber bignumber::modpow(bignumber b, bignumber exp, const bignumber &m) const {
    bignumber res = 1;
    b = mod(b, m);

    while (!exp._v.empty()) {
        if (exp._v[0] & 1) res = mod(res * b, m);

        b = mod(b * b, m);

        // exp /= 2
        uint64 carry = 0;
        for (auto i = exp._v.size() - 1; i >= 0; i--) {
            uint64 cur = exp._v[i] + carry * base;
            exp._v[i] = cur / 2;
            carry = cur % 2;
        }
        exp.trim();
    }
    return res;
}

bignumber bignumber::sqrt(const bignumber &other) const {
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

    if (lhs._v.size() != rhs._v.size()) {
        if (lhs._sign == 1) {
            return lhs._v.size() < rhs._v.size() ? -1 : 1;
        } else {
            return lhs._v.size() < rhs._v.size() ? 1 : -1;
        }
    }

    for (int i = (int)lhs._v.size() - 1; i >= 0; i--) {
        if (lhs._v[i] != rhs._v[i]) {
            if (lhs._sign == 1) {
                return lhs._v[i] < rhs._v[i] ? -1 : 1;
            } else {
                return lhs._v[i] < rhs._v[i] ? 1 : -1;
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
    bignumber res;
    if (v._v.empty()) {
    } else {
        int limb_shift = shift / 32;
        int bit_shift = shift % 32;

        res._sign = v._sign;
        res._v.assign(limb_shift, 0);

        uint64 carry = 0;
        for (uint32 x : v._v) {
            uint64 cur = ((uint64)x << bit_shift) | carry;
            res._v.push_back((uint32)cur);
            carry = cur >> 32;
        }

        if (carry) {
            res._v.push_back((uint32)carry);
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
    bignumber res;
    if (v._v.empty()) {
    } else {
        int limb_shift = shift / 32;
        int bit_shift = shift % 32;

        if ((int)v._v.size() <= limb_shift) {
        } else {
            res._sign = v._sign;
            res._v.resize(v._v.size() - limb_shift);

            uint32 carry = 0;
            for (int i = (int)v._v.size() - 1; i >= limb_shift; --i) {
                uint32 cur = v._v[i];

                res._v[i - limb_shift] = (cur >> bit_shift) | ((uint64)carry << (32 - bit_shift));
                carry = cur & ((1u << bit_shift) - 1);
            }

            res.trim();
        }
    }
    return res;
#endif
}

void bignumber::trim() {
    while ((false == _v.empty()) && (0 == _v.back())) {
        _v.pop_back();
    }
    if (_v.empty()) {
        _sign = 1;
    }
}

int bignumber::abscmp(const bignumber &lhs, const bignumber &rhs) {
    int ret = 0;
    if (lhs._v.size() != rhs._v.size()) {
        ret = lhs._v.size() < rhs._v.size() ? -1 : 1;
    } else {
        for (int i = (int)lhs._v.size() - 1; i >= 0; --i) {
            if (lhs._v[i] != rhs._v[i]) {
                ret = lhs._v[i] < rhs._v[i] ? -1 : 1;
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
    size_t n = std::max(lhs._v.size(), rhs._v.size());
    res._v.resize(n);

    for (size_t i = 0; i < n; i++) {
        int64 sum = carry + (i < lhs._v.size() ? lhs._v[i] : 0) + (i < rhs._v.size() ? rhs._v[i] : 0);
        res._v[i] = sum % base;
        carry = sum / base;
    }
    if (carry) {
        res._v.push_back(carry);
    }
    return res;
}

bignumber bignumber::abssub(const bignumber &lhs, const bignumber &rhs) {
    // |lhs| >= |rhs|
    // O(n)
    bignumber res;
    res._v.resize(lhs._v.size());
    int64 borrow = 0;

    for (size_t i = 0; i < lhs._v.size(); i++) {
        int64 x = (int64)lhs._v[i] - borrow - (i < rhs._v.size() ? rhs._v[i] : 0);
        if (x < 0) {
            x += base;
            borrow = 1;
        } else {
            borrow = 0;
        }
        res._v[i] = (uint32)x;
    }
    res.trim();
    return res;
}

#ifdef __SIZEOF_INT128__
bignumber bignumber::bn_mod(uint128 bits) const
#else
bignumber bignumber::bn_mod(uint64 bits) const
#endif
{
    bignumber res(1);
    return res <<= bits;
}

#ifdef __SIZEOF_INT128__
bignumber bignumber::bn_half(uint128 bits) const
#else
bignumber bignumber::bn_half(uint64 bits) const
#endif
{
    bignumber res(1);
    return res << (bits - 1);
}

#ifdef __SIZEOF_INT128__
bignumber bignumber::normalize(const bignumber &other, uint128 bits, bool sign) const
#else
bignumber bignumber::normalize(const bignumber &other, uint64 bits, bool sign) const
#endif
{
    bignumber res(other);
    auto m = std::move(bn_mod(bits));
    auto h = std::move(bn_half(bits));
    res %= m;
    if (sign) {
        if (res < 0) {
            res += m;
        }
        if (res >= h) {
            res -= m;
        }
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
    _sign = -_sign;
    return *this;
}

bignumber &bignumber::bitwise_and(const bignumber &other) { return *this = bitwise_and(*this, other); }

bignumber &bignumber::bitwise_or(const bignumber &other) { return *this = bitwise_or(*this, other); }

bignumber &bignumber::bitwise_xor(const bignumber &other) { return *this = bitwise_xor(*this, other); }

bignumber &bignumber::bitwise_not() { return *this = bitwise_not(*this); }

size_t bignumber::capacity() const { return _v.size(); }

std::string bignumber::str() const {
#if (bn_intuitive == 0)
    std::stringstream ss;
    // base
    if (_v.empty()) {
        ss << '0';
    } else {
        if (-1 == _sign) {
            ss << '-';
        }
        ss << _v.back();

        for (int i = (int)_v.size() - 2; i >= 0; i--) {
            ss << std::setw(9) << std::setfill('0') << _v[i];
        }
    }
    return ss.str();
#else
    std::string res;
    bignumber tmp = *this;
    if (tmp._v.empty()) {
        res = "0";
    } else {
        while (false == tmp._v.empty()) {
            uint64 carry = 0;
            for (int i = (int)tmp._v.size() - 1; i >= 0; i--) {
                uint64 cur = (carry << 32) | tmp._v[i];
                tmp._v[i] = (uint32)(cur / 10);
                carry = cur % 10;
            }
            res.push_back('0' + carry);
            while (false == tmp._v.empty() && 0 == tmp._v.back()) {
                tmp._v.pop_back();
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

std::string bignumber::hex() const {
    std::string b16str;
    *this >> b16str;
    return b16str;
}

void bignumber::dump(std::function<void(const binary_t &)> func) const {
#if (bn_intuitive == 1)
    binary_t out;
    for (int i = (int)_v.size() - 1; i >= 0; i--) {
        auto x = _v[i];
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
#endif
}

int bignumber::get(binary_t &base16hexstream, bool trimzero) const {
#if (bn_intuitive == 1)
    base16hexstream.clear();

    for (auto rit = _v.rbegin(); rit != _v.rend(); rit++) {
        binary_append(base16hexstream, *rit, ntoh32);
    }
    if (trimzero) {
        if (false == base16hexstream.empty()) {
            while (0 == base16hexstream.front()) {
                base16hexstream.erase(base16hexstream.begin());
            }
        }
    }
#endif
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
