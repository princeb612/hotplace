/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   bignumber_arithmetic.cpp
 * @author Soo Han and ChatGPT
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2006-03-28   Soo Han & ChatGPT   prototype
 *
 */

#include <cmath>
#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/base/encoding/base16.hpp>
#include <hotplace/sdk/base/nostd/binary.hpp>
#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/base/system/bignumber.hpp>

namespace hotplace {

bignumber bignumber::absadd(const bignumber& lhs, const bignumber& rhs) {
    // O(n)
    bignumber res;
    int64 carry = 0;
    size_t n = std::max(lhs._v.size(), rhs._v.size());
    res._v.resize(n);

    for (size_t i = 0; i < n; i++) {
        int64 sum = carry + (i < lhs._v.size() ? lhs._v[i] : 0) + (i < rhs._v.size() ? rhs._v[i] : 0);
        res._v[i] = sum % base2p32;
        carry = sum / base2p32;
    }
    if (carry) {
        res._v.push_back(t_narrow_cast(carry));
    }
    return res;
}

bignumber bignumber::abssub(const bignumber& lhs, const bignumber& rhs) {
    // |lhs| >= |rhs|
    // O(n)
    bignumber res;
    res._v.resize(lhs._v.size());
    int64 borrow = 0;

    for (size_t i = 0; i < lhs._v.size(); i++) {
        int64 x = (int64)lhs._v[i] - borrow - (i < rhs._v.size() ? rhs._v[i] : 0);
        if (x < 0) {
            x += base2p32;
            borrow = 1;
        } else {
            borrow = 0;
        }
        res._v[i] = (uint32)x;
    }
    res.trim();
    return res;
}

bignumber bignumber::add(const bignumber& lhs, const bignumber& rhs) {
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

bignumber bignumber::sub(const bignumber& lhs, const bignumber& rhs) {
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

bignumber bignumber::mult_simple(const bignumber& lhs, const bignumber& rhs) {
    // schoolbook O(n^2)
    bignumber res;
    res._sign = lhs._sign * rhs._sign;
    res._v.assign(lhs._v.size() + rhs._v.size(), 0);

    for (size_t i = 0; i < lhs._v.size(); i++) {
        int64 carry = 0;
        for (size_t j = 0; j < rhs._v.size() || carry; j++) {
            int64 cur = res._v[i + j] + (int64)lhs._v[i] * (j < rhs._v.size() ? rhs._v[j] : 0) + carry;

            res._v[i + j] = cur % base2p32;
            carry = cur / base2p32;
        }
    }
    res.trim();
    return res;
}

bignumber bignumber::mult(const bignumber& lhs, const bignumber& rhs) {
    // karatsuba O(n^1.58)
    bignumber res;
    auto n = lhs._v.size();
    if (n < 32) {
        res = mult_simple(lhs, rhs);
    } else {
        auto k = n / 2;

        bignumber a1;
        bignumber a2;
        bignumber b1;
        bignumber b2;

        a1._v = std::vector<uint32>(lhs._v.begin(), lhs._v.begin() + k);
        a2._v = std::vector<uint32>(lhs._v.begin() + k, lhs._v.end());

        b1._v = std::vector<uint32>(rhs._v.begin(), rhs._v.begin() + std::min(rhs._v.size(), k));
        b2._v = std::vector<uint32>(rhs._v.begin() + std::min(rhs._v.size(), k), rhs._v.end());

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

bignumber bignumber::div(const bignumber& lhs, const bignumber& rhs) {
    auto res = divide(lhs, rhs);
    return res.first;
}

// c++ style remainder
// -7 % 3 = -1, 7 % -3 = 1
bignumber bignumber::mod(const bignumber& lhs, const bignumber& rhs) { return lhs - (lhs / rhs) * rhs; }

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

std::pair<bignumber, bignumber> bignumber::divide(const bignumber& lhs, const bignumber& rhs) {
    std::pair<bignumber, bignumber> res = std::make_pair(bignumber(0), bignumber(0));  // {{{0}}, {{0}}};
    bignumber quotient;
    bignumber remainder;

    if (rhs == 0) {
        throw exception(errorcode_t::divide_by_zero);  // division by zero
    } else if (abscmp(rhs, 1) == 0) {
        quotient = lhs;
        quotient._sign = lhs._sign * rhs._sign;
        res = std::make_pair(quotient, bignumber(0));  // {quotient, {{0}}};
    } else if (abscmp(lhs, rhs) < 0) {
        res = std::make_pair(bignumber(0), lhs);  // {{{0}}, lhs};
    } else {
        auto a = lhs;
        auto b = rhs;

        quotient._sign = a._sign * b._sign;
        quotient._v.resize(a._v.size());

        a._sign = b._sign = 1;

        for (auto i = a._v.size(); i > 0; --i) {
            size_t idx = i - 1;
            remainder._v.insert(remainder._v.begin(), a._v[idx]);
            remainder.trim();

            uint32 limit = base2p32 - 1;
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

            quotient._v[idx] = x;
            remainder = remainder - (b * x);
        }

        quotient.trim();
        remainder.trim();

        res = {quotient, remainder};
    }
    return res;
}

bignumber bignumber::bitwise_and(const bignumber& lhs, const bignumber& rhs) {
    bignumber res;
    auto lsize = lhs._v.size();
    auto rsize = rhs._v.size();
    auto h = std::max(lsize, rsize);
    // auto l = std::min(lsize, rsize);
    for (size_t i = 0; i < h; i++) {
        uint32 lval = (i < lsize) ? lhs._v[i] : 0;
        uint32 rval = (i < rsize) ? rhs._v[i] : 0;
        res._v.push_back(lval & rval);
    }
    return res;
}

bignumber bignumber::bitwise_or(const bignumber& lhs, const bignumber& rhs) {
    bignumber res;
    auto lsize = lhs._v.size();
    auto rsize = rhs._v.size();
    auto h = std::max(lsize, rsize);
    // auto l = std::min(lsize, rsize);
    for (size_t i = 0; i < h; i++) {
        uint32 lval = (i < lsize) ? lhs._v[i] : 0;
        uint32 rval = (i < rsize) ? rhs._v[i] : 0;
        res._v.push_back(lval | rval);
    }
    return res;
}

bignumber bignumber::bitwise_xor(const bignumber& lhs, const bignumber& rhs) {
    bignumber res;
    auto lsize = lhs._v.size();
    auto rsize = rhs._v.size();
    auto h = std::max(lsize, rsize);
    // auto l = std::min(lsize, rsize);
    for (size_t i = 0; i < h; i++) {
        uint32 lval = (i < lsize) ? lhs._v[i] : 0;
        uint32 rval = (i < rsize) ? rhs._v[i] : 0;
        res._v.push_back(lval ^ rval);
    }
    return res;
}

bignumber bignumber::bitwise_not(const bignumber& other) {
    bignumber res;
    for (uint32 item : other._v) {
        res._v.push_back(!item);
    }
    return res;
}

bignumber bignumber::gcd(const bignumber& lhs, const bignumber& rhs) {
    bignumber a = lhs;
    bignumber b = rhs;
    while (false == b._v.empty()) {
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

bignumber bignumber::modpow(bignumber b, bignumber exp, const bignumber& m) {
    bignumber res = 1;
    b = mod(b, m);

    while (false == exp._v.empty()) {
        if (exp._v[0] & 1) res = mod(res * b, m);

        b = mod(b * b, m);

        // exp /= 2
        uint64 carry = 0;
        for (size_t i = exp._v.size(); i > 0; --i) {
            size_t idx = i - 1;
            uint64 cur = exp._v[idx] + carry * base2p32;
            exp._v[idx] = t_narrow_cast(cur / 2);
            carry = cur % 2;
        }
        exp.trim();
    }
    return res;
}

bignumber bignumber::sqrt(const bignumber& other) {
    bignumber x;
#if 0
    // binary search
    if (other._sign > 0) {
        bignumber low = 1;
        bignumber high = other;
        x = 1;
        while (low <= high) {
            bignumber mid = (low + high) / 2;
            if (mid * mid <= other) {
                x = mid;
                low = mid + 1;
            } else {
                high = mid - 1;
            }
        }
    }
#else
    // newton's method
    if (other >= 2) {
        size_t bitlen = other._v.size() << 5;  // uint32
        x = bignumber(1) << (bitlen / 2 + 1);
        bignumber y = (x + 1) / 2;
        while (y < x) {
            x = y;
            y = (x + other / x) / 2;
        }
    }
#endif
    return x;
}

bignumber bignumber::pow(bignumber base, bignumber exp) {
    bignumber res = 1;
    if (exp > 0) {
        while (exp > 0) {
            if (exp % 2 == 1) {
                res *= base;
            }
            base *= base;
            exp /= 2;
        }
    } else if (exp == 0) {
        // res = 1;
    } else {
        if (base == 1) {
            // res = 1;
        } else if (base == -1) {
            res = ((exp % 2) == 0) ? 1 : -1;
        } else {
            // res = 1;
        }
    }
    return res;
}

const bignumber& bignumber::pow2(size_t n) {
    static std::vector<bignumber> cache = {bignumber(1)};

    if (n >= cache.size()) {
        for (size_t i = cache.size(); i <= n; ++i) {
            cache.push_back(cache.back() << 1);
        }
    }
    return cache[n];
}

const bignumber& bignumber::pow10(size_t n) {
    static std::vector<bignumber> cache = {bignumber(1)};

    if (n >= cache.size()) {
        for (size_t i = cache.size(); i <= n; ++i) {
            cache.push_back(cache.back() * 10);
        }
    }
    return cache[n];
}

bool bignumber::ispow2(const bignumber& bn) {
    // 0001, 0010, 0100, 1000
    // 0001 0000, 0010 0000, 0100 0000, 1000 0000
    return (bn > 0) && ((bn & (bn - 1)) == 0);
}

bignumber bignumber::leftshift(const bignumber& v, const bignumber& shift) const {
    // O(n)
    bignumber res;
    if (v._v.empty()) {
        // do nothing
    } else if (shift._sign < 0) {
        throw exception(errorcode_t::not_supported);
    } else if (shift.capacity() > 1) {
        throw exception(errorcode_t::not_implemented);
    } else {
        // auto limb_shift = shift / 32;
        // auto bit_shift = shift % 32;

        auto pqr = divide(shift, 32);  // pair(quotient, remainder)
        auto limb_shift = pqr.first._v.empty() ? 0 : pqr.first._v[0];
        auto bit_shift = pqr.second._v.empty() ? 0 : pqr.second._v[0];

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
}

bignumber bignumber::rightshift(const bignumber& v, const bignumber& shift) const {
    // O(n);
    bignumber res;
    if (v._v.empty()) {
        // do nothing
    } else if (shift._sign < 0) {
        throw exception(errorcode_t::not_supported);
    } else if (shift.capacity() > 1) {
        throw exception(errorcode_t::not_implemented);
    } else {
        // int limb_shift = shift / 32;
        // int bit_shift = shift % 32;

        auto pqr = divide(shift, 32);  // pair(quotient, remainder)
        uint64 limb_shift = pqr.first._v.empty() ? 0 : pqr.first._v[0];
        uint64 bit_shift = pqr.second._v.empty() ? 0 : pqr.second._v[0];

        if (v._v.size() <= limb_shift) {
        } else {
            res._sign = v._sign;
            res._v.resize(v._v.size() - limb_shift);

            uint32 carry = 0;
            for (auto i = v._v.size(); i > limb_shift; --i) {
                size_t idx = i - 1;
                uint32 cur = v._v[idx];

                res._v[idx - limb_shift] = (cur >> bit_shift) | ((uint64)carry << (32 - bit_shift));
                carry = cur & ((1u << bit_shift) - 1);
            }

            res.trim();
        }
    }
    return res;
}

int bignumber::compare(const bignumber& lhs, const bignumber& rhs) {
    auto a = lhs;
    auto b = rhs;

    a.trim();
    b.trim();

    if (a._sign != b._sign) {
        return a._sign < b._sign ? -1 : 1;
    }

    if (a._v.size() != b._v.size()) {
        if (a._sign == 1) {
            return a._v.size() < b._v.size() ? -1 : 1;
        } else {
            return a._v.size() < b._v.size() ? 1 : -1;
        }
    }

    for (size_t i = a._v.size(); i > 0; --i) {
        size_t idx = i - 1;
        if (a._v[idx] != b._v[idx]) {
            if (a._sign == 1) {
                return a._v[idx] < b._v[idx] ? -1 : 1;
            } else {
                return a._v[idx] < b._v[idx] ? 1 : -1;
            }
        }
    }
    return 0;
}

int bignumber::abscmp(const bignumber& lhs, const bignumber& rhs) {
    int ret = 0;
    if (lhs._v.size() != rhs._v.size()) {
        ret = lhs._v.size() < rhs._v.size() ? -1 : 1;
    } else {
        for (auto i = lhs._v.size(); i > 0; --i) {
            size_t idx = i - 1;
            if (lhs._v[idx] != rhs._v[idx]) {
                ret = lhs._v[idx] < rhs._v[idx] ? -1 : 1;
                break;
            }
        }
    }
    return ret;
}

size_t bignumber::unsigned_byte_capacity() const {
    size_t ret_value = 0;
    if (_sign >= 0) {
        bignumber bn(*this);
        bn.trim();
        if (false == bn._v.empty()) {
            uint32 v = bn._v.back();
            ret_value = byte_capacity(v);
            ret_value += (bn._v.size() - 1) << 2;  // uint32 4 bytes
        }
    } else {
        throw exception(errorcode_t::not_supported);
    }
    return ret_value;
}

size_t bignumber::signed_byte_capacity() const {
    size_t ret_value = 0;
    bignumber bn(*this);
    if (bn < 0) {
        bn += 1;
        bn.neg();
    }
    while (bn > 0) {
        ++ret_value;
        bn >>= 1;
    }
    return (ret_value + 8) / 8;
}

}  // namespace hotplace
