/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   bignumber.cpp
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

// #define bn_intuitive 1
// #define base base2p32
//
// static const uint32 base1e9 = 1000000000;    // printf-friendly (setw(9) << limb)

bignumber::bignumber() { set(0); }

bignumber::bignumber(const bignumber& other) {
    _v = other._v;
    _sign = other._sign;
}

bignumber::bignumber(bignumber&& other) : _sign(1) {
    std::swap(_v, other._v);
    std::swap(_sign, other._sign);
}

bignumber::bignumber(const variant_t& vt) { set(vt); }

bignumber::bignumber(const byte_t* p, size_t n, bool isunsigned) { set(p, n, isunsigned); }

bignumber::bignumber(const binary_t& base16hexstream) { set(base16hexstream); }

bignumber::bignumber(const std::string& value) { set(value); }

bignumber::~bignumber() {}

bignumber& bignumber::set(const variant_t& vt) {
    switch (vt.type) {
        case vartype_t::TYPE_BOOL:
            set(vt.data.b ? 1 : 0);
            break;
        case vartype_t::TYPE_INT8:
            set(vt.data.i8);
            break;
        case vartype_t::TYPE_UINT8:
            set(vt.data.ui8);
            break;
        case vartype_t::TYPE_INT16:
            set(vt.data.i16);
            break;
        case vartype_t::TYPE_UINT16:
            set(vt.data.ui16);
            break;
        case vartype_t::TYPE_INT24:
            set(vt.data.i32);
            break;
        case vartype_t::TYPE_UINT24:
            set(vt.data.ui32);
            break;
        case vartype_t::TYPE_INT32:
            set(vt.data.i32);
            break;
        case vartype_t::TYPE_UINT32:
            set(vt.data.ui32);
            break;
        case vartype_t::TYPE_INT48:
            set(vt.data.i64);
            break;
        case vartype_t::TYPE_UINT48:
            set(vt.data.ui64);
            break;
        case vartype_t::TYPE_INT64:
            set(vt.data.i64);
            break;
        case vartype_t::TYPE_UINT64:
            set(vt.data.ui64);
            break;
#if defined __SIZEOF_INT128__
        case vartype_t::TYPE_INT128:
            set(vt.data.i128);
            break;
        case vartype_t::TYPE_UINT128:
            set(vt.data.ui128);
            break;
#endif
        case vartype_t::TYPE_FLOAT: {
            uint32 data = t_narrow_cast(std::round(vt.data.f));
            set(data);
        } break;
        case vartype_t::TYPE_DOUBLE: {
            uint64 data = t_narrow_cast(std::round(vt.data.d));
            set(data);
        } break;
        case vartype_t::TYPE_STRING:
        case vartype_t::TYPE_NSTRING:
            if (vt.size) {
                *this = std::string(vt.data.str, vt.size);
            } else {
                *this = vt.data.str;
            }
            break;
        case vartype_t::TYPE_BINARY:
            set(vt.data.bstr, vt.size);
            break;
        default:
            break;
    }
    if (vt.flag & vt_flag_negative) {
        *this += 1;
        _sign = -_sign;
    }
    return *this;
}

bignumber& bignumber::set(const byte_t* p, size_t n, bool isunsigned) {
    _sign = 1;
    _v.clear();
    if (p && n) {
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
            uint32 t = hton32(*(uint32*)bin.data());
            _v.insert(_v.begin(), t);
            bin.erase(bin.begin(), bin.begin() + 4);
        }

        if (false == isunsigned) {
            // int8  00....7f   (0..127),   ff....80   (-1..-128)
            // int16 0000..7fff (0..32767), ffff..8000 (-1..-32768)
            if (p[0] > 0x7f) {
                binary_t bin_adjust;
                bin_adjust.reserve(n + 1);
                bin_adjust.resize(n, 00);
                bin_adjust.insert(bin_adjust.begin(), 0x1);

                bignumber bn_adjust(bin_adjust);
                *this = std::move(bn_adjust - *this);
                (*this).neg();  // set the minus sign
            }
        }

        trim();
    }
    return *this;
}

bignumber& bignumber::set(const binary_t& base16hexstream) {
    _sign = 1;
    _v.clear();
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
            uint32 t = hton32(*(uint32*)bin.data());
            _v.insert(_v.begin(), t);
            bin.erase(bin.begin(), bin.begin() + 4);
        }
        trim();
    }
    return *this;
}

bignumber& bignumber::set(const char* value) {
    _sign = 1;
    _v.clear();
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
                    uint32 t = hton32(*(uint32*)bin.data());
                    _v.insert(_v.begin(), t);
                    bin.erase(bin.begin(), bin.begin() + 4);
                }
                trim();
            }
        } else {
            // "numeric", "-numeric"

            const char* p = value;
            if (*p == '-') {
                _sign = -1;
                ++p;
            }
            _v.push_back(0);
            while (*p) {
                uint32 digit = *p - '0';
                uint64 carry = digit;
                for (size_t i = 0; i < _v.size(); ++i) {
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
        trim();
    }
    return *this;
}

bignumber& bignumber::set(const std::string& value) { return set(value.c_str()); }

void bignumber::trim() {
    while ((false == _v.empty()) && (0 == _v.back())) {
        _v.pop_back();
    }
    if (_v.empty()) {
        _sign = 1;
    }
}

#ifdef __SIZEOF_INT128__
bignumber bignumber::normalize(const bignumber& other, uint128 bits, bool sign) const
#else
bignumber bignumber::normalize(const bignumber& other, uint64 bits, bool sign) const
#endif
{
    bignumber res(other);
    auto m = bn_mod(bits);
    auto h = bn_half(bits);
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

bignumber& bignumber::add(const bignumber& other) { return *this = add(*this, other); }

bignumber& bignumber::sub(const bignumber& other) { return *this = sub(*this, other); }

bignumber& bignumber::mult(const bignumber& other) { return *this = mult(*this, other); }

bignumber& bignumber::div(const bignumber& other) { return *this = div(*this, other); }

bignumber& bignumber::mod(const bignumber& other) { return *this = mod(*this, other); }

bignumber& bignumber::abs() {
    _sign = 1;
    return *this;
}

bignumber& bignumber::neg() {
    _sign = -_sign;
    return *this;
}

bignumber& bignumber::bitwise_and(const bignumber& other) { return *this = bitwise_and(*this, other); }

bignumber& bignumber::bitwise_or(const bignumber& other) { return *this = bitwise_or(*this, other); }

bignumber& bignumber::bitwise_xor(const bignumber& other) { return *this = bitwise_xor(*this, other); }

bignumber& bignumber::bitwise_not() { return *this = bitwise_not(*this); }

bignumber& bignumber::sqrt() { return *this = sqrt(*this); }

size_t bignumber::capacity() const { return _v.size(); }

std::string bignumber::str() const {
    std::string res;
    bignumber tmp = *this;
    if (tmp._v.empty()) {
        res = "0";
    } else {
        while (false == tmp._v.empty()) {
            uint64 carry = 0;
            for (size_t i = tmp._v.size(); i > 0; --i) {
                size_t idx = i - 1;
                uint64 cur = (carry << 32) | tmp._v[idx];
                tmp._v[idx] = (uint32)(cur / 10);
                carry = cur % 10;
            }
            uint8 c = t_narrow_cast('0' + carry);
            res.push_back(c);
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
}

std::string bignumber::hex() const {
    std::string b16str;
    *this >> b16str;
    return b16str;
}

int bignumber::get(binary_t& base16hexstream, bool trimzero) const {
    base16hexstream.clear();
    // limb (uint32) operation
    for (auto rit = _v.rbegin(); rit != _v.rend(); rit++) {
        binary_append(base16hexstream, *rit, ntoh32);
    }
    // byte operation
    if (trimzero) {
        if (false == base16hexstream.empty()) {
            while (0 == base16hexstream.front()) {
                base16hexstream.erase(base16hexstream.begin());
            }
        }
    }
    return _sign;
}

}  // namespace hotplace
