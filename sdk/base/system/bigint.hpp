/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_BIGINT__
#define __HOTPLACE_SDK_BASE_SYSTEM_BIGINT__

#include <hotplace/sdk/base/system/bignumber.hpp>
#include <hotplace/sdk/base/system/endian.hpp>

namespace hotplace {

/*
 * int8     -128 ~ 127
 * int16    -32768 ~ 32767
 * int32    -2147483648 ~ 2147483647
 * int64    -9223372036854775808 ~ 9223372036854775807
 * int128   -170141183460469231731687303715884105728 ~ 170141183460469231731687303715884105727
 * uint8    0 ~ 255
 * uint16   0 ~ 65535
 * uint32   0 ~ 4294967295
 * uint64   0 ~ 18446744073709551615
 * uint128  0 ~ 340282366920938463463374607431768211455
 */
template <uint32 BITS = 256, bool SIGNED = true>
class t_bigint {
   public:
    t_bigint() {}
    t_bigint(const t_bigint &other) { _bn = other._bn; }
    t_bigint(t_bigint &&other) { _bn = std::move(other._bn); }
    t_bigint(const bignumber &other) { _bn = other; }
    t_bigint(bignumber &&other) { _bn = std::move(other); }
    t_bigint(int64 value) {
        _bn.set(value);
        normalize();
    }
    t_bigint(uint64 value) {
        _bn.set(value);
        normalize();
    }

    t_bigint &operator=(const t_bigint &other) {
        _bn = other._bn;
        normalize();
        return *this;
    }
    t_bigint operator+(const t_bigint &other) const {
        t_bigint i(_bn + other._bn);
        i.normalize();
        return i;
    }
    t_bigint &operator+=(const t_bigint &other) { return *this = (_bn + other._bn); }
    t_bigint operator-(const t_bigint &other) const {
        t_bigint i(_bn - other._bn);
        i.normalize();
        return i;
    }
    t_bigint &operator-=(const t_bigint &other) { return *this = _bn - other._bn; }
    t_bigint operator*(const t_bigint &other) const {
        t_bigint i(_bn * other._bn);
        i.normalize();
        return i;
    }
    t_bigint &operator*=(const t_bigint &other) { return *this = _bn * other._bn; }
    t_bigint operator/(const t_bigint &other) const {
        t_bigint i(_bn / other._bn);
        i.normalize();
        return i;
    }
    t_bigint &operator/=(const t_bigint &other) { return *this = _bn / other._bn; }
    t_bigint operator%(const t_bigint &other) const {
        t_bigint i(_bn % other._bn);
        i.normalize();
        return i;
    }
    t_bigint &operator%=(const t_bigint &other) { return *this = _bn % other._bn; }

    t_bigint operator&(const t_bigint &other) const {
        t_bigint i(_bn & other._bn);
        i.normalize();
        return i;
    }
    t_bigint &operator&=(const t_bigint &other) { return *this = _bn & other._bn; }
    t_bigint operator|(const t_bigint &other) const {
        t_bigint i(_bn | other._bn);
        i.normalize();
        return i;
    }
    t_bigint &operator|=(const t_bigint &other) { return *this = _bn | other._bn; }
    t_bigint operator^(const t_bigint &other) const {
        t_bigint i(_bn ^ other._bn);
        i.normalize();
        return i;
    }
    t_bigint &operator^=(const t_bigint &other) { return *this = _bn ^ other._bn; }

    bool operator<(const t_bigint &other) const { return _bn < other._bn; }
    bool operator<=(const t_bigint &other) const { return _bn <= other._bn; }
    bool operator>(const t_bigint &other) const { return _bn > other._bn; }
    bool operator>=(const t_bigint &other) const { return _bn >= other._bn; }
    t_bigint operator<<(unsigned int k) const {
        t_bigint i(_bn << k);
        i.normalize();
        return i;
    }
    t_bigint &operator<<=(unsigned int k) { return *this = _bn << k; }
    t_bigint operator>>(unsigned int k) const {
        t_bigint i(_bn >> k);
        i.normalize();
        return i;
    }
    t_bigint &operator>>=(unsigned int k) { return *this = _bn >> k; }

    std::string str() { return _bn.str(); }
    std::string hex() { return _bn.hex(); }
    bignumber &get_bn() { return _bn; }

   protected:
    static const bignumber &MOD() {
        static bignumber m = bignumber(1) << (BITS);
        return m;
    }
    static const bignumber &HALF() {
        static bignumber m = bignumber(1) << (BITS - 1);
        return m;
    }
    void normalize() {
        _bn %= MOD();

        if (SIGNED) {
            if (_bn < 0) {
                _bn += MOD();
            }
            if (_bn >= HALF()) {
                _bn -= MOD();
            }
        }
    }

   private:
    bignumber _bn;
};

// typedef t_bigint<256> int256_t;
// typedef t_bigint<512> int512_t;
// typedef t_bigint<1024> int1024_t;

}  // namespace hotplace

#endif
