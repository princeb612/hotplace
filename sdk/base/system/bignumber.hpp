/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_BIGNUMBER__
#define __HOTPLACE_SDK_BASE_SYSTEM_BIGNUMBER__

#include <functional>
#include <hotplace/sdk/base/system/endian.hpp>
#include <hotplace/sdk/base/system/types.hpp>
#include <iomanip>
#include <sstream>
#include <type_traits>

namespace hotplace {

/*
 * @brief   big number
 * @remarks
 *          int128(MSVC), bigint, int512, ...
 *          sizeof(limb) = 4
 *
 *          std::vector<uint32> stream;
 *          bignumber value;
 *          while(value > 0) {
 *              stream.push_back(value % base2p32);
 *              value /= base2p32;
 *          }
 *          sign = (stream.back() < 0x80000000) ? 1 : -1;
 *
 *          // example
 *          // bignumber b = (bignumber(1) << 63) - bignumber(1);
 *          // 9223372036854775807 (0x7fffffffffffffff)
 *          // std::vector<uint32> _limbs;
 *          // _limbs[0] = 0xffffffff;
 *          // _limbs[1] = 0x7fffffff;
 *          // _sign = 1;
 *
 * @refer   ChatGPT (+, -, *, /, mod, gcd, modinv, modpow, sqrt, <<. >>)
 */
class bignumber {
   public:
    bignumber();
    bignumber(int8 value);
    bignumber(uint8 value);
    bignumber(int16 value);
    bignumber(uint16 value);
    bignumber(int32 value);
    bignumber(uint32 value);
    bignumber(int64 value);
    bignumber(uint64 value);
#ifdef __SIZEOF_INT128__
    bignumber(int128 value);
    bignumber(uint128 value);
#endif
    bignumber(const bignumber &other);
    bignumber(bignumber &&other);
    bignumber(const byte_t *p, size_t n);
    bignumber(const binary_t &base16hexstream);
    bignumber(const std::string &base16hexstream);
    ~bignumber();

    bignumber &operator=(const bignumber &other);
    bignumber &operator=(bignumber &&other);
    bignumber &operator=(int8 value);
    bignumber &operator=(uint8 value);
    bignumber &operator=(int16 value);
    bignumber &operator=(uint16 value);
    bignumber &operator=(int32 value);
    bignumber &operator=(uint32 value);
    bignumber &operator=(int64 value);
    bignumber &operator=(uint64 value);
#ifdef __SIZEOF_INT128__
    bignumber &operator=(int128 value);
    bignumber &operator=(uint128 value);
#endif
    bignumber &operator=(const binary_t &base16hexstream);
    bignumber &operator=(const std::string &base16hexstream);

    bignumber operator+(const bignumber &other) const;
    bignumber &operator+=(const bignumber &other);

    bignumber operator-(const bignumber &other) const;
    bignumber &operator-=(const bignumber &other);

    bignumber operator*(const bignumber &other) const;
    bignumber &operator*=(const bignumber &other);

    bignumber operator/(const bignumber &other) const;
    bignumber &operator/=(const bignumber &other);

    bignumber operator%(const bignumber &other) const;
    bignumber &operator%=(const bignumber &other);

    bignumber operator&(const bignumber &other) const;
    bignumber &operator&=(const bignumber &other);

    bignumber operator|(const bignumber &other) const;
    bignumber &operator|=(const bignumber &other);

    bignumber operator^(const bignumber &other) const;
    bignumber &operator^=(const bignumber &other);

    bignumber operator~() const;

    bool operator<(const bignumber &other) const;
    bool operator<=(const bignumber &other) const;
    bool operator>(const bignumber &other) const;
    bool operator>=(const bignumber &other) const;

    bool operator==(const bignumber &other) const;
    bool operator!=(const bignumber &other) const;

    bignumber operator<<(unsigned int shift) const;
    bignumber &operator<<=(unsigned int shift);

    bignumber operator>>(unsigned int shift) const;
    bignumber &operator>>=(unsigned int shift);

    bignumber &operator++();
    bignumber &operator--();

    bignumber operator++(int);
    bignumber operator--(int);

#ifdef __SIZEOF_INT128__
    bignumber &set(int128 value);
    bignumber &setu(uint128 value);
#else
    bignumber &set(int64 value);
    bignumber &setu(uint64 value);
#endif
    bignumber &set(const std::string &base16hexstream);
    bignumber &set(const byte_t *p, size_t n);
    bignumber &set(const binary_t &base16hexstream);

    bignumber add(const bignumber &lhs, const bignumber &rhs) const;
    bignumber sub(const bignumber &lhs, const bignumber &rhs) const;
    bignumber mult_simple(const bignumber &lhs, const bignumber &rhs) const;
    bignumber mult(const bignumber &lhs, const bignumber &rhs) const;
    bignumber div(const bignumber &lhs, const bignumber &rhs) const;
    bignumber mod(const bignumber &lhs, const bignumber &rhs) const;
    std::pair<bignumber, bignumber> divide(const bignumber &lhs, const bignumber &rhs) const;
    bignumber bitwise_and(const bignumber &lhs, const bignumber &rhs) const;
    bignumber bitwise_or(const bignumber &lhs, const bignumber &rhs) const;
    bignumber bitwise_xor(const bignumber &lhs, const bignumber &rhs) const;
    bignumber bitwise_not(const bignumber &other) const;

    bignumber gcd(const bignumber &lhs, const bignumber &rhs) const;
    bignumber modinv(bignumber a, bignumber m) const;
    bignumber modpow(bignumber base, bignumber exp, const bignumber &m) const;
    bignumber sqrt(const bignumber &other) const;

    bignumber &add(const bignumber &other);
    bignumber &sub(const bignumber &other);
    bignumber &mult(const bignumber &other);
    bignumber &div(const bignumber &other);
    bignumber &mod(const bignumber &other);
    bignumber &neg();
    bignumber &bitwise_and(const bignumber &other);
    bignumber &bitwise_or(const bignumber &other);
    bignumber &bitwise_xor(const bignumber &other);
    bignumber &bitwise_not();

    std::string str() const;
    std::string hex() const;
    size_t capacity() const;
    void dump(std::function<void(const binary_t &)> func) const;
    /**
     * @brief base16 hexdecimal stream
     * @param binary_t &base16hexstream [out]
     * @param bool trimzero [inopt] true
     * @return sign 1 positive, -1 negative
     */
    int get(binary_t &base16hexstream, bool trimzero = true) const;

    friend binary_t &operator<<(binary_t &lhs, const bignumber &rhs);
    friend std::string &operator<<(std::string &lhs, const bignumber &rhs);
    friend binary_t &operator>>(const bignumber &lhs, binary_t &rhs);
    friend std::string &operator>>(const bignumber &lhs, std::string &rhs);

    template <typename T>
    T bntoi(const bignumber &other) const {
        size_t tsize = sizeof(T);
        bignumber bn = std::move(normalize(other, tsize >> 3, std::is_signed<T>::value));

        T value = 0;
        binary_t bin;
        other >> bin;  // base16, BE
        size_t size = bin.size();
        if (size > tsize) {
            bin.erase(bin.begin(), bin.begin() + size - tsize);
        } else if (size < tsize) {
            int n = tsize - size;
            while (n--) {
                bin.insert(bin.begin(), 0);
            }
        }
        if (is_big_endian()) {
            value = *(T *)&bin[0];
        } else if (is_little_endian()) {
            value = *(T *)&bin[0];
            if (tsize > 1) {
                value = convert_endian(value);
            }
        }
        return value;
    }

   protected:
    int compare(const bignumber &lhs, const bignumber &rhs) const;

    bignumber leftshift(const bignumber &v, unsigned int shift) const;
    bignumber rightshift(const bignumber &v, unsigned int shift) const;

    void trim();

    static int abscmp(const bignumber &lhs, const bignumber &rhs);
    static bignumber absadd(const bignumber &lhs, const bignumber &rhs);
    static bignumber abssub(const bignumber &lhs, const bignumber &rhs);

#ifdef __SIZEOF_INT128__
    bignumber bn_mod(uint128 bits) const;
    bignumber bn_half(uint128 bits) const;
    bignumber normalize(const bignumber &other, uint128 bits, bool sign) const;
#else
    bignumber bn_mod(uint64 bits) const;
    bignumber bn_half(uint64 bits) const;
    bignumber normalize(const bignumber &other, uint64 bits, bool sign) const;
#endif

   private:
    std::vector<uint32> _v;
    int _sign;
};

}  // namespace hotplace

#endif
