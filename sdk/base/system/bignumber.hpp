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
#include <hotplace/sdk/base/system/types.hpp>
#include <iomanip>
#include <sstream>

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
 * @refer   ChatGPT
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
    bignumber bitwise_and(const bignumber &lhs, const bignumber &rhs) const;
    bignumber bitwise_or(const bignumber &lhs, const bignumber &rhs) const;
    bignumber bitwise_xor(const bignumber &lhs, const bignumber &rhs) const;
    bignumber bitwise_not(const bignumber &other) const;

    static bignumber mod(const bignumber &lhs, const bignumber &rhs);
    static bignumber gcd(const bignumber &lhs, const bignumber &rhs);
    static bignumber modinv(bignumber a, bignumber m);
    static bignumber modpow(bignumber base, bignumber exp, const bignumber &m);
    static bignumber sqrt(const bignumber &other);

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

   protected:
    int compare(const bignumber &lhs, const bignumber &rhs) const;

    bignumber leftshift(const bignumber &v, unsigned int shift) const;
    bignumber rightshift(const bignumber &v, unsigned int shift) const;

    void trim();

    static int abscmp(const bignumber &lhs, const bignumber &rhs);
    static bignumber absadd(const bignumber &lhs, const bignumber &rhs);
    static bignumber abssub(const bignumber &lhs, const bignumber &rhs);

   private:
    static const uint64 base2p32 = 0x100000000;  // intuitive 2^32
    static const uint32 base1e9 = 1000000000;    // printf-friendly (setw(9) << limb)
    std::vector<uint32> _units;
    int _sign;
};

}  // namespace hotplace

#endif
