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
 * int128(MSVC), bigint, int512, ...
 * refer ChatGPT
 */
class bignumber {
#ifdef __SIZEOF_INT128__
    using largeint = int128;  // gcc
#else
    using largeint = int64;  // MSVC
#endif
   public:
    bignumber(largeint value = 0);
    bignumber(const bignumber &other);
    bignumber(bignumber &&other);
    ~bignumber();

    bignumber &operator=(const bignumber &other);
    bignumber &operator=(largeint value);

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

    bignumber add(const bignumber &lhs, const bignumber &rhs) const;
    bignumber sub(const bignumber &lhs, const bignumber &rhs) const;
    bignumber mult_simple(const bignumber &lhs, const bignumber &rhs) const;
    bignumber mult(const bignumber &lhs, const bignumber &rhs) const;
    bignumber div(const bignumber &lhs, const bignumber &rhs) const;

    static bignumber mod(const bignumber &lhs, const bignumber &rhs);
    static bignumber gcd(const bignumber &lhs, const bignumber &rhs);
    static bignumber modinv(bignumber a, bignumber m);
    static bignumber modpow(bignumber base, bignumber exp, const bignumber &m);
    static bignumber sqrt(const bignumber &other);

    std::string str() const;
    void dump(std::function<void(binary_t &)> func);

   protected:
    bignumber &set(largeint value);

    int compare(const bignumber &lhs, const bignumber &rhs) const;

    bignumber leftshift(const bignumber &v, unsigned int shift) const;
    bignumber rightshift(const bignumber &v, unsigned int shift) const;

    void trim();

    static int abscmp(const bignumber &lhs, const bignumber &rhs);
    static bignumber absadd(const bignumber &lhs, const bignumber &rhs);
    static bignumber abssub(const bignumber &lhs, const bignumber &rhs);

    void normalize();

   private:
    static const uint64 base2p32 = 0x100000000;  // intuitive 2^32
    static const uint32 base1e9 = 1000000000;    // printf-friendly (setw(9) << limb)
    std::vector<uint32> _limbs;                  // limb
    int _sign;
};

}  // namespace hotplace

#endif
