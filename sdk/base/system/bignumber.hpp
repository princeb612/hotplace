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
 * @refer   ChatGPT (+, -, *, /, mod, gcd, modinv, modpow, sqrt, <<. >>)
 * @remarks
 *          int8     -128 ~ 127
 *          int16    -32768 ~ 32767
 *          int32    -2147483648 ~ 2147483647
 *          int64    -9223372036854775808 ~ 9223372036854775807
 *          int128   -170141183460469231731687303715884105728 ~ 170141183460469231731687303715884105727
 *          uint8    0 ~ 255
 *          uint16   0 ~ 65535
 *          uint32   0 ~ 4294967295
 *          uint64   0 ~ 18446744073709551615
 *          uint128  0 ~ 340282366920938463463374607431768211455
 *
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
 * @example
 *          // operator + - * / %
 *          {
 *              bignumber n1(123456789012345678LL);
 *              bignumber n2(9876543210LL);
 *              _test_case.assert((n1 + n2).str() == "123456798888888888", __FUNCTION__, "add");
 *              _test_case.assert((n1 - n2).str() == "123456779135802468", __FUNCTION__, "sub");
 *              _test_case.assert((n1 * n2).str() == "1219326311248285312223746380", __FUNCTION__, "mult");
 *              _test_case.assert((n1 / n2).str() == "12499999", __FUNCTION__, "div");
 *              _test_case.assert((n1 % n2).str() == "8763888888", __FUNCTION__, "mod");
 *          }
 *
 *          // bitshift
 *          {
 *              bits = 256;
 *              bignumber intmin = -(bignumber(1) << (bits - 1));                 // int256.min
 *              bignumber intmax =  (bignumber(1) << (bits - 1)) - bignumber(1);  // int256.max
 *              bignumber uintmax = (bignumber(1) << bits) - bignumber(1);        // uint256.max
 *              _logger->writeln("int256.min = %s",   intmin.str().c_str());
 *              _logger->writeln("int256.max = %s",   intmax.str().c_str());
 *              _logger->writeln("uint256.max = %s", uintmin.str().c_str());
 *          }
 *
 *          // bitwise AND OR XOR
 *          {
 *              auto bit_and = n1 & n2;
 *              auto bit_or  = n1 | n2;
 *              auto bit_xor = n1 ^ n2;
 *              _logger->writeln("AND %s, bit_and.hex().c_str());
 *              _logger->writeln("OR  %s, bit_or .hex().c_str());
 *              _logger->writeln("XOR %s, bit_xor.hex().c_str());
 *          }
 */
class bignumber {
   public:
    bignumber();
    bignumber(const bignumber &other);
    bignumber(bignumber &&other);

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
    /**
     * @brief   big-endian byte order stream
     */
    bignumber(const byte_t *p, size_t n);
    /**
     * @brief   base16 hex-stream
     */
    bignumber(const binary_t &base16hexstream);
    /**
     * @brief   numeric, hexdecimal string
     * @example
     *          bignumber bn("1");
     *          bignumber bn("18446744073709551615");
     *          bignumber bn("0x7fffffffffffffff");
     *          bignumber bn("0xffffffffffffffff");  // uint128.max
     *
     *          // larger than c++ types
     *          bignumber bn("340282366920938463463374607431768211456");
     *          bignumber bn("0x10000000000000000");
     */
    bignumber(const std::string &value);
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
    bignumber &operator=(const char *value);
    bignumber &operator=(const std::string &value);

    /**
     * @brief   add
     */
    bignumber operator+(const bignumber &other) const;
    bignumber &operator+=(const bignumber &other);

    /**
     * @brief   subtract
     */
    bignumber operator-(const bignumber &other) const;
    bignumber &operator-=(const bignumber &other);

    /**
     * @brief   multiply
     */
    bignumber operator*(const bignumber &other) const;
    bignumber &operator*=(const bignumber &other);

    /**
     * @brief   divide
     */
    bignumber operator/(const bignumber &other) const;
    bignumber &operator/=(const bignumber &other);

    /**
     * @brief   module
     */
    bignumber operator%(const bignumber &other) const;
    bignumber &operator%=(const bignumber &other);

    /**
     * @brief   AND
     */
    bignumber operator&(const bignumber &other) const;
    bignumber &operator&=(const bignumber &other);

    /**
     * @brief   OR
     */
    bignumber operator|(const bignumber &other) const;
    bignumber &operator|=(const bignumber &other);

    /**
     * @brief   XOR
     */
    bignumber operator^(const bignumber &other) const;
    bignumber &operator^=(const bignumber &other);

    /**
     * @brief   NOT
     */
    bignumber operator~() const;

    /**
     * @brief   compare
     * @example
     *          bignumber bn("340282366920938463463374607431768211456");  // uint128.max + 1
     *          bignumber bn2("0x100000000000000000000000000000000");
     *          _test_case.assert(bn == bn2, __FUNCTION__, "compare");
     */
    bool operator<(const bignumber &other) const;
    bool operator<=(const bignumber &other) const;
    bool operator>(const bignumber &other) const;
    bool operator>=(const bignumber &other) const;

    bool operator==(const bignumber &other) const;
    bool operator!=(const bignumber &other) const;

    /**
     * @brief   bitshift
     */
    bignumber operator<<(unsigned int shift) const;
    bignumber &operator<<=(unsigned int shift);

    bignumber operator>>(unsigned int shift) const;
    bignumber &operator>>=(unsigned int shift);

    /**
     * @example
     *          bn = -bn;
     */
    bignumber &operator-();

    /**
     * @brief   ++bn, --bn
     */
    bignumber &operator++();
    bignumber &operator--();
    /**
     * @brief   bn++, bn--
     */
    bignumber operator++(int);
    bignumber operator--(int);

#ifdef __SIZEOF_INT128__
    bignumber &set(int128 value);
    bignumber &setu(uint128 value);
#else
    bignumber &set(int64 value);
    bignumber &setu(uint64 value);
#endif
    bignumber &set(const byte_t *p, size_t n);
    bignumber &sethex(const binary_t &base16hexstream);
    bignumber &setstring(const char *value);
    bignumber &setstring(const std::string &value);

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

    /**
     * @brief   decimal string
     * @example
     *          bignumber bn("0xffffffffffffffffffffffffffffffff");  // uint128.max
     *          bn = -bn;
     *          bn.str(); // "-340282366920938463463374607431768211455"
     */
    std::string str() const;
    /**
     * @brief   hexdecimal string
     * @example
     *          bignumber bn("340282366920938463463374607431768211456");  // uint128.max + 1
     *          bn.hex(); // "0x100000000000000000000000000000000"
     */
    std::string hex() const;
    /**
     * @brief   capacity
     * @remarks number of internal limb (uint32)
     */
    size_t capacity() const;
    /**
     * @brief   dump (debugging purpose)
     */
    void dump(std::function<void(const binary_t &)> func) const;
    /**
     * @brief   base16 hexdecimal stream
     * @param   binary_t &base16hexstream [out]
     * @param   bool trimzero [inopt] true
     * @return  sign 1 positive, -1 negative
     */
    int get(binary_t &base16hexstream, bool trimzero = true) const;

    /**
     * @brief   bignumber to bytestream (BE) and vice versa.
     */
    friend binary_t &operator<<(binary_t &lhs, const bignumber &rhs);
    friend std::string &operator<<(std::string &lhs, const bignumber &rhs);
    friend binary_t &operator>>(const bignumber &lhs, binary_t &rhs);
    friend std::string &operator>>(const bignumber &lhs, std::string &rhs);

    /*
     * @return T
     * @example
     *          auto i8 = bn.t_bntoi<int8>();
     *          auto i128 = bn.t_bntoi<int128>();
     * @sa      str(), hex()
     */
    template <typename T>
    T t_bntoi() const {
        size_t tsize = sizeof(T);
        bignumber bn = std::move(normalize(*this, tsize << 3, std::is_signed<T>::value));

        T value = 0;
        binary_t bin;
        bn >> bin;  // base16, BE
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
            value = *(T *)bin.data();
        } else if (is_little_endian()) {
            value = *(T *)bin.data();
            if (tsize > 1) {
                value = convert_endian(value);
            }
        }
        if (bn < 0) {
            value = -value;
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
