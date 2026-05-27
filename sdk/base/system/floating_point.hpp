/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   floating_point.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_FLOATINGPOINT__
#define __HOTPLACE_SDK_BASE_SYSTEM_FLOATINGPOINT__

#include <cmath>
#include <hotplace/sdk/base/system/bignumber.hpp>

namespace hotplace {

/**
 * @refer ChatGPT
 * @example
 *          decimal_float d1(1, -1);  //  1e-1  0.1
 *          decimal_float d2(2, -1);  //  2e-1  0.2
 *          auto res1 = d1 + d2;      //  3e-1  0.3
 *          auto res2 = d1 - d2;      // -1e-1 -0.1
 *          auto res3 = d1 * d2;      //  2e-2  0.02
 *          auto res4 = d1 / d2;      //  5e-1  0.5
 *
 *          decimal_float d3("1e-1");
 *          decimal_float d4("2e-1");
 *          // ...
 *
 *          decimal_float d5("0.1");
 *          decimal_float d6("0.2");
 *          // ...
 */
class decimal_float {
    friend class floating_point;

   public:
    decimal_float();
    decimal_float(const bignumber& m, int e);
    decimal_float(bignumber&& m, int e);
    decimal_float(const decimal_float& other);
    decimal_float(decimal_float&& other);
    decimal_float(const std::string& expr);
    virtual ~decimal_float();

    decimal_float& operator=(const decimal_float& other);
    decimal_float& operator=(decimal_float&& other);

    // 123.45, -0.00123 1.2e8 ...
    decimal_float& operator=(const std::string& expr);

    bool operator==(const decimal_float& other);
    bool operator!=(const decimal_float& other);
    bool operator>(const decimal_float& other);
    bool operator<(const decimal_float& other);
    bool operator>=(const decimal_float& other);
    bool operator<=(const decimal_float& other);

    /**
     *  decimal_float d1("1e10");
     *  decimal_float d2("1e-10");
     *  auto res = d1 + d2;
     *  auto str1 = res.str();     // "1.00000000000000000001e+10"
     *  auto str2 = res.fstr(32);  // "10000000000.0000000001"
     */
    std::string str();
    std::string fstr(size_t precision = 32) const;

    static int compare(const decimal_float& lhs, const decimal_float& rhs);

   protected:
    decimal_float& normalize();

   private:
    bignumber _mant;  // mantissa
    int _exp;         // exponent
};

/**
 * @refer ChatGPT
 * @example
 *          rational_float r1(1, 2);  // 1/2
 *          rational_float r2(1, 3);  // 1/3
 *          auto res1 = r1 + r2;      // 5/6
 *          auto res2 = r1 - r2;      // 1/6
 *          auto res3 = r1 * r2;      // 1/6
 *          auto res4 = r1 / r2;      // 3/2
 *
 *          rational_float r1("1/2");  // 1/2
 *          rational_float r2("1/3");  // 1/3
 *          // ...
 */
class rational_float {
    friend class floating_point;

   public:
    rational_float();
    rational_float(const bignumber& n, const bignumber& d);
    rational_float(bignumber&& n, bignumber&& d);
    rational_float(const rational_float& other);
    rational_float(rational_float&& other);
    rational_float(const std::string& expr);
    virtual ~rational_float();

    rational_float& operator=(const rational_float& other);
    rational_float& operator=(rational_float&& other);

    // 1/3 355/113 22/7 ...
    rational_float& operator=(const std::string& expr);

    bool operator==(const rational_float& other);
    bool operator!=(const rational_float& other);
    bool operator>(const rational_float& other);
    bool operator<(const rational_float& other);
    bool operator>=(const rational_float& other);
    bool operator<=(const rational_float& other);

    /**
     * rational_float r1("1/2");  // 1/2
     * rational_float r2("1/3");  // 1/3
     * auto res = r1 + r2;        // 5/6
     * auto str1 = res.str();     // "5/6"
     * auto str2 = res.fstr(32);  // "0.83333333333333333333333333333333"
     */
    std::string str();
    std::string fstr(size_t precision = 32) const;

    static int compare(const rational_float& lhs, const rational_float& rhs);

   protected:
    rational_float& normalize();

   private:
    bignumber _num;  // numerator
    bignumber _den;  // denominator
};

/**
 * @refer ChatGPT
 * @example
 *          floating_point f1("0.1");
 *          floating_point f2("1/3");
 *          auto res = f1 - f2;
 *          auto str1 = res.str();     // "-7/30"
 *          auto str2 = res.fstr(32);  // "-0.23333333333333333333333333333333"
 */
enum class fp_type_t {
    rational_type = 1,
    decimal_type = 2,
};
class floating_point {
   public:
    floating_point(int64 x = 0);

    floating_point(const bignumber& m, int e);
    floating_point(bignumber&& m, int e);
    floating_point(const decimal_float& value);
    floating_point(decimal_float&& value);

    floating_point(const bignumber& n, const bignumber& d);
    floating_point(bignumber&& n, bignumber&& d);
    floating_point(const rational_float& value);
    floating_point(rational_float&& value);

    floating_point(const floating_point& other);
    floating_point(floating_point&& other);

    floating_point(const std::string& expr);

    virtual ~floating_point();

    floating_point& operator=(const floating_point& other);
    floating_point& operator=(floating_point&& other);

    floating_point operator+(const floating_point& other) const;
    floating_point& operator+=(const floating_point& other);
    floating_point operator-(const floating_point& other) const;
    floating_point& operator-=(const floating_point& other);
    floating_point operator*(const floating_point& other) const;
    floating_point& operator*=(const floating_point& other);
    floating_point operator/(const floating_point& other) const;
    floating_point& operator/=(const floating_point& other);

    bool operator==(const floating_point& other);
    bool operator!=(const floating_point& other);
    bool operator>(const floating_point& other);
    bool operator<(const floating_point& other);
    bool operator>=(const floating_point& other);
    bool operator<=(const floating_point& other);

    fp_type_t get_type();
    std::string str();
    std::string fstr(size_t precision = 32) const;

    static int compare(const floating_point& lhs, const floating_point& rhs);

    static floating_point add(const floating_point& lhs, const floating_point& rhs);
    static floating_point subtract(const floating_point& lhs, const floating_point& rhs);
    static floating_point multiply(const floating_point& lhs, const floating_point& rhs);
    static floating_point divide(const floating_point& lhs, const floating_point& rhs);

    // 123.45, -0.00123 1.2e8 1/3 355/113 22/7 ...
    floating_point& operator=(const std::string& expr);

    rational_float to_rational();
    static rational_float to_rational(const floating_point& f);

    friend rational_float operator>>(const floating_point& f, rational_float r);
    friend rational_float operator<<(rational_float r, const floating_point& f);

   protected:
    void release();

   private:
    fp_type_t _type;
    union storage_t {
        decimal_float* _d;
        rational_float* _r;

        storage_t() : _d(nullptr) {}
    } _storage;
};

}  // namespace hotplace

#endif
