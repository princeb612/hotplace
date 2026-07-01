/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   floating_point.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_DECIMALPOINT__
#define __HOTPLACE_SDK_BASE_SYSTEM_DECIMALPOINT__

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

}  // namespace hotplace

#endif
