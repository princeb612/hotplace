/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   floating_point.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_RATIONALPOINT__
#define __HOTPLACE_SDK_BASE_SYSTEM_RATIONALPOINT__

#include <cmath>
#include <hotplace/sdk/base/system/bignumber.hpp>

namespace hotplace {

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

}  // namespace hotplace

#endif
