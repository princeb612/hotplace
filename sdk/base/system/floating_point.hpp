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
#include <hotplace/sdk/base/system/decimal_float.hpp>
#include <hotplace/sdk/base/system/rational_float.hpp>

namespace hotplace {

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
