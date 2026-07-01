/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   rational_float.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <hotplace/sdk/base/system/rational_float.hpp>

namespace hotplace {

rational_float::rational_float() : _num(0), _den(1) {}

rational_float::rational_float(const bignumber& n, const bignumber& d) : _num(n), _den(d) { normalize(); }

rational_float::rational_float(bignumber&& n, bignumber&& d) : _num(std::move(n)), _den(std::move(d)) { normalize(); }

rational_float::rational_float(const rational_float& other) : _num(other._num), _den(other._den) { normalize(); }

rational_float::rational_float(rational_float&& other) : rational_float(0, 1) {
    std::swap(_num, other._num);
    std::swap(_den, other._den);
}

rational_float::rational_float(const std::string& expr) { *this = expr; }

rational_float::~rational_float() {}

rational_float& rational_float::normalize() {
    if (_den == 0) {
        throw exception(errorcode_t::divide_by_zero);
    }

    auto g = bignumber::gcd(_num, _den);
    _num /= g;
    _den /= g;

    if (_den < 0) {
        _num.neg();
        _den.neg();
    }

    return *this;
}

rational_float& rational_float::operator=(const rational_float& other) {
    _num = other._num;
    _den = other._den;
    return *this;
}

rational_float& rational_float::operator=(rational_float&& other) {
    std::swap(_num, other._num);
    std::swap(_den, other._den);
    return *this;
}

rational_float& rational_float::operator=(const std::string& expr) {
    auto slash = expr.find('/');

    if (slash == std::string::npos) {
        throw exception(errorcode_t::bad_format);
    }

    if (slash == 0 || slash + 1 >= expr.size()) {
        throw exception(errorcode_t::bad_format);
    }

    bool neg = false;

    size_t lhs_begin = 0;
    size_t lhs_end = slash;

    if (expr[0] == '-' || expr[0] == '+') {
        neg = (expr[0] == '-');
        lhs_begin = 1;

        if (lhs_begin == lhs_end) {
            throw exception(errorcode_t::bad_format);
        }
    }

    auto is_digit_range = [&](size_t begin, size_t end) {
        for (size_t i = begin; i < end; ++i) {
            unsigned char c = static_cast<unsigned char>(expr[i]);

            if (!std::isdigit(c)) {
                return false;
            }
        }

        return true;
    };

    if (!is_digit_range(lhs_begin, lhs_end) || !is_digit_range(slash + 1, expr.size())) {
        throw exception(errorcode_t::bad_format);
    }

    bignumber num(expr.substr(lhs_begin, lhs_end - lhs_begin));
    bignumber den(expr.substr(slash + 1));

    if (den == 0) {
        throw exception(errorcode_t::divide_by_zero);
    }

    if (neg) {
        num.neg();
    }

    auto g = bignumber::gcd(num, den);

    num /= g;
    den /= g;

    _num = std::move(num);
    _den = std::move(den);

    normalize();
    return *this;
}

bool rational_float::operator==(const rational_float& other) { return compare(*this, other) == 0; }

bool rational_float::operator!=(const rational_float& other) { return compare(*this, other) != 0; }

bool rational_float::operator>(const rational_float& other) { return compare(*this, other) > 0; }

bool rational_float::operator<(const rational_float& other) { return compare(*this, other) < 0; }

bool rational_float::operator>=(const rational_float& other) { return compare(*this, other) >= 0; }

bool rational_float::operator<=(const rational_float& other) { return compare(*this, other) <= 0; }

std::string rational_float::str() {
    normalize();
    std::string res;
    res += _num.str();
    res += "/";
    res += _den.str();
    return res;
}

// Gemini
std::string rational_float::fstr(size_t precision) const {
    std::string res;
    if (_den == 0) {
        res = "NaN";
    } else if (_num == 0) {
        res = "0";
    } else {
        bool is_negative = ((_num < 0) != (_den < 0));
        bignumber n = _num;
        bignumber d = _den;

        n.abs();
        d.abs();

        bignumber quotient = n / d;
        bignumber remainder = n % d;

        std::string integer_part = quotient.str();
        std::string fraction_part;

        if (precision > 0 && remainder != 0) {
            for (size_t i = 0; i < precision; ++i) {
                remainder *= 10;
                bignumber digit = remainder / d;
                fraction_part += digit.str();
                remainder = remainder % d;
                if (remainder == 0) {
                    break;
                }
            }
        }

        int true_exp = static_cast<int>(integer_part.length()) - 1;
        bool small_value = (integer_part == "0" && !fraction_part.empty());

        int leading_zeros = 0;
        if (small_value) {
            for (char c : fraction_part) {
                if (c == '0') {
                    leading_zeros++;
                } else {
                    break;
                }
            }
            true_exp = -(leading_zeros + 1);
        }

        bool use_e = (true_exp >= 6 || true_exp <= -4);

        res = is_negative ? "-" : "";

        if (use_e) {
            if (small_value) {
                res += fraction_part[leading_zeros];
                res += ".";
                res += fraction_part.substr(leading_zeros + 1);
            } else {
                res += integer_part[0];
                if (integer_part.length() > 1 || !fraction_part.empty()) {
                    res += ".";
                    res += integer_part.substr(1) + fraction_part;
                }
            }
            while (res.back() == '0') {
                res.pop_back();
            }
            if (res.back() == '.') {
                res.pop_back();
            }

            res += "e" + (true_exp >= 0 ? std::string("+") : "") + std::to_string(true_exp);
        } else {
            res += integer_part;
            if (!fraction_part.empty()) {
                res += "." + fraction_part;
                while (res.back() == '0') {
                    res.pop_back();
                }
                if (res.back() == '.') {
                    res.pop_back();
                }
            }
        }
    }
    return res;
}

int rational_float::compare(const rational_float& lhs, const rational_float& rhs) { return bignumber::compare(lhs._num * rhs._den, rhs._num * lhs._den); }

}  // namespace hotplace
