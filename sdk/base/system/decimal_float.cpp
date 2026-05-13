/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   decimal_float.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <hotplace/sdk/base/system/floating_point.hpp>

namespace hotplace {

decimal_float::decimal_float() : _mant(0), _exp(0) {}

decimal_float::decimal_float(const bignumber& m, int e) : _mant(m), _exp(e) { normalize(); }

decimal_float::decimal_float(bignumber&& m, int e) : _mant(std::move(m)), _exp(e) { normalize(); }

decimal_float::decimal_float(const decimal_float& other) : _mant(other._mant), _exp(other._exp) {}

decimal_float::decimal_float(decimal_float&& other) : decimal_float() {
    std::swap(_mant, other._mant);
    std::swap(_exp, other._exp);
}

decimal_float::decimal_float(const std::string& expr) : _exp(0) { *this = expr; }

decimal_float::~decimal_float() {}

decimal_float& decimal_float::normalize() {
    if (_mant == 0) {
        _exp = 0;
    } else {
        while (_mant % 10 == 0) {
            _mant /= 10;
            ++_exp;
        }
    }
    return *this;
}

decimal_float& decimal_float::operator=(const decimal_float& other) {
    _mant = other._mant;
    _exp = other._exp;
    return *this;
}

decimal_float& decimal_float::operator=(decimal_float&& other) {
    std::swap(_mant, other._mant);
    std::swap(_exp, other._exp);
    return *this;
}

decimal_float& decimal_float::operator=(const std::string& expr) {
    _mant = 0;
    _exp = 0;

    const size_t n = expr.size();

    if (n == 0) {
        throw exception(bad_format);
    }

    size_t pos = 0;
    bool neg = false;

    if (expr[pos] == '+' || expr[pos] == '-') {
        neg = (expr[pos] == '-');
        ++pos;

        if (pos >= n) {
            throw exception(bad_format);
        }
    }

    // const size_t digits_begin = pos;

    size_t integer_begin = pos;

    while (pos < n && std::isdigit(static_cast<unsigned char>(expr[pos]))) {
        ++pos;
    }

    size_t integer_end = pos;

    size_t fraction_begin = pos;
    size_t fraction_end = pos;

    // fraction
    if (pos < n && expr[pos] == '.') {
        ++pos;

        fraction_begin = pos;

        while (pos < n && std::isdigit(static_cast<unsigned char>(expr[pos]))) {
            ++pos;
        }

        fraction_end = pos;
    }

    const size_t integer_len = integer_end - integer_begin;
    const size_t fraction_len = fraction_end - fraction_begin;

    if (integer_len == 0 && fraction_len == 0) {
        throw exception(bad_format);
    }

    int exp = -(int)fraction_len;

    if (pos < n && (expr[pos] == 'e' || expr[pos] == 'E')) {
        ++pos;

        if (pos >= n) throw exception(bad_format);

        bool exp_neg = false;

        if (expr[pos] == '+' || expr[pos] == '-') {
            exp_neg = (expr[pos] == '-');
            ++pos;
        }

        if (pos >= n || !std::isdigit(static_cast<unsigned char>(expr[pos]))) {
            throw exception(bad_format);
        }

        int e = 0;

        while (pos < n && std::isdigit(static_cast<unsigned char>(expr[pos]))) {
            e = e * 10 + (expr[pos++] - '0');
        }

        exp += exp_neg ? -e : e;
    }

    if (pos != n) {
        throw exception(bad_format);
    }

    std::string digits;

    digits.reserve(integer_len + fraction_len);

    digits.append(expr, integer_begin, integer_len);

    digits.append(expr, fraction_begin, fraction_len);

    size_t nz = 0;
    while (nz < digits.size() && digits[nz] == '0') {
        ++nz;
    }

    if (nz == digits.size()) {
        _mant = 0;
        _exp = 0;
    } else {
        bignumber mant(digits.substr(nz));

        if (neg) {
            mant = -mant;
        }

        _mant = std::move(mant);
        _exp = exp;

        normalize();
    }

    return *this;
}

bool decimal_float::operator==(const decimal_float& other) { return compare(*this, other) == 0; }

bool decimal_float::operator!=(const decimal_float& other) { return compare(*this, other) != 0; }

bool decimal_float::operator>(const decimal_float& other) { return compare(*this, other) > 0; }

bool decimal_float::operator<(const decimal_float& other) { return compare(*this, other) < 0; }

bool decimal_float::operator>=(const decimal_float& other) { return compare(*this, other) >= 0; }

bool decimal_float::operator<=(const decimal_float& other) { return compare(*this, other) <= 0; }

std::string decimal_float::str() {
    std::string res;

    if (_mant == 0) {
        res = "0";
    } else {
        std::string s_mant = _mant.str();
        bool negative = (s_mant[0] == '-');

        const char* digits = s_mant.c_str() + (negative ? 1 : 0);
        size_t mant_len = s_mant.size() - (negative ? 1 : 0);

        if (_exp >= 0) {
            res.reserve(negative + mant_len + _exp);
            if (negative) {
                res.push_back('-');
            }
            res.append(digits, mant_len);
            res.append(_exp, '0');
        } else {
            int pos = static_cast<int>(mant_len) + _exp;

            if (pos <= 0) {
                size_t zeros = static_cast<size_t>(-pos);
                res.reserve(negative + 2 + zeros + mant_len);
                if (negative) {
                    res.push_back('-');
                }
                res.append("0.");
                res.append(zeros, '0');
                res.append(digits, mant_len);
            } else {
                res.reserve(negative + mant_len + 1);
                if (negative) {
                    res.push_back('-');
                }
                res.append(digits, static_cast<size_t>(pos));
                res.push_back('.');
                res.append(digits + pos, mant_len - static_cast<size_t>(pos));
            }
        }
    }

    return res;
}

int decimal_float::compare(const decimal_float& lhs, const decimal_float& rhs) {
    decimal_float a = lhs;
    decimal_float b = rhs;
    int diff = a._exp - b._exp;
    if (diff > 0) {
        a._mant *= bignumber::pow(10, diff);
        a._exp = b._exp;
    } else if (diff < 0) {
        b._mant *= bignumber::pow(10, -diff);
        b._exp = a._exp;
    }
    return bignumber::compare(a._mant, b._mant);
}

}  // namespace hotplace
