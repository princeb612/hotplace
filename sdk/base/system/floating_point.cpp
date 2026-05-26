/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   floating_point.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <hotplace/sdk/base/system/floating_point.hpp>

namespace hotplace {

floating_point::floating_point(int64 value) : _type(fp_type_t::decimal_type) { _storage._d = new decimal_float(value, 0); }

floating_point::floating_point(const floating_point& other) : _type(other._type) {
    if (_type == decimal_type) {
        _storage._d = new decimal_float(*other._storage._d);
    } else {
        _storage._r = new rational_float(*other._storage._r);
    }
}

floating_point::floating_point(floating_point&& other) : _type(fp_type_t::decimal_type) {
    std::swap(_type, other._type);
    std::swap(_storage, other._storage);
}

floating_point::floating_point(const bignumber& m, int e) : _type(fp_type_t::decimal_type) { _storage._d = new decimal_float(m, e); }

floating_point::floating_point(bignumber&& m, int e) : _type(fp_type_t::decimal_type) { _storage._d = new decimal_float(std::move(m), e); }

floating_point::floating_point(const decimal_float& value) : _type(fp_type_t::decimal_type) { _storage._d = new decimal_float(value); }

floating_point::floating_point(decimal_float&& value) : _type(fp_type_t::decimal_type) { _storage._d = new decimal_float(std::move(value)); }

floating_point::floating_point(const bignumber& n, const bignumber& d) : _type(fp_type_t::rational_type) { _storage._r = new rational_float(n, d); }

floating_point::floating_point(bignumber&& n, bignumber&& d) : _type(fp_type_t::rational_type) { _storage._r = new rational_float(std::move(n), std::move(d)); }

floating_point::floating_point(const rational_float& value) : _type(fp_type_t::rational_type) { _storage._r = new rational_float(value); }

floating_point::floating_point(rational_float&& value) : _type(fp_type_t::rational_type) { _storage._r = new rational_float(std::move(value)); }

floating_point::floating_point(const std::string& expr) { *this = expr; }

floating_point::~floating_point() { release(); }

void floating_point::release() {
    if (_storage._d) {
        if (_type == decimal_type) {
            delete _storage._d;
        } else {
            delete _storage._r;
        }
        _storage._d = nullptr;
    }
}

floating_point& floating_point::operator=(const floating_point& other) {
    release();

    if (_type == decimal_type) {
        _storage._d = new decimal_float(*other._storage._d);
    } else {
        _storage._r = new rational_float(*other._storage._r);
    }
    return *this;
}

floating_point& floating_point::operator=(floating_point&& other) {
    std::swap(_type, other._type);
    std::swap(_storage, other._storage);
    return *this;
}

floating_point floating_point::operator+(const floating_point& other) const { return add(*this, other); }

floating_point& floating_point::operator+=(const floating_point& other) { return *this = add(*this, other); }

floating_point floating_point::operator-(const floating_point& other) const { return subtract(*this, other); }

floating_point& floating_point::operator-=(const floating_point& other) { return *this = subtract(*this, other); }

floating_point floating_point::operator*(const floating_point& other) const { return multiply(*this, other); }

floating_point& floating_point::operator*=(const floating_point& other) { return *this = multiply(*this, other); }

floating_point floating_point::operator/(const floating_point& other) const { return divide(*this, other); }

floating_point& floating_point::operator/=(const floating_point& other) { return *this = divide(*this, other); }

bool floating_point::operator==(const floating_point& other) { return compare(*this, other) == 0; }

bool floating_point::operator!=(const floating_point& other) { return compare(*this, other) != 0; }

bool floating_point::operator>(const floating_point& other) { return compare(*this, other) > 0; }

bool floating_point::operator<(const floating_point& other) { return compare(*this, other) < 0; }

bool floating_point::operator>=(const floating_point& other) { return compare(*this, other) >= 0; }

bool floating_point::operator<=(const floating_point& other) { return compare(*this, other) <= 0; }

fp_type_t floating_point::get_type() { return _type; }

std::string floating_point::str() {
    if (_type == decimal_type) {
        return _storage._d->str();
    } else {
        return _storage._r->str();
    }
}

std::string floating_point::fstr(size_t precision) const {
    if (_type == decimal_type) {
        return _storage._d->fstr(precision);
    } else {
        return _storage._r->fstr(precision);
    }
}

int floating_point::compare(const floating_point& lhs, const floating_point& rhs) {
    if (lhs._type == decimal_type && rhs._type == decimal_type) {
        return decimal_float::compare(*lhs._storage._d, *rhs._storage._d);
    } else if (lhs._type == decimal_type && rhs._type == rational_type) {
        return rational_float::compare(*lhs._storage._r, *rhs._storage._r);
    } else {
        auto a = floating_point::to_rational(lhs);
        auto b = floating_point::to_rational(rhs);
        return rational_float::compare(a, b);
    }
}

floating_point floating_point::add(const floating_point& lhs, const floating_point& rhs) {
    floating_point fp;
    if (lhs._type == decimal_type && rhs._type == decimal_type) {
        auto d1 = *lhs._storage._d;
        auto d2 = *rhs._storage._d;
        auto diff = d1._exp - d2._exp;

        const int32 MAX_PRECISION = 1024;
        if (diff > MAX_PRECISION) {
            fp = lhs;
        } else if (diff < -MAX_PRECISION) {
            decimal_float temp(bignumber(0) - d2._mant, d2._exp);
            fp = std::move(temp);
        } else {
            bignumber ml = d1._mant;
            bignumber mr = d2._mant;

            if (diff > 0) {
                ml *= bignumber::pow10(diff);
            } else if (diff < 0) {
                mr *= bignumber::pow10(-diff);
            }

            decimal_float temp(ml + mr, std::min(d1._exp, d2._exp));
            fp = std::move(temp);
        }
    } else {
        auto r1 = floating_point::to_rational(lhs);
        auto r2 = floating_point::to_rational(rhs);
        // a / b + c / d = (ad + bc) / bd
        bignumber num = (r1._num * r2._den) + (r2._num * r1._den);
        bignumber den = r1._den * r2._den;
        rational_float temp(std::move(num), std::move(den));
        fp = std::move(temp);
    }
    return fp;
}

floating_point floating_point::subtract(const floating_point& lhs, const floating_point& rhs) {
    floating_point fp;
    if (lhs._type == decimal_type && rhs._type == decimal_type) {
        auto d1 = *lhs._storage._d;
        auto d2 = *rhs._storage._d;
        auto diff = d1._exp - d2._exp;

        const int32 MAX_PRECISION = 1024;
        if (diff > MAX_PRECISION) {
            fp = lhs;
        } else if (diff < -MAX_PRECISION) {
            decimal_float temp(bignumber(0) - d2._mant, d2._exp);
            fp = std::move(temp);
        } else {
            bignumber ml = d1._mant;
            bignumber mr = d2._mant;

            if (diff > 0) {
                ml *= bignumber::pow10(diff);
            } else if (diff < 0) {
                mr *= bignumber::pow10(-diff);
            }

            decimal_float temp(ml - mr, std::min(d1._exp, d2._exp));
            fp = std::move(temp);
        }
    } else {
        auto r1 = floating_point::to_rational(lhs);
        auto r2 = floating_point::to_rational(rhs);
        // a / b - c / d = (ad - bc) / bd
        bignumber num = (r1._num * r2._den) - (r2._num * r1._den);
        bignumber den = r1._den * r2._den;
        rational_float temp(std::move(num), std::move(den));
        fp = std::move(temp);
    }
    return fp;
}

floating_point floating_point::multiply(const floating_point& lhs, const floating_point& rhs) {
    floating_point fp;
    if (lhs._type == decimal_type && rhs._type == decimal_type) {
        auto a = *lhs._storage._d;
        auto b = *rhs._storage._d;
        auto m = a._mant * b._mant;
        auto e = a._exp + b._exp;
        decimal_float temp(m, e);
        fp = std::move(temp);
    } else {
        auto r1 = to_rational(lhs);
        auto r2 = to_rational(rhs);
        rational_float temp(r1._num * r2._num, r1._den * r2._den);
        fp = std::move(temp);
    }
    return fp;
}

floating_point floating_point::divide(const floating_point& lhs, const floating_point& rhs) {
    floating_point fp;
    if ((rhs._type == decimal_type && rhs._storage._d->_mant == 0) || (rhs._type == rational_type && rhs._storage._r->_num == 0)) {
        throw exception(errorcode_t::divide_by_zero);
    }
    if (lhs._type == decimal_type && rhs._type == decimal_type) {
        auto a = *lhs._storage._d;
        auto b = *rhs._storage._d;
        auto ma = a._mant;
        auto mb = b._mant;
        int e = a._exp - b._exp;
        if (ma % mb == 0) {
            decimal_float temp(ma / mb, e);
            fp = std::move(temp);
        } else {
            rational_float temp(ma, mb);
            fp = std::move(temp);
        }
    } else {
        auto r1 = to_rational(lhs);
        auto r2 = to_rational(rhs);
        rational_float temp(r1._num * r2._den, r1._den * r2._num);
        fp = std::move(temp);
    }
    return fp;
}

floating_point& floating_point::operator=(const std::string& expr) {
    if (std::string::npos == expr.find('/')) {
        // decimal
        decimal_float temp(expr);
        *this = std::move(temp);
    } else {
        // rational
        rational_float temp(expr);
        *this = std::move(temp);
    }
    return *this;
}

rational_float floating_point::to_rational() { return to_rational(*this); }

rational_float floating_point::to_rational(const floating_point& f) {
    rational_float fp;
    if (f._type == rational_type) {
        auto r = *f._storage._r;
        fp = std::move(r);
    } else {
        auto d = *f._storage._d;
        if (d._exp >= 0) {
            rational_float temp(d._mant * bignumber::pow10(d._exp), 1);
            fp = std::move(temp);
        } else {
            rational_float temp(d._mant, bignumber::pow10(-d._exp));
            fp = std::move(temp);
        }
    }
    return fp;
}

rational_float operator>>(const floating_point& f, rational_float r) {
    r = floating_point::to_rational(f);
    return r;
}

rational_float operator<<(rational_float r, const floating_point& f) {
    r = floating_point::to_rational(f);
    return r;
}

}  // namespace hotplace
