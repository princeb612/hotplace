/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   string_set.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/nostd/string_set.hpp>

namespace hotplace {

string_set::string_set() : _invert(false) {}

string_set::string_set(const string_set& other) : string_set() { *this = other; }

string_set::string_set(string_set&& other) : string_set() { *this = std::move(other); }

string_set::~string_set() {}

string_set& string_set::operator=(const string_set& other) {
    _set = other._set;
    return *this;
}

string_set& string_set::operator=(string_set&& other) {
    _set = std::move(other._set);
    return *this;
}

void string_set::reset() { clear(); }

void string_set::insert(const std::string& value) { add(value); }

void string_set::erase(const std::string& value) { subtract(value); }

bool string_set::contains(const std::string& value) { return has(value); }

bool string_set::match(const std::string& value) { return find(value); }

void string_set::union_with(const string_set& other) {
    // see t_range_set
    uint8 lhs_inverted = is_inverted() ? 1 : 0;
    uint8 rhs_inverted = other.is_inverted() ? 1 : 0;
    uint8 res_xor = (lhs_inverted ^ rhs_inverted);
    if ((0 == lhs_inverted) && (0 == res_xor)) {
        add(other);
    } else if ((0 == lhs_inverted) && (1 == res_xor)) {
        string_set temp(other);
        temp.subtract(*this);
        *this = std::move(temp);  // other.is_inverted=true
    } else if ((1 == lhs_inverted) && (1 == res_xor)) {
        subtract(other);  // is_inverted=true
    } else if ((1 == lhs_inverted) && (0 == res_xor)) {
        intersect(other);  // is_inverted=true
    }
}

void string_set::erase_from(const string_set& other) {
    uint8 lhs_inverted = is_inverted() ? 1 : 0;
    uint8 rhs_inverted = other.is_inverted() ? 1 : 0;
    uint8 res_xor = (lhs_inverted ^ rhs_inverted);
    if ((0 == lhs_inverted) && (0 == res_xor)) {
        subtract(other);  // is_inverted=false
    } else if ((0 == lhs_inverted) && (1 == res_xor)) {
        intersect(other);  // is_inverted=false
    } else if ((1 == lhs_inverted) && (1 == res_xor)) {
        add(other);  // is_inverted=true
    } else if ((1 == lhs_inverted) && (0 == res_xor)) {
        string_set temp(other);
        temp.intersect(*this);
        *this = std::move(temp);  // other.is_inverted=false
    }
}

void string_set::intersect_with(const string_set& other) {
    uint8 lhs_inverted = is_inverted() ? 1 : 0;
    uint8 rhs_inverted = other.is_inverted() ? 1 : 0;
    uint8 res_xor = (lhs_inverted ^ rhs_inverted);
    if ((0 == lhs_inverted) && (0 == res_xor)) {
        intersect(other);  // is_inverted=false
    } else if ((0 == lhs_inverted) && (1 == res_xor)) {
        subtract(other);  // is_inverted=false
    } else if ((1 == lhs_inverted) && (1 == res_xor)) {
        string_set temp(other);
        temp.subtract(*this);
        *this = std::move(temp);  // other.is_inverted=false
    } else if ((1 == lhs_inverted) && (0 == res_xor)) {
        add(other);  // is_inverted=true
    }
}

bool string_set::contains_all(const string_set& other) { return has(other); }

bool string_set::is_inverted() const { return _invert; }

string_set& string_set::invert() {
    _invert = !_invert;
    return *this;
}

string_set& string_set::clear() {
    _set.clear();
    return *this;
}

string_set& string_set::add(const std::string& value) {
    _set.insert(value);
    return *this;
}

string_set& string_set::add(const string_set& other) {
    if (this == &other) return *this;

    for (const auto& item : other._set) insert(item);

    return *this;
}

string_set& string_set::subtract(const std::string& value) {
    _set.erase(value);
    return *this;
}

string_set& string_set::subtract(const string_set& other) {
    if (this == &other) return *this;

    for (const auto& item : other._set) erase(item);

    return *this;
}

string_set& string_set::intersect(const string_set& other) {
    if (this == &other) return *this;

    string_set temp(*this);
    clear();
    for (const auto& item : _set) {
        if (temp.has(item)) {
            _set.insert(item);
        }
    }

    return *this;
}

bool string_set::has(const std::string& value) {
    auto test = _set.count(value) > 0;
    if (false == _invert)
        return test;
    else
        return !test;
}

bool string_set::has(const string_set& other) {
    if (this == &other) return true;

    if (other._set.empty()) return true;

    for (const auto& item : other._set) {
        auto expect = (false == _invert) ? false : true;
        if (expect == has(item)) {
            return false;
        }
    }

    return true;
}

/* ASN.1 FROM */
bool string_set::find(const std::string& value) {
    for (const auto& item : _set) {
        auto pos = item.find_first_of(value);
        if (std::string::npos != pos) return true;
    }
    return false;
}

}  // namespace hotplace
