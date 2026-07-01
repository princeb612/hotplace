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

string_set::string_set() {}

string_set::string_set(const string_set& other) { *this = other; }

string_set::string_set(string_set&& other) { *this = std::move(other); }

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

string_set& string_set::union_with(const string_set& other) { return add(other); }

string_set& string_set::erase_from(const string_set& other) { return subtract(other); }

string_set& string_set::intersect_with(const string_set& other) { return intersect(other); }

bool string_set::contains_all(const string_set& other) { return has(other); }

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

bool string_set::has(const std::string& value) { return _set.count(value) > 0; }

bool string_set::has(const string_set& other) {
    if (this == &other) return true;

    if (other._set.empty()) return true;

    for (const auto& item : other._set) {
        if (false == has(item)) {
            return false;
        }
    }

    return true;
}

}  // namespace hotplace
