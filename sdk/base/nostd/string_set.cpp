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

void string_set::insert(const std::string& value) { add(value); }

void string_set::erase(const std::string& value) { subtract(value); }

bool string_set::contains(const std::string& value) { return has(value); }

void string_set::reset() { clear(); }

string_set& string_set::clear() {
    _set.clear();
    return *this;
}

string_set& string_set::add(const std::string& value) {
    _set.insert(value);
    return *this;
}

string_set& string_set::subtract(const std::string& value) {
    auto iter = _set.find(value);
    if (_set.end() != iter) {
        _set.erase(iter);
    }
    return *this;
}

bool string_set::has(const std::string& value) { return _set.count(value) > 0; }

string_set& string_set::intersect(string_set& other) {
    string_set temp(*this);
    clear();
    for (const auto& item : _set) {
        if (temp.has(item)) {
            _set.insert(item);
        }
    }
    return *this;
}

}  // namespace hotplace
