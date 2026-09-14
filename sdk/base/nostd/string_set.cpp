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
#include <hotplace/sdk/base/pattern/regex.hpp>

namespace hotplace {

string_set::string_set() : _invert(false) {}

string_set::string_set(const string_set& other) : string_set() { *this = other; }

string_set::string_set(string_set&& other) : string_set() { *this = std::move(other); }

string_set::~string_set() {}

string_set& string_set::operator=(const string_set& other) {
    if (this != &other) {
        _set = other._set;
        _ranges = other._ranges;
        _invert = other._invert;
    }
    return *this;
}

string_set& string_set::operator=(string_set&& other) {
    if (this != &other) {
        _set = std::move(other._set);
        _ranges = std::move(other._ranges);
        _invert = other._invert;
        other._invert = false;
    }
    return *this;
}

void string_set::reset() { clear(); }

void string_set::insert(const std::string& value) { add(value); }

void string_set::erase(const std::string& value) { subtract(value); }

bool string_set::contains(const std::string& value) const { return has(value); }

bool string_set::regex(const std::string& value) const {
    bool ret = false;
    for (const auto& item : _set) {
        size_t pos = 0;
        std::list<std::string> tokens;
        regex_token(value, item, pos, tokens);
        if (false == tokens.empty()) {
            ret = true;
            break;
        }
    }
    if (true == _invert) {
        ret = !ret;
    }
    return ret;
}

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
    _ranges.clear();
    _invert = false;
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
    if (this == &other) {
        clear();
    } else {
        for (const auto& item : other._set) {
            erase(item);
        }

        if (false == _set.empty()) {
            auto it = _set.begin();
            while (it != _set.end()) {
                if (other.exist_in_range(*it)) {
                    it = _set.erase(it);
                } else {
                    ++it;
                }
            }
        }
    }
    return *this;
}

string_set& string_set::intersect(const string_set& other) {
    if (this == &other) return *this;

    // filter _set
    std::multiset<std::string> temp_set;
    for (const auto& item : _set) {
        if (other.has(item)) {
            temp_set.insert(item);
        }
    }
    _set = std::move(temp_set);

    // intersect _ranges with other._ranges
    std::vector<string_range> temp_ranges;
    for (const auto& r1 : _ranges) {
        for (const auto& r2 : other._ranges) {
            std::string n_begin = (r1.begin > r2.begin) ? r1.begin : r2.begin;
            std::string n_end = (r1.end < r2.end) ? r1.end : r2.end;

            if (n_begin <= n_end) {
                range_flag_t b_flag = (n_begin == r1.begin) ? r1.begin_flag : r2.begin_flag;
                range_flag_t e_flag = (n_end == r1.end) ? r1.end_flag : r2.end_flag;

                if (n_begin == n_end && (range_flag_t::open == b_flag || range_flag_t::open == e_flag)) {
                    continue;
                }
                temp_ranges.emplace_back(n_begin, n_end, b_flag, e_flag);
            }
        }
    }
    _ranges = std::move(temp_ranges);

    return *this;
}

string_set& string_set::insert_range(const std::string& begin, const std::string& end, range_flag_t begin_flag, range_flag_t end_flag) {
    _ranges.emplace_back(begin, end, begin_flag, end_flag);
    return *this;
}

string_set& string_set::erase_range(const std::string& begin, const std::string& end, range_flag_t begin_flag, range_flag_t end_flag) {
    if (begin > end) return *this;

    // 1. erase individual items in _set
    auto it = _set.begin();
    while (it != _set.end()) {
        const std::string& val = *it;
        bool start_ok = (range_flag_t::closed == begin_flag) ? (val >= begin) : (val > begin);
        bool end_ok = (range_flag_t::closed == end_flag) ? (val <= end) : (val < end);

        if (start_ok && end_ok) {
            it = _set.erase(it);
        } else {
            ++it;
        }
    }

    // 2. split or trim ranges
    std::vector<string_range> updated_ranges;
    for (const auto& r : _ranges) {
        // Complete non-overlap check considering boundary flags
        bool no_overlap = false;
        if (r.end < begin || r.begin > end) {
            no_overlap = true;
        } else if (r.end == begin && (range_flag_t::open == r.end_flag || range_flag_t::open == begin_flag)) {
            no_overlap = true;
        } else if (r.begin == end && (range_flag_t::open == r.begin_flag || range_flag_t::open == end_flag)) {
            no_overlap = true;
        }

        if (true == no_overlap) {
            updated_ranges.push_back(r);
            continue;
        }

        // Left remaining part
        if (r.begin < begin || (r.begin == begin && range_flag_t::closed == r.begin_flag && range_flag_t::open == begin_flag)) {
            range_flag_t left_eflag = (range_flag_t::closed == begin_flag) ? range_flag_t::open : range_flag_t::closed;
            updated_ranges.emplace_back(r.begin, begin, r.begin_flag, left_eflag);
        }

        // Right remaining part
        if (r.end > end || (r.end == end && range_flag_t::closed == r.end_flag && range_flag_t::open == end_flag)) {
            range_flag_t right_bflag = (range_flag_t::closed == end_flag) ? range_flag_t::open : range_flag_t::closed;
            updated_ranges.emplace_back(end, r.end, right_bflag, r.end_flag);
        }
    }

    _ranges = std::move(updated_ranges);
    return *this;
}

bool string_set::has(const std::string& value) const {
    auto test = _set.count(value) > 0;
    if (false == test) {
        test = exist_in_range(value);
    }
    return _invert ? !test : test;
}

bool string_set::has(const string_set& other) const {
    if (this == &other) return true;
    // TODO true == other._invert

    auto expect_fail = _invert ? true : false;

    for (const auto& item : other._set) {
        if (expect_fail == has(item)) {
            return false;
        }
    }
    for (const auto& range : other._ranges) {
        if (expect_fail == has(range.begin) || expect_fail == has(range.end)) {
            return false;
        }
    }
    return true;
}

bool string_set::exist_in_range(const std::string& value) const {
    bool exist = false;
    for (const auto& range : _ranges) {
        bool match_start = (range_flag_t::closed == range.begin_flag) ? (value >= range.begin) : (value > range.begin);
        if (false == match_start) {
            continue;
        }

        bool match_end = (range_flag_t::closed == range.end_flag) ? (value <= range.end) : (value < range.end);
        if (true == match_end) {
            exist = true;
            break;
        }
    }
    return exist;
}

/* ASN.1 FROM */
bool string_set::from(const std::string& value) const {
    for (const auto& ch : value) {
        std::string temp;
        temp.push_back(ch);
        bool found = false;
        for (const auto& item : _set) {
            auto pos = item.find_first_of(temp);
            if (std::string::npos != pos) {
                found = true;
                break;
            }
        }
        if (false == found) {
            auto test = exist_in_range(temp);
            if (false == test) return false;
        }
    }
    return true;
}

}  // namespace hotplace
