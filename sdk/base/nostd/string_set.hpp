/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   string_set.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_NOSTD_STRINGSET__
#define __HOTPLACE_SDK_BASE_NOSTD_STRINGSET__

#include <algorithm>
#include <functional>
#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/nostd/traits.hpp>
#include <hotplace/sdk/base/nostd/types.hpp>
#include <hotplace/sdk/base/system/critical_section.hpp>
#include <set>

namespace hotplace {

// "a".."z"
struct string_range {
    std::string begin;
    std::string end;
    range_flag_t begin_flag;
    range_flag_t end_flag;

    string_range(const std::string& s, const std::string& e, range_flag_t bf = range_flag_t::closed, range_flag_t ef = range_flag_t::closed)
        : begin(s), end(e), begin_flag(bf), end_flag(ef) {}
};

class string_set {
   public:
    string_set();
    string_set(const string_set& other);
    string_set(string_set&& other);
    virtual ~string_set();
    string_set& operator=(const string_set& other);
    string_set& operator=(string_set&& other);

    void reset();
    void insert(const std::string& value);
    void erase(const std::string& value);
    bool contains(const std::string& value) const;
    bool regex(const std::string& value) const;

    void union_with(const string_set& other);
    void erase_from(const string_set& other);
    void intersect_with(const string_set& other);
    bool contains_all(const string_set& other);

    bool is_inverted() const;
    string_set& invert();

    string_set& clear();
    string_set& add(const std::string& value);
    string_set& add(const string_set& other);
    string_set& subtract(const std::string& value);
    string_set& subtract(const string_set& other);
    string_set& intersect(const string_set& other);
    string_set& insert_range(const std::string& begin, const std::string& end,  //
                             range_flag_t begin_flag = range_flag_t::closed, range_flag_t end_flag = range_flag_t::closed);
    string_set& erase_range(const std::string& begin, const std::string& end, range_flag_t begin_flag = range_flag_t::closed,
                            range_flag_t end_flag = range_flag_t::closed);
    bool has(const std::string& value) const;
    bool has(const string_set& other) const;
    bool from(const std::string& value) const;

   protected:
    bool exist_in_range(const std::string& value) const;

   private:
    bool _invert;
    std::multiset<std::string> _set;
    std::vector<string_range> _ranges;
};

}  // namespace hotplace

#endif
