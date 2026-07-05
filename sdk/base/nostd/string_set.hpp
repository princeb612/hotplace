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
    bool contains(const std::string& value);
    bool match(const std::string& value);

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
    bool has(const std::string& value);
    bool has(const string_set& other);
    bool find(const std::string& value);

   private:
    bool _invert;
    std::multiset<std::string> _set;
};

}  // namespace hotplace

#endif
