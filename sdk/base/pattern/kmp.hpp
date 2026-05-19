/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   kmp.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2024.06.02   Soo Han, Kim        study (codename.hotplace Revision 536)
 * 2026.05.19   Soo Han, Kim        replace std::function with functor (codename.hotplace Revision 1003)
 *
 */

#ifndef __HOTPLACE_SDK_BASE_PATTERN_KMP__
#define __HOTPLACE_SDK_BASE_PATTERN_KMP__

#include <hotplace/sdk/base/pattern/pattern.hpp>

namespace hotplace {

/**
 * Data Structures & Algorithms 12.3.3 The Knuth-Morris-Pratt Algorithm
 *  O(n+m)
 *
 *  Algorithm KMPMatch(T,P):
 *      Input: Strings T (text) with n characters and P (pattern) with m characters
 *      Output: Starting index of the first substring of T matching P, or an indication
 *              that P is not a substring of T
 *      f ←KMPFailureFunction(P) {construct the failure function f for P}
 *      i←0
 *      j←0
 *      while i < n do
 *          if P[ j] = T[i] then
 *              if j = m−1 then
 *                  return i−m+1 {a match!}
 *              i←i+1
 *              j ← j+1
 *          else if j > 0 {no match, but we have advanced in P} then
 *              j ← f ( j−1) { j indexes just after prefix of P that must match}
 *          else
 *              i←i+1
 *      return “There is no substring of T matching P.”
 *
 *  Algorithm KMPFailureFunction(P):
 *      Input: String P (pattern) with m characters
 *      Output: The failure function f for P, which maps j to the length of the longest
 *              prefix of P that is a suffix of P[1.. j]
 *          i←1
 *          j←0
 *          f (0)←0
 *          while i < m do
 *              if P[ j] = P[i] then
 *                  {we have matched j+1 characters}
 *                  f (i)← j+1
 *                  i←i+1
 *                  j ← j+1
 *              else if j > 0 then
 *                  { j indexes just after a prefix of P that must match}
 *                  j ← f ( j−1)
 *              else
 *                  {we have no match here}
 *                  f (i)←0
 *                  i←i+1
 */
template <typename T = char, typename comparator_t = std::equal_to<T>>
class t_kmp {
   public:
    /**
     * @brief   KMP pattern matching
     * @remarks
     *          comparator for pointer type - t_kmp<object*>
     *
     *          struct object {
     *               int value;
     *               object(int v) : value(v) {}
     *               friend bool operator==(const object& lhs, const object& rhs) { return lhs.value == rhs.value; }
     *          }
     *          auto comparator = [](const object* lhs, const object* rhs) -> bool {
     *               return (lhs->value == rhs->value);
     *          };
     *
     *          std::vector<objec*> data1; // 1 2 3 4 5 by new object
     *          std::vector<objec*> data2; // 3 4 by new object
     *          // data1.push_back(new object(1));
     *          // ...
     *
     *          t_kmp<parser::token*, decltype(comparator)> kmp(comparator);
     *          kmp.learn(pattern);
     *          kmp.search(data);
     *               // if (pattern[j] == data[i]) - incorrect
     *               // return -1
     *
     *          kmp.search(data, 0);
     *               // if (comparator(pattern[j], data[i])) - correct
     *               // return 2
     *
     * @sa      parser::add_pattern, parser::psearch
     *
     *          parser p;
     *          parser::context context;
     *          constexpr char sample[] = R"(int a; int b = 0; bool b = true;)";
     *          p.add_token("bool", 0x1000).add_token("int", 0x1001).add_token("true", 0x1002).add_token("false", 0x1002);
     *          p.parse(context, sample);
     *          // after parsing, convert each word to a token object
     *          p.add_pattern("int a;").add_pattern("int a = 0;").add_pattern("bool a;").add_pattern("bool a = true;");
     *          // pattern matching using t_aho_corasick<int, token*>
     =          result = p.psearch();
     *          // std::multimap<size_t, size_t> expect = {{0, 0}, {3, 1}, {8, 3}};
     *          // sample  : int a; int b = 0; bool b = true;
     *          // tokens  : 0   12 3   4 5 67 8    9 a b   c
     *          // pattern : 0      1          3
     */
    static constexpr size_t npos = static_cast<size_t>(-1);

    t_kmp(comparator_t comparator = comparator_t()) : _comparator(comparator) {}

    t_kmp& learn(const std::vector<T>& pattern) { return learn(pattern.data(), pattern.size()); }

    /*
     * @brief   one pattern multi search
     */
    t_kmp& learn(const T* pattern, size_t size) {
        _failure.resize(size, 0);
        _pattern.clear();
        if (pattern && size) {
            _pattern.insert(_pattern.begin(), pattern, pattern + size);
            _failure[0] = 0;
            size_t j = 0;
            size_t i = 1;
            while (i < size) {
                if (_comparator(pattern[j], pattern[i])) {
                    _failure[i] = j + 1;
                    i++;
                    j++;
                } else if (j > 0) {
                    j = _failure[j - 1];
                } else {
                    _failure[i] = 0;
                    i++;
                }
            }
        }
        return *this;
    }

    size_t search(const std::vector<T>& data, size_t pos = 0) { return search(data.data(), data.size(), pos); }
    size_t search(const std::vector<T>& data, const std::vector<T>& pattern, size_t pos = 0) {
        return search(data.data(), data.size(), pattern.data(), pattern.size(), pos);
    }

    /**
     * @brief   search
     * @return  index, -1 (not found)
     */
    size_t search(const T* data, size_t size_data, size_t pos = 0) {
        size_t ret = npos;
        if (data) {
            auto m = _failure.size();
            auto i = pos;
            size_t j = 0;
            while (i < size_data) {
                bool test = false;
                test = _comparator(_pattern[j], data[i]);
                if (test) {
                    if (j == m - 1) {
                        ret = i - m + 1;
                        break;
                    }
                    i++;
                    j++;
                } else if (j > 0) {
                    j = _failure[j - 1];
                } else {
                    i++;
                }
            }
        }
        return ret;
    }

    /*
     * @brief   learn pattern and search
     * @remarks
     *          for the same pattern
     *              kmp.learn(pattern, size_pattern);
     *              kmp.search(data, size_data);
     *          or
     *              kmp.search(data, size_data, pattern, size_pattern);
     *              kmp.search(data, size_data);  // use the previously provided pattern
     */
    size_t search(const T* data, size_t size_data, const T* pattern, size_t size_pattern, size_t pos = 0) {
        learn(pattern, size_pattern);
        return search(data, size_data, pos);
    }

   protected:
    std::vector<T> _pattern;
    std::vector<size_t> _failure;
    comparator_t _comparator;
};

}  // namespace hotplace

#endif
