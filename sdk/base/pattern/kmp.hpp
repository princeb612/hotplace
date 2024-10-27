/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_PATTERN_KMP__
#define __HOTPLACE_SDK_BASE_PATTERN_KMP__

#include <sdk/base/pattern/pattern.hpp>

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
template <typename T = char>
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
     *          t_kmp<object*> kmp;
     *          kmp.search(data1, data2);
     *               // if (pattern[j] == data[i]) - incorrect
     *               // return -1
     *
     *          kmp.search(data1, data2, 0, comparator);
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
     *          // std::multimap<unsigned, size_t> expect = {{0, 0}, {3, 1}, {8, 3}};
     *          // sample  : int a; int b = 0; bool b = true;
     *          // tokens  : 0   12 3   4 5 67 8    9 a b   c
     *          // pattern : 0      1          3
     */
    typedef typename std::function<bool(const T&, const T&)> comparator_t;

    t_kmp() {}

    int search(const std::vector<T>& data, const std::vector<T>& pattern, unsigned int pos = 0, comparator_t comparator = nullptr) {
        return search(&data[0], data.size(), &pattern[0], pattern.size(), pos, comparator);
    }

    /**
     * @brief   search
     * @return  index, -1 (not found)
     */
    int search(const T* data, size_t size_data, const T* pattern, size_t size_pattern, unsigned int pos = 0, comparator_t comparator = nullptr) {
        int ret = -1;
        if (data && pattern && size_pattern) {
            unsigned int n = size_data;
            unsigned int m = size_pattern;
            std::vector<int> fail = failure(pattern, m, comparator);
            unsigned int i = pos;
            unsigned int j = 0;
            while (i < n) {
                bool test = false;
                if (comparator) {
                    test = comparator(pattern[j], data[i]);
                } else {
                    test = (pattern[j] == data[i]);
                }
                if (test) {
                    if (j == m - 1) {
                        ret = i - m + 1;
                        break;
                    }
                    i++;
                    j++;
                } else if (j > 0) {
                    j = fail[j - 1];
                } else {
                    i++;
                }
            }
        }
        return ret;
    }

   protected:
    std::vector<int> failure(const T* pattern, size_t size, comparator_t comparator = nullptr) {
        std::vector<int> fail(size);
        fail[0] = 0;
        size_t m = size;
        size_t j = 0;
        size_t i = 1;
        while (i < m) {
            bool test = false;
            if (comparator) {
                test = comparator(pattern[j], pattern[i]);
            } else {
                test = (pattern[j] == pattern[i]);
            }
            if (test) {
                fail[i] = j + 1;
                i++;
                j++;
            } else if (j > 0) {
                j = fail[j - 1];
            } else {
                fail[i] = 0;
                i++;
            }
        }
        return fail;
    }
};

}  // namespace hotplace

#endif
