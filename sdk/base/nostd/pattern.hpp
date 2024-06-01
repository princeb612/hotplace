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

#ifndef __HOTPLACE_SDK_BASE_NOSTD_PATTERN__
#define __HOTPLACE_SDK_BASE_NOSTD_PATTERN__

#include <sdk/base/error.hpp>
#include <sdk/base/stl.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>

namespace hotplace {

// Data Structures & Algorithms 12.3.2 The Boyer-Moore Algorithm
//  O(nm+|Sigma|)
//  Algorithm BMMatch(T,P):
//      Input: Strings T (text) with n characters and P (pattern) with m characters
//      Output: Starting index of the first substring of T matching P, or an indication
//              that P is not a substring of T
//      compute function last
//      i←m−1
//      j←m−1
//      repeat
//          if P[ j] = T[i] then
//              if j = 0 then
//                  return i {a match!}
//              else
//                  i←i−1
//                  j ← j−1
//          else
//              i←i+m−min(j,1+last(T[i])) {jump step}
//              j ←m−1
//      until i > n−1
//      return “There is no substring of T matching P.”

// Data Structures & Algorithms 12.3.3 The Knuth-Morris-Pratt Algorithm
//  O(n+m)
//
//  Algorithm KMPMatch(T,P):
//      Input: Strings T (text) with n characters and P (pattern) with m characters
//      Output: Starting index of the first substring of T matching P, or an indication
//              that P is not a substring of T
//      f ←KMPFailureFunction(P) {construct the failure function f for P}
//      i←0
//      j←0
//      while i < n do
//          if P[ j] = T[i] then
//              if j = m−1 then
//                  return i−m+1 {a match!}
//              i←i+1
//              j ← j+1
//          else if j > 0 {no match, but we have advanced in P} then
//              j ← f ( j−1) { j indexes just after prefix of P that must match}
//          else
//              i←i+1
//      return “There is no substring of T matching P.”
//
//  Algorithm KMPFailureFunction(P):
//      Input: String P (pattern) with m characters
//      Output: The failure function f for P, which maps j to the length of the longest
//              prefix of P that is a suffix of P[1.. j]
//          i←1
//          j←0
//          f (0)←0
//          while i < m do
//              if P[ j] = P[i] then
//                  {we have matched j+1 characters}
//                  f (i)← j+1
//                  i←i+1
//                  j ← j+1
//              else if j > 0 then
//                  { j indexes just after a prefix of P that must match}
//                  j ← f ( j−1)
//              else
//                  {we have no match here}
//                  f (i)←0
//                  i←i+1

template <typename T = char>
class t_kmp_pattern {
   public:
    t_kmp_pattern() {}

    int match(const T* data, size_t data_size, const T* pattern, size_t pattern_size, int pos = 0) {
        int ret = -1;
        int n = data_size;
        int m = pattern_size;
        std::vector<int> fail = failure(pattern, pattern_size);
        int i = pos;
        int j = 0;
        while (i < n) {
            if (pattern[j] == data[i]) {
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
        return ret;
    }

   protected:
    std::vector<int> failure(const T* pattern, size_t size) {
        std::vector<int> fail(size);
        fail[0] = 0;
        size_t m = size;
        size_t j = 0;
        size_t i = 1;
        while (i < m) {
            if (pattern[j] == pattern[i]) {
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
