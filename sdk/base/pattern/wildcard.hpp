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

#ifndef __HOTPLACE_SDK_BASE_PATTERN_WILDCARD__
#define __HOTPLACE_SDK_BASE_PATTERN_WILDCARD__

#include <sdk/base/pattern/pattern.hpp>

namespace hotplace {

/*
 * @brief   wildcard pattern matching
 * @refer   https://www.geeksforgeeks.org/wildcard-pattern-matching/?ref=lbp
 *          time complexcity: O(n), auxiliary space: O(1)
 *
 *          bool wildcards(std::string text, std::string pattern) {
 *              int n = text.length();
 *              int m = pattern.length();
 *              int i = 0;
 *              int j = 0;
 *              int startIndex = -1;
 *              int match = 0;
 *
 *              while (i < n) {
 *                  if (j < m && (('?' == pattern[j]) || (pattern[j] == text[i]))) {
 *                      i++;
 *                      j++;
 *                  } else if ((j < m) && ('*' == pattern[j])) {
 *                      startIndex = j;
 *                      match = i;
 *                      j++;
 *                  } else if (-1 != startIndex) {
 *                      j = startIndex + 1;
 *                      match++;
 *                      i = match;
 *                  } else {
 *                      return false;
 *                  }
 *              }
 *
 *              while ((j < m) && ('*' == pattern[j])) {
 *                  j++;
 *              }
 *
 *              return j == m;
 *          }
 * @sample
 *          t_wildcards<char> wild('?', '*');
 *          test = wild.match("baaabab", 7, "*****ba*****ab", 14); // true
 *          test = wild.match("baaabab", 7, "ba?aba?", 7); // true
 */
template <typename BT = char, typename T = BT>
class t_wildcards {
   public:
    typedef typename std::function<BT(const T* source, size_t idx)> memberof_t;
    typedef typename std::function<int(const BT& t)> kindof_t;

    t_wildcards(const BT& wild_single, const BT& wild_any, memberof_t memberof = memberof_defhandler<BT, T>)
        : _wild_single(wild_single), _wild_any(wild_any), _memberof(memberof) {}

    bool match(const std::vector<T>& source, const std::vector<T>& pattern) { return match(&source[0], source.size(), &pattern[0], pattern.size()); }
    bool match(const T* source, size_t n, const T* pattern, size_t m) {
        bool ret = false;
        int i = 0;
        int j = 0;
        int startidx = -1;
        int match = 0;

        while ((i < n) && (j < m)) {
            const BT& t = _memberof(source, i);
            const BT& p = _memberof(pattern, j);
            if (j < m && ((_wild_single == p) || (p == t))) {
                i++;
                j++;
            } else if ((j < m) && (_wild_any == p)) {
                startidx = j;
                match = i;
                j++;
            } else if (-1 != startidx) {
                j = startidx + 1;
                match++;
                i = match;
            } else {
                return false;
            }
        }

        while (j < m) {
            const BT& p = _memberof(pattern, j);
            if (_wild_any == p) {
                j++;
            } else {
                break;
            }
        }

        return (j == m);
    }

   private:
    memberof_t _memberof;
    BT _wild_single;  // ?
    BT _wild_any;     // *
};

}  // namespace hotplace

#endif
