/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   pattern.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_PATTERN_PATTERN__
#define __HOTPLACE_SDK_BASE_PATTERN_PATTERN__

#include <functional>
#include <hotplace/sdk/base/error.hpp>
#include <hotplace/sdk/base/syntax.hpp>
#include <hotplace/sdk/base/types.hpp>
#include <map>
#include <queue>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace hotplace {

/**
 * @brief   access specified element
 * @sa      t_trie, t_suffixtree, t_ukkonen, t_aho_corasick, t_wildcards
 * @remarks
 *
 *      // implementation1. simple array (simply return array[index])
 *          char data[] = { 's', 'a', 'm', 'p', 'l', 'e' };
 *          t_trie<char> trie;
 *          t_suffixtree<char> suffixtree;
 *          t_ukkonen<char> ukkonen;
 *          t_aho_corasick<char> ac;
 *          t_wildcards<char> wild('?', '*');
 *
 *      // implementation2. using pointer data array or vector
 *          struct mystruct {
 *              // other members
 *              int elem; // key
 *              mystruct(char c) : elem(c) {}
 *          }
 *          auto memberof = [](mystruct* const* n, size_t idx) -> int { return n[idx]->elem; };
 *          t_trie<int, mystruct*> trie(memberof);
 *          t_suffixtree<int, mystruct*> suffixtree(memberof);
 *          t_ukkonen<int, mystruct*> ukkonen(memberof);
 *          t_aho_corasick<int, mystruct*> ac(memberof);
 *          t_wildcards<int, mystruct*> wild(kindof_exact_one, kindof_zero_or_more, memberof);
 */
template <typename BT = char, typename T = BT>
struct memberof_defhandler {
    BT operator()(const T* source, size_t idx) const { return source ? static_cast<BT>(source[idx]) : BT(); }
};

/**
 * @brief   pattern matching ignore case
 * @example
 *          t_aho_corasick_wildcard<char, char, memberof_tolower_handler> ac('?', '*');
 */
struct memberof_tolower_handler {
    char operator()(const char* source, size_t idx) const { return source ? std::tolower(source[idx]) : char(); }
};

/**
 * @example
 *          struct symbol_less {
 *              template <typename T>
 *              bool operator()(const T& lhs, const T& rhs) const { return lhs.symmbol < rhs.symbol; }
 *          };
 */
template <typename T, typename comparator_t = std::less<T>>
struct t_comparator_base {
    bool operator()(const T& lhs, const T& rhs) const { return comparator_t{}(lhs, rhs); }
};

}  // namespace hotplace

#endif
