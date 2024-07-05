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

#include <functional>
#include <map>
#include <queue>
#include <sdk/base/error.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>
#include <string>
#include <vector>

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
    /**
     * comparator for pointer type - t_kmp_pattern<object*>
     *
     * struct object {
     *      int value;
     *      friend bool operator==(const object& lhs, const object& rhs) { return lhs.value == rhs.value; }
     * }
     * auto comparator = [](const object* lhs, const object* rhs) -> bool {
     *      return (lhs->value == rhs->value);
     * };
     *
     * std::vector<objec*> data1; // 1 2 3 4 5 by new object
     * std::vector<objec*> data2; // 3 4 by new object
     *
     * t_kmp_pattern<object*> search;
     * search.match(data1, data2);
     *      // if (pattern[j] == data[i]) - incorrect
     *      // return -1
     *
     * search.match(data1, data2, 0, comparator);
     *      // if (comparator(pattern[j], data[i])) - correct
     *      // return 2
     */
    typedef typename std::function<bool(const T&, const T&)> comparator_t;

    t_kmp_pattern() {}

    int match(const std::vector<T>& data, const std::vector<T>& pattern, unsigned int pos = 0, comparator_t comparator = nullptr) {
        return match(&data[0], data.size(), &pattern[0], pattern.size(), pos, comparator);
    }

    /**
     * @brief   match
     * @return  index, -1 (not found)
     */
    int match(const T* data, size_t size_data, const T* pattern, size_t size_pattern, unsigned int pos = 0, comparator_t comparator = nullptr) {
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

/**
 * @brief   Aho-Corasick  algorithm
 * @remarks
 *          multiple-patterns
 *              KMP O(n*k + m)
 *              Aho-Corasick O(n + m + z) ; z count of matches
 * @refer   https://www.javatpoint.com/aho-corasick-algorithm-for-pattern-searching-in-cpp
 * @sample
 *          t_aho_corasick ac;
 *          ac.insert("abc", 3).insert("ab", 2).insert("bc", 2).insert("a", 1);
 *          ac.build_state_machine();
 *          const char* text = "abcaabc";
 *          std::multimap<unsigned, size_t> result;
 *          result = ac.search(text, strlen(text));
 *          for (auto item : result) {
 *              _logger->writeln("pattern[%i] at [%zi]", item.first, item.second);
 *          }
 */

template <typename T = char>
class t_aho_corasick {
   public:
    /**
     * @brief   trie node structure
     */
    struct trienode {
        std::map<T, trienode*> children;
        trienode* fail;
        std::vector<int> output;

        trienode() : fail(nullptr) {}
        ~trienode() {
            for (auto item : children) {
                delete item.second;
            }
        }
    };

   public:
    t_aho_corasick() : _root(new trienode) {}
    ~t_aho_corasick() { delete _root; }

    /**
     * @brief   insert a pattern into the trie
     */
    t_aho_corasick<T>& insert(const std::vector<T>& pattern) { return insert(&pattern[0], pattern.size()); }
    t_aho_corasick<T>& insert(const T* pattern, size_t size) {
        if (pattern) {
            trienode* current = _root;
            std::vector<T> p;

            p.insert(p.end(), pattern, pattern + size);

            for (size_t i = 0; i < size; ++i) {
                const T& t = pattern[i];
                if (nullptr == current->children[t]) {
                    current->children[t] = new trienode();
                }
                current = current->children[t];
            }

            size_t index = _patterns.size();
            current->output.push_back(index);
            _patterns.insert({index, std::move(p)});
        }
        return *this;
    }
    /**
     * @brief   build the Aho-Corasick finite state machine
     */
    void build_state_machine() {
        std::queue<trienode*> q;

        // set failure links
        for (auto& pair : _root->children) {
            pair.second->fail = _root;
            q.push(pair.second);
        }

        // Breadth-first traversal
        while (false == q.empty()) {
            trienode* current = q.front();
            q.pop();

            for (auto& pair : current->children) {
                const T& key = pair.first;
                trienode* child = pair.second;

                q.push(child);

                trienode* failNode = current->fail;
                while (failNode && !failNode->children[key]) {
                    failNode = failNode->fail;
                }

                child->fail = failNode ? failNode->children[key] : _root;

                // Merge output lists
                child->output.insert(child->output.end(), child->fail->output.begin(), child->fail->output.end());
            }
        }
    }

    /**
     * @brief   search for patterns
     * @return  std::multimap<unsigned, size_t> as is multimap<pattern_id, index>
     */
    std::multimap<unsigned, size_t> search(const std::vector<T>& source) { return search(&source[0], source.size()); }
    std::multimap<unsigned, size_t> search(const T* source, size_t size) {
        std::multimap<unsigned, size_t> result;
        if (source) {
            trienode* current = _root;
            for (size_t i = 0; i < size; ++i) {
                const T& t = source[i];
                while (current && (nullptr == current->children[t])) {
                    current = current->fail;
                }
                if (current) {
                    current = current->children[t];
                    for (auto v : current->output) {
                        // v is index of pattern
                        // i is end position of pattern
                        // (i - sizepat + 1) is beginning position of pattern
                        size_t sizepat = _patterns[v].size();
                        size_t pos = i - sizepat + 1;
                        result.insert({v, pos});
                        // debug
                        // printf("pattern:%i at [%zi] pattern [%.*s] \n",  v, pos, (unsigned)sizepat, &(_patterns[v])[0]);
                    }
                } else {
                    current = _root;
                }
            }
        }
        return result;
    }

   private:
    trienode* _root;
    std::map<size_t, std::vector<T>> _patterns;
};

/**
 * @brief   Aho-Corasick  algorithm using pointer
 * @remarks
 *          // sketch
 *          struct token { int type; };
 *          // lambda conversion - const T* to T* const*
 *          auto memberof = [](token* const* source, size_t idx) -> int {
 *              const token* p = source[idx];
 *              return p->type;
 *          };
 *          t_aho_corasick_ptr<int, token*> ac(memberof);
 * @sa      t_aho_corasick
 */
template <typename BT = char, typename T = char>
class t_aho_corasick_ptr {
   public:
    typedef typename std::function<BT(const T* source, size_t idx)> memberof_t;

    /**
     * @brief   trie node structure
     */
    struct trienode {
        std::map<BT, trienode*> children;
        trienode* fail;
        std::vector<int> output;

        trienode() : fail(nullptr) {}
        ~trienode() {
            for (auto item : children) {
                delete item.second;
            }
        }
    };

   public:
    t_aho_corasick_ptr(memberof_t memberof) : _root(new trienode), _memberof(memberof) {}
    ~t_aho_corasick_ptr() { delete _root; }

    /**
     * @brief   insert a pattern into the trie
     */
    t_aho_corasick_ptr<BT, T>& insert(const std::vector<T>& pattern) { return insert(&pattern[0], pattern.size()); }
    t_aho_corasick_ptr<BT, T>& insert(const T* pattern, size_t size) {
        if (pattern) {
            trienode* current = _root;
            std::vector<T> p;

            p.insert(p.end(), pattern, pattern + size);

            for (size_t i = 0; i < size; ++i) {
                const BT& t = _memberof(pattern, i);
                if (nullptr == current->children[t]) {
                    current->children[t] = new trienode();
                }
                current = current->children[t];
            }

            size_t index = _patterns.size();
            current->output.push_back(index);
            _patterns.insert({index, std::move(p)});
        }
        return *this;
    }
    /**
     * @brief   build the Aho-Corasick finite state machine
     */
    void build_state_machine() {
        std::queue<trienode*> q;

        // set failure links
        for (auto& pair : _root->children) {
            pair.second->fail = _root;
            q.push(pair.second);
        }

        // Breadth-first traversal
        while (false == q.empty()) {
            trienode* current = q.front();
            q.pop();

            for (auto& pair : current->children) {
                const BT& key = pair.first;
                trienode* child = pair.second;

                q.push(child);

                trienode* failNode = current->fail;
                while (failNode && !failNode->children[key]) {
                    failNode = failNode->fail;
                }

                child->fail = failNode ? failNode->children[key] : _root;

                // Merge output lists
                child->output.insert(child->output.end(), child->fail->output.begin(), child->fail->output.end());
            }
        }
    }

    /**
     * @brief   search for patterns
     * @return  std::multimap<unsigned, size_t> as is multimap<pattern_id, index>
     */
    std::multimap<unsigned, size_t> search(const std::vector<T>& source) { return search(&source[0], source.size()); }
    std::multimap<unsigned, size_t> search(const T* source, size_t size) {
        std::multimap<unsigned, size_t> result;
        if (source) {
            trienode* current = _root;
            for (size_t i = 0; i < size; ++i) {
                const BT& t = _memberof(source, i);
                while (current && (nullptr == current->children[t])) {
                    current = current->fail;
                }
                if (current) {
                    current = current->children[t];
                    for (auto v : current->output) {
                        // v is index of pattern
                        // i is end position of pattern
                        // (i - sizepat + 1) is beginning position of pattern
                        size_t sizepat = _patterns[v].size();
                        size_t pos = i - sizepat + 1;
                        result.insert({v, pos});
                        // debug
                        // printf("pattern:%i at [%zi] pattern [%.*s] \n",  v, pos, (unsigned)sizepat, &(_patterns[v])[0]);
                    }
                } else {
                    current = _root;
                }
            }
        }
        return result;
    }
    const std::vector<T>& get_patterns(size_t index) { return _patterns[index]; }

   private:
    trienode* _root;
    std::map<size_t, std::vector<T>> _patterns;
    memberof_t _memberof;
};

}  // namespace hotplace

#endif
