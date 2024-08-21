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
#include <sdk/base/nostd/template.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace hotplace {

/**
 * Data Structures & Algorithms 12.3.2 The Boyer-Moore Algorithm
 *  O(nm+|Sigma|)
 *  Algorithm BMMatch(T,P):
 *      Input: Strings T (text) with n characters and P (pattern) with m characters
 *      Output: Starting index of the first substring of T matching P, or an indication
 *              that P is not a substring of T
 *      compute function last
 *      i←m−1
 *      j←m−1
 *      repeat
 *          if P[ j] = T[i] then
 *              if j = 0 then
 *                  return i {a match!}
 *              else
 *                  i←i−1
 *                  j ← j−1
 *          else
 *              i←i+m−min(j,1+last(T[i])) {jump step}
 *              j ←m−1
 *      until i > n−1
 *      return “There is no substring of T matching P.”
 */
// not implemented

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
BT memberof_defhandler(const T* source, size_t idx) {
    return source ? source[idx] : BT();
}

/**
 * @brief   Trie Data Structure
 *          A Trie, also known as a prefix tree, is a tree-like data structure used to store a dynamic set of strings.
 * @refer   https://www.geeksforgeeks.org/trie-data-structure-in-cpp/
 *          https://www.geeksforgeeks.org/auto-complete-feature-using-trie/
 * @sample
 *          t_trie<char> trie;
 *          trie.add("hello", 5).add("dog", 3).add("help", 4);
 *          result = trie.search("hello", 5); // true
 *          result = trie.prefix("he", 2); // true
 *          auto handler = [](const char* p, size_t size) -> void {
 *              if (p) {
 *                  printf("%.*s\n", (unsigned)size, p);
 *              }
 *          };
 *          trie.dump(handler); // dog, hello, help
 *          result = trie.suggest("he", 2, handler); // hello, help
 *          trie.erase("help", 4);
 *          result = trie.search("help", 4); // false
 */
template <typename BT = char, typename T = BT, typename TP = char>
class t_trie {
   public:
    typedef typename std::function<BT(const T* source, size_t idx)> memberof_t;
    typedef typename std::function<void(const BT* t, size_t size)> dump_handler;

    /**
     * @brief   trie node structure
     */
    struct trienode {
        std::map<BT, trienode*> children;
        bool eow;   // end of  word
        int index;  // 0 for reserved

        trienode() : eow(false), index(-1) {}
        virtual ~trienode() {
            for (auto item : children) {
                delete item.second;
            }
        }

        /**
         * is
         */
        bool islast() { return children.empty(); }
        bool iseow() { return eow; }
        /**
         * getter
         */
        int getindex() { return index; }
        /**
         * setter
         */
        void setindex(int idx) { index = idx; }
        /**
         * verb
         */
        virtual void invalidate() {
            eow = false;
            index = -1;
        }
    };

    t_trie(memberof_t memberof = memberof_defhandler<BT, T>) : _root(new trienode), _memberof(memberof), _index(0) {}
    virtual ~t_trie() {
        delete _root;
        clear();
    }

    /**
     * @brief   add
     * @return  *this
     * @sa      insert
     * @remarks
     *          // sketch
     *          {
     *              t_trie<char> trie;
     *              trie.add("pattern", 7);
     *          }
     *
     *          // handle text and addtional info
     *          {
     *              struct mystruct { int blahblah; };
     *              t_trie<char, char, mystruct> trie;
     *              auto tagged = new mystruct(1);
     *              trie.add("pattern", 7, tagged);
     *              mystruct* tag = nullptr;
     *              trie.search("pattern", 7, &tag);
     *              // never delete tagged
     *          }   // ~trie free all tagged
     *
     *          // index-based operations
     *          {
     *              t_trie<char> trie;
     *              auto node = trie.insert("hello", 5);
     *              auto index = trie.find("hello", 5);
     *              bool compare = (node->index == index); // true;
     *
     *              std::vector<char> arr;
     *              trie.rfind(index, arr);
     *              auto rc = strncmp("hello", &arr[0], arr.size()); // 0
     *          }
     */
    t_trie<BT, T, TP>& add(const std::vector<T>& pattern, TP* tag = nullptr) {
        insert(&pattern[0], pattern.size(), tag);
        return *this;
    }
    t_trie<BT, T, TP>& add(const T* pattern, size_t size, TP* tag = nullptr) {
        insert(pattern, size, tag);
        return *this;
    }
    /**
     * @brief   add
     * @return  trienode*
     * @sa      add
     */
    trienode* insert(const std::vector<T>& pattern, TP* tag = nullptr) { return insert(&pattern[0], pattern.size(), tag); }
    trienode* insert(const T* pattern, size_t size, TP* tag = nullptr) {
        trienode* current = _root;
        if (pattern) {
            for (size_t i = 0; i < size; ++i) {
                const BT& t = _memberof(pattern, i);
                trienode* child = current->children[t];
                if (nullptr == child) {
                    child = new trienode;
                    current->children[t] = child;
                }
                current = child;
            }
            inserthook(current, pattern, size, tag);
        }
        return current;
    }
    /**
     * @brief   search
     * @return  true/false
     * @sa      find
     */
    bool search(const std::vector<T>& pattern, TP** tag = nullptr) { return search(&pattern[0], pattern.size(), tag); }
    bool search(const T* pattern, size_t size, TP** tag = nullptr) {
        bool ret = false;
        if (pattern) {
            trienode* current = _root;
            for (size_t i = 0; i < size; ++i) {
                const BT& t = _memberof(pattern, i);
                auto iter = current->children.find(t);
                if (current->children.end() == iter) {
                    return false;
                }
                current = iter->second;
            }
            ret = current->eow;
            gettag(current, tag);
        }
        return ret;
    }
    /**
     * @brief   find in index
     * @return  index (-1 if not found)
     * @sa      search
     */
    int find(const std::vector<T>& pattern, TP** tag = nullptr) { return find(&pattern[0], pattern.size(), tag); }
    int find(const T* pattern, size_t size, TP** tag = nullptr) {
        int index = -1;
        if (pattern) {
            trienode* current = _root;
            for (size_t i = 0; i < size; ++i) {
                const BT& t = this->_memberof(pattern, i);
                auto item = current->children.find(t);
                if (current->children.end() == item) {
                    return -1;  // not found
                }
                current = item->second;
            }
            if (current->eow) {
                gettag(current, tag);
                index = current->index;
            }
        }
        return index;
    }
    /**
     * @brief   find by index
     * @return  bool
     */
    bool rfind(int index, std::vector<BT>& arr) {
        bool ret = false;
        arr.clear();
        std::vector<BT> prefix;
        auto node = searchindex(this->_root, index, prefix, arr);
        if (node) {
            ret = true;
        }
        return ret;
    }

    /**
     * @brief   prefix
     * @return  true/false
     */
    bool prefix(const std::vector<T>& pattern) { return prefix(&pattern[0], pattern.size()); }
    bool prefix(const T* pattern, size_t size, bool* eow = nullptr, TP** tag = nullptr) {
        bool ret = true;
        if (pattern) {
            trienode* current = _root;
            for (size_t i = 0; i < size; ++i) {
                const BT& t = _memberof(pattern, i);
                auto iter = current->children.find(t);
                if (current->children.end() == iter) {
                    return false;
                }
                current = iter->second;
                if (eow) {
                    *eow = current->eow;
                    gettag(current, tag);
                }
            }
        }
        return ret;
    }

    /**
     * @brief   lookup
     * @param   const T* pattern [in]
     * @param   size_t size [in]
     * @param   TP** tag [outopt] nullptr
     * @return  length, 0 if not found
     * @sample
     *          t_trieindexer<char> trie;
     *          trie.add("hello", 5).add("world", 5);
     *          const char* source = "helloworld";
     *          // 0123456789
     *          // helloworld
     *          // hello      - in
     *          //  x         - not in
     *          //      world - in
     *          len = trie.lookup(source, 10);     // 5
     *          len = trie.lookup(source + 1, 9);  // 0
     *          len = trie.lookup(source + 5, 5);  // 5
     */
    size_t lookup(const T* pattern, size_t size, TP** tag = nullptr) {
        size_t len = 0;
        bool ret = true;
        bool eow = false;
        if (pattern) {
            trienode* current = _root;
            for (size_t i = 0; i < size; ++i) {
                const BT& t = _memberof(pattern, i);
                auto iter = current->children.find(t);
                if (current->children.end() == iter) {
                    return 0;
                }
                current = iter->second;
                eow = current->eow;
                if (eow) {
                    gettag(current, tag);
                    len = i + 1;
                    break;
                }
            }
        }
        return len;
    }
    /**
     * @brief   erase
     */
    void erase(const std::vector<T>& pattern) { erase(&pattern[0], pattern.size()); }
    void erase(const T* pattern, size_t size) {
        if (pattern) {
            trienode* current = _root;
            for (size_t i = 0; i < size; ++i) {
                const BT& t = _memberof(pattern, i);
                auto iter = current->children.find(t);
                if (current->children.end() == iter) {
                    return;
                }
                current = iter->second;
            }
            if (current->eow) {
                auto iter = _tags.find(current->index);
                if (_tags.end() != iter) {
                    delete iter->second;
                    _tags.erase(iter);
                }

                current->invalidate();
            }
        }
    }

    t_trie<BT, T>& reset() {
        if (_root.children.size()) {
            delete _root;
            _root = new trienode;
        }
        clear();
        return *this;
    }

    bool suggest(const std::vector<T>& pattern, dump_handler handler) { return suggest(&pattern[0], pattern.size(), handler); }
    bool suggest(const T* pattern, size_t size, dump_handler handler) {
        bool ret = true;
        if (pattern && handler) {
            trienode* current = _root;
            for (size_t i = 0; i < size; ++i) {
                const BT& t = _memberof(pattern, i);
                auto iter = current->children.find(t);
                if (current->children.end() == iter) {
                    return false;
                }
                current = iter->second;
            }
            if (current->islast()) {
                handler(pattern, size);
            } else {
                dump(current, pattern, size, handler);
            }
        } else {
            ret = false;
        }
        return ret;
    }

    void dump(dump_handler handler) const { dump(_root, nullptr, 0, handler); }

   protected:
    trienode* searchindex(trienode* node, int index, std::vector<BT>& prefix, std::vector<BT>& arr) {
        trienode* ret_value = nullptr;
        __try2 {
            if (node->eow && (index == node->index)) {
                ret_value = node;
                arr = prefix;
                __leave2;
            }

            for (auto& item : node->children) {
                prefix.push_back(item.first);
                node = searchindex(item.second, index, prefix, arr);
                prefix.pop_back();
                if (node) {
                    ret_value = node;
                    break;
                }
            }
        }
        __finally2 {
            // do nothing
        }
        return ret_value;
    }
    void clear() {
        for (auto item : _tags) {
            delete item.second;
        }
        _tags.clear();
    }
    virtual void inserthook(trienode* node, const T* pattern, size_t size, TP* tag) {
        if (-1 == node->index) {
            node->setindex(++_index);
        }
        node->eow = true;
        settag(node, tag);
    }
    bool settag(trienode* node, TP* tag) {
        bool ret = false;
        if (node && tag) {
            ret = node->eow;
            if (ret) {
                auto iter = _tags.find(node->index);
                if (_tags.end() != iter) {
                    delete iter->second;
                }
                _tags[node->index] = tag;
            }
        }
        return ret;
    }
    bool gettag(trienode* node, TP** tag) {
        bool ret = false;
        if (node) {
            ret = node->eow;
            if (ret && tag) {
                auto iter = _tags.find(node->index);
                if (_tags.end() != iter) {
                    *tag = iter->second;
                }
            }
        }
        return ret;
    }
    void dump(trienode* node, const T* pattern, size_t size, dump_handler handler) const {
        if (node && handler) {
            if (node->eow) {
                handler(pattern, size);
            }
            for (auto item : node->children) {
                std::vector<BT> v;
                v.insert(v.end(), pattern, pattern + size);
                v.insert(v.end(), item.first);
                dump(item.second, &v[0], v.size(), handler);
            }
        }
    }

    trienode* _root;
    memberof_t _memberof;
    unsigned _index;
    std::unordered_map<int, TP*> _tags;
};

/**
 * @brief   suffix trie
 * @refer   https://www.geeksforgeeks.org/pattern-searching-using-trie-suffixes/
 * @sample
 *          // construct
 *          t_suffixtree<char> suffixtree("geeksforgeeks.org", 17);
 *          std::set<unsigned> result = suffixtree.search("ee", 2);       // 1, 9
 *          std::set<unsigned> result = suffixtree.search("geek", 4);     // 0, 8
 *          std::set<unsigned> result = suffixtree.search("quiz", 4);     // not found
 *          std::set<unsigned> result = suffixtree.search("forgeeks", 8); // 5
 *
 *          //
 *          t_suffixtree<char> suffixtree;
 *          suffixtree.add("geeksforgeeks.org", 17);
 *          std::set<unsigned> result = suffixtree.search("ee", 2);       // 1, 9
 */
template <typename BT = char, typename T = BT>
class t_suffixtree {
   public:
    typedef typename std::function<BT(const T* source, size_t idx)> memberof_t;

    struct trienode {
        std::unordered_map<BT, trienode*> children;
        std::set<unsigned> index;

        trienode() {}
        ~trienode() {
            for (auto item : children) {
                delete item.second;
            }
        }
    };

    t_suffixtree(memberof_t memberof = memberof_defhandler<BT, T>) : _root(new trienode), _memberof(memberof) {}
    t_suffixtree(const T* pattern, size_t size, memberof_t memberof = memberof_defhandler<BT, T>) : _root(new trienode), _memberof(memberof) {
        add(pattern, size);
    }
    virtual ~t_suffixtree() { delete _root; }

    t_suffixtree<BT, T>& add(const std::vector<T>& pattern) { return add(&pattern[0], pattern.size()); }
    t_suffixtree<BT, T>& add(const T* pattern, size_t size) {
        if (pattern) {
            for (size_t i = 0; i < size; ++i) {
                const BT& t = _memberof(pattern, i);
                _source.insert(_source.end(), t);
            }
            size_t size_source = _source.size();
            for (size_t i = 0; i < size_source; ++i) {
                add(&_source[i], size_source - i, i);
            }
        }
        return *this;
    }

    std::set<unsigned> search(const std::vector<T>& pattern) { return search(&pattern[0], pattern.size()); }
    std::set<unsigned> search(const T* pattern, size_t size) {
        std::set<unsigned> index;
        if (pattern) {
            trienode* current = _root;
            for (size_t i = 0; i < size; ++i) {
                const BT& t = _memberof(pattern, i);
                auto item = current->children.find(t);
                if (current->children.end() == item) {
                    return index;  // not found
                }
                current = item->second;
            }
            for (auto item : current->index) {
                index.insert(item - size + 1);
            }
        }
        return index;
    }

    t_suffixtree<BT, T>& reset() {
        if (_root->children.size()) {
            delete _root;
            _root = new trienode;
        }
        return *this;
    }

   protected:
    void add(const BT* pattern, size_t size, unsigned idx) {
        if (pattern) {
            trienode* current = _root;
            for (size_t i = 0; i < size; ++i) {
                const BT& t = pattern[i];
                trienode* child = current->children[t];
                if (nullptr == child) {
                    child = new trienode;
                    current->children[t] = child;
                }
                current = child;
                current->index.insert(idx + i);
            }
        }
    }

   private:
    trienode* _root;
    std::vector<BT> _source;
    memberof_t _memberof;
};

/**
 * @brief   suffix tree (Ukkonen algorithm)
 * @refer   https://www.geeksforgeeks.org/ukkonens-suffix-tree-construction-part-1/
 *          https://brenden.github.io/ukkonen-animation/
 *          https://programmerspatch.blogspot.com/2013/02/ukkonens-suffix-tree-algorithm.html
 */
template <typename BT = char, typename T = BT>
class t_ukkonen {
   public:
    struct trienode;
    typedef typename std::function<BT(const T* _source, size_t idx)> memberof_t;
    typedef typename std::function<void(const BT* t, size_t size)> dump_handler;
    typedef typename std::function<void(trienode* node, int level, const BT* t, size_t size)> debug_handler;

    struct trienode {
        std::unordered_map<BT, trienode*> children;
        trienode* suffix_link;
        int start;
        int end;
        int suffix_index;

        trienode(int start = -1, int end = -1) : start(start), end(end), suffix_index(-1), suffix_link(nullptr) {}
        ~trienode() {
            for (auto item : children) {
                delete item.second;
            }
        }

        int length() { return end - start + 1; }
    };

    t_ukkonen(memberof_t memberof = memberof_defhandler<BT, T>) : _memberof(memberof) { init(_root = new trienode); }
    t_ukkonen(const T* _source, size_t size, memberof_t memberof = memberof_defhandler<BT, T>) : _memberof(memberof) {
        init(_root = new trienode);
        add(_source, size);
    }
    virtual ~t_ukkonen() { delete _root; }

    t_ukkonen<BT, T>& add(const std::vector<T>& pattern) { return add(&pattern[0], pattern.size()); }
    t_ukkonen<BT, T>& add(const T* pattern, size_t size) {
        if (pattern) {
            reset();
            for (int i = 0; i < size; ++i) {
                const BT& t = _memberof(pattern, i);
                _source.insert(_source.end(), t);
            }
            init(_root);
            int source_size = _source.size();
            for (int i = 0; i < source_size; ++i) {
                extend(i);
            }
        }
        set_suffixindex(_root, 0);
        return *this;
    }

    std::set<int> search(const std::vector<T>& pattern) { return search(&pattern[0], pattern.size()); }
    std::set<int> search(const T* pattern, size_t size) {
        std::set<int> result;
        int pos = -1;
        if (pattern) {
            trienode* current = _root;
            int i = 0;
            for (int i = 0; i < size;) {
                const BT& t = _memberof(pattern, i);
                if (current->children.end() != current->children.find(t)) {
                    trienode* child = current->children[t];
                    int len = child->length();
                    for (int j = 0; j < len && i < size; j++, i++) {
                        pos = child->start + j;
                        if (_source[pos] != _memberof(pattern, i)) {
                            return result;  // not found
                        }
                    }
                    current = child;
                } else {
                    return result;  // not found
                }
            }

            collect_suffix_indices(current, result);
        }
        return result;
    }

    t_ukkonen<BT, T>& reset() {
        if (_root->children.size()) {
            delete _root;
            _root = new trienode;
        }
        return *this;
    }

    void dump(dump_handler handler) { dump(_root, 0, handler); }
    void debug(debug_handler handler) { debug(_root, 0, handler); }

   private:
    memberof_t _memberof;
    std::vector<BT> _source;
    trienode* _root;
    trienode* _active_node;
    int _active_edge;
    int _active_length;
    int _remaining_suffix_count;

    void init(trienode* node) {
        _active_node = node;
        _active_edge = -1;
        _active_length = 0;
        _remaining_suffix_count = 0;
    }

    void extend(int pos) {
        trienode* last_new_node = nullptr;
        _remaining_suffix_count++;
        while (_remaining_suffix_count > 0) {
            if (0 == _active_length) {
                _active_edge = pos;
            }

            auto item = _active_node->children.find(_source[_active_edge]);
            if (_active_node->children.end() == item) {
                _active_node->children[_source[_active_edge]] = new trienode(pos, _source.size() - 1);
                if (last_new_node) {
                    last_new_node->suffix_link = _active_node;
                    last_new_node = nullptr;
                }
            } else {
                trienode* next = item->second;
                int len = next->length();
                if (_active_length >= len) {
                    _active_edge += len;
                    _active_length -= len;
                    _active_node = next;
                    continue;
                }

                if (_source[next->start + _active_length] == _source[pos]) {
                    _active_length++;
                    if (last_new_node) {
                        last_new_node->suffix_link = _active_node;
                        last_new_node = nullptr;
                    }
                    break;
                }

                trienode* split = new trienode(next->start, next->start + _active_length - 1);
                _active_node->children[_source[_active_edge]] = split;
                split->children[_source[pos]] = new trienode(pos, _source.size() - 1);
                next->start += _active_length;
                split->children[_source[next->start]] = next;

                if (last_new_node) {
                    last_new_node->suffix_link = split;
                }
                last_new_node = split;
            }

            _remaining_suffix_count--;

            if ((_active_node == _root) && (_active_length > 0)) {
                _active_length--;
                _active_edge = pos - _remaining_suffix_count + 1;
            } else if (_active_node != _root) {
                auto temp = _active_node->suffix_link;
                if (temp) {
                    _active_node = temp;
                } else {
                    _active_node = _root;
                }
            }
        }
    }

    void set_suffixindex(trienode* node, int height) {
        if (node) {
            for (auto child : node->children) {
                set_suffixindex(child.second, height + child.second->length());
            }
            if (node->children.empty()) {
                node->suffix_index = _source.size() - height;
            }
        }
    }

    void collect_suffix_indices(trienode* node, std::set<int>& result) {
        if (node) {
            if (-1 == node->suffix_index) {
                for (auto child : node->children) {
                    collect_suffix_indices(child.second, result);
                }
            } else {
                result.insert(node->suffix_index);
            }
        }
    }

    void dump(trienode* node, int level, dump_handler handler) {
        for (auto& child : node->children) {
            trienode* item = child.second;
            handler(&_source[item->start], item->length());
            dump(child.second, level + 1, handler);
        }
    }
    void debug(trienode* node, int level, debug_handler handler) {
        for (auto& child : node->children) {
            trienode* item = child.second;
            handler(node, level, &_source[item->start], item->length());
            debug(child.second, level + 1, handler);
        }
    }
};

/**
 * @brief   Aho-Corasick algorithm
 * @remarks
 *          multiple-patterns
 *              KMP O(n*k + m)
 *              Aho-Corasick O(n + m + z) ; z count of matches
 * @refer   https://www.javatpoint.com/aho-corasick-algorithm-for-pattern-searching-in-cpp
 *          unserstanding failure link and output
 *          https://daniel.lawrence.lu/blog/y2014m03d25/
 * @sample
 *          // search
 *          {
 *              t_aho_corasick ac;
 *              ac.insert("abc", 3);
 *              ac.insert("ab", 2);
 *              ac.insert("bc", 2);
 *              ac.insert("a", 1);
 *              ac.build();
 *              const char* text = "abcaabc";
 *              std::multimap<range_t, unsigned> result;
 *              result = ac.search(text, strlen(text));
 *              for (auto [range, pid] : result) {
 *                  _logger->writeln("pos [%zi..%zi] pattern[%i]", range.begin, range.end, pid);
 *              }
 *          }
 *          // using pointer
 *          {
 *              struct token { int type; };
 *              // lambda conversion - const T* to T* const*
 *              auto memberof = [](token* const* source, size_t idx) -> int {
 *                  const token* p = source[idx];
 *                  return p->type;
 *              };
 *              t_aho_corasick<int, token*> ac(memberof);
 *          }
 */
template <typename BT = char, typename T = BT>
class t_aho_corasick {
   public:
    typedef typename std::function<BT(const T* source, size_t idx)> memberof_t;

    /**
     * @brief   trie node structure
     */
    struct trienode {
        std::unordered_map<BT, trienode*> children;
        trienode* failure;
        std::set<unsigned> output;
        uint8 flag;  // reserved

        trienode() : failure(nullptr), flag(0) {}
        ~trienode() { clear(); }
        void clear() {
            for (auto item : children) {
                auto child = item.second;
                delete child;
            }
        }
    };

   public:
    t_aho_corasick(memberof_t memberof = memberof_defhandler<BT, T>) : _root(new trienode), _memberof(memberof) {}
    virtual ~t_aho_corasick() { dodestroy(); }

    /**
     * @brief   insert a pattern into the trie
     */
    void insert(const std::vector<T>& pattern) { doinsert(&pattern[0], pattern.size()); }
    void insert(const T* pattern, size_t size) { doinsert(pattern, size); }
    /**
     * @brief   build the Aho-Corasick finite state machine
     */
    void build() { dobuild(); }

    /**
     * @brief   search for patterns
     * @return  std::multimap<range_t, unsigned> as is multimap<pattern_id, position>
     *          pair(range_t, id_pattern)
     */
    std::multimap<range_t, unsigned> search(const std::vector<T>& source) {
        std::map<size_t, std::set<unsigned>> ordered;
        std::multimap<range_t, unsigned> result;
        dosearch(&source[0], source.size(), ordered);
        get_result(ordered, result);
        return result;
    }
    std::multimap<range_t, unsigned> search(const T* source, size_t size) {
        std::map<size_t, std::set<unsigned>> ordered;
        std::multimap<range_t, unsigned> result;
        dosearch(source, size, ordered);
        get_result(ordered, result);
        return result;
    }
    virtual size_t get_pattern_size(size_t index) {
        size_t size = 0;
        auto iter = _patterns.find(index);
        if (_patterns.end() != iter) {
            size = iter->second;
        }
        return size;
    }

    void reset() {
        delete _root;
        _root = new trienode;
        _patterns.clear();
    }

   protected:
    virtual void doinsert(const T* pattern, size_t size) {
        if (pattern) {
            trienode* current = _root;

            for (size_t i = 0; i < size; ++i) {
                const BT& t = _memberof(pattern, i);
                trienode* child = current->children[t];
                if (nullptr == child) {
                    child = new trienode;
                    current->children[t] = child;
                }
                current = child;
            }

            size_t index = _patterns.size();
            current->output.insert(index);
            _patterns.insert({index, size});
        }
    }
    virtual void dobuild() {
        std::queue<trienode*> q;

        // set failure links
        for (auto& pair : _root->children) {
            auto child = pair.second;
            child->failure = _root;
            q.push(child);
        }

        // Breadth-first traversal
        while (false == q.empty()) {
            trienode* current = q.front();
            q.pop();

            for (auto& pair : current->children) {
                const BT& key = pair.first;
                trienode* child = pair.second;
                trienode* failnode = current->failure;

                q.push(child);

                while ((failnode != _root) && (failnode->children.end() == failnode->children.find(key))) {
                    failnode = failnode->failure;
                }
                auto iter = failnode->children.find(key);
                if (failnode->children.end() == iter) {
                    child->failure = _root;
                } else {
                    child->failure = iter->second;
                }

                // merge output lists (pattern ids)
                for (auto item : child->failure->output) {
                    child->output.insert(item);  // cf. std::set merge c++17
                }
            }
        }
    }
    /**
     * @brief   search
     */
    virtual void dosearch(const T* source, size_t size, std::map<size_t, std::set<unsigned>>& result) {
        if (source) {
            trienode* current = _root;
            for (size_t i = 0; i < size; ++i) {
                const BT& t = _memberof(source, i);
                while ((current != _root) && (current->children.end() == current->children.find(t))) {
                    current = current->failure;
                }

                auto iter = current->children.find(t);
                if (current->children.end() != iter) {
                    current = iter->second;
                    collect_results(current, i, result);
                }
            }
        }
    }
    /*
     * @brief   collect results
     */
    virtual void collect_results(trienode* node, size_t pos, std::map<size_t, std::set<unsigned>>& result) {
        if (node) {
            for (auto v : node->output) {
                // pos is an end position of a pattern
                // v is an index of a pattern
                result[pos].insert(v);
            }
        }
    }
    virtual void get_result(const std::map<size_t, std::set<unsigned>>& ordered, std::multimap<range_t, unsigned>& result) {
        for (auto [pos, set] : ordered) {
            for (auto v : set) {
                // v is an index of a pattern
                // i is an end position of a pattern
                // (i - sizepat + 1) is beginning position of pattern
                range_t range;
                range.begin = pos - get_pattern_size(v) + 1;
                range.end = pos;
                result.insert({range, v});
            }
        }
    }

    virtual void dodestroy() { delete _root; }

    trienode* _root;
    std::unordered_map<size_t, size_t> _patterns;
    memberof_t _memberof;
};

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

/**
 * @brief   Aho Corasick + wildcard
 * @remarks
 *
 *          sketch ... aho corasick + wildcard
 *
 *          pattern
 *                  his her hers ?is h?r h*s
 *                  (0 his, 1 her, 2 hers, 3 ?is, 4 h?r, 5 ??s, 6 a?, 7 h*s)
 *          input
 *                  ahishers
 *          results
 *              results.single(?)
 *                  [01234567]
 *                   ahishers
 *                   a?              (0..1)(6)
 *                    his            (1..3)(0)
 *                    ?is            (1..3)(3)
 *                    ??s            (1..3)(5)
 *                       her         (4..6)(1)
 *                       h?r         (4..6)(4)
 *                       hers        (4..7)(2)
 *                        ??s        (5..7)(5)
 *              results.any(*)
 *                    h-s            (1..3)(7)
 *                       h--s        (4..7)(7)
 *
 * @sample
 *          // t_aho_corasick<char> ac(memberof_defhandler<char>);
 *          t_aho_corasick_wildcard<char> ac(memberof_defhandler<char>, '?', '*');
 *          // his her hers ?is h?r h*s
 *          ac.insert("his", 3);   // pattern 0
 *          ac.insert("her", 3);   // pattern 1
 *          ac.insert("hers", 4);  // pattern 2
 *          ac.insert("?is", 3);   // pattern 3
 *          ac.insert("h?r", 3);   // pattern 4
 *          ac.insert("??s", 3);   // pattern 5
 *          ac.insert("a?", 2);    // pattern 6
 *          ac.build();
 *          const char* source = "ahishers";
 *          std::multimap<size_t, unsigned> result;
 *          std::multimap<size_t, unsigned> expect =
 *              {{range_t(0, 1), 6}, {range_t(1, 3), 0}, {range_t(1, 3), 3}, {range_t(1, 3), 5},
 *               {range_t(4, 6), 1}, {range_t(4, 7), 2}, {range_t(4, 6), 4}, {range_t(5, 7), 5}}};
 *          result = ac.search(source, strlen(source));
 *          for (auto item : result) {
 *              _logger->writeln("pos [%zi] pattern[%i]", item.first, item.second);
 *          }
 *          _test_case.assert(result == expect, __FUNCTION__, "Aho Corasick algorithm + wildcards");
 */
template <typename BT = char, typename T = BT>
class t_aho_corasick_wildcard : public t_aho_corasick<BT, T> {
   public:
    typedef typename std::function<BT(const T* source, size_t idx)> memberof_t;
    typedef typename t_aho_corasick<BT, T>::trienode trienode;
    enum {
        flag_single = (1 << 0),
        flag_any = (1 << 1),
    };

   public:
    t_aho_corasick_wildcard(memberof_t memberof = memberof_defhandler<BT, T>, const BT& wildcard_single = BT(), const BT& wildcard_any = BT())
        : t_aho_corasick<BT, T>(memberof), _wildcard_single(wildcard_single), _wildcard_any(wildcard_any) {}

   protected:
    virtual void doinsert(const T* pattern, size_t size) {
        // sketch - same as t_aho_corasick<BT, T>::doinsert but added flag
        trienode* current = this->_root;
        bool has_any = false;

        for (size_t i = 0; i < size; ++i) {
            const BT& t = this->_memberof(pattern, i);

            if (_wildcard_single == t) {
                current->flag |= flag_single;
            } else if (_wildcard_any == t) {
                current->flag |= flag_any;
                has_any = true;
            }
            trienode* child = current->children[t];
            if (nullptr == child) {
                child = new trienode;
                current->children[t] = child;
            }
            current = child;
        }

        size_t index = this->_patterns.size();
        current->output.insert(index);
        this->_patterns.insert({index, size});

        // patterns containing a wildcard *
        if (has_any) {
            std::vector<BT> p;
            for (size_t i = 0; i < size; ++i) {
                const BT& t = this->_memberof(pattern, i);
                p.push_back(t);
            }
            _patterns_any.insert({index, std::move(p)});
        }
    }
    virtual void dosearch(const T* source, size_t size, std::map<size_t, std::set<unsigned>>& result) {
        if (source) {
            typedef std::pair<trienode*, size_t> pair_t;
            std::set<pair_t> visit;
            std::queue<pair_t> q;

            auto enqueue = [&](trienode* node, size_t idx) -> void {
                if (idx < size) {
                    pair_t p = {node, idx};
                    auto iter = visit.find(p);
                    if (visit.end() == iter) {
                        q.push(p);
                        visit.insert(p);
                    }
                }
            };

            enqueue(this->_root, 0);

            while (false == q.empty()) {
                auto [current, i] = q.front();
                visit.insert({current, i});
                q.pop();

                const BT& t = this->_memberof(source, i);
                auto rootiter = this->_root->children.find(t);
                if (this->_root->children.end() != rootiter) {
                    auto child = rootiter->second;
                    _node_pos[child].insert(i);
                }

                while ((current != this->_root) && (current->children.end() == current->children.find(t)) && (false == has_wildcard(current))) {
                    current = current->failure;
                }
                auto iter = current->children.find(t);
                if (current->children.end() != iter) {
                    // case - found t
                    auto node = iter->second;
                    this->collect_results(node, i, result);
                    enqueue(node, i + 1);

                    // case - sibling single/any
                    if (current->flag & flag_single) {
                        auto single = current->children[_wildcard_single];
                        enqueue(single, i + 1);
                    }
                    if (current->flag & flag_any) {
                        auto any = current->children[_wildcard_any];
                        while (any->flag & flag_any) {
                            any = any->children[_wildcard_any];
                        }
                        enqueue(any, i + 1);
                    }

                    // yield - case not t
                    auto fail = current->failure;
                    if (fail) {
                        if (fail->flag & flag_single) {
                            auto single = fail->children[_wildcard_single];
                            enqueue(single, i + 1);
                        }
                        if (fail->flag & flag_any) {
                            auto any = fail->children[_wildcard_any];
                            while (any->flag & flag_any) {
                                any = any->children[_wildcard_any];
                            }
                            enqueue(any, i + 1);
                        }
                    }
                } else if (has_wildcard(current)) {
                    // case - not t but single
                    if (current->flag & flag_single) {
                        auto single = current->children[_wildcard_single];
                        this->collect_results(single, i, result);
                        enqueue(single, i + 1);
                    }
                    if (current->flag & flag_any) {
                        enqueue(current, i + 1);

                        auto temp = current->children[_wildcard_any];
                        while (temp->flag & flag_any) {
                            temp = temp->children[_wildcard_any];
                        }

                        auto iter = temp->children.find(t);
                        if (temp->children.end() != iter) {
                            auto child = iter->second;
                            this->collect_results(child, i, result);
                            enqueue(child, i + 1);
                        }
                    }

                    // yield - case not t nor single
                    auto fail = current->failure;
                    if (fail) {
                        auto iter = fail->children.find(t);
                        if (fail->children.end() != iter) {
                            auto child = iter->second;
                            enqueue(child, i + 1);
                        }
                    }

                    // yield - root
                    enqueue(this->_root, i + 1);
                } else {
                    // yield - root
                    enqueue(this->_root, i + 1);
                }
            }
        }
    }

    virtual void get_result(const std::map<size_t, std::set<unsigned>>& ordered, std::multimap<range_t, unsigned>& result) {
        for (auto [pos, set] : ordered) {
            for (auto v : set) {
                range_t range;
                auto iter = _patterns_any.find(v);
                if (_patterns_any.end() == iter) {
                    range.begin = pos - this->get_pattern_size(v) + 1;
                    range.end = pos;

                    result.insert({range, v});
                } else {
                    // ahishers as an input
                    // 0 h*s, 1 r*s, 2 h*h*e, 3 s*s
                    //  h-s       (1..3)[0]
                    //  h--he     (1..5)[2]
                    //    s---s   (3..7)[3]
                    //     h--s   (4..7)[0]
                    //       rs   (6..7)[1]

                    const std::vector<BT>& pattern = iter->second;
                    const BT& t = pattern[0];
                    if (_wildcard_any == t) {
                        result.insert({range_t(0, pos), v});
                    } else {
                        trienode* node = this->_root->children[t];
                        int letters = 0;
                        for (auto c : pattern) {
                            if (c != _wildcard_any) {
                                letters++;
                            }
                        }
                        size_t p = 0;
                        find_lessthan_or_equal<size_t>(_node_pos[node], pos - letters + 1, p);
                        range.begin = p;
                        range.end = pos;
                        result.insert({range, v});
                    }
                }
            }
        }
    }

   private:
    bool has_wildcard(trienode* node) { return node->flag > 0; } /* check node->flag & (flag_single | flag_any) */
    BT _wildcard_single;
    BT _wildcard_any;

    // patterns containing a wildcard *
    std::map<unsigned, std::vector<BT>> _patterns_any;
    // starting position of a pattern containing a wildcard *
    std::map<trienode*, std::set<size_t>> _node_pos;
};

}  // namespace hotplace

#endif
