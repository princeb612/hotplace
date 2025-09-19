/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_PATTERN_TRIE__
#define __HOTPLACE_SDK_BASE_PATTERN_TRIE__

#include <hotplace/sdk/base/pattern/pattern.hpp>

namespace hotplace {

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
template <typename BT = char, typename T = BT, typename TP = BT>
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
        BT value;
        trienode* parent;

        trienode() : eow(false), index(-1), value(BT()), parent(nullptr) {}
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

    t_trie(memberof_t memberof = memberof_defhandler<BT, T>) : _root(new trienode), _memberof(memberof) {}
    virtual ~t_trie() {
        delete _root;
        clear();
    }

    /**
     * @brief   add (autoindex, index start from 0)
     * @return  *this
     * @sa      insert
     * @sample
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
     *              trie.lookup(index, arr);
     *              auto rc = strncmp("hello", &arr[0], arr.size()); // 0
     *          }
     */
    t_trie<BT, T, TP>& add(const std::vector<T>& pattern, TP* tag = nullptr) {
        insert(&pattern[0], pattern.size(), -1, tag);
        return *this;
    }
    t_trie<BT, T, TP>& add(const T* pattern, size_t size, TP* tag = nullptr) {
        insert(pattern, size, -1, tag);
        return *this;
    }
    /**
     * @brief add (with index)
     */
    t_trie<BT, T, TP>& add(const std::vector<T>& pattern, int index, TP* tag = nullptr) {
        insert(&pattern[0], pattern.size(), index, tag);
        return *this;
    }
    t_trie<BT, T, TP>& add(const T* pattern, size_t size, int index, TP* tag = nullptr) {
        insert(pattern, size, index, tag);
        return *this;
    }
    /**
     * @brief   add
     * @return  trienode*
     * @sa      add
     */
    const trienode* insert(const std::vector<T>& pattern, int index = -1, TP* tag = nullptr) { return insert(&pattern[0], pattern.size(), tag); }
    const trienode* insert(const T* pattern, size_t size, int index = -1, TP* tag = nullptr) {
        trienode* current = _root;
        if (pattern) {
            for (size_t i = 0; i < size; ++i) {
                const BT& t = _memberof(pattern, i);
                trienode* child = current->children[t];
                if (nullptr == child) {
                    child = new trienode;
                    current->children[t] = child;

                    child->value = t;
                    child->parent = current;
                }
                current = child;
            }

            if (-1 == current->index) {
                size_t idx = 0;
                if (-1 == index) {
                    if (false == _rlookup.empty()) {
                        auto iter = _rlookup.rbegin();
                        idx = iter->first + 1;
                    }
                } else {
                    idx = index;
                }
                current->setindex(idx);
            }
            current->eow = true;
            _rlookup.insert({current->getindex(), current});
            settag(current, tag);
        }
        return current;
    }
    /**
     * @brief   search
     * @return  true/false
     * @sa      find
     */
    bool search(const std::vector<T>& pattern, TP** tag = nullptr) const { return search(&pattern[0], pattern.size(), tag); }
    bool search(const T* pattern, size_t size, TP** tag = nullptr) const {
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
    int find(const std::vector<T>& input, TP** tag = nullptr) const { return find(&input[0], input.size(), tag); }
    int find(const T* input, size_t size, TP** tag = nullptr) const {
        int index = -1;
        if (input) {
            trienode* current = _root;
            for (size_t i = 0; i < size; ++i) {
                const BT& t = _memberof(input, i);
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
     * @brief   scan first occurrence
     * @sample
     *          // huffman coding
     *          t_trie<char> trie;
     *          for (auto i = 0;; i++) {
     *              auto item = _h2hcodes + i;
     *              auto sym = item->sym;
     *              auto code = item->code;
     *              if (nullptr == code) {
     *                  break;
     *              }
     *              trie.insert(code, strlen(code), sym);
     *          }
     *
     *          // decode
     *          const char* sample = "...";
     *          size_t len = strlen(sample);
     *          int rc = 0;
     *          size_t pos = 0;
     *          basic_stream bs;
     *          while (true) {
     *              rc = trie.scan(sample, len, pos);
     *              if (-1 == rc) {
     *                  break;
     *              }
     *              bs << (char)rc;
     *          }
     */
    int scan(const T* input, size_t size, size_t& pos, TP** tag = nullptr) const {
        int index = -1;
        if (input) {
            trienode* current = _root;
            for (size_t i = pos; i < size; ++i) {
                const BT& t = _memberof(input, i);
                auto item = current->children.find(t);
                if (current->children.end() == item) {
                    pos = size;
                    return -1;  // not found
                }
                current = item->second;
                if (current->eow) {
                    gettag(current, tag);
                    index = current->index;
                    pos = i + 1;
                    break;
                }
            }
        }
        return index;
    }
    /**
     * @brief   prefix
     * @return  true/false
     */
    bool prefix(const std::vector<T>& input) const { return prefix(&input[0], input.size()); }
    bool prefix(const T* input, size_t size, bool* eow = nullptr, TP** tag = nullptr) const {
        bool ret = true;
        if (input) {
            trienode* current = _root;
            for (size_t i = 0; i < size; ++i) {
                const BT& t = _memberof(input, i);
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
    size_t lookup(const T* input, size_t size, TP** tag = nullptr) const {
        size_t len = 0;
        bool ret = true;
        bool eow = false;
        if (input) {
            trienode* current = _root;
            for (size_t i = 0; i < size; ++i) {
                const BT& t = _memberof(input, i);
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
     * @brief   pattern by index
     * @return  bool
     */
    bool lookup(int index, std::vector<BT>& pattern) const {
        bool ret = false;
        __try2 {
            pattern.clear();

            auto iter = _rlookup.find(index);
            if (_rlookup.end() == iter) {
                __leave2;
            }

            trienode* node = iter->second;
            while (node != _root) {
                pattern.insert(pattern.begin(), node->value);
                node = node->parent;
            }

            ret = true;
        }
        __finally2 {}
        return ret;
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

    t_trie<BT, T, TP>& reset() {
        if (_root->children.size()) {
            delete _root;
            _root = new trienode;
        }
        clear();
        return *this;
    }
    void clear() {
        for (auto item : _tags) {
            delete item.second;
        }
        _tags.clear();
        _rlookup.clear();
    }

    bool suggest(const std::vector<T>& input, dump_handler handler) const { return suggest(&input[0], input.size(), handler); }
    bool suggest(const T* input, size_t size, dump_handler handler) const {
        bool ret = true;
        if (input && handler) {
            trienode* current = _root;
            for (size_t i = 0; i < size; ++i) {
                const BT& t = _memberof(input, i);
                auto iter = current->children.find(t);
                if (current->children.end() == iter) {
                    return false;
                }
                current = iter->second;
            }
            if (current->islast()) {
                handler(input, size);
            } else {
                dump(current, input, size, handler);
            }
        } else {
            ret = false;
        }
        return ret;
    }

    void dump(dump_handler handler) const { dump(_root, nullptr, 0, handler); }

   protected:
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
    bool gettag(trienode* node, TP** tag) const {
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

   private:
    trienode* _root;
    memberof_t _memberof;
    std::unordered_map<int, TP*> _tags;  // index, tag*
    std::map<int, trienode*> _rlookup;   // index, trienode*
};

}  // namespace hotplace

#endif
