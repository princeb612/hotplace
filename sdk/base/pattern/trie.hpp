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

#ifndef __HOTPLACE_SDK_BASE_PATTERN_TRIE__
#define __HOTPLACE_SDK_BASE_PATTERN_TRIE__

#include <sdk/base/pattern/pattern.hpp>

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
                const BT& t = _memberof(pattern, i);
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
        auto node = searchindex(_root, index, prefix, arr);
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

}  // namespace hotplace

#endif
