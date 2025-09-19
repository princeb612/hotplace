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

#ifndef __HOTPLACE_SDK_BASE_PATTERN_SUFFIXTREE__
#define __HOTPLACE_SDK_BASE_PATTERN_SUFFIXTREE__

#include <hotplace/sdk/base/pattern/pattern.hpp>

namespace hotplace {

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

}  // namespace hotplace

#endif
